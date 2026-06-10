#!/usr/bin/env node
// The bridge: the webtorrent-hybrid of this project. One side speaks real
// Bitcoin P2P over TCP (handshake and all, via the schema-driven P2pEngine);
// the other serves browser LightNodes over WebSocket, relaying the same
// wire messages — each complete peer message becomes one WS frame.
//
// Zero dependencies: the WebSocket server is codec/ws.js.
//
//   node bridge/bridge.js [--network mainnet|testnet4] [--port 8334] [--peer host[:port]]

import net from 'node:net';
import http from 'node:http';
import dns from 'node:dns/promises';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { P2pEngine } from '../codec/p2p.js';
import { attachWsServer } from '../codec/ws.js';

const here = new URL('..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, here), 'utf8'));

const SEEDS = {
  'btc:mainnet': { seed: 'seed.bitcoin.sipa.be', port: 8333 },
  'btc:testnet4': { seed: 'seed.testnet4.bitcoin.sprovoost.nl', port: 48333 },
};

// Commands a browser client may send toward the peer, and receive back.
const TO_PEER = new Set(['getheaders', 'getdata', 'ping']);
const FROM_PEER = new Set(['headers', 'block', 'tx', 'inv', 'notfound', 'pong']);

export class PeerConnection {
  constructor(engine, { onStatus = () => {} } = {}) {
    this.engine = engine;
    this.onStatus = onStatus;
    this.buffer = new Uint8Array(0);
    this.waiters = []; // FIFO: {commands:Set, resolve}
    this.peerVersion = null;
  }

  async connect(host, port) {
    this.socket = net.connect(port, host);
    await new Promise((resolve, reject) => {
      this.socket.once('connect', resolve);
      this.socket.once('error', reject);
    });
    this.socket.on('data', (d) => this.#onData(new Uint8Array(d)));
    this.socket.on('error', () => {});
    this.send('version', this.engine.buildVersion({ userAgent: '/bitcoin-schema-bridge:0.0.14/' }));
    await this.waitFor(['verack']);
    this.onStatus(`handshake complete: ${this.peerVersion?.userAgent} height ${this.peerVersion?.startHeight}`);
  }

  send(command, payload = null) {
    this.socket.write(this.engine.encodeMessage(command, payload));
  }

  sendRaw(bytes) { this.socket.write(bytes); }

  waitFor(commands, timeoutMs = 30000) {
    return new Promise((resolve, reject) => {
      const waiter = { commands: new Set(commands), resolve };
      this.waiters.push(waiter);
      setTimeout(() => {
        const i = this.waiters.indexOf(waiter);
        if (i >= 0) { this.waiters.splice(i, 1); reject(new Error(`timeout waiting for ${commands}`)); }
      }, timeoutMs).unref?.();
    });
  }

  #onData(bytes) {
    const merged = new Uint8Array(this.buffer.length + bytes.length);
    merged.set(this.buffer); merged.set(bytes, this.buffer.length);
    const { messages, consumed } = this.engine.decodeStream(merged);
    this.buffer = merged.slice(consumed);
    for (const msg of messages) this.#onMessage(msg, merged);
  }

  #onMessage(msg) {
    if (msg.command === 'version') {
      this.peerVersion = msg.payload;
      this.send('verack');
      return;
    }
    if (msg.command === 'ping') {
      this.send('pong', { nonce: msg.payload?.nonce ?? 0 });
      return;
    }
    const i = this.waiters.findIndex((w) => w.commands.has(msg.command));
    if (i >= 0) this.waiters.splice(i, 1)[0].resolve(msg);
    this.onMessage?.(msg);
  }
}

export async function startBridge({
  network = 'btc:mainnet',
  wsPort = 8334,
  peer = null,           // 'host[:port]' override
  log = console.error,
} = {}) {
  const p2pSchema = await load('schema/p2p.jsonld');
  const codec = new Codec(await load('schema/core.jsonld'), await load('schema/proof.jsonld'), p2pSchema);
  const chainSchema = await load('schema/chain.jsonld');
  const engine = P2pEngine.fromSchemas(codec, p2pSchema, chainSchema, network);

  let host, port;
  if (peer) {
    [host, port] = peer.split(':');
    port = parseInt(port ?? SEEDS[network].port, 10);
  } else {
    const { seed, port: p } = SEEDS[network];
    host = (await dns.resolve4(seed))[0];
    port = p;
  }
  const conn = new PeerConnection(engine, { onStatus: (s) => log(`[peer] ${s}`) });
  await conn.connect(host, port);
  log(`[bridge] connected to ${host}:${port} (${network})`);

  // serialize peer requests: the wire has no request ids
  let queue = Promise.resolve();
  const request = (rawBytes, replyCommands) => {
    const job = queue.then(async () => {
      conn.sendRaw(rawBytes);
      return conn.waitFor(replyCommands);
    });
    queue = job.catch(() => {});
    return job;
  };

  const httpServer = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json', 'access-control-allow-origin': '*' });
    res.end(JSON.stringify({
      bridge: 'bitcoin-schema', network,
      peer: `${host}:${port}`,
      peerAgent: conn.peerVersion?.userAgent,
      peerHeight: conn.peerVersion?.startHeight,
    }));
  });

  attachWsServer(httpServer, (client) => {
    log('[ws] client connected');
    client.onMessage(async (bytes) => {
      let msg;
      try { msg = engine.decodeMessage(bytes); } catch { client.close(); return; }
      if (!msg.checksumOk || !TO_PEER.has(msg.command)) return; // whitelist
      if (msg.command === 'ping') {
        client.send(engine.encodeMessage('pong', { nonce: msg.payload?.nonce ?? 0 }));
        return;
      }
      try {
        const reply = await request(bytes,
          msg.command === 'getheaders' ? ['headers'] : [...FROM_PEER]);
        // re-encode the decoded reply: one complete message per WS frame
        client.send(engine.encodeMessage(reply.command,
          reply.decoded ? reply.payload : reply.payload ?? null));
      } catch (e) {
        log(`[bridge] request failed: ${e.message}`);
      }
    });
    client.onClose(() => log('[ws] client disconnected'));
  });

  await new Promise((resolve) => httpServer.listen(wsPort, resolve));
  const actualPort = httpServer.address().port;
  log(`[bridge] ws://localhost:${actualPort} ready`);
  return {
    port: actualPort,
    peer: conn,
    close: () => { conn.socket.destroy(); httpServer.close(); },
  };
}

// CLI
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const opt = (name, dflt) => {
    const i = args.indexOf(`--${name}`);
    return i >= 0 ? args[i + 1] : dflt;
  };
  const network = { mainnet: 'btc:mainnet', testnet4: 'btc:testnet4' }[opt('network', 'mainnet')];
  startBridge({
    network,
    wsPort: parseInt(opt('port', '8334'), 10),
    peer: opt('peer', null),
  }).catch((e) => { console.error(e.message); process.exit(1); });
}
