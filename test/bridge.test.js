// Bridge tests: WebSocket framing, and the whole webtorrent-hybrid pipeline
// in-process with zero network — a mock TCP peer (built on our own
// P2pEngine) serving real testnet4 headers, the bridge in the middle, and a
// LightNode syncing through a BridgeSource over a real WebSocket.

import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { P2pEngine } from '../codec/p2p.js';
import { HeaderEngine } from '../codec/headers.js';
import { LightNode, MemoryStorage, BridgeSource } from '../codec/node.js';
import { acceptKey, encodeFrame, FrameParser } from '../codec/ws.js';
import { startBridge } from '../bridge/bridge.js';

const root = new URL('..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));

const p2pSchema = await load('schema/p2p.jsonld');
const chainSchema = await load('schema/chain.jsonld');
const validateSchema = await load('schema/validate.jsonld');
const codec = new Codec(await load('schema/core.jsonld'), await load('schema/proof.jsonld'), p2pSchema);
const engine = P2pEngine.fromSchemas(codec, p2pSchema, chainSchema, 'btc:testnet4');
const headerEngine = HeaderEngine.fromSchemas(codec, chainSchema, validateSchema, 'btc:testnet4');
const t4 = await load('test/vectors/testnet4.json');

test('ws framing: accept key and frame round-trips at every size class', () => {
  // RFC 6455's worked example
  assert.equal(acceptKey('dGhlIHNhbXBsZSBub25jZQ=='), 's3pPLMBiTxaQ9kYGzzhZRbK+xOo=');
  for (const n of [0, 1, 125, 126, 65535, 65536, 200000]) {
    const payload = new Uint8Array(n).map((_, i) => i & 0xff);
    const parser = new FrameParser();
    // simulate trickled TCP delivery
    const frame = encodeFrame(payload);
    const mid = Math.floor(frame.length / 2);
    let messages = parser.feed(frame.subarray(0, mid));
    messages = messages.concat(parser.feed(frame.subarray(mid)));
    assert.equal(messages.length, 1, `n=${n}`);
    assert.deepEqual(messages[0].payload, payload, `n=${n}`);
  }
});

// ---- a mock Bitcoin peer speaking the real wire protocol over TCP ----

function startMockPeer({ headers, startHeight, tamperAt = null }) {
  const hashes = headers.map((hex) => codec.blockHash(codec.decode('BlockHeader', hex)));
  const server = net.createServer((socket) => {
    let buffer = new Uint8Array(0);
    socket.on('data', (data) => {
      const merged = new Uint8Array(buffer.length + data.length);
      merged.set(buffer); merged.set(new Uint8Array(data), buffer.length);
      const { messages, consumed } = engine.decodeStream(merged);
      buffer = merged.slice(consumed);
      for (const msg of messages) {
        if (msg.command === 'version') {
          socket.write(engine.encodeMessage('version', engine.buildVersion({
            userAgent: '/mock-peer:1.0/', startHeight: startHeight + headers.length - 1 })));
          socket.write(engine.encodeMessage('verack'));
        } else if (msg.command === 'getheaders') {
          const locator = msg.payload.blockLocator[0];
          const i = hashes.indexOf(locator);
          const entries = (i < 0 ? [] : headers.slice(i + 1, i + 1 + 2000))
            .map((hex, j) => {
              let h = hex;
              if (tamperAt != null && startHeight + i + 1 + j === tamperAt) {
                h = h.slice(0, 8) + 'deadbeef' + h.slice(16);
              }
              return { header: codec.decode('BlockHeader', h), txCount: 0 };
            });
          socket.write(engine.encodeMessage('headers', { entries }));
        } else if (msg.command === 'ping') {
          socket.write(engine.encodeMessage('pong', { nonce: msg.payload.nonce }));
        }
      }
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () =>
    resolve({ port: server.address().port, close: () => server.close() })));
}

const runCheckpoint = {
  height: t4.run.startHeight,
  rawHeader: t4.run.headers[0],
  hash: codec.blockHash(codec.decode('BlockHeader', t4.run.headers[0])),
};

test('full pipeline: mock peer <- TCP - bridge - WebSocket -> LightNode syncs and validates', async () => {
  const peer = await startMockPeer({ headers: t4.run.headers, startHeight: t4.run.startHeight });
  const bridge = await startBridge({
    network: 'btc:testnet4', wsPort: 0,
    peer: `127.0.0.1:${peer.port}`, log: () => {},
  });
  try {
    assert.equal(bridge.peer.peerVersion.userAgent, '/mock-peer:1.0/', 'real handshake happened');

    const source = new BridgeSource(`ws://127.0.0.1:${bridge.port}`, codec, engine);
    const node = new LightNode({
      codec, headerEngine, storage: new MemoryStorage(),
      sources: [], checkpoint: runCheckpoint,
    });
    await node.init();
    const status = await node.syncP2p(source);
    source.close();

    assert.equal(status.tipHeight, t4.run.startHeight + t4.run.headers.length - 1);
    assert.equal(status.tipHash,
      codec.blockHash(codec.decode('BlockHeader', t4.run.headers.at(-1))));
    assert.equal(status.headersStored, t4.run.headers.length);
  } finally {
    bridge.close();
    peer.close();
  }
});

test('full pipeline: a tampering peer is caught by the LightNode rules', async () => {
  const tamperAt = t4.run.startHeight + 20;
  const peer = await startMockPeer({
    headers: t4.run.headers, startHeight: t4.run.startHeight, tamperAt });
  const bridge = await startBridge({
    network: 'btc:testnet4', wsPort: 0,
    peer: `127.0.0.1:${peer.port}`, log: () => {},
  });
  try {
    const source = new BridgeSource(`ws://127.0.0.1:${bridge.port}`, codec, engine);
    const node = new LightNode({
      codec, headerEngine, storage: new MemoryStorage(),
      sources: [], checkpoint: runCheckpoint,
    });
    await node.init();
    await assert.rejects(() => node.syncP2p(source), /rejected/);
    assert.ok(node.meta.tipHeight < tamperAt, 'valid tip retained');
    source.close();
  } finally {
    bridge.close();
    peer.close();
  }
});
