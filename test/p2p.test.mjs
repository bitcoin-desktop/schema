// P2P message layer tests, anchored by a real mainnet handshake our own
// engine performed over TCP (vector: p2p-handshake.json).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { P2pEngine } from '../codec/p2p.js';
import { bytesToHex, hexToBytes } from '../codec/hash.js';

const root = new URL('..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));

const p2pSchema = await load('schema/p2p.jsonld');
const codec = new Codec(await load('schema/core.jsonld'), await load('schema/proof.jsonld'), p2pSchema);
const engine = P2pEngine.fromSchemas(codec, p2pSchema, await load('schema/chain.jsonld'));

const handshake = await load('test/vectors/p2p-handshake.json');
const segwitTxHex = (await load('test/vectors/first-segwit-tx.json')).hex;
const genesisHash = '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f';

test('schema wiring: commands, flags, inventory types', () => {
  assert.ok(engine.commands.size >= 30);
  assert.equal(engine.commands.get('tx').structType, 'btc:Transaction');
  assert.equal(engine.commands.get('merkleblock').structType, 'btc:MerkleBlock');
  assert.ok(engine.commands.has('wtxidrelay'));
});

test('captured mainnet handshake: every message decodes with valid checksums', () => {
  const { messages, remainder } = engine.decodeStream(handshake.streamHex);
  assert.equal(remainder, 0, 'stream splits exactly');
  assert.deepEqual(messages.map((m) => m.command), handshake.expected.commands);
  for (const m of messages) {
    assert.equal(m.magicOk, true, m.command);
    assert.equal(m.checksumOk, true, m.command);
    assert.equal(m.known, true, m.command);
  }
  const version = messages.find((m) => m.command === 'version');
  assert.equal(version.decoded, true);
  assert.equal(version.payload.userAgent, handshake.expected.peerUserAgent);
  assert.equal(version.payload.version, handshake.expected.peerProtocolVersion);
  assert.ok(version.payload.startHeight > 900000);
});

test('captured handshake re-encodes byte-exactly, message by message', () => {
  const bytes = hexToBytes(handshake.streamHex);
  const { messages } = engine.decodeStream(bytes);
  let offset = 0;
  for (const m of messages) {
    const original = bytesToHex(bytes.subarray(offset, m.next));
    const re = m.decoded
      ? engine.encodeMessageHex(m.command, m.payload)
      : engine.encodeMessageHex(m.command, m.payload ?? null);
    assert.equal(re, original, m.command);
    offset = m.next;
  }
});

test('our own version message round-trips, including a > 2^53 nonce', () => {
  const v = engine.buildVersion({ nonce: '18446744073709551610', startHeight: 12345 });
  const wire = engine.encodeMessage('version', v);
  const back = engine.decodeMessage(wire);
  assert.equal(back.checksumOk, true);
  assert.equal(back.payload.nonce, '18446744073709551610', 'u64 precision preserved');
  assert.equal(back.payload.startHeight, 12345);
  assert.equal(back.payload.relay, 1);
  assert.equal(engine.encodeMessageHex('version', back.payload), bytesToHex(wire));
});

test('tx command carries the core Transaction struct unchanged', () => {
  const tx = codec.decode('Transaction', segwitTxHex);
  const wire = engine.encodeMessage('tx', tx);
  const back = engine.decodeMessage(wire);
  assert.equal(back.decoded, true);
  assert.equal(codec.txid(back.payload), codec.txid(tx));
  assert.equal(codec.encodeHex('Transaction', back.payload), segwitTxHex);
});

test('getheaders with a genesis locator round-trips', () => {
  const msg = { version: 70016, blockLocator: [genesisHash], hashStop: '0'.repeat(64) };
  const back = engine.decodeMessage(engine.encodeMessage('getheaders', msg));
  assert.deepEqual(back.payload, msg);
});

test('ping/pong nonce echo', () => {
  const wire = engine.encodeMessage('ping', { nonce: 42 });
  const ping = engine.decodeMessage(wire);
  const pong = engine.decodeMessage(engine.encodeMessage('pong', { nonce: ping.payload.nonce }));
  assert.equal(pong.payload.nonce, 42);
});

test('a corrupted byte fails the checksum', () => {
  const wire = engine.encodeMessage('ping', { nonce: 7 });
  wire[wire.length - 1] ^= 0xff;
  assert.equal(engine.decodeMessage(wire).checksumOk, false);
});

test('unknown commands keep their raw payload and re-encode byte-exactly', () => {
  const exotic = engine.encodeMessage('ping', { nonce: 1 });
  // rewrite the command field to something we do not model
  const mangled = hexToBytes(bytesToHex(exotic));
  const cmd = new TextEncoder().encode('frobnicate\0\0');
  mangled.set(cmd, 4);
  // checksum unchanged (payload identical), command unknown
  const m = engine.decodeMessage(mangled);
  assert.equal(m.known, false);
  assert.equal(m.checksumOk, true);
  assert.equal(engine.encodeMessageHex('frobnicate', m.payload), bytesToHex(mangled));
});

test('partial trailing message is left in the stream', () => {
  const full = engine.encodeMessage('ping', { nonce: 9 });
  const stream = new Uint8Array(full.length + 10);
  stream.set(full);
  stream.set(full.subarray(0, 10), full.length);
  const { messages, remainder } = engine.decodeStream(stream);
  assert.equal(messages.length, 1);
  assert.equal(remainder, 10);
});
