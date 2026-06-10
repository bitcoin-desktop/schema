// BIP 158 compact filter tests against the official testnet vectors, plus
// membership semantics on the mainnet pruned window.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { GcsFilter, siphash } from '../codec/filters.js';
import { P2pEngine } from '../codec/p2p.js';
import { bytesToHex, hexToBytes } from '../codec/hash.js';

const root = new URL('..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));

const codec = new Codec(await load('schema/core.jsonld'));
const gcs = new GcsFilter();
const bip158 = await load('test/vectors/bip158.json');
const window100k = await load('test/vectors/pruned-window-100000.json');

test('siphash sanity: keyed and length-sensitive', () => {
  const key = new Uint8Array(16).fill(7);
  const a = siphash(key, new TextEncoder().encode('hello'));
  const b = siphash(key, new TextEncoder().encode('hello!'));
  const c = siphash(new Uint8Array(16).fill(8), new TextEncoder().encode('hello'));
  assert.notEqual(a, b);
  assert.notEqual(a, c);
});

test('official BIP 158 vectors: filters built from raw blocks match byte-exactly', () => {
  for (const v of bip158.vectors) {
    const block = codec.decode('Block', v.rawBlock);
    assert.equal(codec.blockHash(block.header), v.blockHash, `block hash @${v.height}`);
    const key = gcs.keyFor(v.blockHash);
    const filter = gcs.encode(key, gcs.basicItems(block, v.prevOutputScripts));
    assert.equal(bytesToHex(filter), v.filter, `filter @${v.height} (${v.notes})`);
  }
});

test('official BIP 158 vectors: filter-header chain matches', () => {
  for (const v of bip158.vectors) {
    assert.equal(gcs.filterHeader(hexToBytes(v.filter), v.prevFilterHeader),
      v.filterHeader, `header @${v.height}`);
  }
});

test('mainnet window: every created script matches its block filter; a stranger does not', () => {
  const external = new Map(
    Object.entries(window100k.prevTxs).map(([txid, hex]) => [txid, codec.decode('Transaction', hex)]));
  const windowTx = new Map();
  const blocks = window100k.blocks.map((hex) => codec.decode('Block', hex));
  for (const b of blocks) for (const tx of b.transactions) windowTx.set(codec.txid(tx), tx);

  const stranger = hexToBytes('0014' + 'ab'.repeat(20)); // not in 2010 blocks
  for (const block of blocks) {
    const prevScripts = block.transactions.slice(1).flatMap((tx) =>
      tx.inputs.map((inp) => {
        const prev = windowTx.get(inp.prevout.txid) ?? external.get(inp.prevout.txid);
        return prev.outputs[inp.prevout.vout].scriptPubKey;
      }));
    const key = gcs.keyFor(codec.blockHash(block.header));
    const filter = gcs.encode(key, gcs.basicItems(block, prevScripts));

    for (const tx of block.transactions) {
      for (const out of tx.outputs) {
        assert.equal(gcs.matchAny(key, filter, [hexToBytes(out.scriptPubKey)]), true,
          `created script matches its filter`);
      }
    }
    assert.equal(gcs.matchAny(key, filter, [stranger]), false, 'stranger script absent');
    assert.ok(filter.length < codec.encode('Block', block).length / 10,
      'filter is a small fraction of the block');
  }
});

test('empty filter matches nothing', () => {
  const key = new Uint8Array(16);
  const filter = gcs.encode(key, []);
  assert.equal(filter[0], 0);
  assert.equal(gcs.matchAny(key, filter, [hexToBytes('51')]), false);
});

test('cfilter p2p message carries a real filter round-trip', async () => {
  const p2pSchema = await load('schema/p2p.jsonld');
  const engine = P2pEngine.fromSchemas(
    new Codec(await load('schema/core.jsonld'), p2pSchema),
    p2pSchema, await load('schema/chain.jsonld'));
  const v = bip158.vectors.at(-1);
  const wire = engine.encodeMessage('cfilter', {
    filterType: 0, blockHash: v.blockHash, filter: v.filter,
  });
  const back = engine.decodeMessage(wire);
  assert.equal(back.checksumOk, true);
  assert.equal(back.payload.blockHash, v.blockHash);
  assert.equal(back.payload.filter, v.filter);
  assert.equal(gcs.filterHeader(hexToBytes(back.payload.filter), v.prevFilterHeader), v.filterHeader);
});
