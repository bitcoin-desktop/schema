// Lite-client tests: testnet4 consensus semantics (min-difficulty walk-back,
// BIP 94 retarget and timewarp) against real testnet4 headers, esplora
// header reconstruction, and the LightNode sync lifecycle.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { HeaderEngine } from '../codec/headers.js';
import { LightNode, MemoryStorage, EsploraSource } from '../codec/node.js';

const root = new URL('..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));

const codec = new Codec(await load('schema/core.jsonld'), await load('schema/proof.jsonld'));
const chainSchema = await load('schema/chain.jsonld');
const validateSchema = await load('schema/validate.jsonld');
const t4 = await load('test/vectors/testnet4.json');
const esploraVec = await load('test/vectors/esplora-header.json');

const params = chainSchema['@graph'].find((n) => n['@id'] === 'btc:testnet4');
const engine = HeaderEngine.fromSchemas(codec, chainSchema, validateSchema, 'btc:testnet4');
const dec = (hex) => codec.decode('BlockHeader', hex);

test('testnet4 genesis hash derives from our params', () => {
  const genesis = dec(t4.genesisHeader);
  assert.equal(codec.blockHash(genesis), params.genesisHash);
  assert.equal(params.genesisHash, t4.genesisHash);
  assert.ok(engine.checks['btc:rule-header-pow']({ header: genesis }));
});

test('BIP 94 retarget: epoch-first based, reproduced bit-for-bit', () => {
  const first = dec(t4.retarget.epochFirst);
  const last = dec(t4.retarget.epochLast);
  const next = dec(t4.retarget.next);
  const expected = engine.expectedBits(last, t4.retarget.epochLastHeight, first);
  assert.equal(expected, next.bits, 'real testnet4 retarget matches');
});

test('timewarp rule: real boundary passes, a warped one fails, mainnet skips', () => {
  const prev = dec(t4.retarget.epochLast);
  const next = dec(t4.retarget.next);
  const check = engine.checks['btc:rule-header-timewarp'];
  assert.equal(check({ header: next, prev, height: t4.retarget.nextHeight }), true);
  assert.equal(check({ header: { ...next, time: prev.time - 601 }, prev, height: t4.retarget.nextHeight }), false);
  assert.equal(check({ header: next, prev, height: t4.retarget.nextHeight + 1 }), true, 'non-boundary vacuous');
  const mainnetEngine = HeaderEngine.fromSchemas(codec, chainSchema, validateSchema, 'btc:mainnet');
  assert.equal(mainnetEngine.checks['btc:rule-header-timewarp']({ header: next, prev, height: 2016 }), null);
});

test('a real min-difficulty testnet4 run validates, including walk-backs', () => {
  const headers = t4.run.headers.map(dec);
  const powBits = engine.compactFromTarget(engine.powLimit);
  assert.ok(headers.some((h) => h.bits === powBits), 'run contains min-difficulty blocks');
  assert.ok(headers.some((h) => h.bits !== powBits), 'run contains real-difficulty blocks');
  const rows = engine.validateChain(headers.slice(11), {
    startHeight: t4.run.startHeight + 11,
    prevContext: headers.slice(0, 11),
    now: headers.at(-1).time + 7200,
  });
  for (const row of rows) {
    assert.equal(row.ok, true, `${row.height}: ${JSON.stringify(row.results.filter((r) => r.ok === false))}`);
    const diff = row.results.find((r) => r.label === 'difficulty');
    assert.equal(diff.ok, true, `difficulty decided at ${row.height} (not skipped)`);
  }
});

test('min-difficulty cheating is rejected: powLimit bits without the 20-minute gap', () => {
  const headers = t4.run.headers.map(dec);
  const powBits = engine.compactFromTarget(engine.powLimit);
  // find a real-difficulty header whose gap is small, then claim powLimit bits
  const i = headers.findIndex((h, idx) => idx > 11 && h.bits !== powBits
    && h.time <= headers[idx - 1].time + 2 * params.targetSpacing);
  assert.ok(i > 0, 'found a candidate');
  const tampered = headers.map((h, idx) => idx === i ? { ...h, bits: powBits } : h);
  const rows = engine.validateChain(tampered.slice(11), {
    startHeight: t4.run.startHeight + 11,
    prevContext: tampered.slice(0, 11),
    now: headers.at(-1).time + 7200,
  });
  const bad = rows.find((r) => r.height === t4.run.startHeight + i);
  assert.equal(bad.results.find((r) => r.label === 'difficulty').error, 'bad-diffbits');
});

test('esplora block JSON reconstructs a byte-exact, self-verified header', () => {
  const source = new EsploraSource('https://example.invalid', codec);
  const hex = source.headerFromBlockJson(esploraVec.block);
  assert.equal(codec.blockHash(codec.decode('BlockHeader', hex)), esploraVec.block.id);
  const lying = { ...esploraVec.block, nonce: esploraVec.block.nonce + 1 };
  assert.throws(() => source.headerFromBlockJson(lying), /inconsistent/);
});

// ---- LightNode lifecycle against a mock source serving the real run ----

class MockSource {
  constructor(startHeight, headerHexes, { tamperAt = null } = {}) {
    this.base = 'mock://';
    this.start = startHeight;
    this.headers = headerHexes;
    this.tamperAt = tamperAt;
  }
  async tipHeight() { return this.start + this.headers.length - 1; }
  async headersRange(start, count) {
    return Array.from({ length: count }, (_, i) => {
      const h = start + i;
      let hex = this.headers[h - this.start];
      if (h === this.tamperAt) hex = hex.slice(0, 8) + 'deadbeef' + hex.slice(16);
      return hex;
    });
  }
}

// a synthetic checkpoint at the start of the real run
const runCheckpoint = {
  height: t4.run.startHeight,
  rawHeader: t4.run.headers[0],
  hash: codec.blockHash(dec(t4.run.headers[0])),
};
const makeNode = (storage, sources) => new LightNode({
  codec, headerEngine: engine,
  storage, sources, checkpoint: runCheckpoint, batchSize: 25,
});

test('LightNode syncs the run from a checkpoint, validating every header', async () => {
  const storage = new MemoryStorage();
  const node = makeNode(storage, [new MockSource(t4.run.startHeight, t4.run.headers)]);
  await node.init();
  const progress = [];
  const status = await node.sync({ onProgress: (a, b) => progress.push([a, b]) });
  assert.equal(status.tipHeight, t4.run.startHeight + t4.run.headers.length - 1);
  assert.equal(status.tipHash, codec.blockHash(dec(t4.run.headers.at(-1))));
  assert.ok(progress.length >= 2, 'batched');
  assert.ok(BigInt('0x' + status.chainWork) > 0n);

  // persistence: a fresh node over the same storage resumes at the tip
  const resumed = makeNode(storage, []);
  const meta = await resumed.init();
  assert.equal(meta.tipHeight, status.tipHeight);
  assert.equal(meta.tipHash, status.tipHash);
});

test('LightNode rejects a tampered header mid-sync and keeps its valid tip', async () => {
  const tamperAt = t4.run.startHeight + 30;
  const node = makeNode(new MemoryStorage(),
    [new MockSource(t4.run.startHeight, t4.run.headers, { tamperAt })]);
  await node.init();
  await assert.rejects(() => node.sync(), /rejected/);
  assert.ok(node.meta.tipHeight < tamperAt, 'tip stops before the tampered header');
});

test('LightNode flags divergence between sources', async () => {
  const honest = new MockSource(t4.run.startHeight, t4.run.headers);
  const divergent = new MockSource(t4.run.startHeight, t4.run.headers, {
    tamperAt: t4.run.startHeight + t4.run.headers.length - 1 }); // disagrees at the tip
  divergent.base = 'mock://divergent';
  const node = makeNode(new MemoryStorage(), [honest, divergent]);
  await node.init();
  const status = await node.sync();
  assert.ok(status.divergence, 'divergence detected');
  assert.equal(status.divergence.source, 'mock://divergent');
});
