// Reorg walk-back (issue #38): a node whose tip was orphaned finds the
// fork point, demands more work, and reorganizes — or refuses loudly and
// stays untouched. Branches are MINED here, for real, on regtest (trivial
// PoW, ~2 tries per header), so every header on every branch passes the
// full ruleset — the same approach as the mining milestone's tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { HeaderEngine } from '../codec/headers.js';
import { LightNode, MemoryStorage } from '../codec/node.js';

const dep = (p) => readFile(new URL('../' + p, import.meta.url), 'utf8').then(JSON.parse);
const codec = new Codec(await dep('schema/core.jsonld'), await dep('schema/proof.jsonld'));
const chainSchema = await dep('schema/chain.jsonld');
const validateSchema = await dep('schema/validate.jsonld');
const engine = HeaderEngine.fromSchemas(codec, chainSchema, validateSchema, 'btc:regtest');
const regtest = chainSchema['@graph'].find((n) => n['@id'] === 'btc:regtest');

// regtest genesis, derived from our own params exactly as test/mine.test.js does
const mainGenesis = codec.decode('Block', (await dep('test/vectors/genesis-block.json')).hex);
const genesisHeader = { ...mainGenesis.header, time: 1296688602, bits: 0x207fffff, nonce: 2 };
const GENESIS_HEX = codec.encodeHex('BlockHeader', genesisHeader);
assert.equal(codec.blockHash(genesisHeader), regtest.genesisHash);

const TARGET = BigInt('0x' + regtest.powLimit);

function mineOn(prevHex, { merkle = 'aa'.repeat(32), dt = 600 } = {}) {
  const prev = codec.decode('BlockHeader', prevHex);
  const header = {
    version: 4, // BIP 34/66/65 are buried from the start on regtest
    prevBlockHash: codec.blockHash(prev),
    merkleRoot: merkle,
    time: prev.time + dt,
    bits: 0x207fffff,
    nonce: 0,
  };
  for (let nonce = 0; nonce <= 0xffffffff; nonce++) {
    header.nonce = nonce;
    if (BigInt('0x' + codec.blockHash(header)) <= TARGET) {
      return codec.encodeHex('BlockHeader', header);
    }
  }
  throw new Error('unminable');
}

// a freshly mined chain of `length` headers on top of `base`
function mineChain(base, length, opts = {}) {
  const out = [];
  let prev = base;
  for (let i = 0; i < length; i++) { prev = mineOn(prev, opts); out.push(prev); }
  return out;
}

class VectorSource {
  constructor(headers, claimTip = headers.length - 1) {
    this.headers = headers; this.claimTip = claimTip; this.base = 'vector://';
  }
  async tipHeight() { return this.claimTip; }
  async headersRange(start, count) { return this.headers.slice(start, start + count); }
}

const freshNode = (sources, opts = {}) => new LightNode({
  codec, headerEngine: engine, storage: new MemoryStorage(),
  sources, batchSize: 10, ...opts,
  checkpoint: { height: 0, rawHeader: GENESIS_HEX, hash: regtest.genesisHash },
});

// canonical chain A: genesis + 24 mined headers (heights 1-24), shared by tests
const A = [GENESIS_HEX, ...mineChain(GENESIS_HEX, 24)];

test('reorg: an orphaned tip walks back to the fork and follows the heavier branch', async () => {
  // branch B orphans the last two: b23/b24 mined on the real 22
  const B = [...A.slice(0, 23), ...mineChain(A[22], 2, { merkle: 'bb'.repeat(32) })];
  const node = freshNode([new VectorSource(B)]);
  await node.init();
  await node.sync();
  assert.equal(node.meta.tipHeight, 24);
  assert.equal(node.meta.tipHash, codec.blockHash(codec.decode('BlockHeader', B[24])), 'on the orphan branch');

  // the canonical chain pulls ahead: a25 mined on the real 24 (3 > 2 above the fork)
  const a25 = mineOn(A[24]);
  node.sources = [new VectorSource([...A, a25])];
  await node.sync();

  assert.equal(node.meta.tipHeight, 25, 'reorganized and extended');
  assert.equal(node.meta.tipHash, codec.blockHash(codec.decode('BlockHeader', a25)));
  assert.equal(codec.encodeHex('BlockHeader', await node.headerAt(23)), A[23], 'orphan replaced by canonical');

  // chainWork is exact: recompute the whole branch independently
  let work = 0n;
  for (let h = 0; h <= 25; h++) work += engine.work(await node.headerAt(h));
  assert.equal(work.toString(16), node.meta.chainWork);
});

// On constant-difficulty regtest any valid taller branch is also heavier,
// so the more-work bar cannot be tripped by construction here — it guards
// the variable-difficulty networks (retarget boundaries, testnet min-diff).
// What IS constructible: a source that lies about its tip.
test('refused: a source claiming a tip it cannot serve leaves the node untouched', async () => {
  const B = [...A.slice(0, 23), ...mineChain(A[22], 2, { merkle: 'bb'.repeat(32) })];
  const node = freshNode([new VectorSource(B)]);
  await node.init();
  await node.sync();
  const before = { ...node.meta };

  // claims tip 26, serves nothing above 23
  node.sources = [new VectorSource(A.slice(0, 24), 26)];
  await assert.rejects(() => node.sync(), /refusing/);
  assert.deepEqual(node.meta, before, 'node untouched after refusal');
});

test('reorg refused: disagreement beyond reorgDepth', async () => {
  // branch B orphans the last three; the node only allows walking back 2
  const B = [...A.slice(0, 22), ...mineChain(A[21], 3, { merkle: 'bb'.repeat(32) })];
  const node = freshNode([new VectorSource(B)], { reorgDepth: 2 });
  await node.init();
  await node.sync(); // tip 24 on the 3-orphan branch
  const before = { ...node.meta };

  const a25 = mineOn(A[24]);
  node.sources = [new VectorSource([...A, a25])]; // fork is 3 back, depth allows 2
  await assert.rejects(() => node.sync(), /beyond reorg depth/);
  assert.deepEqual(node.meta, before, 'node untouched');
});
