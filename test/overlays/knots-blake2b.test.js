// The Bitcoin Knots BLAKE2b overlay as the first consumer of the codec hooks:
// chain-scoped struct variants and a chain-declared proof-of-work hash.
// Proves (1) the base is untouched without the overlay, (2) the overlay is
// add-only, (3) Knots' own header vectors round-trip and hash exactly, and
// (4) real blocks from the live fork decode, hash, validate and weigh as the
// node says — the smoke test that started this, made permanent.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Codec } from '../../codec/codec.js';
import { HeaderEngine } from '../../codec/headers.js';
import { BlockEngine } from '../../codec/blocks.js';
import { mergeSchemas } from '../../codec/overlay.js';
import { registerKnotsBlake2b, hashHeaderV2Detailed, headerTime, POW_HASH_NAME } from '../../codec/pow/knots-header-v2.js';
import { bytesToHex, hexToBytes } from '../../codec/hash.js';

const root = new URL('../..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));
const core = await load('schema/core.jsonld');
const proof = await load('schema/proof.jsonld');
const chain = await load('schema/chain.jsonld');
const validate = await load('schema/validate.jsonld');
const script = await load('schema/script.jsonld');
const overlay = await load('schema/overlays/knots-blake2b.jsonld');
const vectors = (await load('test/vectors/knots/block_header_v2.json')).headers;
const anchors = await load('test/vectors/knots/testnet4-anchors.json');
const merged = mergeSchemas(chain, overlay);
const NET = 'btc:testnet4-blake2b';

const fresh = () => registerKnotsBlake2b(new Codec(core, proof, overlay));
const bound = () => { const c = fresh(); c.setChainParams(merged['@graph'].find((n) => n['@id'] === NET)); return c; };
const rev16 = (hex) => bytesToHex(hexToBytes(hex).reverse());
// Knots' vector fields (C++ names, GetHex order for the 128-bit ones) -> our object
const fromVector = (f) => ({
  version: (f.nVersion | 0x80000000) >>> 0, prevBlockHash: f.hashPrevBlock, merkleRoot: f.hashMerkleRoot,
  timeOnWire: f.m_flags & 4 ? (f.nTime - f.m_time_offset) >>> 0 : f.nTime, bits: f.nBits, nonce: f.nNonce,
  nonce2: f.m_nonce2, nonce3: f.m_nonce3, extranonce: rev16(f.m_extranonce), timeOffset: f.m_time_offset,
  txCount: f.m_txcount, flags: f.m_flags, xorKeyMaskClearBits: f.m_xor_key_mask_clear_bits,
  xorKey: rev16(f.m_xor_key), height: f.m_height, mmRhs: f.m_mm_rhs,
});

test('base model untouched: unbound codec knows only the 80-byte header and SHA256d', () => {
  const c = new Codec(core, proof);
  const v1 = anchors.headers[0];
  assert.equal(c.blockHash(c.decode('BlockHeader', v1.header)), v1.hash);
  assert.throws(() => c.decode('BlockHeader', anchors.headers[1].header), /84 trailing bytes/);
  assert.equal(c.chain, null);
  // even with the overlay's structs loaded, no chain binding => no variants
  assert.throws(() => fresh().decode('BlockHeader', anchors.headers[1].header), /84 trailing bytes/);
  // and bound to plain testnet4 (no variants declared) it is the same
  const t4 = fresh(); t4.setChainParams(merged['@graph'].find((n) => n['@id'] === 'btc:testnet4'));
  assert.throws(() => t4.decode('BlockHeader', anchors.headers[1].header), /84 trailing bytes/);
});

test('overlay is additive: adds two chains and one struct, resolves extends, refuses redefinition', () => {
  const ids = (g) => new Set(g['@graph'].map((n) => n['@id']));
  const before = ids(chain), after = ids(merged);
  for (const id of before) assert.ok(after.has(id));
  assert.equal(after.size, before.size + 3); // two chains + one struct
  const t4b = merged['@graph'].find((n) => n['@id'] === NET);
  assert.equal(t4b.genesisHash, chain['@graph'].find((n) => n['@id'] === 'btc:testnet4').genesisHash); // inherited
  assert.equal(t4b.powHash, POW_HASH_NAME);
  assert.equal(t4b.blake2bHeight, 150308);
  assert.ok(!('extends' in t4b));
  assert.throws(() => mergeSchemas(chain, { '@graph': [{ '@id': 'btc:mainnet', foo: 1 }] }), /redefines btc:mainnet/);
  assert.throws(() => mergeSchemas(chain, { '@graph': [{ '@id': 'x:y', extends: 'btc:nope' }] }), /extends unknown/);
  // the base graph object itself is not mutated
  assert.equal(chain['@graph'].length, before.size);
});

test("Knots' block_header_v2.json: every vector round-trips through the codec and hashes stage-for-stage", () => {
  const c = bound();
  let n = 0;
  for (const t of vectors) {
    const h = fromVector(t.fields);
    const hex = bytesToHex(c.encode('BlockHeader', h));
    assert.equal(hex, t.serialized, `${t.name}: encode`);
    assert.deepEqual(c.decode('BlockHeader', t.serialized), h, `${t.name}: decode`);
    const d = hashHeaderV2Detailed(h);
    for (const [ours, theirs] of [['xorKeyHash', 'xor_key_hash'], ['h1', 'h1'], ['h2', 'h2'], ['blake2b1', 'blake2b_1'],
      ['blake2b2', 'blake2b_2'], ['mask', 'mask'], ['asicInput', 'asic_input'], ['blockHash', 'block_hash']]) {
      assert.equal(d[ours], t[theirs], `${t.name}: ${ours}`);
    }
    assert.equal(d.asicProfile, t.asic_profile);
    assert.equal(c.blockHash(h), t.block_hash, `${t.name}: codec.blockHash`);
    assert.equal(headerTime(h), t.fields.nTime, `${t.name}: time`);
    n++;
  }
  assert.ok(n >= 4, `ran ${n} vectors`);
});

test('live testnet4-blake2b anchors: pre-fork v1 header is SHA256d, v2 headers are BLAKE2b, PoW holds', () => {
  const c = bound();
  for (const a of anchors.headers) {
    const h = c.decode('BlockHeader', a.header);
    assert.equal(bytesToHex(c.encode('BlockHeader', h)), a.header, `${a.height}: round-trip`);
    assert.equal(c.blockHash(h), a.hash, `${a.height}: hash`);
    assert.ok(c.checkProofOfWork(h), `${a.height}: pow`);
    if (a.height >= 150308) assert.equal(h.height, a.height, 'committed height');
  }
});

test('a real post-fork block decodes, hashes, weighs and validates as the node says', () => {
  const c = bound();
  const be = BlockEngine.fromSchemas(c, merged, validate, script, NET);
  const b = c.decode('Block', anchors.block.raw);
  assert.equal(c.blockHash(b.header), anchors.block.hash);
  assert.deepEqual(b.transactions.map((t) => c.txid(t)), anchors.block.txids);
  assert.equal(c.merkleRoot(b.transactions.map((t) => c.txid(t))), anchors.block.merkleroot);
  assert.equal(be.blockWeight(b), anchors.block.weight); // 164-byte header counted, no special case
  assert.equal(b.header.txCount, b.transactions.length);
  const s = be.validateBlockStructure(b);
  assert.ok(s.ok, JSON.stringify(s.results.filter((r) => !r.ok)));
  assert.equal(bytesToHex(c.encode('Block', b)), anchors.block.raw);
});

test('HeaderEngine.fromSchemas binds the codec to the chain (prev-link and PoW rules see BLAKE2b hashes)', () => {
  const c = fresh();
  const he = HeaderEngine.fromSchemas(c, merged, validate, NET);
  assert.equal(c.chain['@id'], NET);
  const [prev, cur] = anchors.headers.slice(1).map((a) => c.decode('BlockHeader', a.header));
  assert.equal(he.checks['btc:rule-header-pow']({ header: cur }), true);
  const fork = c.decode('BlockHeader', anchors.headers[1].header);
  const last = c.decode('BlockHeader', anchors.headers[0].header);
  assert.equal(he.checks['btc:rule-header-prev-link']({ header: fork, prev: last }), true); // v2 links to a v1 parent
  assert.throws(() => HeaderEngine.fromSchemas(new Codec(core, proof), chain, validate, 'btc:nope'), /unknown network/);
});
