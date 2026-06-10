// SPV engine tests: BIP 37 merkleblock round-trips and proof verification
// against real mainnet proofs.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { SpvEngine } from '../codec/spv.js';

const root = new URL('..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));

const codec = new Codec(await load('schema/core.jsonld'), await load('schema/proof.jsonld'));
const engine = SpvEngine.fromSchemas(codec, await load('schema/validate.jsonld'));

const deepProof = await load('test/vectors/merkleblock-first-segwit.json');
const shallowProof = await load('test/vectors/merkleblock-block100000.json');
const genesis = await load('test/vectors/genesis-block.json');

test('schema wiring: spv ruleset loads with bound checks', () => {
  assert.equal(engine.ruleSet.rules.length, 4);
  assert.ok(engine.ruleSet.rules.every((r) => engine.checks[r['@id']]));
});

for (const vector of [deepProof, shallowProof]) {
  test(`${vector.name}: byte-exact re-encode`, () => {
    const mb = codec.decode('MerkleBlock', vector.hex);
    assert.equal(codec.encodeHex('MerkleBlock', mb), vector.hex);
  });

  test(`${vector.name}: proof verifies, tx matched at expected position`, () => {
    const mb = codec.decode('MerkleBlock', vector.hex);
    const verdict = engine.verify(mb, { txid: vector.txid });
    assert.equal(verdict.ok, true, JSON.stringify(verdict.results));
    assert.equal(verdict.root, mb.header.merkleRoot);
    const match = verdict.matches.find((m) => m.txid === vector.txid);
    assert.equal(match.index, vector.expected.position);
  });
}

test('wrong txid fails only the inclusion rule', () => {
  const mb = codec.decode('MerkleBlock', deepProof.hex);
  const verdict = engine.verify(mb, { txid: shallowProof.txid });
  assert.equal(verdict.ok, false);
  const byLabel = Object.fromEntries(verdict.results.map((r) => [r.label, r]));
  assert.equal(byLabel['inclusion'].error, 'tx-not-included');
  assert.equal(byLabel['merkle-root'].ok, true);
  assert.equal(byLabel['proof-of-work'].ok, true);
});

test('tampered proof hash fails merkle-root with bad-txnmrklroot', () => {
  const mb = codec.decode('MerkleBlock', deepProof.hex);
  const tampered = mb.hashes[0].replace(/^../, mb.hashes[0].startsWith('00') ? 'ff' : '00');
  mb.hashes = [tampered, ...mb.hashes.slice(1)];
  const verdict = engine.verify(mb, { txid: deepProof.txid });
  assert.equal(verdict.ok, false);
  assert.ok(verdict.results.some((r) => r.error === 'bad-txnmrklroot'));
});

test('truncated flags fail tree-consistency with bad-merkle-tree', () => {
  const mb = codec.decode('MerkleBlock', deepProof.hex);
  mb.flags = '';
  const verdict = engine.verify(mb, { txid: deepProof.txid });
  assert.ok(verdict.results.some((r) => r.error === 'bad-merkle-tree'));
});

test('synthetic single-tx proof: genesis coinbase', () => {
  // In a single-transaction block the merkle root IS the txid; the proof is
  // one hash and one set flag bit. Built by hand, round-tripped, verified.
  const block = codec.decode('Block', genesis.hex);
  const txid = codec.txid(block.transactions[0]);
  const mb = { header: block.header, txCount: 1, hashes: [txid], flags: '01' };
  const decoded = codec.decode('MerkleBlock', codec.encodeHex('MerkleBlock', mb));
  const verdict = engine.verify(decoded, { txid });
  assert.equal(verdict.ok, true, JSON.stringify(verdict.results));
  assert.equal(verdict.root, block.header.merkleRoot);
  assert.deepEqual(verdict.matches, [{ txid, index: 0 }]);
});
