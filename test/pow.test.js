// Proof-of-work target range checks.
//
// Negative vectors: each nBits below is one Bitcoin Core's CheckProofOfWork
// rejects before it ever compares the hash. Asserting rejections is the point —
// a suite that only confirms valid data validates cannot catch a validator
// that is too permissive, and accepts-invalid is the dangerous direction.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { HeaderEngine } from '../codec/headers.js';
import { SpvEngine } from '../codec/spv.js';

const root = new URL('..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));

const codec = new Codec(await load('schema/core.jsonld'), await load('schema/proof.jsonld'));
const chain = await load('schema/chain.jsonld');
const validate = await load('schema/validate.jsonld');
// binds the mainnet powLimit onto the codec
HeaderEngine.fromSchemas(codec, chain, validate);
const spv = SpvEngine.fromSchemas(codec, validate);

const genesis = {
  version: 1,
  prevBlockHash: '0'.repeat(64),
  merkleRoot: '4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b',
  time: 1231006505,
  bits: 0x1d00ffff,
  nonce: 2083236893,
};

test('genesis header passes proof of work', () => {
  assert.equal(codec.blockHash(genesis),
    '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
  assert.equal(codec.checkProofOfWork(genesis), true);
});

test('target above powLimit is rejected', () => {
  // regtest-style target, evaluated against mainnet params
  const h = { ...genesis, merkleRoot: 'de'.repeat(32), nonce: 1, bits: 0x207fffff };
  assert.equal(codec.checkProofOfWork(h), false);
});

test('overflowing nBits is rejected', () => {
  assert.equal(codec.expandCompactChecked(0xff123456).overflow, true);
  assert.equal(codec.checkProofOfWork(
    { ...genesis, merkleRoot: 'de'.repeat(32), nonce: 1, bits: 0xff123456 }), false);
});

test('negative nBits is rejected', () => {
  assert.equal(codec.expandCompactChecked(0x1d80ffff).negative, true);
  assert.equal(codec.checkProofOfWork({ ...genesis, bits: 0x1d80ffff }), false);
});

test('zero target is rejected', () => {
  assert.equal(codec.checkProofOfWork({ ...genesis, nonce: 1, bits: 0x03000000 }), false);
});

test('SetCompact overflow boundaries match Core', () => {
  // overflow iff word != 0 and
  // (size > 34) || (word > 0xff && size > 33) || (word > 0xffff && size > 32)
  const ov = (b) => codec.expandCompactChecked(b).overflow;
  assert.equal(ov(0x00123456), false); // size 0
  assert.equal(ov(0x20ffffff), false); // size 32, at the limit
  assert.equal(ov(0x21ffffff), true);  // size 33, word > 0xffff
  assert.equal(ov(0x2200ffff), true);  // size 34, word > 0xff
  assert.equal(ov(0x23000001), true);  // size 35
  assert.equal(ov(0xff000000), false); // word == 0 never overflows
});

test('a forged SPV inclusion proof is rejected', () => {
  // The regression this file exists for: fabricate a block containing a
  // transaction that was never mined, do no work, and claim inclusion.
  const fakeTxid = 'ba'.repeat(32);
  const header = {
    version: 1, prevBlockHash: '0'.repeat(64), merkleRoot: fakeTxid,
    time: 1700000000, bits: 0x207fffff, nonce: 1,
  };
  const res = spv.verify({ header, txCount: 1, hashes: [fakeTxid], flags: '01' },
    { txid: fakeTxid });
  const pow = res.results.find((r) => r.rule === 'btc:rule-spv-pow');
  assert.equal(pow.ok, false, 'btc:rule-spv-pow must reject an out-of-range target');
  assert.equal(res.ok, false, 'the forged proof must not verify');
});

test('real mainnet proofs still verify', async () => {
  for (const f of ['merkleblock-block100000', 'merkleblock-first-segwit']) {
    const v = await load(`test/vectors/${f}.json`);
    const res = spv.verify(codec.decode('MerkleBlock', v.hex), { txid: v.txid });
    assert.equal(res.ok, true, `${f} must still verify`);
  }
});

test('universal checks apply even without chain params', () => {
  const bare = new Codec();
  assert.equal(bare.powLimit, null);
  assert.equal(bare.expandCompactChecked(0xff123456).overflow, true);
  assert.equal(bare.checkProofOfWork({ ...genesis, bits: 0xff123456 }), false);
});
