// Pay-to-anchor (BIP 431): OP_1 <0x4e73>, the 2-byte witness v1 program that
// anyone can spend with an empty witness. Classification and address on both
// networks, then real spends from the BLAKE2b testnet4 chain through
// verifyInput, and the edges Core draws: empty witness only, bare only.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createKernel } from '../codec/kernel.js';
import { knotsBlake2b } from '../codec/overlays/knots-blake2b.js';

const root = new URL('..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));
const schemas = { core: await load('schema/core.jsonld'), proof: await load('schema/proof.jsonld'), script: await load('schema/script.jsonld'), chain: await load('schema/chain.jsonld'), validate: await load('schema/validate.jsonld') };
const mainnet = createKernel({ ...schemas, network: 'btc:mainnet' });
const overlay = knotsBlake2b(await load('schema/overlays/knots-blake2b.jsonld'));
const txbt4 = createKernel({ ...schemas, network: 'btc:testnet4-blake2b', overlays: [overlay] });
const spends = (await load('test/vectors/anchor-spends.json')).spends;

test('anchor: classification and address, mainnet and testnet', () => {
  const m = mainnet.script.classify('51024e73');
  assert.equal(m.type, 'anchor');
  assert.equal(m.address, 'bc1pfeessrawgf'); // Core's address for the anchor
  const t = txbt4.script.classify('51024e73');
  assert.equal(t.type, 'anchor');
  assert.equal(t.address, 'tb1pfees9rn5nz');
  assert.equal(mainnet.script.classify('51024e74').type, 'nonstandard'); // another 2-byte program is not an anchor
  assert.equal(mainnet.script.classify('51034e7300').type, 'nonstandard');
  assert.equal(mainnet.script.classify('51204e73' + '00'.repeat(30)).type, 'p2tr');
});

test('anchor: real txbt4 spends verify, the anchor input by the anyone-can-spend rule', () => {
  for (const s of spends) {
    const tx = txbt4.codec.decode('Transaction', s.hex);
    assert.equal(txbt4.codec.txid(tx), s.txid);
    const prevouts = s.prevouts.map(({ value, scriptPubKey }) => ({ value, scriptPubKey }));
    const anchorIn = s.prevouts.findIndex((p) => p.type === 'anchor');
    assert.deepEqual(tx.witness[anchorIn], []);
    tx.inputs.forEach((_, i) => {
      const v = txbt4.interpreter.verifyInput(tx, i, prevouts[i], prevouts, null, { unifiedSighash: true });
      assert.equal(v.ok, true, `${s.txid} input ${i}: ${v.error ?? v.reason}`);
      assert.equal(v.type, i === anchorIn ? 'anchor' : 'p2tr');
      if (i === anchorIn) assert.equal(v.path, 'anchor');
    });
    // policy flags do not discourage it, unlike other unknown programs
    const flags = new Set(['P2SH', 'WITNESS', 'TAPROOT', 'DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM', 'CLEANSTACK']);
    assert.equal(txbt4.interpreter.verifyInput(tx, anchorIn, prevouts[anchorIn], prevouts, flags).ok, true);
    // a witness on an anchor is not the anchor rule: unknown program, discouraged under the flag
    const stuffed = { ...tx, witness: tx.witness.map((w, i) => (i === anchorIn ? ['00'] : w)) };
    assert.equal(txbt4.interpreter.verifyInput(stuffed, anchorIn, prevouts[anchorIn], prevouts).ok, null);
    assert.equal(txbt4.interpreter.verifyInput(stuffed, anchorIn, prevouts[anchorIn], prevouts, flags).ok, false);
    // any other 2-byte v1 program stays honestly unknown
    const other = { ...prevouts[anchorIn], scriptPubKey: '51024e74' };
    assert.equal(txbt4.interpreter.verifyInput(tx, anchorIn, other, prevouts).ok, null);
  }
});
