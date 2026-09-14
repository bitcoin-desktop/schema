// Bitcoin Knots' unified opt-in signature hash (SIGHASH_UNIFIED, 0x20; PR 357,
// doc/unified-sighash.md): the 166 Knots vectors across all four script types,
// then real txbt4 spends that only verify under it, and the block rule gating
// it at the fork height through the overlay's unifiedSighashParam.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createKernel } from '../../codec/kernel.js';
import { knotsBlake2b } from '../../codec/overlays/knots-blake2b.js';
import { compactSize, SIGHASH_UNIFIED } from '../../codec/interpreter.js';
import { taggedHash, hexToBytes, bytesToHex } from '../../codec/hash.js';

const root = new URL('../..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));
const schemas = { core: await load('schema/core.jsonld'), proof: await load('schema/proof.jsonld'), script: await load('schema/script.jsonld'), chain: await load('schema/chain.jsonld'), validate: await load('schema/validate.jsonld') };
const overlay = knotsBlake2b(await load('schema/overlays/knots-blake2b.jsonld'));
const k = createKernel({ ...schemas, network: 'btc:testnet4-blake2b', overlays: [overlay] });
const base = createKernel({ ...schemas, network: 'btc:testnet4' });

const [header, ...rows] = await load('test/vectors/knots/unified_sighash.json');
const spends = (await load('test/vectors/knots/unified-spends.json')).spends;
const blockVector = await load('test/vectors/knots/block-150376.json');

test('unified sighash: the 166 Knots vectors, all four script types', () => {
  assert.equal(header.join(), 'scriptCode,rawTx,inIdx,hashType,scriptType,spentOutputs,sighash');
  const perType = {};
  for (const [scriptCodeHex, rawTx, inIdx, hashType, scriptType, spent, expected] of rows) {
    const tx = k.codec.decode('Transaction', rawTx);
    const prevouts = spent.map(([value, scriptPubKey]) => ({ value, scriptPubKey }));
    const script = hexToBytes(scriptCodeHex);
    const opts = scriptType === 3
      ? { leafHash: taggedHash('TapLeaf', Uint8Array.of(0xc0), compactSize(script.length), script) }
      : { scriptCodeHex };
    const got = bytesToHex(k.interpreter.sighashUnified(tx, inIdx, prevouts, hashType, scriptType, opts));
    assert.equal(got, expected, `type ${scriptType} hashType 0x${hashType.toString(16)} input ${inIdx}`);
    perType[scriptType] = (perType[scriptType] ?? 0) + 1;
  }
  assert.deepEqual(Object.keys(perType).sort(), ['0', '1', '2', '3']);
  assert.equal(rows.length, 166);
});

test('unified sighash: refuses what the spec refuses', () => {
  const [scriptCodeHex, rawTx, inIdx, , , spent] = rows.find((r) => r[4] === 0);
  const tx = k.codec.decode('Transaction', rawTx);
  const prevouts = spent.map(([value, scriptPubKey]) => ({ value, scriptPubKey }));
  assert.throws(() => k.interpreter.sighashUnified(tx, inIdx, prevouts, 0x01, 0, { scriptCodeHex }), /without SIGHASH_UNIFIED/);
  assert.throws(() => k.interpreter.sighashUnified(tx, inIdx, prevouts, 0x24, 2, {}), /invalid taproot sighash type/); // reserved bits stay reserved for taproot
  assert.throws(() => k.interpreter.sighashUnified(tx, inIdx, prevouts, 0x21, 3, {}), /leaf hash/);
  assert.throws(() => k.interpreter.sighashUnified(tx, inIdx, prevouts.slice(0, -1), 0x21, 0, { scriptCodeHex }), /needs every input prevout/);
  // legacy types keep the legacy reading: 0x24 is "ALL" for a bare input and hashes fine
  assert.equal(k.interpreter.sighashUnified(tx, inIdx, prevouts, 0x24, 0, { scriptCodeHex }).length, 32);
});

test('real txbt4 spends verify only under the unified message', () => {
  const types = new Set();
  for (const s of spends) {
    const tx = k.codec.decode('Transaction', s.hex);
    assert.equal(k.codec.txid(tx), s.txid);
    tx.inputs.forEach((inp, i) => {
      const sig = (tx.witness?.[i]?.[0]) ?? k.script.parse(inp.scriptSig)[0].data;
      assert.equal(hexToBytes(sig).at(-1) & SIGHASH_UNIFIED, SIGHASH_UNIFIED, 'opted in');
      // before activation (and on a chain without the fork) the byte reads legacy and the signature fails
      assert.equal(k.interpreter.verifyInput(tx, i, s.prevouts[i], s.prevouts).ok, false, `${s.types[i]} legacy reading`);
      assert.equal(base.interpreter.verifyInput(tx, i, s.prevouts[i], s.prevouts, null, { unifiedSighash: true }).ok, true, 'the message does not depend on the chain');
      const v = k.interpreter.verifyInput(tx, i, s.prevouts[i], s.prevouts, null, { unifiedSighash: true });
      assert.equal(v.ok, true, `${s.types[i]} ${s.txid} input ${i}: ${v.error}`);
      // the message commits to every spent output, so without them it is unverifiable, not wrong
      assert.equal(k.interpreter.verifyInput(tx, i, s.prevouts[i], null, null, { unifiedSighash: true }).ok, null);
      types.add(s.types[i]);
    });
  }
  assert.deepEqual([...types].sort(), ['p2pkh', 'p2tr', 'p2wpkh']);
});

test('block rule: the overlay activates the unified sighash at the fork height', () => {
  assert.equal(k.params.unifiedSighashParam, 'blake2bHeight');
  assert.equal(createKernel({ ...schemas, network: 'btc:mainnet-blake2b', overlays: [overlay] }).params.unifiedSighashParam, 'blake2bHeight');
  assert.equal(base.params.unifiedSighashParam, undefined);
  const block = k.codec.decode('Block', blockVector.hex);
  assert.equal(k.codec.blockHash(block.header), blockVector.hash);
  const utxo = new Map(Object.entries(blockVector.prevouts).map(([key, c]) => {
    const [txid, vout] = key.split(':');
    return [key, { outpoint: { txid, vout: Number(vout) }, output: { value: c.value, scriptPubKey: c.scriptPubKey }, height: c.height, coinbase: c.coinbase }];
  }));
  const mtp = k.headers.medianTimePast(blockVector.mtpHeaders.map((h) => k.codec.decode('BlockHeader', h)));
  const scripts = (r) => r.results.find((x) => x.rule === 'btc:rule-blockctx-scripts').ok;
  const at = k.blocks.validateBlockContext(block, { height: blockVector.height, utxo: new Map(utxo), mtp });
  assert.equal(scripts(at), true);
  assert.equal(at.ok, true, JSON.stringify(at.results.filter((r) => r.ok === false)));
  // the same block judged below the fork height: every opted-in signature reads legacy and fails
  assert.equal(scripts(k.blocks.validateBlockContext(block, { height: k.params.blake2bHeight - 1, utxo: new Map(utxo), mtp })), false);
  // and on plain testnet4 there is no such parameter
  assert.equal(scripts(base.blocks.validateBlockContext(block, { height: blockVector.height, utxo: new Map(utxo), mtp })), false);
});
