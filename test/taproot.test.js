// Taproot tests: official BIP 340/341 vectors plus real mainnet key-path
// and script-path spends.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { ScriptEngine } from '../codec/script.js';
import { ScriptInterpreter } from '../codec/interpreter.js';
import { verifySchnorr, checkTapTweak } from '../codec/secp256k1.js';
import { taggedHash, hexToBytes, bytesToHex } from '../codec/hash.js';

const root = new URL('..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));

const codec = new Codec(await load('schema/core.jsonld'));
const scriptSchema = await load('schema/script.jsonld');
const scripts = ScriptEngine.fromSchemas(scriptSchema, await load('schema/chain.jsonld'));
const limits = scriptSchema['@graph'].find((n) => n['@id'] === 'btc:scriptLimits');
const interp = new ScriptInterpreter(codec, scripts, limits);

const bip340 = await load('test/vectors/bip340.json');
const bip341 = await load('test/vectors/bip341.json');
const mainnet = (await load('test/vectors/taproot-spends.json')).spends;

test('all official BIP 340 Schnorr vectors', () => {
  for (const v of bip340.vectors) {
    const ok = verifySchnorr(hexToBytes(v.message), hexToBytes(v.signature), hexToBytes(v.pubkey));
    assert.equal(ok, v.valid, v.note || v.pubkey);
  }
});

// merkle root of a BIP 341 script tree (nested arrays; leaves are
// {script, leafVersion}) — exercises TapLeaf/TapBranch hashing
function treeRoot(node) {
  if (node == null) return null;
  if (Array.isArray(node)) {
    const [l, r] = node.map(treeRoot);
    const less = bytesToHex(l) < bytesToHex(r);
    return taggedHash('TapBranch', ...(less ? [l, r] : [r, l]));
  }
  const script = hexToBytes(node.script);
  const size = Uint8Array.of(script.length); // vector scripts are < 0xfd
  return taggedHash('TapLeaf', Uint8Array.of(node.leafVersion), size, script);
}

test('official BIP 341 scriptPubKey vectors: merkle roots and tweaked keys', () => {
  for (const c of bip341.scriptPubKey) {
    const rootHash = treeRoot(c.given.scriptTree);
    assert.equal(rootHash ? bytesToHex(rootHash) : null, c.intermediary.merkleRoot, 'merkle root');
    const internal = hexToBytes(c.given.internalPubkey);
    const tweaked = hexToBytes(c.intermediary.tweakedPubkey);
    assert.ok(
      checkTapTweak(internal, rootHash, tweaked, 0) || checkTapTweak(internal, rootHash, tweaked, 1),
      'tweaked key derives');
    assert.equal(c.expected.scriptPubKey, '5120' + c.intermediary.tweakedPubkey);
  }
});

test('official BIP 341 key-path vectors: sighash intermediates match exactly', () => {
  const c = bip341.keyPathSpending[0];
  const tx = codec.decode('Transaction', c.given.rawUnsignedTx);
  const prevouts = c.given.utxosSpent.map((u) => ({
    scriptPubKey: u.scriptPubKey, value: u.amountSats,
  }));
  for (const spend of c.inputSpending) {
    const hash = interp.sighashTaproot(tx, spend.given.txinIndex, prevouts,
      spend.given.hashType, {});
    assert.equal(bytesToHex(hash), spend.intermediary.sigHash,
      `input ${spend.given.txinIndex} hashType 0x${spend.given.hashType.toString(16)}`);
  }
});

test('official BIP 341 fully-signed transaction: every taproot input verifies', () => {
  const c = bip341.keyPathSpending[0];
  const tx = codec.decode('Transaction', c.auxiliary.fullySignedTx);
  const prevouts = c.given.utxosSpent.map((u) => ({
    scriptPubKey: u.scriptPubKey, value: u.amountSats,
  }));
  let verified = 0;
  prevouts.forEach((prevout, i) => {
    if (scripts.classify(prevout.scriptPubKey).type !== 'p2tr') return;
    const v = interp.verifyInput(tx, i, prevout, prevouts);
    assert.equal(v.ok, true, `input ${i}: ${v.error ?? v.reason}`);
    verified++;
  });
  assert.ok(verified >= 5, `verified ${verified} official key-path inputs (varied sighash types)`);
});

for (const [kind, vector] of Object.entries(mainnet)) {
  test(`real mainnet taproot ${kind} spend verifies`, () => {
    const tx = codec.decode('Transaction', vector.txHex);
    const v = interp.verifyInput(tx, vector.inputIndex,
      vector.prevouts[vector.inputIndex], vector.prevouts);
    assert.equal(v.ok, true, `${kind}: ${v.error ?? v.reason}`);
    assert.equal(v.path, kind === 'keypath' ? 'key' : 'script');
  });
}

test('tampered key-path signature fails', () => {
  const vector = mainnet.keypath;
  const tx = codec.decode('Transaction', vector.txHex);
  const sig = tx.witness[vector.inputIndex][0];
  tx.witness[vector.inputIndex][0] =
    sig.slice(0, 6) + (parseInt(sig.slice(6, 8), 16) ^ 1).toString(16).padStart(2, '0') + sig.slice(8);
  const v = interp.verifyInput(tx, vector.inputIndex,
    vector.prevouts[vector.inputIndex], vector.prevouts);
  assert.equal(v.ok, false);
});

test('tampered control block fails the commitment check', () => {
  const vector = mainnet.scriptpath;
  const tx = codec.decode('Transaction', vector.txHex);
  const w = tx.witness[vector.inputIndex];
  const control = w[w.length - 1];
  w[w.length - 1] = control.slice(0, 4) +
    (parseInt(control.slice(4, 6), 16) ^ 0xff).toString(16).padStart(2, '0') + control.slice(6);
  const v = interp.verifyInput(tx, vector.inputIndex,
    vector.prevouts[vector.inputIndex], vector.prevouts);
  assert.equal(v.ok, false);
  assert.match(v.error, /commitment|control/);
});

test('taproot without all prevouts still skips honestly', () => {
  const vector = mainnet.keypath;
  const tx = codec.decode('Transaction', vector.txHex);
  const v = interp.verifyInput(tx, vector.inputIndex, vector.prevouts[vector.inputIndex]);
  assert.equal(v.ok, null);
  assert.match(v.reason, /taproot/);
});

test('OP_SUCCESS makes a tapscript unconditionally valid', () => {
  const r = interp.execute('50', [], { sigVersion: 'tapscript', tx: null });
  assert.equal(r.ok, true);
  assert.equal(r.opSuccess, true);
  // ...but not outside tapscript
  assert.equal(interp.execute('50', [], {}).ok, false);
});
