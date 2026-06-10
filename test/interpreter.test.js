// Script interpreter tests: hash primitives, the stack machine, and real
// mainnet signature verification across every supported spend path.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { ScriptEngine } from '../codec/script.js';
import { ScriptInterpreter, numEncode, numDecode } from '../codec/interpreter.js';
import { sha1, ripemd160, hash160, bytesToHex, hexToBytes } from '../codec/hash.js';

const root = new URL('..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));

const codec = new Codec(await load('schema/core.jsonld'));
const scriptSchema = await load('schema/script.jsonld');
const chainSchema = await load('schema/chain.jsonld');
const scripts = ScriptEngine.fromSchemas(scriptSchema, chainSchema);
const limits = scriptSchema['@graph'].find((n) => n['@id'] === 'btc:scriptLimits');
const interp = new ScriptInterpreter(codec, scripts, limits);

const spends = (await load('test/vectors/script-spends.json')).spends;
const window100k = await load('test/vectors/pruned-window-100000.json');
const genesis = await load('test/vectors/genesis-block.json');

const enc = (s) => new TextEncoder().encode(s);

test('hash primitives match known vectors', () => {
  assert.equal(bytesToHex(sha1(enc('abc'))), 'a9993e364706816aba3e25717850c26c9cd0d89d');
  assert.equal(bytesToHex(ripemd160(new Uint8Array(0))), '9c1185a5c5e9fc54612808977ee8f548b2258d31');
  assert.equal(bytesToHex(ripemd160(enc('abc'))), '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc');
});

test('scriptnum round-trips with sign-bit semantics', () => {
  for (const n of [0, 1, -1, 127, 128, -128, 255, 256, -1000, 2 ** 31 - 1]) {
    assert.equal(numDecode(numEncode(n), 5), n, `n=${n}`);
  }
  assert.deepEqual([...numEncode(128)], [128, 0]); // needs a padding byte
  assert.deepEqual([...numEncode(-1)], [0x81]);
});

test('stack machine basics', () => {
  const run = (hex) => { const s = []; const r = interp.execute(hex, s); return { r, s }; };
  // OP_1 OP_1 OP_ADD OP_2 OP_EQUAL
  assert.equal(run('5151935287').s.pop()[0], 1);
  // OP_1 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF -> 2
  assert.equal(numDecode(run('5163526753 68'.replace(/ /g, '')).s.pop()), 2);
  // OP_0 OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF -> 3
  assert.equal(numDecode(run('0063526753 68'.replace(/ /g, '')).s.pop()), 3);
  assert.equal(run('6a').r.ok, false);          // OP_RETURN fails
  assert.equal(run('7e').r.ok, false);          // OP_CAT disabled
  assert.equal(run('63').r.ok, false);          // unbalanced IF
  // OP_HASH160 of empty push: OP_0 OP_HASH160
  const { s } = run('00a9');
  assert.equal(bytesToHex(s.pop()), bytesToHex(hash160(new Uint8Array(0))));
});

test('every signature in blocks 100000-100005 verifies (p2pk + p2pkh era)', () => {
  const blocks = window100k.blocks.map((hex) => codec.decode('Block', hex));
  const external = new Map(
    Object.entries(window100k.prevTxs).map(([txid, hex]) => [txid, codec.decode('Transaction', hex)]));
  const windowTx = new Map();
  let verified = 0;
  for (const block of blocks) {
    for (const tx of block.transactions) windowTx.set(codec.txid(tx), tx);
  }
  for (const block of blocks) {
    for (const [j, tx] of block.transactions.entries()) {
      if (j === 0) continue;
      tx.inputs.forEach((inp, inIndex) => {
        const prevTx = windowTx.get(inp.prevout.txid) ?? external.get(inp.prevout.txid);
        assert.ok(prevTx, `prevout tx available ${inp.prevout.txid}`);
        const prevout = prevTx.outputs[inp.prevout.vout];
        const v = interp.verifyInput(tx, inIndex, prevout);
        assert.equal(v.ok, true, `${codec.txid(tx)}:${inIndex} (${v.type}): ${v.error}`);
        verified++;
      });
    }
  }
  assert.ok(verified >= 40, `verified ${verified} real signatures`);
});

for (const [kind, vector] of Object.entries(spends)) {
  test(`real ${kind} spend verifies`, () => {
    const tx = codec.decode('Transaction', vector.txHex);
    const v = interp.verifyInput(tx, vector.inputIndex,
      { value: vector.prevoutValue, scriptPubKey: vector.prevoutScript });
    assert.equal(v.ok, true, `${kind}: ${v.error ?? v.reason}`);
  });
}

test('tampered witness signature fails', () => {
  const vector = spends['v0_p2wpkh'];
  const tx = codec.decode('Transaction', vector.txHex);
  const sig = tx.witness[vector.inputIndex][0];
  const flipped = (parseInt(sig.slice(10, 12), 16) ^ 0x01).toString(16).padStart(2, '0');
  tx.witness[vector.inputIndex][0] = sig.slice(0, 10) + flipped + sig.slice(12);
  const v = interp.verifyInput(tx, vector.inputIndex,
    { value: vector.prevoutValue, scriptPubKey: vector.prevoutScript });
  assert.equal(v.ok, false);
});

test('wrong prevout value breaks a BIP143 signature', () => {
  const vector = spends['v0_p2wpkh'];
  const tx = codec.decode('Transaction', vector.txHex);
  const v = interp.verifyInput(tx, vector.inputIndex,
    { value: vector.prevoutValue + 1, scriptPubKey: vector.prevoutScript });
  assert.equal(v.ok, false, 'amount is committed by the BIP143 sighash');
});

test('taproot inputs skip honestly', () => {
  const tx = codec.decode('Transaction', spends['v0_p2wpkh'].txHex);
  const v = interp.verifyInput(tx, 0,
    { value: 1000, scriptPubKey: '5120' + 'ab'.repeat(32) });
  assert.equal(v.ok, null);
  assert.match(v.reason, /taproot/);
});

test('genesis p2pk output script is executable (spend attempt with empty sig fails cleanly)', () => {
  const block = codec.decode('Block', genesis.hex);
  const spk = block.transactions[0].outputs[0].scriptPubKey;
  const fakeSpend = {
    version: 1, lockTime: 0,
    inputs: [{ prevout: { txid: codec.txid(block.transactions[0]), vout: 0 }, scriptSig: '00', sequence: 0xffffffff }],
    outputs: [{ value: 1, scriptPubKey: '51' }],
  };
  const v = interp.verifyInput(fakeSpend, 0, { value: 5000000000, scriptPubKey: spk });
  assert.equal(v.ok, false, 'no one spends the genesis coinbase on our watch');
});
