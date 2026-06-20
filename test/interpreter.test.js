// Script interpreter tests: hash primitives, the stack machine, and real
// mainnet signature verification across every supported spend path.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { ScriptEngine } from '../codec/script.js';
import { ScriptInterpreter, numEncode, numDecode, compactSize } from '../codec/interpreter.js';
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

test('compactSize encodes all four ranges incl. >64kB tapscripts (schema#67)', () => {
  const h = (n) => bytesToHex(compactSize(n));
  assert.equal(h(0), '00');
  assert.equal(h(252), 'fc');
  assert.equal(h(253), 'fdfd00');
  assert.equal(h(0xffff), 'fdffff');
  // The boundary the old TapLeaf code got wrong: >= 65,536 needs the 0xfe form.
  assert.equal(h(0x10000), 'fe00000100');
  // The real failure: testnet4 block 29,572 spent a 167,093-byte inscription
  // tapscript; the broken 3-byte prefix corrupted the TapLeaf hash so the
  // control-block commitment never matched.
  assert.equal(h(167093), 'feb58c0200');
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

test('BIP342: tapscript exempt from the 10kB size and 201-opcode limits (schema#61)', () => {
  const tap = (hex) => interp.execute(hex, [], { sigVersion: 'tapscript' });
  const legacy = (hex) => interp.execute(hex, []);
  // unit = OP_1 OP_DROP: 2 bytes, stack-neutral, 1 counted (non-push) opcode.
  // A >10kB script that also blows past the 201-opcode limit, ending truthy.
  const big = '5175'.repeat(6000) + '51'; // 12,001 bytes, 6,000 OP_DROPs
  assert.ok(big.length / 2 > limits.maxScriptSize, 'fixture must exceed 10kB');

  // tapscript: neither legacy limit applies -> validates.
  assert.deepEqual(tap(big), { ok: true }, 'tapscript >10kB / >201 ops must validate');
  // legacy: the 10kB MAX_SCRIPT_SIZE still bites (checked before parse).
  assert.deepEqual(legacy(big), { ok: false, error: 'script too large' });

  // Isolate the opcode limit: under 10kB but >201 counted ops.
  const manyOps = '5175'.repeat(300) + '51'; // 601 bytes, 300 OP_DROPs
  assert.ok(manyOps.length / 2 <= limits.maxScriptSize && 300 > limits.maxOpsPerScript);
  assert.deepEqual(tap(manyOps), { ok: true }, 'tapscript ignores the 201-opcode limit');
  assert.deepEqual(legacy(manyOps), { ok: false, error: 'op count' });
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

test('OP_CODESEPARATOR truncates the segwit-v0 sighash scriptCode (schema#70)', () => {
  // testnet4 block 46,779, tx #1 (fb9b18c7…e28aa5), input #0: a p2wsh spend whose
  // witnessScript is `OP_SIZE 0x50 OP_LESSTHAN OP_VERIFY OP_CODESEPARATOR <pubkey>
  // OP_CHECKSIG`. The BIP143 scriptCode must start *after* the separator (just
  // `<pubkey> OP_CHECKSIG`); signing over the whole script rejects the signature.
  const txHex = '020000000001020dc0150d2844efb332aff927b5c7e8341f87741ffe568c3200f45df9cf5976fb0000000000fdffffff085d15233e2ef68a7a26226cbdfa40ea7088166181fc815e5e7de79b22f6d67e0000000000fdffffff0277040000000000000451024e7300f2052a010000001600143ea3e6ec3a8612e661a3cc2d79aed2f5fb46a81502473044022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802205bc597cfbb5b01be850d68ebb65f5a15637b34a1dd3bc99293ca7901ef7d85e983298201509f69ab210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac02473044022060c5880f95e08aea070a477e9921534d4c18646e444b87031be1d275bbf3018d02202401070862c823dab2e33320af4e29ae5793ba943713d0e04b1f2149074bb2b283210360f2408f00eff55b359a200acccb4766dabf90cc2fee6c4ae483118d3917706600000000';
  const tx = codec.decode('Transaction', txHex);
  const witnessScript = tx.witness[0][tx.witness[0].length - 1];
  assert.ok(scripts.parse(witnessScript).some((op) => op.code === 0xab), 'witnessScript contains OP_CODESEPARATOR');
  const v = interp.verifyInput(tx, 0, { value: 1143, scriptPubKey: '0020359eaf2fdfc8952db69827596cf6fe9093f203bdbbd83749a9953f58a3a93829' });
  assert.equal(v.ok, true, `expected pass with scriptCode truncated at the separator: ${v.error ?? v.reason}`);
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
