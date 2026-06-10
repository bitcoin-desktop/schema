// Wallet tests: SHA-512/HMAC, BIP 32 public derivation against the official
// chains, BIP 86 taproot addresses, BIP 174 PSBT round-trips and finalized
// extraction with signature verification, BIP 21.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { ScriptEngine } from '../codec/script.js';
import { ScriptInterpreter } from '../codec/interpreter.js';
import { Bip32, Psbt, parseBip21, XPUB_VERSIONS } from '../codec/wallet.js';
import { publicKeyFromPrivate } from '../codec/secp256k1.js';
import { hexToBytes as h2b } from '../codec/hash.js';
import { sha512, hmacSha512, bytesToHex } from '../codec/hash.js';

const root = new URL('..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));

const codec = new Codec(await load('schema/core.jsonld'));
const scriptSchema = await load('schema/script.jsonld');
const chainSchema = await load('schema/chain.jsonld');
const scripts = ScriptEngine.fromSchemas(scriptSchema, chainSchema);
const limits = scriptSchema['@graph'].find((n) => n['@id'] === 'btc:scriptLimits');
const interp = new ScriptInterpreter(codec, scripts, limits);

const bip32 = await load('test/vectors/bip32.json');
const bip86 = await load('test/vectors/bip86.json');
const bip174 = await load('test/vectors/bip174.json');
const taprootSpends = (await load('test/vectors/taproot-spends.json')).spends;

const enc = (s) => new TextEncoder().encode(s);

test('sha512 and hmac-sha512 known vectors', () => {
  assert.equal(bytesToHex(sha512(enc('abc'))),
    'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a'
    + '2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f');
  assert.equal(bytesToHex(hmacSha512(new Uint8Array(20).fill(0x0b), enc('Hi There'))),
    '87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde'
    + 'daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854');
});

test('every official BIP 32 xpub decodes and re-encodes identically', () => {
  for (const c of bip32.chains) {
    const node = Bip32.decode(c.xpub);
    assert.ok(node, c.path);
    assert.equal(Bip32.encode(node), c.xpub, c.path);
  }
});

test('official BIP 32 chains: every non-hardened step derives publicly', () => {
  let derived = 0;
  for (const child of bip32.chains) {
    const lastSlash = child.path.lastIndexOf('/');
    if (lastSlash < 0) continue;
    const step = child.path.slice(lastSlash + 1);
    if (step.includes('H')) continue; // hardened: impossible from xpub
    const parentPath = child.path.slice(0, lastSlash);
    const parent = bip32.chains.find(
      (c) => c.seed === child.seed && c.path === parentPath);
    if (!parent) continue;
    const node = Bip32.derive(Bip32.decode(parent.xpub), parseInt(step, 10));
    assert.equal(Bip32.encode(node), child.xpub, child.path);
    derived++;
  }
  assert.ok(derived >= 4, `derived ${derived} official public steps`);
});

test('hardened derivation from an xpub refuses', () => {
  const node = Bip32.decode(bip32.chains[0].xpub);
  assert.throws(() => Bip32.derive(node, 0x80000000));
  assert.throws(() => Bip32.derivePath(node, "0'/1"));
});

test('official BIP 86 taproot addresses derive from the account xpub', () => {
  const account = Bip32.decode(bip86.accountXpub);
  for (const { path, xpub, address } of bip86.addresses) {
    const node = Bip32.derivePath(account, path);
    assert.equal(Bip32.encode(node), xpub, `${path} xpub`);
    const spk = Bip32.scriptPubKey(node, 'p2tr');
    assert.equal(scripts.classify(spk).address, address, `${path} address`);
  }
});

test('all official BIP 174 PSBTs round-trip byte-exactly', () => {
  for (const [i, b64] of bip174.valid.entries()) {
    const psbt = Psbt.parse(b64, codec);
    assert.equal(Psbt.toBase64(psbt), b64, `valid[${i}]`);
  }
});

test('official invalid PSBTs are rejected', () => {
  let rejected = 0;
  for (const b64 of bip174.invalid) {
    try { Psbt.parse(b64, codec); } catch { rejected++; }
  }
  assert.ok(rejected >= bip174.invalid.length - 2,
    `${rejected}/${bip174.invalid.length} invalid vectors rejected`);
});

test('a finalized PSBT built from a real taproot spend extracts and verifies', () => {
  // take the real mainnet key-path spend, decompose it into a PSBT, then
  // extract it back and verify the signature with the interpreter
  const vector = taprootSpends.keypath;
  const original = codec.decode('Transaction', vector.txHex);
  const unsigned = {
    version: original.version,
    inputs: original.inputs.map((i) => ({ ...i, scriptSig: '' })),
    outputs: original.outputs,
    lockTime: original.lockTime,
  };
  const witnessSer = (stack) => {
    let hex = stack.length.toString(16).padStart(2, '0');
    for (const item of stack) hex += (item.length / 2).toString(16).padStart(2, '0') + item;
    return hex;
  };
  const psbt = {
    global: [['00', codec.encodeHex('Transaction', unsigned, { legacy: true })]],
    inputs: original.inputs.map((_, i) => [
      ['01', codec.encodeHex('TransactionOutput', {
        value: vector.prevouts[i].value, scriptPubKey: vector.prevouts[i].scriptPubKey })],
      ['08', witnessSer(original.witness[i])],
    ]),
    outputs: original.outputs.map(() => []),
    tx: unsigned,
  };

  const reparsed = Psbt.parse(Psbt.toBase64(psbt), codec);
  const prevouts = reparsed.tx.inputs.map((_, i) => Psbt.utxo(reparsed, i, codec));
  assert.ok(prevouts.every(Boolean), 'every input has a utxo');

  const extracted = Psbt.extract(reparsed, codec);
  assert.equal(codec.encodeHex('Transaction', extracted), vector.txHex, 'extraction is byte-exact');

  const v = interp.verifyInput(extracted, vector.inputIndex, prevouts[vector.inputIndex], prevouts);
  assert.equal(v.ok, true, `signature verifies: ${v.error ?? ''}`);
});

test('unfinalized PSBTs do not extract', () => {
  const psbt = Psbt.parse(bip174.valid[0], codec);
  assert.equal(Psbt.extract(psbt, codec), null);
});

test('bip21 payment URIs parse', () => {
  const r = parseBip21('bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=0.00123456&label=Coffee%20Fund');
  assert.equal(r.address, 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4');
  assert.equal(r.amountSats, 123456);
  assert.equal(r.label, 'Coffee Fund');
  assert.equal(parseBip21('litecoin:whatever'), null);
});

test('tpub: testnet extended keys round-trip and derive', () => {
  const mainnetNode = Bip32.decode(bip32.chains[0].xpub);
  const tpub = Bip32.encode({ ...mainnetNode, version: XPUB_VERSIONS.testnet });
  assert.match(tpub, /^tpub/);
  const node = Bip32.decode(tpub);
  assert.equal(node.publicKey, mainnetNode.publicKey);
  assert.equal(node.version, XPUB_VERSIONS.testnet);
  const child = Bip32.derive(node, 0);
  assert.equal(child.version, XPUB_VERSIONS.testnet, 'children keep their network version');
  assert.equal(Bip32.decode('xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi'), null, 'xprv refused');
});

test('publicKeyFromPrivate matches the generator for d=1', () => {
  const pub = publicKeyFromPrivate(h2b('01'.padStart(64, '0')));
  assert.equal(bytesToHex(pub), '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  assert.equal(publicKeyFromPrivate(new Uint8Array(32)), null, 'zero scalar refused');
});
