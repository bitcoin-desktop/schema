// Script engine tests: parsing, classification, and address derivation
// against real mainnet outputs with esplora's classification as oracle.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { ScriptEngine } from '../codec/script.js';

const root = new URL('..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));

const codec = new Codec(await load('schema/core.jsonld'));
const engine = ScriptEngine.fromSchemas(await load('schema/script.jsonld'), await load('schema/chain.jsonld'));
const vectors = await load('test/vectors/script-classification.json');
const genesis = await load('test/vectors/genesis-block.json');

// esplora's type names -> ours
const TYPE_MAP = {
  p2pk: 'p2pk', p2pkh: 'p2pkh', p2sh: 'p2sh',
  v0_p2wpkh: 'p2wpkh', v0_p2wsh: 'p2wsh', v1_p2tr: 'p2tr',
  op_return: 'nulldata', multisig: 'multisig',
};

test('schema wiring: opcode table loads', () => {
  assert.equal(engine.byName.get('OP_CHECKSIG'), 0xac);
  assert.equal(engine.byName.get('OP_CHECKSIGADD'), 0xba);
  assert.equal(engine.byCode.get(0xb1), 'OP_CHECKLOCKTIMEVERIFY');
  assert.ok(engine.byName.size >= 110);
  assert.equal(engine.scriptTypes.length, 10);
});

test('real mainnet outputs classify and derive the same address as esplora', () => {
  for (const out of vectors.outputs) {
    const { type, address } = engine.classify(out.scriptHex);
    assert.equal(type, TYPE_MAP[out.esploraType], `${out.esploraType}: ${out.scriptHex}`);
    assert.equal(address, out.address ?? null, `${out.esploraType} address`);
  }
});

test('genesis coinbase output is p2pk with no address', () => {
  const block = codec.decode('Block', genesis.hex);
  const spk = block.transactions[0].outputs[0].scriptPubKey;
  const { type, address, asm } = engine.classify(spk);
  assert.equal(type, 'p2pk');
  assert.equal(address, null);
  assert.ok(asm.endsWith('OP_CHECKSIG'));
  assert.ok(asm.startsWith('04678afdb0'));
});

test('bare 1-of-1 multisig classifies as multisig', () => {
  const key = '02' + '11'.repeat(32);
  const hex = '51' + '21' + key + '51' + 'ae'; // OP_1 <33B> OP_1 OP_CHECKMULTISIG
  assert.equal(engine.classify(hex).type, 'multisig');
});

test('witness v2 program classifies as witness-unknown with a bech32m address', () => {
  const hex = '52' + '20' + 'ab'.repeat(32); // OP_2 <32 bytes>
  const { type, address } = engine.classify(hex);
  assert.equal(type, 'witness-unknown');
  assert.ok(address.startsWith('bc1z')); // witness version 2 encodes as 'z'
});

test('truncated push classifies as nonstandard without throwing', () => {
  const { type, address, asm } = engine.classify('4c20abcd');
  assert.equal(type, 'nonstandard');
  assert.equal(address, null);
  assert.ok(asm.includes('[truncated push]'));
});

test('asm renders opcodes and pushes', () => {
  const p2pkh = vectors.outputs.find((o) => o.esploraType === 'p2pkh');
  const asm = engine.asm(p2pkh.scriptHex);
  assert.match(asm, /^OP_DUP OP_HASH160 [0-9a-f]{40} OP_EQUALVERIFY OP_CHECKSIG$/);
});
