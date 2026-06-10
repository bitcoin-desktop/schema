// Byte-exact round-trip tests against real mainnet data.
// These are the keystone: if the schema-driven codec reproduces consensus
// bytes exactly, the schema is canonical rather than descriptive.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';

const root = new URL('..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));

const core = await load('schema/core.jsonld');
const codec = new Codec(core);
const genesis = await load('test/vectors/genesis-block.json');
const segwitTx = await load('test/vectors/first-segwit-tx.json');

test('genesis block: decode fields', () => {
  const block = codec.decode('Block', genesis.hex);
  const e = genesis.expected;
  assert.equal(block.header.version, e.version);
  assert.equal(block.header.prevBlockHash, e.prevBlockHash);
  assert.equal(block.header.merkleRoot, e.merkleRoot);
  assert.equal(block.header.time, e.time);
  assert.equal(block.header.bits, e.bits);
  assert.equal(block.header.nonce, e.nonce);
  assert.equal(block.transactions.length, e.txCount);
  assert.equal(block.transactions[0].outputs[0].value, e.coinbaseValue);
});

test('genesis block: byte-exact re-encode', () => {
  const block = codec.decode('Block', genesis.hex);
  assert.equal(codec.encodeHex('Block', block), genesis.hex);
});

test('genesis block: derived hash, txid, merkle root, proof of work', () => {
  const block = codec.decode('Block', genesis.hex);
  assert.equal(codec.blockHash(block.header), genesis.expected.hash);
  assert.equal(codec.txid(block.transactions[0]), genesis.expected.coinbaseTxid);
  const root_ = codec.merkleRoot(block.transactions.map((tx) => codec.txid(tx)));
  assert.equal(root_, block.header.merkleRoot);
  assert.ok(codec.checkProofOfWork(block.header));
});

test('first segwit tx: decode fields', () => {
  const tx = codec.decode('Transaction', segwitTx.hex);
  assert.equal(tx.version, segwitTx.expected.version);
  assert.equal(tx.lockTime, segwitTx.expected.lockTime);
  assert.ok(tx.witness.some((stack) => stack.length > 0));
});

test('first segwit tx: byte-exact re-encode', () => {
  const tx = codec.decode('Transaction', segwitTx.hex);
  assert.equal(codec.encodeHex('Transaction', tx), segwitTx.hex);
});

test('first segwit tx: derived txid, wtxid, size, weight, vsize', () => {
  const tx = codec.decode('Transaction', segwitTx.hex);
  const e = segwitTx.expected;
  assert.equal(codec.txid(tx), e.txid);
  assert.notEqual(codec.wtxid(tx), codec.txid(tx));
  assert.equal(codec.txSize(tx), e.size);
  assert.equal(codec.txWeight(tx), e.weight);
  assert.equal(codec.txVsize(tx), e.vsize);
});

test('legacy tx: txid equals wtxid', () => {
  const block = codec.decode('Block', genesis.hex);
  const coinbase = block.transactions[0];
  assert.equal(codec.txid(coinbase), codec.wtxid(coinbase));
});
