// Mining tests: address decoding, regtest genesis derivation from our own
// params, and the headline — mined blocks pass our own full validator.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { Miner } from '../codec/mine.js';
import { HeaderEngine } from '../codec/headers.js';
import { BlockEngine } from '../codec/blocks.js';
import { addressToScript } from '../codec/script.js';

const root = new URL('..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));

const codec = new Codec(await load('schema/core.jsonld'));
const chainSchema = await load('schema/chain.jsonld');
const validateSchema = await load('schema/validate.jsonld');
const scriptSchema = await load('schema/script.jsonld');

const mainnetParams = chainSchema['@graph'].find((n) => n['@id'] === 'btc:mainnet');
const regtest = chainSchema['@graph'].find((n) => n['@id'] === 'btc:regtest');
const miner = Miner.fromSchemas(codec, chainSchema, 'btc:regtest');
const headerEngine = HeaderEngine.fromSchemas(codec, chainSchema, validateSchema, 'btc:regtest');
const blockEngine = BlockEngine.fromSchemas(codec, chainSchema, validateSchema, scriptSchema, 'btc:regtest');

const genesisVector = await load('test/vectors/genesis-block.json');
const segwitTxHex = (await load('test/vectors/first-segwit-tx.json')).hex;
const classification = await load('test/vectors/script-classification.json');

// The regtest genesis block reuses the mainnet genesis coinbase; only
// time, bits, and nonce differ. Deriving its hash from our own schema
// params is a self-check of the regtest instance.
const mainGenesis = codec.decode('Block', genesisVector.hex);
const regtestGenesisHeader = {
  ...mainGenesis.header, time: 1296688602, bits: 0x207fffff, nonce: 2,
};

test('regtest genesis hash derives from our own params', () => {
  assert.equal(codec.blockHash(regtestGenesisHeader), regtest.genesisHash);
  assert.ok(headerEngine.checks['btc:rule-header-pow']({ header: regtestGenesisHeader }));
});

test('address decoding round-trips every esplora-verified address', () => {
  for (const out of classification.outputs) {
    if (!out.address) continue;
    assert.equal(addressToScript(out.address, mainnetParams), out.scriptHex, out.address);
  }
  assert.equal(addressToScript('not-an-address', mainnetParams), null);
  assert.equal(addressToScript('bc1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq', mainnetParams), null);
});

test('regtest subsidy halves every 150 blocks', () => {
  assert.equal(miner.subsidy(1), 50_0000_0000);
  assert.equal(miner.subsidy(150), 25_0000_0000);
  assert.equal(miner.subsidy(300), 12_5000_0000);
});

function validateMined(block, height, prevHeaders, { mtp, now }) {
  const headerRows = headerEngine.validateChain([block.header], {
    startHeight: height, prevContext: prevHeaders, now,
  });
  const structural = blockEngine.validateBlockStructure(block);
  const txPhase = block.transactions.map((tx, i) => blockEngine.validateTransaction(tx, i === 0));
  const context = blockEngine.validateBlockContext(block, { height, utxo: new Map(), external: new Map(), mtp });
  return { headerRows, structural, txPhase, context };
}

test('a freshly mined regtest block passes all four validation phases', () => {
  const time = regtestGenesisHeader.time + 600;
  const { block, hash, attempts } = miner.mine({
    prevHash: regtest.genesisHash, height: 1, bits: 0x207fffff, time,
    scriptPubKey: addressToScript('bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080', regtest) ?? '51',
  });
  assert.ok(block, 'a block was found');
  assert.ok(attempts >= 1);
  assert.equal(codec.blockHash(block.header), hash);

  const v = validateMined(block, 1, [regtestGenesisHeader], { mtp: regtestGenesisHeader.time, now: time + 60 });
  assert.equal(v.headerRows[0].ok, true, JSON.stringify(v.headerRows[0].results));
  for (const r of v.headerRows[0].results) assert.notEqual(r.ok, false, r.label);
  assert.equal(v.structural.ok, true, JSON.stringify(v.structural.results));
  assert.ok(v.txPhase.every((t) => t.ok));
  assert.equal(v.context.ok, true, JSON.stringify(v.context.results));
  // BIP 34 is active from height 1 on regtest: the rule must RUN and pass
  const byLabel = Object.fromEntries(v.context.results.map((r) => [r.label, r.ok]));
  assert.equal(byLabel['coinbase-height'], true);
  assert.equal(byLabel['coinbase-amount'], true);

  // byte-exact round trip of a block that did not exist a moment ago
  assert.equal(codec.encodeHex('Block', codec.decode('Block', codec.encodeHex('Block', block))),
    codec.encodeHex('Block', block));
});

test('mining with a segwit transaction produces a valid witness commitment', () => {
  const segwitTx = codec.decode('Transaction', segwitTxHex);
  const time = regtestGenesisHeader.time + 600;
  const { block } = miner.mine({
    prevHash: regtest.genesisHash, height: 1, bits: 0x207fffff, time,
    scriptPubKey: '51', transactions: [segwitTx],
  });
  const v = validateMined(block, 1, [regtestGenesisHeader], { mtp: regtestGenesisHeader.time, now: time + 60 });
  const byLabel = Object.fromEntries(v.context.results.map((r) => [r.label, r.ok]));
  assert.equal(byLabel['witness-commitment'], true, 'commitment present and correct');
  assert.equal(v.structural.ok, true);
});

test('a premature coinbase spend in block 2 is rejected by our own validator', () => {
  const time = regtestGenesisHeader.time + 600;
  const b1 = miner.mine({
    prevHash: regtest.genesisHash, height: 1, bits: 0x207fffff, time, scriptPubKey: '51',
  }).block;
  const utxo = new Map();
  blockEngine.applyBlock(utxo, b1, 1);

  const spend = {
    version: 2, lockTime: 0,
    inputs: [{ prevout: { txid: codec.txid(b1.transactions[0]), vout: 0 }, scriptSig: '', sequence: 0xffffffff }],
    outputs: [{ value: 1, scriptPubKey: '51' }],
  };
  const b2 = miner.mine({
    prevHash: codec.blockHash(b1.header), height: 2, bits: 0x207fffff, time: time + 600,
    scriptPubKey: '51', transactions: [spend],
  }).block;
  const ctx = blockEngine.validateBlockContext(b2, { height: 2, utxo, external: new Map(), mtp: time });
  assert.equal(ctx.ok, false);
  assert.equal(ctx.results.find((r) => r.label === 'coinbase-maturity').error,
    'bad-txns-premature-spend-of-coinbase');
});

test('continuing mainnet at toy difficulty fails bad-diffbits', async () => {
  const window100k = await load('test/vectors/pruned-window-100000.json');
  const tip = codec.decode('Block', window100k.blocks.at(-1)).header;
  const mainnetHeaderEngine = HeaderEngine.fromSchemas(codec, chainSchema, validateSchema, 'btc:mainnet');
  const mainnetMiner = Miner.fromSchemas(codec, chainSchema, 'btc:mainnet');
  const { block } = mainnetMiner.mine({
    prevHash: codec.blockHash(tip), height: 100006, bits: 0x207fffff, time: tip.time + 600,
    scriptPubKey: '51',
  });
  const rows = mainnetHeaderEngine.validateChain([block.header], {
    startHeight: 100006, prevContext: [tip], now: tip.time + 7000,
  });
  assert.equal(rows[0].ok, false);
  assert.equal(rows[0].results.find((r) => r.label === 'difficulty').error, 'bad-diffbits');
});
