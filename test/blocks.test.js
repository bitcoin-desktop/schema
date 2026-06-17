// Pruned-window validation tests: blocks 100000-100005 validated entirely
// from raw bytes (the blocks plus their out-of-window prevout transactions),
// evolving a UTXO window across all six blocks.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { BlockEngine, isCoinbase } from '../codec/blocks.js';

const root = new URL('..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));

const codec = new Codec(await load('schema/core.jsonld'));
const engine = BlockEngine.fromSchemas(
  codec, await load('schema/chain.jsonld'), await load('schema/validate.jsonld'),
  await load('schema/script.jsonld'));

const vector = await load('test/vectors/pruned-window-100000.json');
const segwitTxHex = (await load('test/vectors/first-segwit-tx.json')).hex;
const blocks = vector.blocks.map((hex) => codec.decode('Block', hex));
const external = new Map(
  Object.entries(vector.prevTxs).map(([txid, hex]) => [txid, codec.decode('Transaction', hex)]));
const prevHeaders = vector.prevHeaders.map((hex) => codec.decode('BlockHeader', hex));
const medianOf = (times) => {
  const t = times.slice(-11).sort((a, b) => a - b);
  return t[t.length >> 1];
};

test('schema wiring: three rulesets load with bound checks', () => {
  assert.equal(engine.ruleSets.transaction.rules.length, 7);
  assert.equal(engine.ruleSets.block.rules.length, 7);
  assert.equal(engine.ruleSets.blockContext.rules.length, 9);
  for (const [set, checks] of [
    [engine.ruleSets.transaction, engine.txChecks],
    [engine.ruleSets.block, engine.blockChecks],
    [engine.ruleSets.blockContext, engine.contextChecks]]) {
    assert.ok(set.rules.every((r) => checks[r['@id']]), set.label);
  }
});

test('subsidy schedule', () => {
  assert.equal(engine.subsidy(0), 50_0000_0000);
  assert.equal(engine.subsidy(100000), 50_0000_0000);
  assert.equal(engine.subsidy(210000), 25_0000_0000);
  assert.equal(engine.subsidy(840000), 3_1250_0000);
});

test('all six blocks round-trip byte-exactly', () => {
  blocks.forEach((block, i) => {
    assert.equal(codec.encodeHex('Block', block), vector.blocks[i], `block ${100000 + i}`);
  });
});

test('the 6-block window fully validates with UTXO evolution', () => {
  const utxo = new Map();
  const times = prevHeaders.map((h) => h.time);
  blocks.forEach((block, i) => {
    const height = vector.startHeight + i;
    const mtp = medianOf(times);
    for (const [j, tx] of block.transactions.entries()) {
      const v = engine.validateTransaction(tx, j === 0);
      assert.ok(v.ok, `tx phase ${height}/${j}: ${JSON.stringify(v.results)}`);
    }
    const structural = engine.validateBlockStructure(block);
    assert.ok(structural.ok, `block phase ${height}: ${JSON.stringify(structural.results)}`);

    const ctx = engine.validateBlockContext(block, { height, utxo, external, mtp });
    assert.ok(ctx.ok, `context phase ${height}: ${JSON.stringify(ctx.results)}`);
    assert.equal(ctx.spending.valueUnresolved, 0, 'every input value resolves');
    assert.equal(ctx.spending.deficits.length, 0);

    // pre-BIP34 heights: the activation-gated rules must be skipped, not run
    const byLabel = Object.fromEntries(ctx.results.map((r) => [r.label, r.ok]));
    assert.equal(byLabel['coinbase-height'], null, 'BIP34 not active at 100k');
    assert.equal(byLabel['witness-commitment'], null, 'no witness data at 100k');
    assert.equal(byLabel['coinbase-amount'], true, 'coinbase <= subsidy + fees');
    assert.equal(byLabel['scripts'], true, 'every signature in the block verifies');

    engine.applyBlock(utxo, block, height);
    times.push(block.header.time);
  });
  assert.ok(utxo.size > 0);
});

test('sigop counting matches Core semantics', () => {
  assert.equal(engine.legacySigOps('ac'), 1);   // OP_CHECKSIG
  assert.equal(engine.legacySigOps('ae'), 20);  // OP_CHECKMULTISIG
  assert.equal(engine.legacySigOps('76a914' + '00'.repeat(20) + '88ac'), 1); // p2pkh
  const structural = engine.validateBlockStructure(blocks[0]);
  assert.equal(structural.results.find((r) => r.label === 'sigop-limit').ok, true);
});

test('non-final transaction fails bad-txns-nonfinal', () => {
  const block = structuredClone(blocks[0]);
  block.transactions[1].lockTime = 200000; // beyond the block height
  block.transactions[1].inputs.forEach((i) => { i.sequence = 0; });
  const ctx = engine.validateBlockContext(block, { height: 100000, utxo: new Map(), external, mtp: 1 });
  assert.equal(ctx.results.find((r) => r.label === 'tx-finality').error, 'bad-txns-nonfinal');
});

test('time-locked transaction without MTP context skips finality', () => {
  const block = structuredClone(blocks[0]);
  block.transactions[1].lockTime = 1600000000; // time-based lock
  block.transactions[1].inputs.forEach((i) => { i.sequence = 0; });
  const ctx = engine.validateBlockContext(block, { height: 100000, utxo: new Map(), external });
  assert.equal(ctx.results.find((r) => r.label === 'tx-finality').ok, null);
});

test('premature spend of a window coinbase fails maturity', () => {
  const utxo = new Map([['aa'.repeat(32) + ':0', {
    outpoint: { txid: 'aa'.repeat(32), vout: 0 },
    output: { value: 50_0000_0000, scriptPubKey: '51' },
    height: 100004, coinbase: true,
  }]]);
  const block = {
    header: blocks[0].header,
    transactions: [structuredClone(blocks[0].transactions[0]), {
      version: 1, lockTime: 0,
      inputs: [{ prevout: { txid: 'aa'.repeat(32), vout: 0 }, scriptSig: '', sequence: 0xffffffff }],
      outputs: [{ value: 49_0000_0000, scriptPubKey: '51' }],
    }],
  };
  const ctx = engine.validateBlockContext(block, { height: 100005, utxo, external: new Map(), mtp: 1 });
  assert.equal(ctx.results.find((r) => r.label === 'coinbase-maturity').error,
    'bad-txns-premature-spend-of-coinbase');
  // same spend 100 blocks later is mature
  const late = engine.validateBlockContext(block, { height: 100104, utxo, external: new Map(), mtp: 1 });
  assert.equal(late.results.find((r) => r.label === 'coinbase-maturity').ok, true);
});

// BIP68/112 relative lock-time (issue #45). A v2 input spending a window coin
// with a height-based relative lock of N is invalid until N blocks have passed.
function seqlockCase({ version, sequence, coinHeight, spendHeight }) {
  const utxo = new Map([['bb'.repeat(32) + ':0', {
    output: { value: 50_0000_0000, scriptPubKey: '51' },
    height: coinHeight, coinbase: false,
  }]]);
  const block = {
    header: blocks[0].header,
    transactions: [structuredClone(blocks[0].transactions[0]), {
      version, lockTime: 0,
      inputs: [{ prevout: { txid: 'bb'.repeat(32), vout: 0 }, scriptSig: '', sequence }],
      outputs: [{ value: 49_0000_0000, scriptPubKey: '51' }],
    }],
  };
  return engine.validateBlockContext(block, { height: spendHeight, utxo, external: new Map(), mtp: 1 })
    .results.find((r) => r.label === 'sequence-locks');
}

test('BIP68 height lock: immature relative lock fails, mature passes', () => {
  // relative lock of 5; coin at 100000
  const immature = seqlockCase({ version: 2, sequence: 5, coinHeight: 100000, spendHeight: 100004 });
  assert.equal(immature.ok, false);
  assert.equal(immature.error, 'bad-txns-nonfinal');
  const mature = seqlockCase({ version: 2, sequence: 5, coinHeight: 100000, spendHeight: 100005 });
  assert.equal(mature.ok, true, 'spendHeight == coinHeight + 5 satisfies the lock');
});

test('BIP68 is exempt for v1 txs and for the disable flag', () => {
  // identical immature case but version 1 -> no relative lock
  assert.equal(seqlockCase({ version: 1, sequence: 5, coinHeight: 100000, spendHeight: 100001 }).ok, true);
  // v2 but disable flag (bit 31) set -> exempt; 0xffffffff is the canonical final sequence
  assert.equal(seqlockCase({ version: 2, sequence: 0xffffffff, coinHeight: 100000, spendHeight: 100001 }).ok, true);
  assert.equal(seqlockCase({ version: 2, sequence: 0x80000005, coinHeight: 100000, spendHeight: 100001 }).ok, true);
});

test('BIP68 time-based and out-of-window locks skip honestly', () => {
  // type flag (bit 22) set -> time-based; no per-coin MTP in this context -> skip (null)
  assert.equal(seqlockCase({ version: 2, sequence: 0x00400005, coinHeight: 100000, spendHeight: 100001 }).ok, null);
  // height-based lock on an out-of-window coin (external, height unknown) -> skip
  const block = {
    header: blocks[0].header,
    transactions: [structuredClone(blocks[0].transactions[0]), {
      version: 2, lockTime: 0,
      inputs: [{ prevout: { txid: 'cc'.repeat(32), vout: 0 }, scriptSig: '', sequence: 5 }],
      outputs: [{ value: 1, scriptPubKey: '51' }],
    }],
  };
  const ext = new Map([['cc'.repeat(32), { version: 1, lockTime: 0,
    inputs: [{ prevout: { txid: 'dd'.repeat(32), vout: 0 }, scriptSig: '', sequence: 0xffffffff }],
    outputs: [{ value: 2, scriptPubKey: '51' }] }]]);
  const r = engine.validateBlockContext(block, { height: 100001, utxo: new Map(), external: ext, mtp: 1 })
    .results.find((x) => x.label === 'sequence-locks');
  assert.equal(r.ok, null, 'unknown coin height -> honest skip, never a false reject');
});

test('block 100000 facts: fees and coinbase amount', () => {
  const ctx = engine.validateBlockContext(blocks[0], { height: 100000, utxo: new Map(), external });
  const coinbaseOut = blocks[0].transactions[0].outputs.reduce((s, o) => s + o.value, 0);
  assert.equal(coinbaseOut, engine.subsidy(100000) + ctx.spending.fees,
    'satoshi-exact: coinbase claims subsidy plus fees');
});

test('tamper: duplicated input fails bad-txns-inputs-duplicate', () => {
  const tx = structuredClone(blocks[0].transactions[1]);
  tx.inputs = [...tx.inputs, tx.inputs[0]];
  const v = engine.validateTransaction(tx);
  assert.equal(v.results.find((r) => r.label === 'inputs-unique').error, 'bad-txns-inputs-duplicate');
});

test('tamper: double spend across transactions fails bad-txns-inputs-missingorspent', () => {
  const block = structuredClone(blocks[1]);
  block.transactions.push(structuredClone(block.transactions[1])); // respend same inputs
  const ctx = engine.validateBlockContext(block, { height: 100001, utxo: new Map(), external });
  assert.equal(ctx.results.find((r) => r.label === 'inputs-available').error,
    'bad-txns-inputs-missingorspent');
});

test('tamper: removing the coinbase fails bad-cb-missing', () => {
  const block = { ...blocks[0], transactions: blocks[0].transactions.slice(1) };
  const v = engine.validateBlockStructure(block);
  assert.equal(v.results.find((r) => r.label === 'coinbase-first').error, 'bad-cb-missing');
});

test('tamper: inflated coinbase fails bad-cb-amount', () => {
  const block = structuredClone(blocks[0]);
  block.transactions[0].outputs[0].value += 1; // one satoshi too greedy
  const ctx = engine.validateBlockContext(block, { height: 100000, utxo: new Map(), external });
  assert.equal(ctx.results.find((r) => r.label === 'coinbase-amount').error, 'bad-cb-amount');
});

test('tamper: swapped transaction order fails bad-txnmrklroot', () => {
  const block = structuredClone(blocks[1]);
  [block.transactions[1], block.transactions[2]] = [block.transactions[2], block.transactions[1]];
  const v = engine.validateBlockStructure(block);
  assert.equal(v.results.find((r) => r.label === 'merkle-root').error, 'bad-txnmrklroot');
});

test('witness commitment: self-consistent segwit block verifies and tampers fail', () => {
  // Build a minimal segwit block: coinbase (with reserved witness) + the
  // first segwit tx, commitment computed by the engine itself, then verify
  // the rule logic both ways.
  const segwitTx = codec.decode('Transaction', segwitTxHex);
  const coinbase = {
    version: 1,
    inputs: [{ prevout: { txid: '0'.repeat(64), vout: 0xffffffff }, scriptSig: '03a0bb0d', sequence: 0xffffffff }],
    outputs: [{ value: 0, scriptPubKey: '6a24aa21a9ed' + '0'.repeat(64) }],
    witness: [['0'.repeat(64)]],
    lockTime: 0,
  };
  const block = { header: blocks[0].header, transactions: [coinbase, segwitTx] };
  coinbase.outputs[0].scriptPubKey = '6a24aa21a9ed' + engine.witnessCommitmentHash(block);

  const check = engine.contextChecks['btc:rule-blockctx-witness-commitment'];
  assert.equal(check({ block }), true);
  coinbase.outputs[0].scriptPubKey = '6a24aa21a9ed' + 'f'.repeat(64);
  assert.equal(check({ block }), false);
});

test('isCoinbase discriminates', () => {
  assert.ok(isCoinbase(blocks[0].transactions[0]));
  assert.ok(!isCoinbase(blocks[0].transactions[1]));
});
