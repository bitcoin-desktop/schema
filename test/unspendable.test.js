// Which outputs become coins (#102): Core's CScript::IsUnspendable leaves out an output whose scriptPubKey starts
// with OP_RETURN or is longer than MAX_SCRIPT_SIZE (10,000) bytes, and CCoinsViewCache::AddCoin never adds it.
// The engine must agree, or its coin set (counts, hash_serialized_3, MuHash, epoch packages) splits from Core's.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { BlockEngine } from '../codec/blocks.js';
import { isUnspendable, MAX_SCRIPT_SIZE } from '../codec/script.js';

const root = new URL('..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));
const codec = new Codec(await load('schema/core.jsonld'));
const engine = BlockEngine.fromSchemas(codec, await load('schema/chain.jsonld'), await load('schema/validate.jsonld'), await load('schema/script.jsonld'));
const vector = await load('test/vectors/pruned-window-100000.json');

const P2PKH = '76a914' + '11'.repeat(20) + '88ac';
const script = (bytes) => '51'.repeat(bytes); // OP_TRUE repeated: any script of that many bytes
// mainnet block 100000 with its coinbase's outputs replaced: an ordinary one, OP_RETURN, one at the limit, one over it
function block() {
  const b = codec.decode('Block', vector.blocks[0]);
  b.transactions[0].outputs = [
    { value: 50e8, scriptPubKey: P2PKH },
    { value: 0, scriptPubKey: '6a' + '04' + 'deadbeef' },
    { value: 1, scriptPubKey: script(MAX_SCRIPT_SIZE) },
    { value: 1, scriptPubKey: script(MAX_SCRIPT_SIZE + 1) },
  ];
  b.transactions = b.transactions.slice(0, 1);
  return b;
}

test('isUnspendable is Core\'s rule: OP_RETURN, or more than 10,000 bytes', () => {
  assert.equal(MAX_SCRIPT_SIZE, 10000);
  assert.equal(isUnspendable('6a'), true);
  assert.equal(isUnspendable('6a04deadbeef'), true);
  assert.equal(isUnspendable(P2PKH), false);
  assert.equal(isUnspendable(''), false); // an empty script is spendable (by a scriptSig that leaves true)
  assert.equal(isUnspendable(script(10000)), false); // at the limit: still a coin (Core tests size() > MAX_SCRIPT_SIZE)
  assert.equal(isUnspendable(script(10001)), true);
});

test('the engine takes the limit from the schema\'s scriptLimits', () => {
  assert.equal(engine.maxScriptSize, 10000);
});

test('applyBlock adds the ordinary and at-limit outputs, not OP_RETURN or the oversized one', () => {
  const b = block(), txid = codec.txid(b.transactions[0]), utxo = new Map();
  engine.applyBlock(utxo, b, 100000);
  assert.deepEqual([...utxo.keys()].sort(), [`${txid}:0`, `${txid}:2`]);
});

// In a block, an input resolves against the coins created earlier in it. Spending the at-limit output finds that coin
// (and, as a fresh coinbase output, is premature); spending the oversized one finds none: with no record of it
// anywhere, the engine's pruned-window context counts it as unresolved. Before #102 it, too, was found and premature.
test('in the same block, the oversized output is no coin to spend; the at-limit one is', () => {
  const b = block(), txid = codec.txid(b.transactions[0]);
  const spend = (vout) => ({ version: 1, inputs: [{ prevout: { txid, vout }, scriptSig: '', sequence: 0xffffffff }], outputs: [{ value: 0, scriptPubKey: P2PKH }], lockTime: 0 });
  b.transactions.push(spend(3), spend(2));
  const s = engine.validateBlockContext(b, { height: 100000, utxo: new Map(), mtp: 1 }).spending;
  assert.deepEqual(s.premature, [`${txid}:2`]);
  assert.equal(s.valueUnresolved, 1);
  assert.ok(!s.resolvedInputs.some((r) => r.tx.inputs[r.inIndex].prevout.vout === 3), 'nothing resolves the oversized output');
});
