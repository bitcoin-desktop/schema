// Epoch packages against schema/epoch.jsonld: two real testnet5 packages (epochs 1 and 2, blocks 1..4032,
// built by blaketestnode's lib/epoch.mjs from bitcoin-kernel/testnet5's validated chain) pass every rule
// that can be checked without blocks, chain together, and each tampered copy fails the rule meant to catch it.
// Their end states were checked against Bitcoin Core 32.1 (testnet5 branch): hash_serialized_3 at 2016 and
// 4032 as dumptxoutset printed it, and the MuHash of the same coin set at the tip as gettxoutsetinfo printed it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { EpochChecker, muhashDigest } from '../codec/epoch.js';

const root = new URL('..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));
const checker = new EpochChecker(await load('schema/epoch.jsonld'));
const e1 = await load('test/vectors/epoch/tbtc5-2016.json'), e2 = await load('test/vectors/epoch/tbtc5-4032.json');
const copy = (o) => JSON.parse(JSON.stringify(o));
const failed = (r) => r.results.filter((x) => x.ok === false).map((x) => x.label);

test('every rule in the schema is bound, and only the product rule is left to a verifier with blocks', () => {
  const r = checker.check(e1);
  assert.equal(r.results.length, 8);
  assert.deepEqual(r.results.filter((x) => x.ok === null).map((x) => x.label), ['product']);
});

test('testnet5 epochs 1 and 2 pass, and chain', () => {
  for (const e of [e1, e2]) { const r = checker.check(e); assert.ok(r.ok, JSON.stringify(failed(r))); }
  assert.ok(checker.checkChain([e1, e2]).ok);
  assert.equal(e1.start.height, 0); assert.equal(e1.end.height, 2016); assert.equal(e2.end.height, 4032);
});

test('the end states are the ones Core committed to', () => {
  assert.equal(e1.end.hashSerialized3, '34b419b3fe6679758f563ba280f8f100be912a948e7930c5c0475c2035eb8a5c'); // dumptxoutset rollback=2016
  assert.equal(e2.end.hashSerialized3, 'e9d84460b6180218b015a960458dd053ecc5e74b11644ceffe8e3cd6ee7685eb'); // rollback=4032
  assert.equal(e1.end.coins, 6483); assert.equal(e2.end.coins, 14454);
});

test('the empty set: value 1, and Core\'s digest of it', () => {
  const one = '01' + '00'.repeat(383);
  assert.equal(e1.start.value, one);
  assert.equal(muhashDigest(one), 'dd5ad2a105c2d29495f577245c357409002329b9f4d6182c0af3dc2f462555c8');
});

test('each tampered copy fails the rule meant for it', () => {
  const cases = [
    ['fields', (p) => { delete p.end.muhash; }],
    ['fields', (p) => { p.outputs = -1; }],
    ['span', (p) => { p.end.height = 4031; }],
    ['span', (p) => { p.blocks.count = 2015; }],
    ['empty-genesis', (p) => { p.start.coins = 1; p.end.coins += 1; }],
    ['digest', (p) => { p.end.value = p.start.value; }],
    ['hints', (p) => { p.unspent += 1; p.end.coins += 1; }],
    ['side-data', (p) => { p.spent.push([...p.spent[0]]); p.end.coins -= 1; }],
    ['side-data', (p) => { p.spent[0][1] = p.start.height + 1; }],
    ['coin-count', (p) => { p.end.coins += 1; }],
  ];
  for (const [rule, tamper] of cases) {
    const p = copy(rule === 'empty-genesis' ? e1 : e2); tamper(p);
    assert.deepEqual(failed(checker.check(p)), [rule], `${rule}: ${tamper}`);
  }
});

test('a chain breaks where a package does not start at the previous end', () => {
  const b = copy(e2); b.start.muhash = 'ff'.repeat(32);
  const r = checker.checkChain([e1, b]);
  assert.deepEqual(failed(r), ['link']);
  const n = copy(e2); n.network = 'tbtc4';
  assert.deepEqual(failed(checker.checkChain([e1, n])), ['same-network']);
});
