// #84: a chain-declared one-off target adjustment (the first block of a
// proof-of-work change) and an explicit retarget seed. Pinned by the real
// mainnet fork block, whose bits are the SHA256d target eased by 2^22, and by
// the testnet4 fork block, mined under the minimum-difficulty exception where
// Core applies no adjustment.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createKernel } from '../../codec/kernel.js';
import { HeaderEngine } from '../../codec/headers.js';
import { knotsBlake2b } from '../../codec/overlays/knots-blake2b.js';

const root = new URL('../..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));
const schemas = { core: await load('schema/core.jsonld'), proof: await load('schema/proof.jsonld'), script: await load('schema/script.jsonld'),
  chain: await load('schema/chain.jsonld'), validate: await load('schema/validate.jsonld') };
const overlayGraph = await load('schema/overlays/knots-blake2b.jsonld');
const mainnet = await load('test/vectors/knots/mainnet-anchors.json');
const testnet = await load('test/vectors/knots/testnet4-anchors.json');
const kernelFor = (network) => createKernel({ ...schemas, network, overlays: [knotsBlake2b(overlayGraph)] });

test('mainnet fork block: expected bits are the last SHA256d bits eased by 2^22, and only at that height', () => {
  const k = kernelFor('btc:mainnet-blake2b');
  const h = Object.fromEntries(mainnet.headers.map((a) => [a.height, k.codec.decode('BlockHeader', a.header)]));
  assert.equal(h[961639].bits, 0x1702353d);
  assert.equal(h[961640].bits, 0x1a008d4f);
  assert.equal(k.headers.expectedBits(h[961639], 961639, null, { header: h[961640] }), 0x1a008d4f);
  assert.equal(k.headers.expectedBits(h[961640], 961640, null, { header: h[961641] }), 0x1a008d4f); // ordinary: prev bits, no adjustment
  // the shift really is 2^22 of the target, not a coincidence of compact encoding
  const eased = k.codec.expandCompact(0x1702353d) << 22n;
  assert.equal(k.headers.compactFromTarget(eased), 0x1a008d4f);
  // the fork block now passes every header rule, including difficulty
  const res = k.headers.validateChain([h[961639], h[961640], h[961641]], { startHeight: 961639 });
  for (const r of res) assert.deepEqual(r.results.filter((x) => x.ok === false).map((x) => x.rule), [], `${r.height}`);
  assert.equal(res[1].results.find((x) => x.rule === 'btc:rule-header-difficulty').ok, true);
  assert.equal(res[2].results.find((x) => x.rule === 'btc:rule-header-difficulty').ok, true);
});

test('testnet4 fork block: mined under the 20-minute exception, so no adjustment applies', () => {
  const k = kernelFor('btc:testnet4-blake2b');
  const [last, fork] = testnet.headers.map((a) => k.codec.decode('BlockHeader', a.header));
  assert.equal(k.headers.expectedBits(last, 150307, null, { header: fork }), 0x1d00ffff);
  assert.equal(fork.bits, 0x1d00ffff);
  // had it been mined within 20 minutes, the last real (non-minimum) bits eased by 2^20 would have been required:
  // the walk-back over min-difficulty blocks lands on 150287's 0x190295cb (the epoch's real difficulty)
  const soon = { ...fork, time: last.time + 60 };
  const chainAt = (h) => ({ bits: h <= 150287 ? 0x190295cb : 0x1d00ffff, time: 0 });
  const eased = k.headers.expectedBits(last, 150307, null, { header: soon, chainAt });
  assert.notEqual(eased, 0x1d00ffff);
  assert.equal(eased, k.headers.compactFromTarget(k.codec.expandCompact(0x190295cb) << 20n));
});

test('retargetSeed: first-of-period (BIP 94) vs last block, explicit and defaulted', () => {
  const mainnetParams = schemas.chain['@graph'].find((n) => n['@id'] === 'btc:mainnet');
  const testnet4Params = schemas.chain['@graph'].find((n) => n['@id'] === 'btc:testnet4');
  assert.equal(testnet4Params.retargetSeed, 'first');
  const ruleSet = schemas.validate['@graph'].find((n) => n['@type'] === 'RuleSet' && n.phase === 'header');
  const k = createKernel({ ...schemas, network: 'btc:mainnet' });
  const interval = mainnetParams.difficultyAdjustmentInterval;
  const first = { bits: 0x1a008d4f, time: 1000000 }, last = { bits: 0x1d00ffff, time: 1000000 + mainnetParams.targetTimespan };
  const at = (params) => new HeaderEngine(k.codec, params, ruleSet).expectedBits(last, interval - 1, first, {});
  assert.equal(at(mainnetParams), 0x1d00ffff);                                   // Bitcoin: scales the last block's bits
  assert.equal(at({ ...mainnetParams, retargetSeed: 'first' }), 0x1a008d4f);     // BIP 94: the period's first block
  assert.equal(at({ ...mainnetParams, timewarpFix: true }), 0x1a008d4f);         // defaulted from timewarpFix
  assert.equal(at({ ...mainnetParams, timewarpFix: true, retargetSeed: 'last' }), 0x1d00ffff); // explicit wins
});
