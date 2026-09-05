// Overlay rules (#83): rule nodes from an overlay join the base rule sets,
// their checks are installed by the overlay's code half, and createKernel
// wires it all. Exercised with the Knots BLAKE2b fork rules against real
// testnet4-blake2b data and against tampered copies.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createKernel } from '../../codec/kernel.js';
import { mergeSchemas } from '../../codec/overlay.js';
import { knotsBlake2b, rdtsActiveAt } from '../../codec/overlays/knots-blake2b.js';
import { bytesToHex, hexToBytes } from '../../codec/hash.js';

const root = new URL('../..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));
const schemas = { core: await load('schema/core.jsonld'), proof: await load('schema/proof.jsonld'), script: await load('schema/script.jsonld'),
  chain: await load('schema/chain.jsonld'), validate: await load('schema/validate.jsonld') };
const overlayGraph = await load('schema/overlays/knots-blake2b.jsonld');
const anchors = await load('test/vectors/knots/testnet4-anchors.json');
const NET = 'btc:testnet4-blake2b';
const kernel = () => createKernel({ ...schemas, network: NET, overlays: [knotsBlake2b(overlayGraph)] });
const failing = (v) => v.results.filter((r) => r.ok === false).map((r) => r.rule);

test('overlay rules join the base rule sets without mutating the base graph', () => {
  const baseSets = Object.fromEntries(schemas.validate['@graph'].filter((n) => n['@type'] === 'RuleSet').map((n) => [n['@id'], n.rules.length]));
  const merged = mergeSchemas(schemas.validate, overlayGraph);
  const sets = Object.fromEntries(merged['@graph'].filter((n) => n['@type'] === 'RuleSet').map((n) => [n['@id'], n.rules.map((r) => r['@id'])]));
  assert.equal(sets['btc:HeaderRules'].length, baseSets['btc:HeaderRules'] + 4);
  assert.equal(sets['btc:BlockRules'].length, baseSets['btc:BlockRules'] + 2);
  assert.equal(sets['btc:BlockContextRules'].length, baseSets['btc:BlockContextRules'] + 1);
  assert.ok(sets['btc:HeaderRules'].slice(0, baseSets['btc:HeaderRules']).every((id) => id.startsWith('btc:'))); // base rules first, untouched
  // the base document's own rule sets are exactly as before
  for (const n of schemas.validate['@graph']) if (n['@type'] === 'RuleSet') assert.equal(n.rules.length, baseSets[n['@id']]);
  const notASet = schemas.validate['@graph'].find((n) => n['@id'] && n['@type'] !== 'RuleSet')['@id'];
  assert.throws(() => mergeSchemas(schemas.validate, { '@graph': [{ '@id': 'x:r', '@type': 'ValidationRule', ruleSet: notASet }] }), /is not a RuleSet/);
  assert.throws(() => createKernel({ ...schemas, network: 'x:chain', overlays: [{ graph: { '@graph': [{ '@id': 'x:chain', extends: 'btc:nope' }] } }] }), /extends unknown/);
});

test('merged @context keeps the base string and overlay objects as an array; derived fields cannot shadow consensus fields', () => {
  const m = mergeSchemas(schemas.chain, overlayGraph);
  assert.ok(Array.isArray(m['@context']));
  assert.equal(m['@context'][0], schemas.chain['@context']);
  assert.deepEqual(m['@context'][1], overlayGraph['@context']);
  assert.equal(mergeSchemas(schemas.chain)['@context'], schemas.chain['@context']); // nothing to merge: unchanged
  const k = kernel();
  k.codec.registerDerived('knots:BlockHeaderV2', () => ({ bits: 0 }));
  assert.throws(() => k.codec.decode('BlockHeader', anchors.headers[1].header), /derived field bits collides/);
});

test('createKernel without overlays is the hand wiring; a rule without a check is an error', () => {
  const k = createKernel({ ...schemas, network: 'btc:mainnet' });
  assert.equal(k.codec.chain['@id'], 'btc:mainnet');
  assert.equal(k.headers.params.genesisHash, schemas.chain['@graph'].find((n) => n['@id'] === 'btc:mainnet').genesisHash);
  // an overlay that declares a rule but installs no check fails loudly at validation time
  const rogue = { graph: { '@graph': [{ '@id': 'x:rule', '@type': 'ValidationRule', ruleSet: 'btc:HeaderRules', label: 'x', errorCode: 'x' }] } };
  const k2 = createKernel({ ...schemas, network: 'btc:mainnet', overlays: [rogue] });
  assert.throws(() => k2.headers.validateHeader({ header: k.codec.decode('BlockHeader', anchors.headers[0].header) }), /no check registered for x:rule/);
});

test('v2 headers get a derived `time`; the header chain across the fork validates', () => {
  const k = kernel();
  const [last, fork, later] = anchors.headers.map((a) => k.codec.decode('BlockHeader', a.header));
  assert.equal(fork.time, fork.timeOnWire); // flags 0: no offset
  assert.equal(typeof later.time, 'number');
  assert.equal(bytesToHex(k.codec.encode('BlockHeader', fork)), anchors.headers[1].header); // `time` is not serialized
  const res = k.headers.validateChain([last, fork], { startHeight: 150307 });
  for (const r of res) assert.deepEqual(failing(r), [], `${r.height}: ${JSON.stringify(r.results)}`);
  const at = (r, id) => r.results.find((x) => x.rule === id).ok;
  assert.equal(at(res[0], 'knots:rule-header-v2-from-fork'), null); // gated below the fork height
  assert.equal(at(res[1], 'knots:rule-header-v2-from-fork'), true);
  assert.equal(at(res[1], 'knots:rule-header-height'), true);
  assert.equal(at(res[1], 'btc:rule-header-prev-link'), true);
  assert.equal(at(res[1], 'btc:rule-header-pow'), true);
  assert.equal(at(res[1], 'btc:rule-header-difficulty'), true); // 20-minute rule, inherited from testnet4
});

test('header rules reject the four things Knots rejects', () => {
  const k = kernel();
  const [last, fork] = anchors.headers.map((a) => k.codec.decode('BlockHeader', a.header));
  // (tampering a v2 header's committed fields also breaks its proof of work, as it must — look at the fork rules only)
  const v = (header, height) => failing(k.headers.validateHeader({ header, height, prev: null })).filter((id) => id.startsWith('knots:'));
  assert.deepEqual(v(last, 150308), ['knots:rule-header-v2-from-fork']);           // v1 at/after the fork
  assert.deepEqual(v({ ...fork, height: 150000 }, 150000), ['knots:rule-header-v1-until-fork']); // v2 claiming a pre-fork height
  assert.deepEqual(v(fork, 150309), ['knots:rule-header-height']);                  // committed height != chain height
  assert.deepEqual(v({ ...fork, flags: 0x40 }, 150308), ['knots:rule-header-flags-reserved']);
  assert.deepEqual(failing(k.headers.validateHeader({ header: fork, height: 150308, prev: null })), []);
});

test('block rules: committed tx count, headline at the fork block, RDTS weight cap', () => {
  const k = kernel();
  const block = k.codec.decode('Block', anchors.block.raw);
  assert.deepEqual(failing(k.blocks.validateBlockStructure(block)), []);
  const tampered = { ...block, header: { ...block.header, txCount: block.header.txCount + 1 } };
  assert.deepEqual(failing(k.blocks.validateBlockStructure(tampered)), ['knots:rule-block-txcount']);
  // headline: testnet4 sets none, so the fork block passes; mainnet requires the literal
  const forkBlockCtx = (net, scriptSig) => {
    const kk = createKernel({ ...schemas, network: net, overlays: [knotsBlake2b(overlayGraph)] });
    const h = { ...block.header, height: kk.params.blake2bHeight };
    return kk.blocks.blockChecks['knots:rule-block-headline']({ block: { header: h, transactions: [{ inputs: [{ scriptSig }] }] } });
  };
  const headline = bytesToHex(new TextEncoder().encode('8-30 NYPost Deride And Conquer'));
  assert.equal(forkBlockCtx(NET, '03' + '44b202'), true);
  assert.equal(forkBlockCtx('btc:mainnet-blake2b', '03' + '44b202' + '1e' + headline), true);
  assert.equal(forkBlockCtx('btc:mainnet-blake2b', '03' + '44b202'), false);
  // RDTS
  const p = k.params;
  assert.equal(rdtsActiveAt(p, p.blake2bHeight - 1, 0), false);
  assert.equal(rdtsActiveAt(p, p.blake2bHeight, p.rdtsExpiryTime - 1), true);
  assert.equal(rdtsActiveAt(p, p.blake2bHeight, p.rdtsExpiryTime), false);
  const w = k.blocks.contextChecks['knots:rule-blockctx-weight-rdts'];
  assert.equal(w({ block, height: 150462, mtp: 1788500000 }), true);   // 4291 <= 800000
  assert.equal(w({ block, height: 150462, mtp: null }), null);          // needs the parent MTP
  const copies = Math.ceil(800000 / k.codec.txWeight(block.transactions[1])) + 1;
  const heavy = { block: { ...block, transactions: Array(copies).fill(block.transactions[1]) }, height: 150462, mtp: 1788500000 };
  assert.ok(k.blocks.blockWeight(heavy.block) > 800000);
  assert.equal(w(heavy), false);
  assert.equal(w({ ...heavy, mtp: p.rdtsExpiryTime }), true);            // RDTS expired: the 4 MWU limit applies instead
});
