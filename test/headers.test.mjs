// Header chain engine tests against real mainnet retargets and headers.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { HeaderEngine } from '../codec/headers.js';

const root = new URL('..', import.meta.url);
const load = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));

const codec = new Codec(await load('schema/core.jsonld'));
const engine = HeaderEngine.fromSchemas(
  codec, await load('schema/chain.jsonld'), await load('schema/validate.jsonld'));

const retarget1 = await load('test/vectors/retarget-32256.json');
const retargetModern = await load('test/vectors/retarget-modern.json');
const chain100k = await load('test/vectors/header-chain-100k.json');

const dec = (hex) => codec.decode('BlockHeader', hex);

test('schema wiring: mainnet params and header ruleset load', () => {
  assert.equal(engine.params.name, 'mainnet');
  assert.equal(engine.interval, 2016);
  assert.equal(engine.ruleSet.rules.length, 6);
  assert.ok(engine.ruleSet.rules.every((r) => engine.checks[r['@id']]));
});

test('header version requirements follow buried deployments', () => {
  const check = engine.checks['btc:rule-header-version'];
  assert.equal(check({ header: { version: 1 }, height: 100000 }), true, 'v1 fine pre-BIP34');
  assert.equal(check({ header: { version: 1 }, height: 227931 }), false, 'v1 rejected from BIP34');
  assert.equal(check({ header: { version: 2 }, height: 363725 }), false, 'v2 rejected from BIP66');
  assert.equal(check({ header: { version: 3 }, height: 388381 }), false, 'v3 rejected from BIP65');
  assert.equal(check({ header: { version: 4 }, height: 500000 }), true);
  assert.equal(check({ header: { version: 1 }, height: null }), null, 'unknown height skips');
});

test('compact bits round-trip', () => {
  for (const bits of [0x1d00ffff, 0x1d00d86a, 0x1b0404cb, 0x17031abe]) {
    assert.equal(engine.compactFromTarget(codec.expandCompact(bits)), bits);
  }
});

test('genesis chain work is 0x100010001', () => {
  assert.equal(engine.work({ bits: 0x1d00ffff }), 0x100010001n);
});

test('first retarget in history (block 32256) reproduces bits 0x1d00d86a', () => {
  const first = dec(retarget1.epochFirst);
  const last = dec(retarget1.epochLast);
  const next = dec(retarget1.next);
  assert.equal(next.bits, 0x1d00d86a);
  assert.equal(engine.retarget(first.time, last.time, last.bits), next.bits);
  assert.equal(engine.expectedBits(last, retarget1.epochLastHeight, first), next.bits);
});

test('modern retarget reproduces actual bits', () => {
  const first = dec(retargetModern.epochFirst);
  const last = dec(retargetModern.epochLast);
  const next = dec(retargetModern.next);
  assert.equal(engine.retarget(first.time, last.time, last.bits), next.bits);
});

test('31-header mainnet window validates under the full ruleset', () => {
  const headers = chain100k.headers.map(dec);
  const rows = engine.validateChain(headers.slice(11), {
    startHeight: chain100k.startHeight + 11,
    prevContext: headers.slice(0, 11),
    now: headers.at(-1).time + 600,
  });
  assert.equal(rows.length, 20);
  for (const row of rows) {
    assert.equal(row.ok, true, `height ${row.height}: ${JSON.stringify(row.results)}`);
    for (const r of row.results) assert.equal(r.ok, true, `${row.height} ${r.label}`);
  }
  const block100000 = rows.find((r) => r.height === 100000);
  assert.equal(block100000.hash, chain100k.expected.hash100000);
  assert.ok(rows.at(-1).chainWork > rows[0].chainWork);
});

test('tampered nonce fails proof-of-work, and breaks the next prev-link', () => {
  const headers = chain100k.headers.map(dec);
  headers[15] = { ...headers[15], nonce: headers[15].nonce ^ 1 };
  const rows = engine.validateChain(headers.slice(11), {
    startHeight: chain100k.startHeight + 11,
    prevContext: headers.slice(0, 11),
    now: headers.at(-1).time + 600,
  });
  const tampered = rows[4]; // height startHeight+15
  const next = rows[5];
  assert.equal(tampered.ok, false);
  assert.equal(tampered.results.find((r) => r.label === 'proof-of-work').error, 'high-hash');
  assert.equal(next.results.find((r) => r.label === 'prev-link').error, 'bad-prevblk');
});

test('future timestamp fails the future-time rule', () => {
  const headers = chain100k.headers.map(dec);
  const rows = engine.validateChain(headers.slice(11), {
    startHeight: chain100k.startHeight + 11,
    prevContext: headers.slice(0, 11),
    now: headers[11].time - 7201, // every header now > 2h in the "future"
  });
  assert.equal(rows[0].results.find((r) => r.label === 'future-time').error, 'time-too-new');
});
