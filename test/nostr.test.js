// NostrSource tests. Event verification runs against a REAL production
// NIP-333 event captured from a relay (golden vector) — the schema can
// verify but never sign, so live capture is the only honest fixture.
// Source behavior runs against a mock relay serving testnet4 vector
// headers, end-to-end through a LightNode.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { LightNode, MemoryStorage } from '../codec/node.js';
import { HeaderEngine } from '../codec/headers.js';
import { attachWsServer } from '../codec/ws.js';
import { NostrSource, verifyNostrEvent } from '../codec/nostr.js';

const dep = (p) => readFile(new URL('../' + p, import.meta.url), 'utf8').then(JSON.parse);
const codec = new Codec(await dep('schema/core.jsonld'), await dep('schema/proof.jsonld'));
const chainSchema = await dep('schema/chain.jsonld');
const validateSchema = await dep('schema/validate.jsonld');
const t4 = await dep('test/vectors/testnet4.json');
const golden = await dep('test/vectors/nostr-btc-event.json');

test('golden vector: a real production event verifies; tampered copies fail', () => {
  assert.equal(verifyNostrEvent(golden.event), true);

  const tamperedContent = { ...golden.event, content: 'ff' + golden.event.content.slice(2) };
  assert.equal(verifyNostrEvent(tamperedContent), false, 'content change breaks the id hash');

  const flipped = golden.event.sig[10] === '0' ? '1' : '0';
  const tamperedSig = { ...golden.event, sig: golden.event.sig.slice(0, 10) + flipped + golden.event.sig.slice(11) };
  assert.equal(verifyNostrEvent(tamperedSig), false, 'sig change fails BIP-340');
});

// ---- mock relay + crafted (unsigned) events over testnet4 vectors ----
// verifySig:false for these: the schema cannot sign, and what is under
// test here is window arithmetic and the LightNode integration.

const TIP = t4.run.startHeight + t4.run.headers.length - 1;
const PUBKEY = 'ab'.repeat(32);

function makeEvent(headers, tip) {
  return {
    kind: 33333, pubkey: PUBKEY, created_at: 1765000000,
    tags: [['d', 'tbtc4'], ['n', 'tbtc4'], ['tip', String(tip)]],
    content: headers.join(''), id: '00'.repeat(32), sig: '00'.repeat(64),
  };
}

function startMockRelay(events) {
  const server = http.createServer();
  attachWsServer(server, (client) => {
    client.onMessage((bytes) => {
      const m = JSON.parse(new TextDecoder().decode(bytes));
      if (m[0] !== 'REQ') return;
      const send = (x) => client.send(new TextEncoder().encode(JSON.stringify(x)));
      for (const e of events) send(['EVENT', m[1], e]);
      send(['EOSE', m[1]]);
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () =>
    resolve({ url: `ws://127.0.0.1:${server.address().port}`, close: () => server.close() })));
}

const makeSource = (relayUrl) => new NostrSource({
  relays: [relayUrl], pubkey: PUBKEY, network: 'tbtc4', codec, verifySig: false,
});

test('a LightNode five behind syncs to the event tip through NostrSource', async () => {
  const relay = await startMockRelay([makeEvent(t4.run.headers.slice(-12), TIP)]);
  try {
    const checkpointIdx = t4.run.headers.length - 6; // node tip = TIP - 5
    const contextStart = Math.max(0, checkpointIdx - 10);
    const node = new LightNode({
      codec,
      headerEngine: HeaderEngine.fromSchemas(codec, chainSchema, validateSchema, 'btc:testnet4'),
      storage: new MemoryStorage(),
      sources: [],
      checkpoint: {
        height: t4.run.startHeight + checkpointIdx,
        rawHeader: t4.run.headers[checkpointIdx],
        hash: codec.blockHash(codec.decode('BlockHeader', t4.run.headers[checkpointIdx])),
        contextHeaders: t4.run.headers.slice(contextStart, checkpointIdx),
      },
    });
    await node.init();
    await node.syncP2p(makeSource(relay.url));
    assert.equal(node.meta.tipHeight, TIP, 'validated all five missing headers');
  } finally { relay.close(); }
});

test('headersAfter: up to date -> [], unknown tip -> [], window-start link -> all 12', async () => {
  const relay = await startMockRelay([makeEvent(t4.run.headers.slice(-12), TIP)]);
  try {
    const src = makeSource(relay.url);
    const hashAt = (i) => codec.blockHash(codec.decode('BlockHeader', t4.run.headers[i]));
    assert.deepEqual(await src.headersAfter(hashAt(t4.run.headers.length - 1)), [], 'already at tip');
    assert.deepEqual(await src.headersAfter('ee'.repeat(32)), [], 'unconnectable tip');
    const all = await src.headersAfter(hashAt(t4.run.headers.length - 13));
    assert.equal(all.length, 12, 'tip just before the window gets the whole window');
    assert.equal(all[11], t4.run.headers.at(-1));
  } finally { relay.close(); }
});

test('cross-check contract: tipHeight + in-window headersRange; outside throws', async () => {
  const relay = await startMockRelay([makeEvent(t4.run.headers.slice(-12), TIP)]);
  try {
    const src = makeSource(relay.url);
    assert.equal(await src.tipHeight(), TIP);
    assert.deepEqual(await src.headersRange(TIP, 1), [t4.run.headers.at(-1)]);
    assert.deepEqual(await src.headersRange(TIP - 11, 2), t4.run.headers.slice(-12, -10));
    await assert.rejects(() => src.headersRange(TIP - 12, 1), /outside window/);
  } finally { relay.close(); }
});

test('relay junk is re-filtered client-side: wrong pubkey/d never accepted', async () => {
  const stranger = { ...makeEvent(t4.run.headers.slice(-12), TIP), pubkey: 'cd'.repeat(32) };
  const wrongNet = { ...makeEvent(t4.run.headers.slice(-12), TIP), tags: [['d', 'btc'], ['n', 'btc'], ['tip', String(TIP)]] };
  const relay = await startMockRelay([stranger, wrongNet]);
  try {
    await assert.rejects(() => makeSource(relay.url).tipHeight(), /no valid event/);
  } finally { relay.close(); }
});

test('signature checking is on by default and rejects unsigned events', async () => {
  const relay = await startMockRelay([makeEvent(t4.run.headers.slice(-12), TIP)]);
  try {
    const src = new NostrSource({ relays: [relay.url], pubkey: PUBKEY, network: 'tbtc4', codec });
    await assert.rejects(() => src.tipHeight(), /no valid event/);
  } finally { relay.close(); }
});
