// A LightNode header source backed by the NIP-333 live stream: kind-33333
// parameterized replaceable events carrying the newest 12 headers, one
// stream per network (d = network code). See https://nip-333.github.io/.
//
// READ-ONLY by design: this module verifies events (NIP-01 id hash plus
// BIP-340 signature, using our own verifier) and never signs anything —
// publishing lives outside the schema. The publisher key is a filter, not
// a security boundary: headers from here pass the same LightNode
// validation rules as headers from any other source.
//
// Within its 12-header window the source serves both LightNode contracts:
// headersAfter(tipHash) for syncP2p-style tip following, and
// tipHeight()/headersRange() so the divergence cross-check can use it.

import { sha256, hexToBytes, bytesToHex } from './hash.js';
import { verifySchnorr } from './secp256k1.js';

const HEADER_HEX = 160; // 80 bytes
const KIND = 33333;

// NIP-01: id is the sha256 of the canonical serialization; sig is BIP-340
// over the id. Returns true iff both hold.
export function verifyNostrEvent(event) {
  const serial = JSON.stringify([
    0, event.pubkey, event.created_at, event.kind, event.tags, event.content,
  ]);
  if (bytesToHex(sha256(new TextEncoder().encode(serial))) !== event.id) return false;
  return verifySchnorr(hexToBytes(event.id), hexToBytes(event.sig), hexToBytes(event.pubkey));
}

export class NostrSource {
  constructor({ relays, pubkey, network, codec, verifySig = true, timeoutMs = 8000 }) {
    if (!relays?.length) throw new Error('NostrSource needs at least one relay');
    this.relays = relays;
    this.pubkey = pubkey;
    this.network = network; // NIP-333 code: btc | tbtc3 | tbtc4
    this.codec = codec;
    this.verifySig = verifySig;
    this.timeoutMs = timeoutMs;
    this.base = `nostr://${network}`;
    this.lastEvent = null; // newest accepted event, for callers that care
  }

  // newest matching event from one relay; null on miss/timeout/junk
  #fetchFrom(url) {
    return new Promise((resolve) => {
      let ws;
      const done = (v) => { clearTimeout(timer); try { ws?.close(); } catch { /* closing */ } resolve(v); };
      const timer = setTimeout(() => done(null), this.timeoutMs);
      try { ws = new WebSocket(url); } catch { return done(null); }
      ws.binaryType = 'arraybuffer';
      let newest = null;
      ws.onopen = () => ws.send(JSON.stringify(['REQ', 'nostr-source',
        { kinds: [KIND], authors: [this.pubkey], '#d': [this.network], limit: 1 }]));
      ws.onmessage = (ev) => {
        const m = JSON.parse(typeof ev.data === 'string' ? ev.data : new TextDecoder().decode(ev.data));
        if (m[0] === 'EVENT') {
          const e = m[2];
          // never trust relay filtering — re-check everything ourselves
          const d = e.tags?.find((t) => t[0] === 'd')?.[1];
          if (e.kind === KIND && e.pubkey === this.pubkey && d === this.network
              && (!newest || e.created_at > newest.created_at)) newest = e;
        } else if (m[0] === 'EOSE') done(newest);
      };
      ws.onerror = () => done(newest);
      ws.onclose = () => done(newest);
    });
  }

  // newest event across all relays, signature-checked; throws if nothing usable
  async #fetchEvent() {
    const events = (await Promise.all(this.relays.map((r) => this.#fetchFrom(r)))).filter(Boolean);
    const ok = this.verifySig ? events.filter((e) => verifyNostrEvent(e)) : events;
    if (!ok.length) throw new Error(`${this.base}: no valid event on ${this.relays.length} relay(s)`);
    this.lastEvent = ok.reduce((a, b) => (b.created_at > a.created_at ? b : a));
    return this.lastEvent;
  }

  // the event's 12 headers as [{hex, hash, prevBlockHash}], ascending
  #window(event) {
    const c = event.content ?? '';
    if (!/^[0-9a-f]+$/.test(c) || c.length % HEADER_HEX !== 0 || !c.length) {
      throw new Error(`${this.base}: malformed event content`);
    }
    const out = [];
    for (let i = 0; i < c.length / HEADER_HEX; i++) {
      const hex = c.slice(i * HEADER_HEX, (i + 1) * HEADER_HEX);
      const header = this.codec.decode('BlockHeader', hex);
      out.push({ hex, hash: this.codec.blockHash(header), prevBlockHash: header.prevBlockHash });
    }
    return out;
  }

  #tip(event) {
    const tip = parseInt(event.tags.find((t) => t[0] === 'tip')?.[1] ?? '', 10);
    if (!Number.isFinite(tip)) throw new Error(`${this.base}: event has no tip tag`);
    return tip;
  }

  // headers strictly after tipHash, [] if we can't connect to it — the
  // window only reaches 12 back, so a node further behind needs another
  // source (or the NIP's u-tag bulk channels) first.
  async headersAfter(tipHash) {
    const w = this.#window(await this.#fetchEvent());
    if (w[0].prevBlockHash === tipHash) return w.map((h) => h.hex);
    const i = w.findIndex((h) => h.hash === tipHash);
    return i < 0 ? [] : w.slice(i + 1).map((h) => h.hex);
  }

  async tipHeight() { return this.#tip(await this.#fetchEvent()); }

  // serve heights inside the window; throw outside it (the cross-check
  // treats an unreachable source as not-divergence, which is honest)
  async headersRange(start, count) {
    const event = await this.#fetchEvent();
    const w = this.#window(event);
    const tip = this.#tip(event);
    const first = tip - w.length + 1;
    if (start < first || start + count - 1 > tip) {
      throw new Error(`${this.base}: heights ${start}..${start + count - 1} outside window ${first}..${tip}`);
    }
    return w.slice(start - first, start - first + count).map((h) => h.hex);
  }
}
