// BIP 158 compact block filters: Golomb-Rice coded sets over SipHash-2-4,
// plus the BIP 157 filter-header chain. A ~20 KB filter answers "could
// anything in this block be mine?" locally and in private; a match is
// confirmed by fetching the full block — omission is impossible because
// the client checks the block itself.

import { dsha256, bytesToHex, hexToBytes, reverseHex } from './hash.js';

const M64 = (1n << 64n) - 1n;
const rotl = (x, b) => ((x << b) | (x >> (64n - b))) & M64;

// SipHash-2-4 (64-bit output) keyed with 16 bytes.
export function siphash(key16, data) {
  const dv = new DataView(key16.buffer, key16.byteOffset);
  const k0 = dv.getBigUint64(0, true);
  const k1 = dv.getBigUint64(8, true);
  let v0 = k0 ^ 0x736f6d6570736575n;
  let v1 = k1 ^ 0x646f72616e646f6dn;
  let v2 = k0 ^ 0x6c7967656e657261n;
  let v3 = k1 ^ 0x7465646279746573n;
  const round = () => {
    v0 = (v0 + v1) & M64; v1 = rotl(v1, 13n) ^ v0; v0 = rotl(v0, 32n);
    v2 = (v2 + v3) & M64; v3 = rotl(v3, 16n) ^ v2;
    v0 = (v0 + v3) & M64; v3 = rotl(v3, 21n) ^ v0;
    v2 = (v2 + v1) & M64; v1 = rotl(v1, 17n) ^ v2; v2 = rotl(v2, 32n);
  };
  const n = data.length;
  for (let off = 0; off + 8 <= n; off += 8) {
    let m = 0n;
    for (let i = 7; i >= 0; i--) m = (m << 8n) | BigInt(data[off + i]);
    v3 ^= m; round(); round(); v0 ^= m;
  }
  let last = BigInt(n & 0xff) << 56n;
  for (let i = n - (n % 8); i < n; i++) last |= BigInt(data[i]) << BigInt(8 * (i % 8));
  v3 ^= last; round(); round(); v0 ^= last;
  v2 ^= 0xffn; round(); round(); round(); round();
  return (v0 ^ v1 ^ v2 ^ v3) & M64;
}

class BitWriter {
  constructor() { this.bytes = []; this.acc = 0; this.nbits = 0; }
  write(value, bits) {
    for (let i = bits - 1n; i >= 0n; i--) {
      this.acc = (this.acc << 1) | Number((value >> i) & 1n);
      if (++this.nbits === 8) { this.bytes.push(this.acc); this.acc = 0; this.nbits = 0; }
    }
  }
  out() {
    if (this.nbits) this.bytes.push(this.acc << (8 - this.nbits));
    return Uint8Array.from(this.bytes);
  }
}

class BitReader {
  constructor(bytes) { this.b = bytes; this.pos = 0; }
  bit() {
    const byte = this.b[this.pos >> 3];
    if (byte === undefined) throw new Error('filter bitstream exhausted');
    return (byte >> (7 - (this.pos++ & 7))) & 1;
  }
  bits(n) {
    let v = 0n;
    for (let i = 0; i < n; i++) v = (v << 1n) | BigInt(this.bit());
    return v;
  }
}

export class GcsFilter {
  // Basic-filter parameters (BIP 158): P = 19, M = 784931.
  constructor(params = { p: 19, m: 784931 }) {
    this.p = params.p;
    this.m = BigInt(params.m);
  }

  // The SipHash key: the first 16 bytes of the block hash in internal order.
  keyFor(blockHashDisplayHex) {
    return hexToBytes(blockHashDisplayHex).reverse().subarray(0, 16);
  }

  #hashToRange(key, item, f) {
    return (siphash(key, item) * f) >> 64n; // fast 64x64->128 range reduction
  }

  // items: array of byte arrays (deduplicated by the caller or here).
  encode(key, items) {
    const seen = new Set();
    const unique = items.filter((it) => {
      const h = bytesToHex(it);
      if (!h.length || seen.has(h)) return false;
      seen.add(h);
      return true;
    });
    const n = unique.length;
    const f = BigInt(n) * this.m;
    const values = unique.map((it) => this.#hashToRange(key, it, f)).sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    const w = new BitWriter();
    let prev = 0n;
    for (const v of values) {
      let q = (v - prev) >> BigInt(this.p);
      while (q > 0n) { w.write(1n, 1n); q--; }
      w.write(0n, 1n);
      w.write((v - prev) & ((1n << BigInt(this.p)) - 1n), BigInt(this.p));
      prev = v;
    }
    // serialized filter: CompactSize N followed by the bitstream
    const body = w.out();
    const nPrefix = n < 0xfd ? Uint8Array.of(n)
      : Uint8Array.of(0xfd, n & 0xff, n >> 8);
    const out = new Uint8Array(nPrefix.length + body.length);
    out.set(nPrefix); out.set(body, nPrefix.length);
    return out;
  }

  #decodeValues(filterBytes) {
    let n, offset;
    if (filterBytes[0] < 0xfd) { n = filterBytes[0]; offset = 1; }
    else { n = filterBytes[1] | (filterBytes[2] << 8); offset = 3; }
    const r = new BitReader(filterBytes.subarray(offset));
    const values = [];
    let prev = 0n;
    for (let i = 0; i < n; i++) {
      let q = 0n;
      while (r.bit()) q++;
      prev += (q << BigInt(this.p)) | r.bits(this.p);
      values.push(prev);
    }
    return values;
  }

  // Does the filter (probably) contain any of the target items?
  matchAny(key, filterBytes, targets) {
    let n, _;
    if (filterBytes[0] < 0xfd) n = filterBytes[0];
    else n = filterBytes[1] | (filterBytes[2] << 8);
    const f = BigInt(n) * this.m;
    const wanted = new Set(targets.map((t) => this.#hashToRange(key, t, f).toString()));
    if (n === 0) return false;
    for (const v of this.#decodeValues(filterBytes)) {
      if (wanted.has(v.toString())) return true;
    }
    return false;
  }

  // The items of a block's BASIC filter: every spent prevout scriptPubKey
  // (coinbase excluded) and every created scriptPubKey, except empty
  // scripts and OP_RETURN data carriers. Spent scripts come from
  // `prevoutScripts` (hex array, in input order, coinbase input excluded) —
  // a pruned window resolves them exactly like the block validator does.
  basicItems(block, prevoutScripts) {
    const items = [];
    for (const hex of prevoutScripts) {
      if (hex && !hex.startsWith('6a')) items.push(hexToBytes(hex));
    }
    for (const tx of block.transactions) {
      for (const out of tx.outputs) {
        if (out.scriptPubKey && !out.scriptPubKey.startsWith('6a')) {
          items.push(hexToBytes(out.scriptPubKey));
        }
      }
    }
    return items;
  }

  // BIP 157 header chain: header = dsha256(filterHash || prevHeader),
  // hashes in internal order; exposed in display order like everything else.
  filterHash(filterBytes) {
    return reverseHex(dsha256(filterBytes));
  }

  filterHeader(filterBytes, prevHeaderDisplayHex) {
    const cat = new Uint8Array(64);
    cat.set(dsha256(filterBytes));
    cat.set(hexToBytes(prevHeaderDisplayHex).reverse(), 32);
    return reverseHex(dsha256(cat));
  }
}
