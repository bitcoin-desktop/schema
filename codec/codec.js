// Schema-driven Bitcoin codec.
//
// The codec contains no per-type serialization logic: it walks the ordered
// `fields` lists in the JSON-LD schema and interprets each field's wireType.
// Two genuine special cases of the protocol are handled by named wire rules
// rather than hardcoded types:
//   - presentIf "segwit": on decode, segwit serialization is detected by the
//     0x00 marker byte (a legacy transaction cannot have zero inputs); on
//     encode, by the presence of a non-empty `witness` array.
//   - wireType "witness": the witness vector carries no count prefix; its
//     length equals the number of inputs already decoded.
//
// Hashes (hash256) and scripts (varbytes) are represented as hex strings in
// instances; hash256 values use display order (byte-reversed), as in every
// explorer and RPC interface. Satoshi amounts (i64le) are plain numbers —
// the maximum supply (2.1e15 sats) is well inside Number.MAX_SAFE_INTEGER.

import { dsha256, bytesToHex, hexToBytes, reverseHex } from './hash.js';

const shortId = (id) => id.replace(/^btc:/, '').replace(/^.*\//, '');

class Reader {
  constructor(bytes) {
    this.bytes = bytes;
    this.dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    this.pos = 0;
  }
  peek() { return this.bytes[this.pos]; }
  take(n) {
    if (this.pos + n > this.bytes.length) throw new Error('unexpected end of data');
    const out = this.bytes.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  u8() { return this.take(1)[0]; }
  u16le() { const v = this.dv.getUint16(this.pos, true); this.pos += 2; return v; }
  u16be() { const v = this.dv.getUint16(this.pos, false); this.pos += 2; return v; }
  u64le() {
    const v = this.dv.getBigUint64(this.pos, true); this.pos += 8;
    return v <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(v) : v.toString();
  }
  u32le() { const v = this.dv.getUint32(this.pos, true); this.pos += 4; return v; }
  i32le() { const v = this.dv.getInt32(this.pos, true); this.pos += 4; return v; }
  i64le() { const v = this.dv.getBigInt64(this.pos, true); this.pos += 8; return Number(v); }
  varint() {
    const first = this.u8();
    if (first < 0xfd) return first;
    if (first === 0xfd) return this.u16le();
    if (first === 0xfe) return this.u32le();
    const v = this.dv.getBigUint64(this.pos, true); this.pos += 8;
    return Number(v);
  }
}

class Writer {
  constructor() { this.chunks = []; }
  bytes(b) { this.chunks.push(b); }
  u8(v) { this.bytes(Uint8Array.of(v)); }
  u16le(v) { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, v, true); this.bytes(b); }
  u16be(v) { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, v, false); this.bytes(b); }
  u64le(v) { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(v), true); this.bytes(b); }
  u32le(v) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, v, true); this.bytes(b); }
  i32le(v) { const b = new Uint8Array(4); new DataView(b.buffer).setInt32(0, v, true); this.bytes(b); }
  i64le(v) { const b = new Uint8Array(8); new DataView(b.buffer).setBigInt64(0, BigInt(v), true); this.bytes(b); }
  varint(v) {
    if (v < 0xfd) this.u8(v);
    else if (v <= 0xffff) { this.u8(0xfd); this.u16le(v); }
    else if (v <= 0xffffffff) { this.u8(0xfe); this.u32le(v); }
    else { this.u8(0xff); const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(v), true); this.bytes(b); }
  }
  out() {
    const len = this.chunks.reduce((n, c) => n + c.length, 0);
    const all = new Uint8Array(len);
    let p = 0;
    for (const c of this.chunks) { all.set(c, p); p += c.length; }
    return all;
  }
}

export class Codec {
  constructor(...schemas) {
    this.types = new Map();
    for (const schema of schemas) {
      for (const node of schema['@graph'] ?? []) {
        if (node['@type'] === 'ConsensusStruct') this.types.set(shortId(node['@id']), node);
      }
    }
  }

  def(typeName) {
    const def = this.types.get(typeName);
    if (!def) throw new Error(`unknown type: ${typeName}`);
    return def;
  }

  // ---- decode ----

  decode(typeName, bytesOrHex, opts = {}) {
    const bytes = typeof bytesOrHex === 'string' ? hexToBytes(bytesOrHex) : bytesOrHex;
    const r = new Reader(bytes);
    const obj = this.#readStruct(typeName, r, opts);
    if (r.pos !== bytes.length) throw new Error(`${bytes.length - r.pos} trailing bytes after ${typeName}`);
    return obj;
  }

  #readStruct(typeName, r, opts = {}) {
    const def = this.def(typeName);
    const obj = {};
    let segwit = opts.legacy ? false : null;
    for (const f of def.fields) {
      if (f.presentIf === 'segwit') {
        if (segwit === null) segwit = r.peek() === 0x00;
        if (!segwit) continue;
      }
      if (f.optionalTrailing && r.pos >= r.bytes.length) continue;
      const v = this.#readField(f, r, obj);
      if (f.constValue !== undefined) {
        if (v !== f.constValue) throw new Error(`${typeName}.${f.label}: expected ${f.constValue}, got ${v}`);
        continue; // marker/flag are serialization artifacts, not data
      }
      obj[f.label] = v;
    }
    return obj;
  }

  #readField(f, r, obj) {
    switch (f.wireType) {
      case 'u8': return r.u8();
      case 'u16le': return r.u16le();
      case 'u16be': return r.u16be();
      case 'u32le': return r.u32le();
      case 'i32le': return r.i32le();
      case 'i64le': return r.i64le();
      case 'u64le': return r.u64le();
      case 'varint': return r.varint();
      case 'hash256': return reverseHex(r.take(32));
      case 'varbytes': return bytesToHex(r.take(r.varint()));
      case 'bytes': return bytesToHex(r.take(f.wireSize));
      case 'ascii': {
        const raw = r.take(f.wireSize);
        let end = raw.length;
        while (end > 0 && raw[end - 1] === 0) end--;
        return new TextDecoder().decode(raw.subarray(0, end));
      }
      case 'varstr': return new TextDecoder().decode(r.take(r.varint()));
      case 'struct': return this.#readStruct(shortId(f.structType), r);
      case 'vec': {
        const n = r.varint();
        const out = [];
        for (let i = 0; i < n; i++) out.push(this.#readItem(f.itemType, r));
        return out;
      }
      case 'witness': {
        const out = [];
        for (let i = 0; i < obj.inputs.length; i++) {
          const items = r.varint();
          const stack = [];
          for (let j = 0; j < items; j++) stack.push(bytesToHex(r.take(r.varint())));
          out.push(stack);
        }
        return out;
      }
      default: throw new Error(`unknown wireType: ${f.wireType}`);
    }
  }

  #readItem(itemType, r) {
    if (itemType === 'varbytes') return bytesToHex(r.take(r.varint()));
    if (itemType === 'hash256') return reverseHex(r.take(32));
    return this.#readStruct(shortId(itemType), r);
  }

  // ---- encode ----

  encode(typeName, obj, opts = {}) {
    const w = new Writer();
    this.#writeStruct(typeName, obj, w, opts);
    return w.out();
  }

  encodeHex(typeName, obj, opts = {}) { return bytesToHex(this.encode(typeName, obj, opts)); }

  #writeStruct(typeName, obj, w, opts = {}) {
    const def = this.def(typeName);
    const segwit = !opts.legacy && Array.isArray(obj.witness) && obj.witness.some((s) => s.length > 0);
    for (const f of def.fields) {
      if (f.presentIf === 'segwit' && !segwit) continue;
      if (f.optionalTrailing && obj[f.label] === undefined) continue;
      this.#writeField(f, f.constValue !== undefined ? f.constValue : obj[f.label], w);
    }
  }

  #writeField(f, v, w) {
    switch (f.wireType) {
      case 'u8': return w.u8(v);
      case 'u16le': return w.u16le(v);
      case 'u16be': return w.u16be(v);
      case 'u32le': return w.u32le(v);
      case 'i32le': return w.i32le(v);
      case 'i64le': return w.i64le(v);
      case 'u64le': return w.u64le(v);
      case 'varint': return w.varint(v);
      case 'hash256': return w.bytes(hexToBytes(v).reverse());
      case 'bytes': {
        const b = hexToBytes(v);
        if (b.length !== f.wireSize) throw new Error(`${f.label}: expected ${f.wireSize} bytes`);
        return w.bytes(b);
      }
      case 'ascii': {
        const b = new Uint8Array(f.wireSize);
        b.set(new TextEncoder().encode(v).subarray(0, f.wireSize));
        return w.bytes(b);
      }
      case 'varstr': {
        const b = new TextEncoder().encode(v);
        w.varint(b.length);
        return w.bytes(b);
      }
      case 'varbytes': { const b = hexToBytes(v); w.varint(b.length); return w.bytes(b); }
      case 'struct': return this.#writeStruct(shortId(f.structType), v, w);
      case 'vec': {
        w.varint(v.length);
        for (const item of v) this.#writeItem(f.itemType, item, w);
        return;
      }
      case 'witness': {
        for (const stack of v) {
          w.varint(stack.length);
          for (const item of stack) { const b = hexToBytes(item); w.varint(b.length); w.bytes(b); }
        }
        return;
      }
      default: throw new Error(`unknown wireType: ${f.wireType}`);
    }
  }

  #writeItem(itemType, v, w) {
    if (itemType === 'varbytes') { const b = hexToBytes(v); w.varint(b.length); return w.bytes(b); }
    if (itemType === 'hash256') return w.bytes(hexToBytes(v).reverse());
    return this.#writeStruct(shortId(itemType), v, w);
  }

  // ---- derived fields (implementations of the schema's `derivation` formulas) ----

  txid(tx) { return reverseHex(dsha256(this.encode('Transaction', tx, { legacy: true }))); }
  wtxid(tx) { return reverseHex(dsha256(this.encode('Transaction', tx))); }
  blockHash(header) { return reverseHex(dsha256(this.encode('BlockHeader', header))); }
  txSize(tx) { return this.encode('Transaction', tx).length; }
  txWeight(tx) {
    return 3 * this.encode('Transaction', tx, { legacy: true }).length + this.encode('Transaction', tx).length;
  }
  txVsize(tx) { return Math.ceil(this.txWeight(tx) / 4); }

  // Merkle root over display-order txids (BIP 98 duplicate-last for odd levels).
  merkleRoot(txids) {
    let level = txids.map((id) => hexToBytes(id).reverse());
    while (level.length > 1) {
      const next = [];
      for (let i = 0; i < level.length; i += 2) {
        const a = level[i];
        const b = level[i + 1] ?? a;
        const cat = new Uint8Array(64);
        cat.set(a); cat.set(b, 32);
        next.push(dsha256(cat));
      }
      level = next;
    }
    return reverseHex(level[0]);
  }

  // Expand compact nBits to a 256-bit target (as BigInt).
  expandCompact(bits) {
    const exponent = bits >>> 24;
    const mantissa = BigInt(bits & 0x007fffff);
    return exponent <= 3 ? mantissa >> (8n * BigInt(3 - exponent)) : mantissa << (8n * BigInt(exponent - 3));
  }

  checkProofOfWork(header) {
    return BigInt('0x' + this.blockHash(header)) <= this.expandCompact(header.bits);
  }
}
