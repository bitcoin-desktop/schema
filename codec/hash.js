// Pure-JS SHA-256 and Bitcoin hash helpers. Zero dependencies, works in
// browsers and Node alike. Operates on Uint8Array.

const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const rotr = (x, n) => (x >>> n) | (x << (32 - n));

// Optional SHA-256 backend (e.g. native node:crypto / WebCrypto / WASM) injected
// by performance-sensitive callers; null = the pure-JS path below. Keeps this
// module zero-dependency: the engine never imports an accelerated hasher, the
// caller supplies one. Must return a 32-byte Uint8Array byte-identical to the
// pure-JS implementation (callers gate on a consensus-equivalence proof).
let __sha256Backend = null;
export function setSha256Backend(fn) { __sha256Backend = fn; }

export function sha256(data) {
  if (__sha256Backend) return __sha256Backend(data);
  const len = data.length;
  const bitLen = len * 8;
  const padded = new Uint8Array((((len + 8) >> 6) + 1) << 6);
  padded.set(data);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
  dv.setUint32(padded.length - 4, bitLen >>> 0);

  const h = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  ]);
  const w = new Uint32Array(64);

  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (hh + S1 + ch + K[i] + w[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0;
    h[2] = (h[2] + c) >>> 0; h[3] = (h[3] + d) >>> 0;
    h[4] = (h[4] + e) >>> 0; h[5] = (h[5] + f) >>> 0;
    h[6] = (h[6] + g) >>> 0; h[7] = (h[7] + hh) >>> 0;
  }

  const out = new Uint8Array(32);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) ov.setUint32(i * 4, h[i]);
  return out;
}

// Bitcoin's hash function: double SHA-256.
export const dsha256 = (data) => sha256(sha256(data));

export function bytesToHex(bytes) {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

export function hexToBytes(hex) {
  if (hex.length % 2) throw new Error('odd-length hex');
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

// Internal byte order -> display order (and vice versa).
export const reverseHex = (bytes) => bytesToHex(Uint8Array.from(bytes).reverse());

// ---- SHA-1 (needed only for OP_SHA1) ----
export function sha1(data) {
  const len = data.length, bitLen = len * 8;
  const padded = new Uint8Array((((len + 8) >> 6) + 1) << 6);
  padded.set(data); padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
  dv.setUint32(padded.length - 4, bitLen >>> 0);
  const h = new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]);
  const w = new Uint32Array(80);
  const rol = (x, n) => (x << n) | (x >>> (32 - n));
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) w[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 80; i++) w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    let [a, b, c, d, e] = h;
    for (let i = 0; i < 80; i++) {
      const [f, k] = i < 20 ? [(b & c) | (~b & d), 0x5a827999]
        : i < 40 ? [b ^ c ^ d, 0x6ed9eba1]
        : i < 60 ? [(b & c) | (b & d) | (c & d), 0x8f1bbcdc]
        : [b ^ c ^ d, 0xca62c1d6];
      const t = (rol(a, 5) + f + e + k + w[i]) >>> 0;
      e = d; d = c; c = rol(b, 30); b = a; a = t;
    }
    h[0] = (h[0] + a) >>> 0; h[1] = (h[1] + b) >>> 0; h[2] = (h[2] + c) >>> 0;
    h[3] = (h[3] + d) >>> 0; h[4] = (h[4] + e) >>> 0;
  }
  const out = new Uint8Array(20);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 5; i++) ov.setUint32(i * 4, h[i]);
  return out;
}

// ---- RIPEMD-160 (OP_RIPEMD160, and OP_HASH160 = ripemd160(sha256(x))) ----
const RL = [
  0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
  7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
  3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,
  1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
  4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
const RR = [
  5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,
  6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
  15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,
  8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
  12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
const SL = [
  11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,
  7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
  11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,
  11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
  9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
const SR = [
  8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,
  9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
  9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,
  15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
  8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];

export function ripemd160(data) {
  const len = data.length, bitLen = len * 8;
  const padded = new Uint8Array((((len + 8) >> 6) + 1) << 6);
  padded.set(data); padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, bitLen >>> 0, true);          // little-endian length
  dv.setUint32(padded.length - 4, Math.floor(bitLen / 0x100000000), true);
  const h = new Uint32Array([0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0]);
  const rol = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
  const F = [
    (x, y, z) => x ^ y ^ z,
    (x, y, z) => (x & y) | (~x & z),
    (x, y, z) => (x | ~y) ^ z,
    (x, y, z) => (x & z) | (y & ~z),
    (x, y, z) => x ^ (y | ~z),
  ];
  const KL = [0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
  const KR = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0];
  for (let off = 0; off < padded.length; off += 64) {
    const x = new Uint32Array(16);
    for (let i = 0; i < 16; i++) x[i] = dv.getUint32(off + i * 4, true);
    let [al, bl, cl, dl, el] = h;
    let [ar, br, cr, dr, er] = h;
    for (let j = 0; j < 80; j++) {
      const round = j >> 4;
      let t = (al + F[round](bl, cl, dl) + x[RL[j]] + KL[round]) >>> 0;
      t = (rol(t, SL[j]) + el) >>> 0;
      al = el; el = dl; dl = rol(cl, 10); cl = bl; bl = t;
      t = (ar + F[4 - round](br, cr, dr) + x[RR[j]] + KR[round]) >>> 0;
      t = (rol(t, SR[j]) + er) >>> 0;
      ar = er; er = dr; dr = rol(cr, 10); cr = br; br = t;
    }
    const t = (h[1] + cl + dr) >>> 0;
    h[1] = (h[2] + dl + er) >>> 0;
    h[2] = (h[3] + el + ar) >>> 0;
    h[3] = (h[4] + al + br) >>> 0;
    h[4] = (h[0] + bl + cr) >>> 0;
    h[0] = t;
  }
  const out = new Uint8Array(20);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 5; i++) ov.setUint32(i * 4, h[i], true);
  return out;
}

export const hash160 = (data) => ripemd160(sha256(data));

// BIP 340 tagged hash: sha256(sha256(tag) || sha256(tag) || msg).
const tagMidstates = new Map();
export function taggedHash(tag, ...chunks) {
  let pre = tagMidstates.get(tag);
  if (!pre) {
    const th = sha256(new TextEncoder().encode(tag));
    pre = new Uint8Array(64); pre.set(th); pre.set(th, 32);
    tagMidstates.set(tag, pre);
  }
  const len = chunks.reduce((s, c) => s + c.length, 64);
  const buf = new Uint8Array(len);
  buf.set(pre);
  let p = 64;
  for (const c of chunks) { buf.set(c, p); p += c.length; }
  return sha256(buf);
}

// ---- SHA-512 + HMAC-SHA512 (BIP 32 key derivation) ----
// Round constants are the fractional parts of cube/square roots of the
// first primes — generated here with integer Newton iterations rather
// than hardcoding 80 magic numbers.
const M64 = (1n << 64n) - 1n;

function primes(n) {
  const out = [];
  for (let c = 2; out.length < n; c++) {
    if (out.every((p) => c % p)) out.push(c);
  }
  return out;
}
function isqrt(n) {
  let x = n, y = (x + 1n) >> 1n;
  while (y < x) { x = y; y = (x + n / x) >> 1n; }
  return x;
}
function icbrt(n) {
  let x = 1n << BigInt(Math.ceil(n.toString(2).length / 3) + 1);
  for (;;) {
    const y = (2n * x + n / (x * x)) / 3n;
    if (y >= x) return x;
    x = y;
  }
}
const P80 = primes(80).map(BigInt);
const K512 = P80.map((p) => icbrt(p << 192n) & M64);
const H512 = P80.slice(0, 8).map((p) => isqrt(p << 128n) & M64);

const rotr64 = (x, n) => ((x >> n) | (x << (64n - n))) & M64;

export function sha512(data) {
  const len = data.length;
  const padded = new Uint8Array((((len + 16) >> 7) + 1) << 7);
  padded.set(data);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  const bitLen = BigInt(len) * 8n;
  dv.setBigUint64(padded.length - 8, bitLen & M64);
  dv.setBigUint64(padded.length - 16, bitLen >> 64n);

  const h = [...H512];
  const w = new Array(80);
  for (let off = 0; off < padded.length; off += 128) {
    for (let i = 0; i < 16; i++) w[i] = dv.getBigUint64(off + i * 8);
    for (let i = 16; i < 80; i++) {
      const s0 = rotr64(w[i - 15], 1n) ^ rotr64(w[i - 15], 8n) ^ (w[i - 15] >> 7n);
      const s1 = rotr64(w[i - 2], 19n) ^ rotr64(w[i - 2], 61n) ^ (w[i - 2] >> 6n);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & M64;
    }
    let [a, b, c, d, e, f, g, hh] = h;
    for (let i = 0; i < 80; i++) {
      const S1 = rotr64(e, 14n) ^ rotr64(e, 18n) ^ rotr64(e, 41n);
      const ch = (e & f) ^ (~e & g & M64);
      const t1 = (hh + S1 + ch + K512[i] + w[i]) & M64;
      const S0 = rotr64(a, 28n) ^ rotr64(a, 34n) ^ rotr64(a, 39n);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) & M64;
      hh = g; g = f; f = e; e = (d + t1) & M64;
      d = c; c = b; b = a; a = (t1 + t2) & M64;
    }
    h[0] = (h[0] + a) & M64; h[1] = (h[1] + b) & M64; h[2] = (h[2] + c) & M64; h[3] = (h[3] + d) & M64;
    h[4] = (h[4] + e) & M64; h[5] = (h[5] + f) & M64; h[6] = (h[6] + g) & M64; h[7] = (h[7] + hh) & M64;
  }
  const out = new Uint8Array(64);
  const ov = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) ov.setBigUint64(i * 8, h[i]);
  return out;
}

export function hmacSha512(key, data) {
  if (key.length > 128) key = sha512(key);
  const ipad = new Uint8Array(128 + data.length);
  const opad = new Uint8Array(128 + 64);
  for (let i = 0; i < 128; i++) {
    ipad[i] = (key[i] ?? 0) ^ 0x36;
    opad[i] = (key[i] ?? 0) ^ 0x5c;
  }
  ipad.set(data, 128);
  opad.set(sha512(ipad), 128);
  return sha512(opad);
}
