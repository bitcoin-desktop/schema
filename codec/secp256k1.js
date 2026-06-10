// Zero-dependency ECDSA *verification* over secp256k1, in BigInt arithmetic.
// Verification only — no signing, no private keys, and no constant-time
// requirements. Jacobian coordinates avoid a field inversion per step.

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

const mod = (a, m = P) => ((a % m) + m) % m;

function modpow(b, e, m) {
  let r = 1n; b = mod(b, m);
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}
const inv = (a, m) => modpow(a, m - 2n, m); // m prime (Fermat)

// Jacobian point ops; null = point at infinity.
function jDouble(p) {
  if (!p) return null;
  const [X, Y, Z] = p;
  if (Y === 0n) return null;
  const S = mod(4n * X * Y * Y);
  const M = mod(3n * X * X); // a = 0 for secp256k1
  const X2 = mod(M * M - 2n * S);
  const Y2 = mod(M * (S - X2) - 8n * Y * Y * Y * Y);
  return [X2, Y2, mod(2n * Y * Z)];
}

function jAdd(p, q) {
  if (!p) return q;
  if (!q) return p;
  const [X1, Y1, Z1] = p, [X2, Y2, Z2] = q;
  const Z1Z1 = mod(Z1 * Z1), Z2Z2 = mod(Z2 * Z2);
  const U1 = mod(X1 * Z2Z2), U2 = mod(X2 * Z1Z1);
  const S1 = mod(Y1 * Z2 * Z2Z2), S2 = mod(Y2 * Z1 * Z1Z1);
  if (U1 === U2) return S1 === S2 ? jDouble(p) : null;
  const H = mod(U2 - U1);
  const R = mod(S2 - S1);
  const HH = mod(H * H), HHH = mod(H * HH);
  const X3 = mod(R * R - HHH - 2n * U1 * HH);
  const Y3 = mod(R * (U1 * HH - X3) - S1 * HHH);
  return [X3, Y3, mod(H * Z1 * Z2)];
}

function jMul(p, k) {
  let acc = null, addend = p;
  while (k > 0n) {
    if (k & 1n) acc = jAdd(acc, addend);
    addend = jDouble(addend);
    k >>= 1n;
  }
  return acc;
}

const toAffineX = (p) => {
  const zi = inv(p[2], P);
  return mod(p[0] * zi * zi);
};

const bytesToBig = (bytes) => {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  return n;
};

// 33-byte compressed (02/03) or 65-byte uncompressed (04) SEC1 public key
// -> affine point, or null if not on the curve.
export function parsePubkey(bytes) {
  if (bytes.length === 65 && bytes[0] === 0x04) {
    const x = bytesToBig(bytes.subarray(1, 33));
    const y = bytesToBig(bytes.subarray(33, 65));
    if (mod(y * y) !== mod(x * x * x + 7n)) return null;
    return [x, y];
  }
  if (bytes.length === 33 && (bytes[0] === 0x02 || bytes[0] === 0x03)) {
    const x = bytesToBig(bytes.subarray(1));
    if (x >= P) return null;
    let y = modpow(mod(x * x * x + 7n), (P + 1n) / 4n, P);
    if (mod(y * y) !== mod(x * x * x + 7n)) return null;
    if ((y & 1n) !== BigInt(bytes[0] & 1)) y = P - y;
    return [x, y];
  }
  return null;
}

// Lenient DER (r, s) parsing — pre-BIP66 chain data is not always minimally
// encoded, and verification of historical blocks must accept it.
export function parseDerSignature(bytes) {
  try {
    if (bytes[0] !== 0x30) return null;
    let i = 2;
    if (bytes[i] !== 0x02) return null;
    const rLen = bytes[i + 1];
    const r = bytesToBig(bytes.subarray(i + 2, i + 2 + rLen));
    i += 2 + rLen;
    if (bytes[i] !== 0x02) return null;
    const sLen = bytes[i + 1];
    const s = bytesToBig(bytes.subarray(i + 2, i + 2 + sLen));
    return { r, s };
  } catch {
    return null;
  }
}

// ECDSA verify: signature (parsed r,s) over a 32-byte message hash with an
// affine public key point.
export function verifyEcdsa(msgHash, sig, pubkey) {
  const { r, s } = sig;
  if (r <= 0n || r >= N || s <= 0n || s >= N) return false;
  const e = mod(bytesToBig(msgHash), N);
  const w = inv(s, N);
  const u1 = mod(e * w, N);
  const u2 = mod(r * w, N);
  const G = [GX, GY, 1n];
  const Q = [pubkey[0], pubkey[1], 1n];
  const R = jAdd(jMul(G, u1), jMul(Q, u2));
  if (!R) return false;
  return mod(toAffineX(R), N) === r;
}

// ---- BIP 340 Schnorr verification ----

import { taggedHash } from './hash.js';

const bigToBytes = (n) => {
  const out = new Uint8Array(32);
  for (let i = 31; i >= 0; i--) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
};

// Lift an x-only key to the even-y curve point, or null.
export function liftX(xBytes) {
  const x = bytesToBig(xBytes);
  if (x >= P) return null;
  const c = mod(x * x * x + 7n);
  const y = modpow(c, (P + 1n) / 4n, P);
  if (mod(y * y) !== c) return null;
  return [x, (y & 1n) === 0n ? y : P - y];
}

export function verifySchnorr(msg32, sig64, pubkey32) {
  if (sig64.length !== 64 || pubkey32.length !== 32) return false;
  const Ppoint = liftX(pubkey32);
  if (!Ppoint) return false;
  const r = bytesToBig(sig64.subarray(0, 32));
  const s = bytesToBig(sig64.subarray(32));
  if (r >= P || s >= N) return false;
  const e = mod(bytesToBig(taggedHash('BIP0340/challenge',
    sig64.subarray(0, 32), pubkey32, msg32)), N);
  // R = s*G - e*P
  const G = [GX, GY, 1n];
  const R = jAdd(jMul(G, s), jMul([Ppoint[0], Ppoint[1], 1n], mod(N - e, N)));
  if (!R) return false;
  const zi = inv(R[2], P);
  const ax = mod(R[0] * zi * zi);
  const ay = mod(R[1] * zi * zi * zi);
  return (ay & 1n) === 0n && ax === r;
}

// Verify a taproot output-key commitment: outputKey == lift_x(internalKey) + t*G
// with the given y-parity, where t = taggedHash("TapTweak", internalKey || merkleRoot).
export function checkTapTweak(internalKey32, merkleRoot, outputKey32, parity) {
  const Pp = liftX(internalKey32);
  if (!Pp) return false;
  const t = bytesToBig(taggedHash('TapTweak',
    internalKey32, ...(merkleRoot ? [merkleRoot] : [])));
  if (t >= N) return false;
  const G = [GX, GY, 1n];
  const Q = jAdd([Pp[0], Pp[1], 1n], jMul(G, t));
  if (!Q) return false;
  const zi = inv(Q[2], P);
  const qx = mod(Q[0] * zi * zi);
  const qy = mod(Q[1] * zi * zi * zi);
  return qx === bytesToBig(outputKey32) && Number(qy & 1n) === parity;
}
