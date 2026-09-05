// Bitcoin Knots BLAKE2b proof of work for the v2 block header (v29.4.1,
// src/primitives/block.cpp CBlockHeader::GetHash). Operates on the object the
// codec decodes for knots:BlockHeaderV2 (see schema/overlays/knots-blake2b.jsonld):
// hashes in display order, 16-byte fields in wire order, `version` raw.
//
//   h1  = tagged("Bitcoin block header 1", version‖prev‖height‖merkle‖time‖0‖bits‖txCount(u32)‖flags‖clearBits‖sha256tag(xorKey))
//   h2  = tagged("Merge-mining hook", h1 ‖ 0¹⁶ ‖ 0¹⁶ ‖ mmRhs)
//   b1  = blake2b-256(0³² ‖ h2 ‖ extranonce)
//   b2  = blake2b-256(profile-dependent layout of prevHidden/h2, nonces, b1)
//   hash = b2 XOR mask(xorKey, clearBits)          (display-order bytes)
import { taggedHash, bytesToHex, hexToBytes } from '../hash.js';
import { blake2b } from './blake2b.js';

export const VERSION_HEADER_V2_FLAG = 0x80000000;
export const FLAG_USE_TIME_OFFSET = 4;
export const POW_HASH_NAME = 'knots:blake2b-v2';

const rev = (b) => Uint8Array.from(b).reverse();
const u32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const cat = (...parts) => { const out = new Uint8Array(parts.reduce((s, p) => s + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };

export const isHeaderV2 = (h) => ((h.version >>> 0) & VERSION_HEADER_V2_FLAG) !== 0;
// Consensus block time: the wire time plus the offset when the flag says so.
export const headerTime = (h) => (h.flags & FLAG_USE_TIME_OFFSET) ? (h.timeOnWire + h.timeOffset) >>> 0 : h.timeOnWire;

export function hashHeaderV2Detailed(h) {
  const xorKeyWire = hexToBytes(h.xorKey);
  const prevDisplay = hexToBytes(h.prevBlockHash);          // hashPrevBlock.ReversedBytes()
  const xorKeyHash = taggedHash('Bitcoin block hash PoW XOR key', xorKeyWire);
  const mask = new Uint8Array(32);
  if (xorKeyWire.some((x) => x !== 0)) {
    mask.set(taggedHash('Bitcoin block hash PoW XOR mask', xorKeyWire));
    const clearBytes = h.xorKeyMaskClearBits >> 3;
    mask.fill(0, 0, clearBytes);
    if (clearBytes < 32) mask[clearBytes] &= 0xff >> (h.xorKeyMaskClearBits & 7);
  }
  const prevHidden = taggedHash('Bitcoin prevblock header, hashed', prevDisplay);
  const h1 = taggedHash('Bitcoin block header 1', cat(
    u32(h.version), prevDisplay, u32(h.height), rev(hexToBytes(h.merkleRoot)), u32(h.timeOnWire),
    Uint8Array.of(0), u32(h.bits), u32(h.txCount), Uint8Array.of(h.flags, h.xorKeyMaskClearBits), xorKeyHash,
  ));
  const zeros16 = new Uint8Array(16);
  const h2 = taggedHash('Merge-mining hook', cat(h1, zeros16, zeros16, rev(hexToBytes(h.mmRhs))));
  const b1 = blake2b(cat(u32(0), h2, hexToBytes(h.extranonce)), 32);
  const nonces = [u32(h.nonce), u32(h.nonce2), u32(h.timeOffset), u32(h.nonce3)];
  let asicInput;
  switch (h.flags & 3) {
    case 0: { const p = Uint8Array.from(prevHidden); p.fill(0, 0, 6); asicInput = cat(p, ...nonces, b1); break; }
    case 1: asicInput = cat(u32(h.nonce), u32(h.nonce2), u32(h.nonce3), u32(h.timeOffset), b1, h2); break;
    case 2: asicInput = cat(new Uint8Array(48), h2, ...nonces, b1); break;
    default: asicInput = cat(new Uint8Array(80), h2, ...nonces, b1); break;
  }
  const b2 = blake2b(asicInput, 32);
  const hash = b2.map((x, i) => x ^ mask[i]);
  return {
    xorKeyHash: bytesToHex(xorKeyHash), h1: bytesToHex(h1), h2: bytesToHex(h2),
    blake2b1: bytesToHex(b1), blake2b2: bytesToHex(b2), mask: bytesToHex(mask),
    asicProfile: h.flags & 3, asicInput: bytesToHex(asicInput), blockHash: bytesToHex(hash),
  };
}
export const hashHeaderV2 = (h) => hashHeaderV2Detailed(h).blockHash;

// Register the chain's PoW hash on a codec. A v1 (80-byte) header on these
// chains — the pre-fork history — is still SHA256d.
export function registerKnotsBlake2b(codec) {
  const sha256d = codec.powHashes.get('sha256d');
  codec.registerPowHash(POW_HASH_NAME, (bytes, header) => isHeaderV2(header) ? hashHeaderV2(header) : sha256d(bytes));
  return codec;
}
