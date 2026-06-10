// Wallet layer, verification-oriented: BIP 32 watch-only derivation (public
// child keys from an xpub — no private keys anywhere in this codebase),
// BIP 174 PSBT parsing with byte-exact round-trips and finalized-transaction
// extraction, and BIP 21 payment URIs.

import { dsha256, hash160, hmacSha512, sha256, bytesToHex, hexToBytes } from './hash.js';
import { ckdPubKey, tapOutputKey } from './secp256k1.js';

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function b58checkEncode(payload) {
  const data = new Uint8Array(payload.length + 4);
  data.set(payload);
  data.set(dsha256(payload).subarray(0, 4), payload.length);
  let n = 0n;
  for (const b of data) n = (n << 8n) | BigInt(b);
  let out = '';
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of data) { if (b !== 0) break; out = '1' + out; }
  return out;
}

function b58checkDecode(str) {
  let n = 0n;
  for (const ch of str) {
    const v = B58.indexOf(ch);
    if (v < 0) return null;
    n = n * 58n + BigInt(v);
  }
  const bytes = [];
  while (n > 0n) { bytes.unshift(Number(n & 0xffn)); n >>= 8n; }
  for (const ch of str) { if (ch !== '1') break; bytes.unshift(0); }
  const data = Uint8Array.from(bytes);
  if (data.length < 5) return null;
  const payload = data.subarray(0, data.length - 4);
  const check = dsha256(payload).subarray(0, 4);
  if (!check.every((b, i) => b === data[data.length - 4 + i])) return null;
  return payload;
}

const XPUB_VERSION = 0x0488b21e; // mainnet public

export class Bip32 {
  // xpub string -> node {version, depth, parentFingerprint, childNumber,
  // chainCode (hex), publicKey (hex, 33 bytes)} — or null. Private keys
  // (xprv) are rejected by design.
  static decode(xkey) {
    const data = b58checkDecode(xkey);
    if (!data || data.length !== 78) return null;
    const dv = new DataView(data.buffer, data.byteOffset);
    const version = dv.getUint32(0);
    if (version !== XPUB_VERSION) return null; // watch-only: xpub or nothing
    if (data[45] !== 0x02 && data[45] !== 0x03) return null;
    return {
      version,
      depth: data[4],
      parentFingerprint: bytesToHex(data.subarray(5, 9)),
      childNumber: dv.getUint32(9),
      chainCode: bytesToHex(data.subarray(13, 45)),
      publicKey: bytesToHex(data.subarray(45, 78)),
    };
  }

  static encode(node) {
    const data = new Uint8Array(78);
    const dv = new DataView(data.buffer);
    dv.setUint32(0, node.version);
    data[4] = node.depth;
    data.set(hexToBytes(node.parentFingerprint), 5);
    dv.setUint32(9, node.childNumber);
    data.set(hexToBytes(node.chainCode), 13);
    data.set(hexToBytes(node.publicKey), 45);
    return b58checkEncode(data);
  }

  static fingerprint(node) {
    return bytesToHex(hash160(hexToBytes(node.publicKey)).subarray(0, 4));
  }

  // Non-hardened public child derivation (CKDpub). Hardened indices are
  // impossible without the private key and throw.
  static derive(node, index) {
    if (index >= 0x80000000) throw new Error('hardened derivation requires the private key');
    const pub = hexToBytes(node.publicKey);
    const data = new Uint8Array(37);
    data.set(pub);
    new DataView(data.buffer).setUint32(33, index);
    const I = hmacSha512(hexToBytes(node.chainCode), data);
    const childKey = ckdPubKey(pub, I.subarray(0, 32));
    if (!childKey) throw new Error('invalid child (try the next index)');
    return {
      version: node.version,
      depth: node.depth + 1,
      parentFingerprint: Bip32.fingerprint(node),
      childNumber: index,
      chainCode: bytesToHex(I.subarray(32)),
      publicKey: bytesToHex(childKey),
    };
  }

  // "0/1/5" or "m/0/1" (hardened steps like 0' or 0H throw).
  static derivePath(node, path) {
    let n = node;
    for (const part of path.split('/')) {
      if (part === 'm' || part === '') continue;
      if (/['hH]$/.test(part)) throw new Error('hardened derivation requires the private key');
      n = Bip32.derive(n, parseInt(part, 10));
    }
    return n;
  }

  // scriptPubKey for a derived key: p2wpkh, p2pkh, or p2tr (BIP 86 tweak
  // with an empty script tree).
  static scriptPubKey(node, type = 'p2wpkh') {
    const pub = hexToBytes(node.publicKey);
    if (type === 'p2pkh') return '76a914' + bytesToHex(hash160(pub)) + '88ac';
    if (type === 'p2wpkh') return '0014' + bytesToHex(hash160(pub));
    if (type === 'p2tr') {
      const output = tapOutputKey(pub.subarray(1)); // x-only internal key
      if (!output) throw new Error('invalid taproot tweak');
      return '5120' + bytesToHex(output);
    }
    throw new Error(`unsupported type: ${type}`);
  }
}

// ---- BIP 174 PSBT ----

const PSBT_MAGIC = '70736274ff';

function b64ToBytes(b64) {
  if (typeof Buffer !== 'undefined') return new Uint8Array(Buffer.from(b64, 'base64'));
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
function bytesToB64(bytes) {
  if (typeof Buffer !== 'undefined') return Buffer.from(bytes).toString('base64');
  return btoa(String.fromCharCode(...bytes));
}

class PsbtReader {
  constructor(bytes) { this.b = bytes; this.pos = 0; }
  varint() {
    const first = this.b[this.pos++];
    if (first < 0xfd) return first;
    if (first === 0xfd) { const v = this.b[this.pos] | (this.b[this.pos + 1] << 8); this.pos += 2; return v; }
    if (first === 0xfe) {
      const v = new DataView(this.b.buffer, this.b.byteOffset + this.pos, 4).getUint32(0, true);
      this.pos += 4; return v;
    }
    throw new Error('oversized varint');
  }
  take(n) {
    if (this.pos + n > this.b.length) throw new Error('truncated psbt');
    const out = this.b.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  // one key-value map: ordered [keyHex, valueHex] pairs until a 0x00 separator
  map() {
    const pairs = [];
    const seen = new Set();
    for (;;) {
      if (this.pos >= this.b.length) throw new Error('unterminated map');
      const keyLen = this.varint();
      if (keyLen === 0) return pairs;
      const key = bytesToHex(this.take(keyLen));
      if (seen.has(key)) throw new Error('duplicate key in map');
      seen.add(key);
      const value = bytesToHex(this.take(this.varint()));
      pairs.push([key, value]);
    }
  }
}

const mapGet = (pairs, keyHex) => pairs.find(([k]) => k === keyHex)?.[1] ?? null;

export class Psbt {
  // Accepts base64 or hex. The unsigned transaction is decoded with `codec`
  // and validated (it must carry no signatures and no witness data).
  static parse(input, codec) {
    const bytes = /^[0-9a-f]+$/i.test(input.trim()) && input.trim().toLowerCase().startsWith(PSBT_MAGIC)
      ? hexToBytes(input.trim().toLowerCase())
      : b64ToBytes(input.trim());
    if (bytesToHex(bytes.subarray(0, 5)) !== PSBT_MAGIC) throw new Error('bad psbt magic');
    const r = new PsbtReader(bytes.subarray(5));

    const global = r.map();
    const txHex = mapGet(global, '00');
    if (!txHex) throw new Error('missing unsigned transaction');
    const tx = codec.decode('Transaction', txHex, { legacy: true });
    if (tx.inputs.some((i) => i.scriptSig !== '')) throw new Error('unsigned tx must have empty scriptSigs');

    const inputs = tx.inputs.map(() => r.map());
    const outputs = tx.outputs.map(() => r.map());
    if (r.pos !== bytes.length - 5) throw new Error('trailing bytes after psbt');
    return { global, inputs, outputs, tx };
  }

  static serialize(psbt) {
    const chunks = [hexToBytes(PSBT_MAGIC)];
    const varint = (n) => {
      if (n < 0xfd) return Uint8Array.of(n);
      if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, n >> 8);
      const b = new Uint8Array(5); b[0] = 0xfe;
      new DataView(b.buffer).setUint32(1, n, true);
      return b;
    };
    const writeMap = (pairs) => {
      for (const [k, v] of pairs) {
        const kb = hexToBytes(k), vb = hexToBytes(v);
        chunks.push(varint(kb.length), kb, varint(vb.length), vb);
      }
      chunks.push(Uint8Array.of(0));
    };
    writeMap(psbt.global);
    for (const m of psbt.inputs) writeMap(m);
    for (const m of psbt.outputs) writeMap(m);
    const len = chunks.reduce((s, c) => s + c.length, 0);
    const out = new Uint8Array(len);
    let p = 0;
    for (const c of chunks) { out.set(c, p); p += c.length; }
    return out;
  }

  static toBase64(psbt) { return bytesToB64(Psbt.serialize(psbt)); }

  // The prevout for input i, from witness_utxo (0x01) or non_witness_utxo
  // (0x00); null if neither is present.
  static utxo(psbt, i, codec) {
    const witnessUtxo = mapGet(psbt.inputs[i], '01');
    if (witnessUtxo) return codec.decode('TransactionOutput', witnessUtxo);
    const nonWitness = mapGet(psbt.inputs[i], '00');
    if (nonWitness) {
      const prev = codec.decode('Transaction', nonWitness);
      const { txid, vout } = psbt.tx.inputs[i].prevout;
      if (codec.txid(prev) !== txid) throw new Error(`non_witness_utxo txid mismatch on input ${i}`);
      return prev.outputs[vout];
    }
    return null;
  }

  // Extract the network-ready transaction from a fully finalized PSBT
  // (final_scriptsig 0x07 / final_scriptwitness 0x08 on every input).
  static extract(psbt, codec) {
    const inputs = [];
    const witness = [];
    let anyWitness = false;
    for (const [i, inp] of psbt.tx.inputs.entries()) {
      const finalSig = mapGet(psbt.inputs[i], '07');
      const finalWit = mapGet(psbt.inputs[i], '08');
      if (finalSig == null && finalWit == null) return null; // not finalized
      inputs.push({ ...inp, scriptSig: finalSig ?? '' });
      if (finalWit) {
        anyWitness = true;
        const wr = new PsbtReader(hexToBytes(finalWit));
        const stack = [];
        const count = wr.varint();
        for (let j = 0; j < count; j++) stack.push(bytesToHex(wr.take(wr.varint())));
        witness.push(stack);
      } else {
        witness.push([]);
      }
    }
    const tx = { version: psbt.tx.version, inputs, outputs: psbt.tx.outputs, lockTime: psbt.tx.lockTime };
    if (anyWitness) tx.witness = witness;
    return tx;
  }
}

// ---- BIP 21 payment URIs ----

export function parseBip21(uri) {
  const m = /^bitcoin:([^?]*)(?:\?(.*))?$/i.exec(uri.trim());
  if (!m) return null;
  const out = { address: m[1] };
  for (const kv of (m[2] ?? '').split('&')) {
    if (!kv) continue;
    const [k, v = ''] = kv.split('=');
    const key = decodeURIComponent(k);
    const value = decodeURIComponent(v.replace(/\+/g, ' '));
    if (key === 'amount') out.amountSats = Math.round(parseFloat(value) * 1e8);
    else out[key] = value;
  }
  return out;
}
