// Bitcoin script interpreter, Hornet-style: each opcode is a self-contained
// handler (contrast Bitcoin Core's ~1,500-line EvalScript), keyed by the
// opcode names of the schema's Opcode enumeration, with execution limits
// taken from the schema's scriptLimits instance.
//
// Supported spend paths: p2pk, p2pkh, bare multisig, p2sh (including
// wrapped segwit), p2wpkh, p2wsh — with legacy and BIP 143 sighash and
// real ECDSA verification. OP_CODESEPARATOR truncates the legacy/segwit-v0
// sighash scriptCode at the last executed separator (Core's pbegincodehash).
// verifyInput follows Core's VerifyScript, including the BIP 141 structural
// rules (witness program shape and length, malleated scriptSig, unexpected
// witness, 520-byte witness elements). Unknown witness versions return
// ok:null rather than Core's "success", by design.
// Legacy (pre-segwit) sighash follows Core exactly: every OP_CODESEPARATOR is
// dropped from the serialized scriptCode, and CHECKSIG/CHECKMULTISIG first
// FindAndDelete the signature push(es) from it (SCRIPT_VERIFY_CONST_SCRIPTCODE
// turns both into failures). Known simplification, accepted for now: the
// tapscript codeseparator position (BIP 342) is not yet committed in the
// BIP 341 message.

import { sha256, dsha256, sha1, ripemd160, hash160, bytesToHex, hexToBytes, taggedHash } from './hash.js';
import { parsePubkey, parseDerSignature, verifyEcdsa, verifySchnorr, checkTapTweak, N } from './secp256k1.js';

class ScriptError extends Error {}
const fail = (msg) => { throw new ScriptError(msg); };

// CScriptNum: little-endian, sign bit in the high bit of the last byte.
export function numDecode(bytes, maxLen = 4, requireMinimal = false) {
  if (bytes.length > maxLen) fail('scriptnum overflow');
  // BIP 62 minimal scriptnum (SCRIPT_VERIFY_MINIMALDATA): no trailing zero
  // byte unless it sets the sign bit of the previous byte.
  if (requireMinimal && bytes.length > 0
      && (bytes[bytes.length - 1] & 0x7f) === 0
      && (bytes.length <= 1 || (bytes[bytes.length - 2] & 0x80) === 0)) {
    fail('non-minimal scriptnum');
  }
  if (bytes.length === 0) return 0;
  let n = 0;
  for (let i = 0; i < bytes.length; i++) n += bytes[i] * 2 ** (8 * i);
  if (bytes[bytes.length - 1] & 0x80) n = -(n - 2 ** (8 * bytes.length - 1));
  return n;
}

export function numEncode(n) {
  if (n === 0) return new Uint8Array(0);
  const neg = n < 0;
  let abs = Math.abs(n);
  const bytes = [];
  while (abs > 0) { bytes.push(abs % 256); abs = Math.floor(abs / 256); }
  if (bytes[bytes.length - 1] & 0x80) bytes.push(neg ? 0x80 : 0x00);
  else if (neg) bytes[bytes.length - 1] |= 0x80;
  return Uint8Array.from(bytes);
}

const truthy = (bytes) => {
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== 0) return !(i === bytes.length - 1 && bytes[i] === 0x80); // negative zero
  }
  return false;
};
const boolBytes = (b) => (b ? Uint8Array.of(1) : new Uint8Array(0));
const eq = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
// BIP 141 IsWitnessProgram: 4..42 bytes, OP_0 or OP_1..OP_16, then a single
// direct push of exactly the rest. A PUSHDATA-encoded program is not a program.
function witnessProgram(scriptHex) {
  const b = hexToBytes(scriptHex);
  if (b.length < 4 || b.length > 42) return null;
  if (b[0] !== 0x00 && (b[0] < 0x51 || b[0] > 0x60)) return null;
  if (b[1] + 2 !== b.length) return null;
  return { version: b[0] === 0x00 ? 0 : b[0] - 0x50, program: bytesToHex(b.subarray(2)) };
}
// Core's SigVersion::BASE: the pre-segwit sighash rules (callers that omit
// sigVersion get legacy semantics throughout this file).
const isLegacy = (sigVersion) => sigVersion !== 'witnessV0' && sigVersion !== 'tapscript';

// ---- byte-level script walking, for the two legacy-sighash quirks ----
// End offset of the op starting at `pos`, or -1 when the push is truncated
// (Core's CScript::GetOp failing).
function opEnd(bytes, pos) {
  const op = bytes[pos];
  let len = 0, hdr = 1;
  if (op < 0x4c) len = op;
  else if (op === 0x4c) { if (pos + 2 > bytes.length) return -1; len = bytes[pos + 1]; hdr = 2; }
  else if (op === 0x4d) { if (pos + 3 > bytes.length) return -1; len = bytes[pos + 1] | (bytes[pos + 2] << 8); hdr = 3; }
  else if (op === 0x4e) { if (pos + 5 > bytes.length) return -1; len = (bytes[pos + 1] | (bytes[pos + 2] << 8) | (bytes[pos + 3] << 16) | (bytes[pos + 4] << 24)) >>> 0; hdr = 5; }
  const end = pos + hdr + len;
  return end > bytes.length ? -1 : end;
}
// CScript() << vector: the push encoding Core uses for a signature element.
function pushEncode(data) {
  const n = data.length;
  const head = n < 0x4c ? [n] : n <= 0xff ? [0x4c, n] : n <= 0xffff ? [0x4d, n & 0xff, n >> 8]
    : [0x4e, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff];
  return Uint8Array.from([...head, ...data]);
}
// Core's FindAndDelete: at every opcode boundary, delete each consecutive
// occurrence of `needle`; returns {script, found}.
export function findAndDelete(script, needle) {
  if (!needle.length) return { script, found: 0 };
  const out = []; let found = 0, pc = 0, pc2 = 0;
  do {
    for (let i = pc2; i < pc; i++) out.push(script[i]);
    while (script.length - pc >= needle.length && eq(script.subarray(pc, pc + needle.length), needle)) { pc += needle.length; found++; }
    pc2 = pc;
    if (pc >= script.length) break;
    pc = opEnd(script, pc);
  } while (pc !== -1);
  if (!found) return { script, found: 0 };
  for (let i = pc2; i < script.length; i++) out.push(script[i]);
  return { script: Uint8Array.from(out), found };
}
// Core's CTransactionSignatureSerializer::SerializeScriptCode: the legacy
// sighash commits to scriptCode with every OP_CODESEPARATOR removed. On a
// malformed trailing push (GetOp fails) the remainder is emitted verbatim.
// (Core also keeps the pre-strip length in the size prefix in that case; a
// scriptCode ending in a truncated push cannot execute to completion, so the
// resulting digest never decides validity and the difference is not modelled.)
export function stripCodeSeparators(script) {
  const out = []; let pc = 0;
  while (pc < script.length) {
    const end = opEnd(script, pc);
    if (end === -1) { for (let i = pc; i < script.length; i++) out.push(script[i]); break; }
    if (script[pc] !== 0xab) for (let i = pc; i < end; i++) out.push(script[i]);
    pc = end;
  }
  return Uint8Array.from(out);
}

// Bitcoin CompactSize (1/3/5/9 bytes), matching the codec's varint writer.
// Used for the script-length prefix in the BIP341 TapLeaf hash; tapscripts can
// exceed 65,535 bytes (large inscriptions), so the 0xfe 4-byte case is required.
export function compactSize(n) {
  if (n < 0xfd) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, (n >>> 8) & 0xff);
  if (n <= 0xffffffff) return Uint8Array.of(0xfe, n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff);
  const b = new Uint8Array(9); b[0] = 0xff; new DataView(b.buffer).setBigUint64(1, BigInt(n), true); return b;
}

const DEFAULT_LIMITS = {
  maxScriptSize: 10000, maxScriptElementSize: 520,
  maxOpsPerScript: 201, maxStackSize: 1000, maxMultisigKeys: 20,
};

// BIP 62 minimal-push (SCRIPT_VERIFY_MINIMALDATA): a data push must use the
// shortest possible encoding. `code` is the push opcode actually used.
function minimalPushOk(code, dataHex) {
  const len = dataHex.length / 2;
  if (len === 0) return code === 0x00;                 // must be OP_0
  if (len === 1) {
    const b = parseInt(dataHex.slice(0, 2), 16);
    if (b >= 1 && b <= 16) return false;               // must be OP_1..OP_16
    if (b === 0x81) return false;                       // must be OP_1NEGATE
    return code === 0x01;                               // else a direct 1-byte push
  }
  if (len <= 75) return code === len;                   // direct push
  if (len <= 255) return code === 0x4c;                 // OP_PUSHDATA1
  if (len <= 65535) return code === 0x4d;               // OP_PUSHDATA2
  return true;
}

// ---- signature/pubkey encoding rules, gated by verification flags ----
// (sig includes its trailing 1-byte hashtype.)
// BIP 66 strict DER:
function isValidDerSig(sig) {
  const len = sig.length;
  if (len < 9 || len > 73) return false;
  if (sig[0] !== 0x30 || sig[1] !== len - 3 || sig[2] !== 0x02) return false;
  const lenR = sig[3];
  if (5 + lenR >= len) return false;
  const lenS = sig[5 + lenR];
  if (lenR + lenS + 7 !== len) return false;
  if (lenR === 0 || (sig[4] & 0x80)) return false;
  if (lenR > 1 && sig[4] === 0x00 && !(sig[5] & 0x80)) return false;
  if (sig[lenR + 4] !== 0x02 || lenS === 0 || (sig[lenR + 6] & 0x80)) return false;
  if (lenS > 1 && sig[lenR + 6] === 0x00 && !(sig[lenR + 7] & 0x80)) return false;
  return true;
}
// BIP 62 low-S:
function isLowDerSig(sig) {
  const p = parseDerSignature(sig.subarray(0, sig.length - 1));
  return !!p && p.s <= N / 2n;
}
// STRICTENC defined hashtype (SIGHASH_ALL/NONE/SINGLE, optionally ANYONECANPAY):
function isDefinedHashtype(sig) {
  const ht = sig[sig.length - 1] & ~0x80;
  return ht >= 1 && ht <= 3;
}
// STRICTENC pubkey: compressed (33, 0x02/0x03) or uncompressed (65, 0x04):
function isPubKeyEnc(pub) {
  return (pub.length === 33 && (pub[0] === 0x02 || pub[0] === 0x03))
      || (pub.length === 65 && pub[0] === 0x04);
}

export class ScriptInterpreter {
  constructor(codec, scriptEngine, limits = DEFAULT_LIMITS) {
    this.codec = codec;
    this.scriptEngine = scriptEngine;
    this.limits = limits;
    this.handlers = this.#buildHandlers();
    // Per-transaction sighash midstate cache (BIP143/BIP341 hashPrevouts,
    // hashSequence, hashOutputs, etc. depend only on the whole tx, not the input
    // being signed). Without this, a tx with n segwit/taproot inputs recomputes
    // these O(n)-sized hashes n times = O(n^2); a 1,400-input consolidation then
    // takes ~minutes. Keyed by the tx object (WeakMap) so it clears itself.
    this._sigCache = new WeakMap();
  }

  #txCache(tx) {
    let c = this._sigCache.get(tx);
    if (!c) { c = {}; this._sigCache.set(tx, c); }
    return c;
  }

  // ---- sighash ----

  sighashLegacy(tx, inIndex, scriptCodeHex, hashType) {
    scriptCodeHex = bytesToHex(stripCodeSeparators(hexToBytes(scriptCodeHex)));
    const anyone = hashType & 0x80;
    const base = hashType & 0x1f;
    if (base === 3 && inIndex >= tx.outputs.length) {
      // historical SIGHASH_SINGLE bug: the "hash" is the number 1
      const one = new Uint8Array(32); one[0] = 1;
      return one;
    }
    const inputs = (anyone ? [tx.inputs[inIndex]] : tx.inputs).map((inp, i) => ({
      ...inp,
      scriptSig: (anyone || i === inIndex) ? scriptCodeHex : '',
      sequence: (!anyone && (base === 2 || base === 3) && i !== inIndex) ? 0 : inp.sequence,
    }));
    const outputs = base === 2 ? []
      : base === 3 ? tx.outputs.slice(0, inIndex + 1).map((o, i) =>
          i < inIndex ? { value: -1, scriptPubKey: '' } : o)
      : tx.outputs;
    const ser = this.codec.encode('Transaction',
      { version: tx.version, inputs, outputs, lockTime: tx.lockTime }, { legacy: true });
    const buf = new Uint8Array(ser.length + 4);
    buf.set(ser);
    new DataView(buf.buffer).setUint32(ser.length, hashType, true);
    return dsha256(buf);
  }

  sighashWitnessV0(tx, inIndex, scriptCodeHex, amount, hashType) {
    const anyone = hashType & 0x80;
    const base = hashType & 0x1f;
    const zero = new Uint8Array(32);
    const w = [];
    const push = (b) => w.push(b);
    const u32 = (v) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, v, true); return b; };
    const i64 = (v) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigInt64(0, BigInt(v), true); return b; };
    const outpoint = (inp) => {
      const b = new Uint8Array(36);
      b.set(hexToBytes(inp.prevout.txid).reverse());
      b.set(u32(inp.prevout.vout), 32);
      return b;
    };
    const cat = (arrs) => {
      const out = new Uint8Array(arrs.reduce((s, a) => s + a.length, 0));
      let p = 0; for (const a of arrs) { out.set(a, p); p += a.length; }
      return out;
    };
    const serOut = (o) => this.codec.encode('TransactionOutput', o);
    // These three depend only on the whole tx — memoize per tx (see #txCache).
    const C = this.#txCache(tx);
    const hashPrevouts = anyone ? zero : (C.wPrevouts ??= dsha256(cat(tx.inputs.map(outpoint))));
    const hashSequence = (anyone || base === 2 || base === 3) ? zero
      : (C.wSequence ??= dsha256(cat(tx.inputs.map((i) => u32(i.sequence)))));
    const hashOutputs = (base !== 2 && base !== 3) ? (C.wOutputs ??= dsha256(cat(tx.outputs.map(serOut))))
      : (base === 3 && inIndex < tx.outputs.length) ? dsha256(serOut(tx.outputs[inIndex]))
      : zero;
    const script = hexToBytes(scriptCodeHex);
    const scriptLen = script.length < 0xfd ? Uint8Array.of(script.length)
      : cat([Uint8Array.of(0xfd), new Uint8Array(new Uint16Array([script.length]).buffer)]);
    push(u32(tx.version)); push(hashPrevouts); push(hashSequence);
    push(outpoint(tx.inputs[inIndex]));
    push(scriptLen); push(script);
    push(i64(amount));
    push(u32(tx.inputs[inIndex].sequence));
    push(hashOutputs);
    push(u32(tx.lockTime)); push(u32(hashType));
    return dsha256(cat(w));
  }

  // BIP 341 signature message. Single SHA-256 hashing throughout (not double),
  // wrapped in the TapSighash tag. Commits to every input's amount AND
  // scriptPubKey — hence `prevouts` is the full per-input array.
  sighashTaproot(tx, inIndex, prevouts, hashType, { annex = null, leafHash = null } = {}) {
    if (![0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83].includes(hashType)) fail('invalid taproot sighash type');
    const anyone = hashType & 0x80;
    const base = hashType & 0x03; // 0 = DEFAULT (ALL semantics)
    const u8 = (v) => Uint8Array.of(v);
    const u32 = (v) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, v, true); return b; };
    const i64 = (v) => { const b = new Uint8Array(8); new DataView(b.buffer).setBigInt64(0, BigInt(v), true); return b; };
    const varbytes = (bytes) => {
      if (bytes.length >= 0xfd) fail('oversized script in sighash');
      const b = new Uint8Array(1 + bytes.length); b[0] = bytes.length; b.set(bytes, 1);
      return b;
    };
    const cat = (arrs) => {
      const out = new Uint8Array(arrs.reduce((s, a) => s + a.length, 0));
      let p = 0; for (const a of arrs) { out.set(a, p); p += a.length; }
      return out;
    };
    const outpoint = (inp) => cat([hexToBytes(inp.prevout.txid).reverse(), u32(inp.prevout.vout)]);

    // sha_prevouts/amounts/scriptpubkeys/sequences/outputs depend only on the
    // whole tx (+ its prevout set, identical across inputs) — memoize per tx.
    const C = this.#txCache(tx);
    const parts = [u8(0x00), u8(hashType), u32(tx.version), u32(tx.lockTime)];
    if (!anyone) {
      parts.push(C.tPrevouts ??= sha256(cat(tx.inputs.map(outpoint))));
      parts.push(C.tAmounts ??= sha256(cat(prevouts.map((p) => i64(p.value)))));
      parts.push(C.tScriptpubkeys ??= sha256(cat(prevouts.map((p) => varbytes(hexToBytes(p.scriptPubKey))))));
      parts.push(C.tSequences ??= sha256(cat(tx.inputs.map((i) => u32(i.sequence)))));
    }
    if (base !== 2 && base !== 3) {
      parts.push(C.tOutputs ??= sha256(cat(tx.outputs.map((o) => this.codec.encode('TransactionOutput', o)))));
    }
    parts.push(u8((leafHash ? 2 : 0) + (annex ? 1 : 0))); // spend_type
    if (anyone) {
      parts.push(outpoint(tx.inputs[inIndex]), i64(prevouts[inIndex].value),
        varbytes(hexToBytes(prevouts[inIndex].scriptPubKey)), u32(tx.inputs[inIndex].sequence));
    } else {
      parts.push(u32(inIndex));
    }
    if (annex) parts.push(sha256(varbytes(annex)));
    if (base === 3) {
      if (inIndex >= tx.outputs.length) fail('sighash single without matching output');
      parts.push(sha256(this.codec.encode('TransactionOutput', tx.outputs[inIndex])));
    }
    if (leafHash) parts.push(leafHash, u8(0x00), u32(0xffffffff));
    return taggedHash('TapSighash', cat(parts));
  }

  // Tapscript signature check (BIP 342): an empty signature pushes false;
  // a non-empty INVALID signature fails the whole script; a non-32-byte
  // public key is an "unknown key type" and succeeds (upgrade hook).
  #checkSigTapscript(sigBytes, pubBytes, ctx) {
    if (pubBytes.length === 0) fail('empty pubkey');
    if (sigBytes.length === 0) return false;
    if (ctx.budget) { ctx.budget.n -= 50; if (ctx.budget.n < 0) fail('sigops budget exceeded'); }
    if (pubBytes.length !== 32) return true; // unknown pubkey type
    let hashType = 0x00, sig = sigBytes;
    if (sigBytes.length === 65) {
      hashType = sigBytes[64];
      if (hashType === 0x00) fail('explicit SIGHASH_DEFAULT in 65-byte signature');
      sig = sigBytes.subarray(0, 64);
    } else if (sigBytes.length !== 64) fail('bad schnorr signature size');
    const msg = this.sighashTaproot(ctx.tx, ctx.inIndex, ctx.prevouts, hashType,
      { annex: ctx.annex, leafHash: ctx.leafHash });
    if (!verifySchnorr(msg, sig, pubBytes)) fail('invalid schnorr signature');
    return true;
  }

  #checkSig(sigBytes, pubBytes, ctx) {
    if (ctx.sigVersion === 'tapscript') return this.#checkSigTapscript(sigBytes, pubBytes, ctx);
    const f = ctx.flags;
    // scriptCode is truncated to start after the last executed OP_CODESEPARATOR
    let scriptCode = ctx.codeSepOffset ? ctx.scriptCode.slice(ctx.codeSepOffset * 2) : ctx.scriptCode;
    // Legacy only, and before any encoding check (Core's order): the signature
    // push is deleted from scriptCode. An empty signature is the push OP_0, so
    // it deletes OP_0 opcodes too, which CONST_SCRIPTCODE then rejects.
    // (CHECKMULTISIG deletes every signature up front and sets _sigsDeleted.)
    if (isLegacy(ctx.sigVersion) && !ctx._sigsDeleted) {
      const { script, found } = findAndDelete(hexToBytes(scriptCode), pushEncode(sigBytes));
      if (found && f?.has('CONST_SCRIPTCODE')) fail('SIG_FINDANDDELETE');
      if (found) scriptCode = bytesToHex(script);
    }
    if (f && sigBytes.length > 0) {
      if ((f.has('DERSIG') || f.has('LOW_S') || f.has('STRICTENC')) && !isValidDerSig(sigBytes)) fail('non-DER signature');
      if (f.has('LOW_S') && !isLowDerSig(sigBytes)) fail('high-S signature');
      if (f.has('STRICTENC') && !isDefinedHashtype(sigBytes)) fail('undefined hashtype');
    }
    if (f?.has('STRICTENC') && !isPubKeyEnc(pubBytes)) fail('bad pubkey encoding');
    // BIP 143: witness v0 pubkeys must be compressed under WITNESS_PUBKEYTYPE
    if (ctx.sigVersion === 'witnessV0' && f?.has('WITNESS_PUBKEYTYPE')
        && !(pubBytes.length === 33 && (pubBytes[0] === 0x02 || pubBytes[0] === 0x03))) {
      fail('WITNESS_PUBKEYTYPE');
    }
    if (sigBytes.length === 0) return false;
    const hashType = sigBytes[sigBytes.length - 1];
    const sig = parseDerSignature(sigBytes.subarray(0, sigBytes.length - 1));
    const pub = parsePubkey(pubBytes);
    if (!sig || !pub) return false;
    const hash = ctx.sigVersion === 'witnessV0'
      ? this.sighashWitnessV0(ctx.tx, ctx.inIndex, scriptCode, ctx.amount, hashType)
      : this.sighashLegacy(ctx.tx, ctx.inIndex, scriptCode, hashType);
    return verifyEcdsa(hash, sig, pub);
  }

  // ---- opcode handlers ----

  #buildHandlers() {
    const L = this.limits;
    const pop = (s) => { if (!s.length) fail('stack underflow'); return s.pop(); };
    const peek = (s, n = 1) => { if (s.length < n) fail('stack underflow'); return s[s.length - n]; };
    const num = (s) => numDecode(pop(s), 4, this.requireMinimalNum);
    const pushNum = (s, n) => s.push(numEncode(n));
    const unary = (f) => (s) => pushNum(s, f(num(s)));
    const binary = (f) => (s) => { const b = num(s), a = num(s); pushNum(s, f(a, b)); };
    const binBool = (f) => (s) => { const b = num(s), a = num(s); s.push(boolBytes(f(a, b))); };
    const hashOp = (f) => (s) => s.push(f(pop(s)));

    const h = {
      OP_0: (s) => s.push(new Uint8Array(0)),
      OP_1NEGATE: (s) => pushNum(s, -1),
      OP_NOP: () => {},
      // Legacy/segwit-v0: the sighash scriptCode begins after the last *executed*
      // OP_CODESEPARATOR (Core's pbegincodehash). Only updated when executing, so
      // a separator inside an untaken IF branch has no effect.
      OP_CODESEPARATOR: (s, ctx, exec, op) => {
        if (isLegacy(ctx.sigVersion) && ctx.flags?.has('CONST_SCRIPTCODE')) fail('OP_CODESEPARATOR under CONST_SCRIPTCODE');
        ctx.codeSepOffset = op.at + 1;
      },
      OP_IF: (s, ctx, exec, _, executing) => {
        let f = false;
        if (executing) {
          const v = pop(s);
          if ((ctx.sigVersion === 'tapscript'
               || (ctx.sigVersion === 'witnessV0' && ctx.flags?.has('MINIMALIF')))
              && !(v.length === 0 || (v.length === 1 && v[0] === 1))) {
            fail('minimal IF'); // BIP 342 (tapscript) / SCRIPT_VERIFY_MINIMALIF (witness v0)
          }
          f = truthy(v);
        }
        exec.push(f);
      },
      OP_NOTIF: (s, ctx, exec, _, executing) => {
        let f = false;
        if (executing) {
          const v = pop(s);
          if ((ctx.sigVersion === 'tapscript'
               || (ctx.sigVersion === 'witnessV0' && ctx.flags?.has('MINIMALIF')))
              && !(v.length === 0 || (v.length === 1 && v[0] === 1))) {
            fail('minimal IF');
          }
          f = !truthy(v);
        }
        exec.push(f);
      },
      OP_ELSE: (s, ctx, exec) => {
        if (!exec.length) fail('unbalanced ELSE');
        exec[exec.length - 1] = !exec[exec.length - 1];
      },
      OP_ENDIF: (s, ctx, exec) => {
        if (!exec.length) fail('unbalanced ENDIF');
        exec.pop();
      },
      OP_VERIFY: (s) => { if (!truthy(pop(s))) fail('verify failed'); },
      OP_RETURN: () => fail('op_return'),

      OP_TOALTSTACK: (s, ctx) => ctx.alt.push(pop(s)),
      OP_FROMALTSTACK: (s, ctx) => { if (!ctx.alt.length) fail('alt underflow'); s.push(ctx.alt.pop()); },
      OP_2DROP: (s) => { pop(s); pop(s); },
      OP_2DUP: (s) => { const a = peek(s, 2), b = peek(s, 1); s.push(a, b); },
      OP_3DUP: (s) => { const a = peek(s, 3), b = peek(s, 2), c = peek(s, 1); s.push(a, b, c); },
      OP_2OVER: (s) => { const a = peek(s, 4), b = peek(s, 3); s.push(a, b); },
      OP_2ROT: (s) => { if (s.length < 6) fail('stack underflow'); s.push(...s.splice(s.length - 6, 2)); },
      OP_2SWAP: (s) => { if (s.length < 4) fail('stack underflow'); s.push(...s.splice(s.length - 4, 2)); },
      OP_IFDUP: (s) => { if (truthy(peek(s))) s.push(peek(s)); },
      OP_DEPTH: (s) => pushNum(s, s.length),
      OP_DROP: (s) => pop(s),
      OP_DUP: (s) => s.push(peek(s)),
      OP_NIP: (s) => { const t = pop(s); pop(s); s.push(t); },
      OP_OVER: (s) => s.push(peek(s, 2)),
      OP_PICK: (s) => { const n = num(s); if (n < 0 || n >= s.length) fail('pick range'); s.push(s[s.length - 1 - n]); },
      OP_ROLL: (s) => { const n = num(s); if (n < 0 || n >= s.length) fail('roll range'); s.push(s.splice(s.length - 1 - n, 1)[0]); },
      OP_ROT: (s) => { if (s.length < 3) fail('stack underflow'); s.push(s.splice(s.length - 3, 1)[0]); },
      OP_SWAP: (s) => { if (s.length < 2) fail('stack underflow'); s.push(s.splice(s.length - 2, 1)[0]); },
      OP_TUCK: (s) => { if (s.length < 2) fail('stack underflow'); s.splice(s.length - 2, 0, peek(s)); },
      OP_SIZE: (s) => pushNum(s, peek(s).length),

      OP_EQUAL: (s) => s.push(boolBytes(eq(pop(s), pop(s)))),
      OP_EQUALVERIFY: (s) => { if (!eq(pop(s), pop(s))) fail('equalverify'); },

      OP_1ADD: unary((a) => a + 1), OP_1SUB: unary((a) => a - 1),
      OP_NEGATE: unary((a) => -a), OP_ABS: unary(Math.abs),
      OP_NOT: (s) => s.push(boolBytes(num(s) === 0)),
      OP_0NOTEQUAL: (s) => s.push(boolBytes(num(s) !== 0)),
      OP_ADD: binary((a, b) => a + b), OP_SUB: binary((a, b) => a - b),
      OP_BOOLAND: binBool((a, b) => a !== 0 && b !== 0),
      OP_BOOLOR: binBool((a, b) => a !== 0 || b !== 0),
      OP_NUMEQUAL: binBool((a, b) => a === b),
      OP_NUMEQUALVERIFY: (s) => { const b = num(s), a = num(s); if (a !== b) fail('numequalverify'); },
      OP_NUMNOTEQUAL: binBool((a, b) => a !== b),
      OP_LESSTHAN: binBool((a, b) => a < b),
      OP_GREATERTHAN: binBool((a, b) => a > b),
      OP_LESSTHANOREQUAL: binBool((a, b) => a <= b),
      OP_GREATERTHANOREQUAL: binBool((a, b) => a >= b),
      OP_MIN: binary(Math.min), OP_MAX: binary(Math.max),
      OP_WITHIN: (s) => { const max = num(s), min = num(s), x = num(s); s.push(boolBytes(x >= min && x < max)); },

      OP_RIPEMD160: hashOp(ripemd160), OP_SHA1: hashOp(sha1),
      OP_SHA256: hashOp(sha256), OP_HASH160: hashOp(hash160), OP_HASH256: hashOp(dsha256),

      OP_CHECKSIG: (s, ctx) => {
        const pub = pop(s), sig = pop(s);
        const ok = this.#checkSig(sig, pub, ctx);
        if (!ok && sig.length > 0 && ctx.flags?.has('NULLFAIL')) fail('NULLFAIL');
        s.push(boolBytes(ok));
      },
      OP_CHECKSIGVERIFY: (s, ctx) => {
        const pub = pop(s), sig = pop(s);
        const ok = this.#checkSig(sig, pub, ctx);
        if (!ok && sig.length > 0 && ctx.flags?.has('NULLFAIL')) fail('NULLFAIL');
        if (!ok) fail('checksigverify');
      },
      OP_CHECKMULTISIG: (s, ctx) => {
        if (ctx.sigVersion === 'tapscript') fail('CHECKMULTISIG disabled in tapscript');
        s.push(boolBytes(this.#checkMultisig(s, ctx)));
      },
      OP_CHECKMULTISIGVERIFY: (s, ctx) => {
        if (ctx.sigVersion === 'tapscript') fail('CHECKMULTISIG disabled in tapscript');
        if (!this.#checkMultisig(s, ctx)) fail('checkmultisigverify');
      },
      OP_CHECKSIGADD: (s, ctx) => {
        if (ctx.sigVersion !== 'tapscript') fail('CHECKSIGADD outside tapscript');
        const pub = pop(s);
        const n = numDecode(pop(s));
        const sig = pop(s);
        s.push(numEncode(n + (this.#checkSigTapscript(sig, pub, ctx) ? 1 : 0)));
      },

      // BIP 65 / BIP 112 are flag-gated in Core: without the flag the opcode is
      // the pre-softfork NOP2 / NOP3 (a plain no-op, not "discouraged"). With
      // no flag set at all (null/undefined, the block-validation default) both
      // stay enforced, matching the P2SH gate; a flag set that omits them
      // turns them off.
      OP_CHECKLOCKTIMEVERIFY: (s, ctx) => {
        if (ctx.flags != null && !ctx.flags.has('CHECKLOCKTIMEVERIFY')) return;
        const n = numDecode(peek(s), 5);
        if (n < 0) fail('negative locktime');
        const sameKind = (n < 500000000) === (ctx.tx.lockTime < 500000000);
        if (!sameKind || n > ctx.tx.lockTime) fail('unsatisfied locktime');
        if (ctx.tx.inputs[ctx.inIndex].sequence === 0xffffffff) fail('final sequence');
      },
      OP_CHECKSEQUENCEVERIFY: (s, ctx) => {
        if (ctx.flags != null && !ctx.flags.has('CHECKSEQUENCEVERIFY')) return;
        const n = numDecode(peek(s), 5);
        if (n < 0) fail('negative sequence');
        if (n & (1 << 31)) return; // disable flag: behaves as NOP
        const seq = ctx.tx.inputs[ctx.inIndex].sequence;
        if (ctx.tx.version < 2) fail('csv pre-v2');
        if (seq & 0x80000000) fail('sequence disable flag set');
        const typeMask = 1 << 22, valueMask = 0xffff;
        if ((n & typeMask) !== (seq & typeMask)) fail('sequence type mismatch');
        if ((n & valueMask) > (seq & valueMask)) fail('unsatisfied sequence');
      },
    };
    for (let i = 1; i <= 16; i++) h[`OP_${i}`] = ((v) => (s) => pushNum(s, v))(i);
    // OP_NOP1, OP_NOP4..OP_NOP10 are upgradable no-ops; rejected under
    // SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS. (NOP2/NOP3 are CLTV/CSV.)
    for (let i = 1; i <= 10; i++) h[`OP_NOP${i}`] = (s, ctx) => {
      if (ctx.flags?.has('DISCOURAGE_UPGRADABLE_NOPS')) fail('upgradable NOP');
    };
    return h;
  }

  #checkMultisig(s, ctx) {
    const pop = () => { if (!s.length) fail('stack underflow'); return s.pop(); };
    const n = numDecode(pop(), 4, this.requireMinimalNum);
    if (n < 0 || n > this.limits.maxMultisigKeys) fail('pubkey count');
    ctx._extraOps = (ctx._extraOps || 0) + n; // CHECKMULTISIG adds its key count to the op limit
    const pubs = [];
    for (let i = 0; i < n; i++) pubs.push(pop());
    const m = numDecode(pop(), 4, this.requireMinimalNum);
    if (m < 0 || m > n) fail('sig count');
    const sigs = [];
    for (let i = 0; i < m; i++) sigs.push(pop());
    const dummy = pop(); // the historical extra-pop dummy
    if (ctx.flags?.has('NULLDUMMY') && dummy.length !== 0) fail('NULLDUMMY');
    // sigs and pubs are in stack-pop order (top first) — Core evaluates in
    // exactly this order, checking the current pair's encoding before the
    // not-enough-keys early-exit, so a later invalid key/sig may never be
    // reached. (No reverse: matching is order-preserving for valid cases.)
    let sigCtx = ctx;
    if (isLegacy(ctx.sigVersion)) {
      // Legacy: every signature is FindAndDelete'd from scriptCode before any is checked
      let code = hexToBytes(ctx.codeSepOffset ? ctx.scriptCode.slice(ctx.codeSepOffset * 2) : ctx.scriptCode);
      for (const sg of sigs) {
        const { script, found } = findAndDelete(code, pushEncode(sg));
        if (found && ctx.flags?.has('CONST_SCRIPTCODE')) fail('SIG_FINDANDDELETE');
        code = script;
      }
      sigCtx = { ...ctx, scriptCode: bytesToHex(code), codeSepOffset: 0, _sigsDeleted: true };
    }
    let isig = 0, ikey = 0, success = true;
    while (success && isig < sigs.length) {
      if (this.#checkSig(sigs[isig], pubs[ikey], sigCtx)) isig++;
      ikey++;
      if (sigs.length - isig > pubs.length - ikey) success = false;
    }
    const ok = success && isig === sigs.length;
    // BIP 146: a failed multisig requires every signature to be empty
    if (!ok && ctx.flags?.has('NULLFAIL')) {
      for (const sg of sigs) if (sg.length > 0) fail('NULLFAIL');
    }
    return ok;
  }

  // ---- execution ----

  // Execute one script against a stack. ctx: {tx, inIndex, scriptCode,
  // amount, sigVersion, alt}. Returns {ok, error?}; stack is mutated.
  execute(scriptHex, stack, ctx = {}) {
    try {
      // BIP342: tapscript has no per-script size limit. The legacy 10kB
      // MAX_SCRIPT_SIZE does not apply; a tapscript's size is bounded only by the
      // transaction/block weight limit (it has to fit in a block).
      if (ctx.sigVersion !== 'tapscript' && scriptHex.length / 2 > this.limits.maxScriptSize) fail('script too large');
      ctx.alt = ctx.alt ?? [];
      ctx.scriptCode = ctx.scriptCode ?? scriptHex;
      ctx.codeSepOffset = 0;          // bytes before the last executed OP_CODESEPARATOR; reset per script run
      this.requireMinimalNum = !!ctx.flags?.has('MINIMALDATA'); // for the shared num() helper

      const ops = this.scriptEngine.parse(scriptHex);
      if (ctx.sigVersion === 'tapscript') {
        // BIP 342: OP_SUCCESSx is decided at parse time, before execution
        for (const op of ops) {
          if (op.error) fail(op.error);
          if (op.data == null && this.#isOpSuccess(op.code)) return { ok: true, opSuccess: true };
        }
      }
      const exec = [];
      let opCount = 0;
      for (const op of ops) {
        if (op.error) fail(op.error);
        const executing = exec.every(Boolean);
        if (op.data != null) {
          if (op.data.length / 2 > this.limits.maxScriptElementSize) fail('push too large');
          if (executing) {
            if (ctx.flags?.has('MINIMALDATA') && !minimalPushOk(op.code, op.data)) fail('non-minimal data push');
            stack.push(hexToBytes(op.data));
          }
          continue;
        }
        // BIP342: tapscript removes the 201-non-push-opcode-per-script limit
        // entirely (there is no opcode-count cap). Signature-checking cost is
        // instead bounded separately by the per-input sigops budget.
        if (ctx.sigVersion !== 'tapscript' && op.code > 0x60 && ++opCount > this.limits.maxOpsPerScript) fail('op count');
        if (this.#isDisabled(op.name)) fail(`disabled opcode ${op.name}`);
        const isBranch = ['OP_IF', 'OP_NOTIF', 'OP_ELSE', 'OP_ENDIF'].includes(op.name);
        if (!executing && !isBranch) continue;
        const handler = this.handlers[op.name];
        if (!handler) fail(`bad opcode ${op.name}`);
        handler(stack, ctx, exec, op, executing);
        if (ctx._extraOps) { // CHECKMULTISIG key count, counted after the op runs
          opCount += ctx._extraOps; ctx._extraOps = 0;
          if (opCount > this.limits.maxOpsPerScript) fail('op count');
        }
        if (stack.length + ctx.alt.length > this.limits.maxStackSize) fail('stack size');
      }
      if (exec.length) fail('unbalanced conditional');
      return { ok: true };
    } catch (e) {
      if (e instanceof ScriptError) return { ok: false, error: e.message };
      throw e;
    }
  }

  #isDisabled(name) {
    return ['OP_CAT', 'OP_SUBSTR', 'OP_LEFT', 'OP_RIGHT', 'OP_INVERT', 'OP_AND', 'OP_OR',
      'OP_XOR', 'OP_2MUL', 'OP_2DIV', 'OP_MUL', 'OP_DIV', 'OP_MOD', 'OP_LSHIFT', 'OP_RSHIFT',
      'OP_VERIF', 'OP_VERNOTIF'].includes(name);
  }

  // BIP 342 OP_SUCCESSx set: these byte values make a tapscript
  // unconditionally valid, reserving them for future upgrades.
  #isOpSuccess(code) {
    return code === 80 || code === 98
      || (code >= 126 && code <= 129) || (code >= 131 && code <= 134)
      || code === 137 || code === 138 || code === 141 || code === 142
      || (code >= 149 && code <= 153) || (code >= 187 && code <= 254);
  }


  // Core's VerifyWitnessProgram. `isP2SH` matters for v1: a P2SH-wrapped
  // 32-byte v1 program is not taproot (BIP 341) and falls through as unknown.
  #verifyWitnessProgram(tx, inIndex, version, programHex, amount, flags, isP2SH, allPrevouts) {
    const witness = (tx.witness?.[inIndex] ?? []).map(hexToBytes);
    if (version === 0) {
      if (programHex.length === 64) { // BIP 141 P2WSH
        if (!witness.length) return { ok: false, error: 'WITNESS_PROGRAM_WITNESS_EMPTY' };
        const witnessScript = witness.pop();
        if (bytesToHex(sha256(witnessScript)) !== programHex) return { ok: false, error: 'WITNESS_PROGRAM_MISMATCH' };
        return this.#executeWitnessScript(witness, bytesToHex(witnessScript), tx, inIndex, amount, flags);
      }
      if (programHex.length === 40) { // BIP 141 P2WPKH
        if (witness.length !== 2) return { ok: false, error: 'WITNESS_PROGRAM_MISMATCH' };
        return this.#executeWitnessScript(witness, '76a914' + programHex + '88ac', tx, inIndex, amount, flags);
      }
      return { ok: false, error: 'WITNESS_PROGRAM_WRONG_LENGTH' };
    }
    if (version === 1 && programHex.length === 64 && !isP2SH) { // BIP 341 taproot
      if (flags && !flags.has('TAPROOT')) return { ok: true }; // not enabled: anyone-can-spend, as in Core
      if (!allPrevouts) return { ok: null, reason: 'taproot needs every input prevout resolved' };
      return this.#verifyTaproot(tx, inIndex, allPrevouts, flags);
    }
    if (flags?.has('DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM')) return { ok: false, error: 'DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM' };
    // Core returns success here (future soft-fork compatibility); we decline
    // to vouch for rules we do not know rather than claim they passed.
    return { ok: null, reason: 'unknown witness version' };
  }

  // Core's ExecuteWitnessScript for witness v0: 520-byte cap on every initial
  // stack element, evaluate, exactly one truthy element must remain.
  #executeWitnessScript(stack, scriptHex, tx, inIndex, amount, flags) {
    for (const el of stack) if (el.length > this.limits.maxScriptElementSize) return { ok: false, error: 'PUSH_SIZE' };
    const st = stack.map((w) => Uint8Array.from(w));
    const r = this.execute(scriptHex, st, { tx, inIndex, amount, sigVersion: 'witnessV0', scriptCode: scriptHex, flags });
    if (!r.ok) return r;
    if (st.length !== 1) return { ok: false, error: 'CLEANSTACK' };
    return truthy(st[0]) ? { ok: true } : { ok: false, error: 'EVAL_FALSE' };
  }

  // BIP 341 taproot spend verification: key path (one Schnorr signature
  // with the tweaked output key) or script path (reveal a leaf script and
  // a control block proving its commitment, then execute as tapscript).
  #verifyTaproot(tx, inIndex, prevouts, flags = null) {
    const program = hexToBytes(prevouts[inIndex].scriptPubKey.slice(4));
    const witness = (tx.witness?.[inIndex] ?? []).map(hexToBytes);
    if (!witness.length) return { ok: false, error: 'empty taproot witness' };

    // total serialized witness size, for the tapscript sigops budget
    const witnessSize = witness.reduce((s, w) =>
      s + w.length + (w.length < 0xfd ? 1 : w.length <= 0xffff ? 3 : 5), 1);

    let annex = null;
    if (witness.length >= 2 && witness[witness.length - 1][0] === 0x50) annex = witness.pop();

    if (witness.length === 1) { // key path
      const raw = witness[0];
      let hashType = 0x00, sig = raw;
      if (raw.length === 65) {
        hashType = raw[64];
        if (hashType === 0x00) return { ok: false, error: 'explicit SIGHASH_DEFAULT in 65-byte signature' };
        sig = raw.subarray(0, 64);
      } else if (raw.length !== 64) return { ok: false, error: 'bad key-path signature size' };
      try {
        const msg = this.sighashTaproot(tx, inIndex, prevouts, hashType, { annex });
        return verifySchnorr(msg, sig, program)
          ? { ok: true, path: 'key' } : { ok: false, error: 'invalid key-path schnorr signature' };
      } catch (e) {
        if (e instanceof ScriptError) return { ok: false, error: e.message };
        throw e;
      }
    }

    // script path
    const control = witness.pop();
    const script = witness.pop();
    if (control.length < 33 || (control.length - 33) % 32 !== 0 || control.length > 33 + 32 * 128) {
      return { ok: false, error: 'bad control block size' };
    }
    const leafVersion = control[0] & 0xfe;
    const parity = control[0] & 0x01;
    const internalKey = control.subarray(1, 33);
    const leafHash = taggedHash('TapLeaf', Uint8Array.of(leafVersion), compactSize(script.length), script);
    let k = leafHash;
    for (let i = 33; i < control.length; i += 32) {
      const e = control.subarray(i, i + 32);
      const less = bytesToHex(k) < bytesToHex(e);
      k = less ? taggedHash('TapBranch', k, e) : taggedHash('TapBranch', e, k);
    }
    if (!checkTapTweak(internalKey, k, program, parity)) {
      return { ok: false, error: 'control block commitment mismatch' };
    }
    if (leafVersion !== 0xc0) return { ok: null, reason: 'unknown tapleaf version', path: 'script' };

    const stack = witness; // remaining items are the initial stack
    const scriptHex = bytesToHex(script);
    const ctx = {
      tx, inIndex, prevouts, amount: prevouts[inIndex].value,
      sigVersion: 'tapscript', leafHash, annex, budget: { n: 50 + witnessSize }, flags,
    };
    const r = this.execute(scriptHex, stack, ctx);
    if (!r.ok) return { ...r, path: 'script' };
    if (r.opSuccess) return { ok: true, path: 'script' };
    return (stack.length === 1 && truthy(stack[0]))
      ? { ok: true, path: 'script' } : { ok: false, error: 'tapscript evaluated false', path: 'script' };
  }

  // Verify one input against its prevout. For taproot, `allPrevouts` (one
  // {value, scriptPubKey} per input, in order) is required because the
  // BIP 341 sighash commits to all of them. Returns {ok: true|false|null};
  // null = honestly unverifiable (missing prevouts / future versions).
  verifyInput(tx, inIndex, prevout, allPrevouts = null, flags = null) {
    // Core's VerifyScript, in its order: scriptSig then scriptPubKey on one
    // stack; bare witness program; P2SH (redeem script, then a wrapped witness
    // program); CLEANSTACK; unexpected witness. P2SH and segwit are only active
    // under their flags; legacy callers (flags=null) keep both on, and a P2SH-
    // or witness-shaped scriptPubKey runs as a plain script when they are off.
    const spk = prevout.scriptPubKey;
    let type = this.scriptEngine.classify(spk).type;
    const input = tx.inputs[inIndex];
    const ctx = { tx, inIndex, amount: prevout.value, sigVersion: 'legacy', flags };
    const p2shActive = flags === null || flags.has('P2SH');
    const witnessActive = flags === null || flags.has('WITNESS');
    const pushOnly = this.scriptEngine.parse(input.scriptSig).every((o) => o.code <= 0x60);
    if (flags?.has('SIGPUSHONLY') && !pushOnly) return { ok: false, error: 'SIG_PUSHONLY', type };

    let stack = [];
    let r = this.execute(input.scriptSig, stack, { ...ctx, scriptCode: input.scriptSig });
    if (!r.ok) return { ...r, type };
    const stackCopy = p2shActive ? stack.slice() : null;
    r = this.execute(spk, stack, { ...ctx, scriptCode: spk });
    if (!r.ok) return { ...r, type };
    if (!stack.length || !truthy(stack[stack.length - 1])) return { ok: false, error: 'EVAL_FALSE', type };

    let hadWitness = false, witnessResult = {};
    const bare = witnessActive ? witnessProgram(spk) : null;
    if (bare) {
      hadWitness = true;
      if (input.scriptSig.length) return { ok: false, error: 'WITNESS_MALLEATED', type };
      const w = this.#verifyWitnessProgram(tx, inIndex, bare.version, bare.program, prevout.value, flags, false, allPrevouts);
      if (w.ok !== true) return { ...w, type };
      witnessResult = w; // keeps e.g. the taproot `path`
      stack = [Uint8Array.of(1)]; // Core: stack.resize(1) — the witness path bypasses CLEANSTACK
    } else if (p2shActive && type === 'p2sh') {
      if (!pushOnly) return { ok: false, error: 'SIG_PUSHONLY', type };
      stack = stackCopy; // the stack as scriptSig left it; its top is the redeem script
      const redeem = stack.pop();
      const redeemHex = bytesToHex(redeem);
      const redeemType = this.scriptEngine.classify(redeemHex).type;
      type = `p2sh-${redeemType}`;
      r = this.execute(redeemHex, stack, { ...ctx, scriptCode: redeemHex });
      if (!r.ok) return { ...r, type };
      if (!stack.length || !truthy(stack[stack.length - 1])) return { ok: false, error: 'EVAL_FALSE', type };
      const wrapped = witnessActive ? witnessProgram(redeemHex) : null;
      if (wrapped) {
        hadWitness = true;
        // the scriptSig must be exactly one push of the redeem script
        if (input.scriptSig !== bytesToHex(pushEncode(redeem))) return { ok: false, error: 'WITNESS_MALLEATED_P2SH', type };
        const w = this.#verifyWitnessProgram(tx, inIndex, wrapped.version, wrapped.program, prevout.value, flags, true, allPrevouts);
        if (w.ok !== true) return { ...w, type };
        witnessResult = w;
        stack = [Uint8Array.of(1)];
      }
    }
    if (flags?.has('CLEANSTACK') && stack.length !== 1) return { ok: false, error: 'CLEANSTACK', type };
    if (witnessActive && !hadWitness && (tx.witness?.[inIndex] ?? []).length) return { ok: false, error: 'WITNESS_UNEXPECTED', type };
    return { ...witnessResult, ok: true, type };
  }
}
