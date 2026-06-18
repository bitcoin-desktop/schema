// Bitcoin script interpreter, Hornet-style: each opcode is a self-contained
// handler (contrast Bitcoin Core's ~1,500-line EvalScript), keyed by the
// opcode names of the schema's Opcode enumeration, with execution limits
// taken from the schema's scriptLimits instance.
//
// Supported spend paths: p2pk, p2pkh, bare multisig, p2sh (including
// wrapped segwit), p2wpkh, p2wsh — with legacy and BIP 143 sighash and
// real ECDSA verification. NOT supported (verifyInput returns ok:null):
// taproot (Schnorr/BIP 341). Known simplifications, accepted for now:
// OP_CODESEPARATOR is a no-op (scriptCode is the full executing script)
// and signature pushes are not FindAndDelete'd from legacy scriptCode.

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
  }

  // ---- sighash ----

  sighashLegacy(tx, inIndex, scriptCodeHex, hashType) {
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
    const hashPrevouts = anyone ? zero : dsha256(cat(tx.inputs.map(outpoint)));
    const hashSequence = (anyone || base === 2 || base === 3) ? zero
      : dsha256(cat(tx.inputs.map((i) => u32(i.sequence))));
    const serOut = (o) => this.codec.encode('TransactionOutput', o);
    const hashOutputs = (base !== 2 && base !== 3) ? dsha256(cat(tx.outputs.map(serOut)))
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

    const parts = [u8(0x00), u8(hashType), u32(tx.version), u32(tx.lockTime)];
    if (!anyone) {
      parts.push(sha256(cat(tx.inputs.map(outpoint))));
      parts.push(sha256(cat(prevouts.map((p) => i64(p.value)))));
      parts.push(sha256(cat(prevouts.map((p) => varbytes(hexToBytes(p.scriptPubKey))))));
      parts.push(sha256(cat(tx.inputs.map((i) => u32(i.sequence)))));
    }
    if (base !== 2 && base !== 3) {
      parts.push(sha256(cat(tx.outputs.map((o) => this.codec.encode('TransactionOutput', o)))));
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
    if (f && sigBytes.length > 0) {
      if ((f.has('DERSIG') || f.has('LOW_S') || f.has('STRICTENC')) && !isValidDerSig(sigBytes)) fail('non-DER signature');
      if (f.has('LOW_S') && !isLowDerSig(sigBytes)) fail('high-S signature');
      if (f.has('STRICTENC') && !isDefinedHashtype(sigBytes)) fail('undefined hashtype');
    }
    if (f?.has('STRICTENC') && !isPubKeyEnc(pubBytes)) fail('bad pubkey encoding');
    if (sigBytes.length === 0) return false;
    const hashType = sigBytes[sigBytes.length - 1];
    const sig = parseDerSignature(sigBytes.subarray(0, sigBytes.length - 1));
    const pub = parsePubkey(pubBytes);
    if (!sig || !pub) return false;
    const hash = ctx.sigVersion === 'witnessV0'
      ? this.sighashWitnessV0(ctx.tx, ctx.inIndex, ctx.scriptCode, ctx.amount, hashType)
      : this.sighashLegacy(ctx.tx, ctx.inIndex, ctx.scriptCode, hashType);
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
      OP_NOP: () => {}, OP_CODESEPARATOR: () => {},
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

      OP_CHECKLOCKTIMEVERIFY: (s, ctx) => {
        const n = numDecode(peek(s), 5);
        if (n < 0) fail('negative locktime');
        const sameKind = (n < 500000000) === (ctx.tx.lockTime < 500000000);
        if (!sameKind || n > ctx.tx.lockTime) fail('unsatisfied locktime');
        if (ctx.tx.inputs[ctx.inIndex].sequence === 0xffffffff) fail('final sequence');
      },
      OP_CHECKSEQUENCEVERIFY: (s, ctx) => {
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
    let isig = 0, ikey = 0, success = true;
    while (success && isig < sigs.length) {
      if (this.#checkSig(sigs[isig], pubs[ikey], ctx)) isig++;
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
      if (scriptHex.length / 2 > this.limits.maxScriptSize) fail('script too large');
      ctx.alt = ctx.alt ?? [];
      ctx.scriptCode = ctx.scriptCode ?? scriptHex;
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
        if (op.code > 0x60 && ++opCount > this.limits.maxOpsPerScript) fail('op count');
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

  #runPair(scriptSigHex, scriptPubKeyHex, ctx) {
    const stack = [];
    let r = this.execute(scriptSigHex, stack, { ...ctx, scriptCode: scriptSigHex });
    if (!r.ok) return { r, stack };
    r = this.execute(scriptPubKeyHex, stack, { ...ctx, scriptCode: scriptPubKeyHex });
    if (!r.ok) return { r, stack };
    if (!stack.length || !truthy(stack[stack.length - 1])) {
      return { r: { ok: false, error: 'script evaluated false' }, stack };
    }
    return { r: { ok: true }, stack };
  }

  #verifyWitnessProgram(tx, inIndex, version, programHex, amount) {
    const witness = (tx.witness?.[inIndex] ?? []).map(hexToBytes);
    if (version !== 0) return { ok: null, reason: 'unsupported witness version' };
    if (programHex.length === 40) { // p2wpkh
      if (witness.length !== 2) return { ok: false, error: 'p2wpkh witness size' };
      const scriptCode = '76a914' + programHex + '88ac';
      const stack = witness.map((w) => Uint8Array.from(w));
      const r = this.execute(scriptCode, stack,
        { tx, inIndex, amount, sigVersion: 'witnessV0', scriptCode });
      if (!r.ok) return r;
      return (stack.length === 1 && truthy(stack[0]))
        ? { ok: true } : { ok: false, error: 'p2wpkh evaluated false' };
    }
    // p2wsh
    if (!witness.length) return { ok: false, error: 'empty p2wsh witness' };
    const witnessScript = witness[witness.length - 1];
    if (bytesToHex(sha256(witnessScript)) !== programHex) {
      return { ok: false, error: 'p2wsh script hash mismatch' };
    }
    const scriptHex = bytesToHex(witnessScript);
    const stack = witness.slice(0, -1);
    const r = this.execute(scriptHex, stack,
      { tx, inIndex, amount, sigVersion: 'witnessV0', scriptCode: scriptHex });
    if (!r.ok) return r;
    return (stack.length === 1 && truthy(stack[0]))
      ? { ok: true } : { ok: false, error: 'p2wsh evaluated false' };
  }

  // BIP 341 taproot spend verification: key path (one Schnorr signature
  // with the tweaked output key) or script path (reveal a leaf script and
  // a control block proving its commitment, then execute as tapscript).
  #verifyTaproot(tx, inIndex, prevouts) {
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
    const sizePrefix = script.length < 0xfd
      ? Uint8Array.of(script.length)
      : Uint8Array.of(0xfd, script.length & 0xff, script.length >> 8);
    const leafHash = taggedHash('TapLeaf', Uint8Array.of(leafVersion), sizePrefix, script);
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
      sigVersion: 'tapscript', leafHash, annex, budget: { n: 50 + witnessSize },
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
  verifyInput(tx, inIndex, prevout, allPrevouts = null) {
    const spk = prevout.scriptPubKey;
    const type = this.scriptEngine.classify(spk).type;
    const input = tx.inputs[inIndex];
    const ctx = { tx, inIndex, amount: prevout.value, sigVersion: 'legacy' };

    if (type === 'p2tr') {
      if (!allPrevouts) return { ok: null, reason: 'taproot needs every input prevout resolved', type };
      return { ...this.#verifyTaproot(tx, inIndex, allPrevouts), type };
    }
    if (type === 'witness-unknown') return { ok: null, reason: 'unknown witness version', type };
    if (type === 'p2wpkh' || type === 'p2wsh') {
      const program = this.scriptEngine.parse(spk)[1].data;
      return { ...this.#verifyWitnessProgram(tx, inIndex, 0, program, prevout.value), type };
    }

    const { r, stack } = this.#runPair(input.scriptSig, spk, ctx);
    if (!r.ok) return { ...r, type };
    if (type !== 'p2sh') return { ok: true, type };

    // p2sh: re-run the scriptSig alone to recover the pre-evaluation stack,
    // pop the redeem script, and evaluate it
    const sigStack = [];
    this.execute(input.scriptSig, sigStack, { ...ctx });
    if (!sigStack.length) return { ok: false, error: 'empty p2sh stack', type };
    const redeem = sigStack.pop();
    const redeemHex = bytesToHex(redeem);
    const redeemType = this.scriptEngine.classify(redeemHex).type;
    if (redeemType === 'p2wpkh' || redeemType === 'p2wsh') { // wrapped segwit
      const program = this.scriptEngine.parse(redeemHex)[1].data;
      return { ...this.#verifyWitnessProgram(tx, inIndex, 0, program, prevout.value), type: `p2sh-${redeemType}` };
    }
    if (redeemType === 'p2tr' || redeemType === 'witness-unknown') {
      return { ok: null, reason: 'wrapped future witness version', type };
    }
    const r2 = this.execute(redeemHex, sigStack, { ...ctx, scriptCode: redeemHex });
    if (!r2.ok) return { ...r2, type };
    return (sigStack.length && truthy(sigStack[sigStack.length - 1]))
      ? { ok: true, type: `p2sh-${redeemType}` }
      : { ok: false, error: 'redeem script evaluated false', type };
  }
}
