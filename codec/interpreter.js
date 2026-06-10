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

import { sha256, dsha256, sha1, ripemd160, hash160, bytesToHex, hexToBytes } from './hash.js';
import { parsePubkey, parseDerSignature, verifyEcdsa } from './secp256k1.js';

class ScriptError extends Error {}
const fail = (msg) => { throw new ScriptError(msg); };

// CScriptNum: little-endian, sign bit in the high bit of the last byte.
export function numDecode(bytes, maxLen = 4) {
  if (bytes.length > maxLen) fail('scriptnum overflow');
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

  #checkSig(sigBytes, pubBytes, ctx) {
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
    const num = (s) => numDecode(pop(s));
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
        if (executing) f = truthy(pop(s));
        exec.push(f);
      },
      OP_NOTIF: (s, ctx, exec, _, executing) => {
        let f = false;
        if (executing) f = !truthy(pop(s));
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
      OP_TUCK: (s) => { const t = peek(s); s.splice(s.length - 2, 0, t); },
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
        s.push(boolBytes(this.#checkSig(sig, pub, ctx)));
      },
      OP_CHECKSIGVERIFY: (s, ctx) => {
        const pub = pop(s), sig = pop(s);
        if (!this.#checkSig(sig, pub, ctx)) fail('checksigverify');
      },
      OP_CHECKMULTISIG: (s, ctx) => s.push(boolBytes(this.#checkMultisig(s, ctx))),
      OP_CHECKMULTISIGVERIFY: (s, ctx) => { if (!this.#checkMultisig(s, ctx)) fail('checkmultisigverify'); },

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
    for (let i = 1; i <= 10; i++) h[`OP_NOP${i}`] = () => {};
    return h;
  }

  #checkMultisig(s, ctx) {
    const pop = () => { if (!s.length) fail('stack underflow'); return s.pop(); };
    const n = numDecode(pop());
    if (n < 0 || n > this.limits.maxMultisigKeys) fail('pubkey count');
    const pubs = [];
    for (let i = 0; i < n; i++) pubs.push(pop());
    const m = numDecode(pop());
    if (m < 0 || m > n) fail('sig count');
    const sigs = [];
    for (let i = 0; i < m; i++) sigs.push(pop());
    pop(); // the historical extra-pop dummy
    sigs.reverse(); pubs.reverse(); // restore script order
    let isig = 0;
    for (let ikey = 0; ikey < pubs.length && isig < sigs.length; ikey++) {
      if (sigs.length - isig > pubs.length - ikey) return false;
      if (this.#checkSig(sigs[isig], pubs[ikey], ctx)) isig++;
    }
    return isig === sigs.length;
  }

  // ---- execution ----

  // Execute one script against a stack. ctx: {tx, inIndex, scriptCode,
  // amount, sigVersion, alt}. Returns {ok, error?}; stack is mutated.
  execute(scriptHex, stack, ctx = {}) {
    try {
      if (scriptHex.length / 2 > this.limits.maxScriptSize) fail('script too large');
      ctx.alt = ctx.alt ?? [];
      ctx.scriptCode = ctx.scriptCode ?? scriptHex;
      const ops = this.scriptEngine.parse(scriptHex);
      const exec = [];
      let opCount = 0;
      for (const op of ops) {
        if (op.error) fail(op.error);
        const executing = exec.every(Boolean);
        if (op.data != null) {
          if (op.data.length / 2 > this.limits.maxScriptElementSize) fail('push too large');
          if (executing) stack.push(hexToBytes(op.data));
          continue;
        }
        if (op.code > 0x60 && ++opCount > this.limits.maxOpsPerScript) fail('op count');
        if (this.#isDisabled(op.name)) fail(`disabled opcode ${op.name}`);
        const isBranch = ['OP_IF', 'OP_NOTIF', 'OP_ELSE', 'OP_ENDIF'].includes(op.name);
        if (!executing && !isBranch) continue;
        const handler = this.handlers[op.name];
        if (!handler) fail(`bad opcode ${op.name}`);
        handler(stack, ctx, exec, op, executing);
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

  // Verify one input against its prevout. Returns {ok: true|false|null, ...};
  // null = honest unsupported (taproot / future witness versions).
  verifyInput(tx, inIndex, prevout) {
    const spk = prevout.scriptPubKey;
    const type = this.scriptEngine.classify(spk).type;
    const input = tx.inputs[inIndex];
    const ctx = { tx, inIndex, amount: prevout.value, sigVersion: 'legacy' };

    if (type === 'p2tr') return { ok: null, reason: 'taproot not yet supported', type };
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
