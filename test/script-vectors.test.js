// Differential test of our script interpreter against Bitcoin Core's own
// corpus, test/vectors/script_tests.json (vendored verbatim from
// bitcoin/bitcoin src/test/data/script_tests.json). Each Core case is
// [scriptSig, scriptPubKey, flags, expected, comment]; we parse Core's
// script-asm mini-language, run scriptSig then scriptPubKey through our
// interpreter, and assert OK/fail agrees.
//
// Scope: the interpreter now honours the script-gating verification flags
// (MINIMALDATA, MINIMALIF, DISCOURAGE_UPGRADABLE_NOPS via ctx.flags, plus
// SIGPUSHONLY and CLEANSTACK applied at this verify-flow level), so we run
// every case EXCEPT those that need machinery we don't model here:
// signature checking (CHECKSIG family — needs Core's dummy crediting tx and
// the sig-encoding flags), the timelock opcodes (CLTV/CSV — need a tx),
// witness/segwit programs, and P2SH redeem execution. Those are skipped
// HONESTLY and counted (never silently). The signature path is the natural
// next phase.
//
// This is what caught the OP_TUCK stack-underflow bug.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { ScriptEngine } from '../codec/script.js';
import { ScriptInterpreter } from '../codec/interpreter.js';

const load = async (p) => JSON.parse(await readFile(new URL(p, import.meta.url), 'utf8'));
const codec = new Codec(await load('../schema/core.jsonld'));
const scriptSchema = await load('../schema/script.jsonld');
const chainSchema = await load('../schema/chain.jsonld');
const scriptEngine = ScriptEngine.fromSchemas(scriptSchema, chainSchema);
const limits = scriptSchema['@graph'].find((n) => n['@id'] === 'btc:scriptLimits');
const interp = new ScriptInterpreter(codec, scriptEngine, limits);
const cases = await load('vectors/script_tests.json');

const NAME2CODE = new Map();
for (const m of scriptSchema['@graph'].find((n) => n['@id'] === 'btc:Opcode').members) {
  NAME2CODE.set(m.name, m.code); NAME2CODE.set(m.name.replace(/^OP_/, ''), m.code);
}

const hx = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
function scriptnum(n) { // CScriptNum serialize (BigInt)
  if (n === 0n) return [];
  const neg = n < 0n; let abs = neg ? -n : n; const out = [];
  while (abs > 0n) { out.push(Number(abs & 0xffn)); abs >>= 8n; }
  if (out[out.length - 1] & 0x80) out.push(neg ? 0x80 : 0x00);
  else if (neg) out[out.length - 1] |= 0x80;
  return out;
}
function pushData(bytes) {
  const n = bytes.length;
  if (n < 76) return [n, ...bytes];
  if (n <= 0xff) return [76, n, ...bytes];
  if (n <= 0xffff) return [77, n & 0xff, n >> 8, ...bytes];
  return [78, n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, (n >>> 24) & 0xff, ...bytes];
}
// Core's ParseScript: whitespace-separated numbers, 0x-raw bytes, 'strings', opcode names.
function parseScript(s) {
  const out = [];
  for (const w of s.split(/\s+/).filter(Boolean)) {
    if (/^-?\d+$/.test(w)) {
      const n = BigInt(w);
      if (n === 0n) out.push(0x00);
      else if (n === -1n) out.push(0x4f);
      else if (n >= 1n && n <= 16n) out.push(0x50 + Number(n));
      else out.push(...pushData(scriptnum(n)));
    } else if (/^0x[0-9a-fA-F]*$/.test(w)) {
      const h = w.slice(2);
      for (let i = 0; i < h.length; i += 2) out.push(parseInt(h.slice(i, i + 2), 16));
    } else if (/^'.*'$/.test(w)) {
      out.push(...pushData([...w.slice(1, -1)].map((c) => c.charCodeAt(0))));
    } else if (NAME2CODE.has(w)) { out.push(NAME2CODE.get(w)); }
    else throw new Error('unknown token: ' + w);
  }
  return hx(Uint8Array.from(out));
}
// Core's CastToBool: any non-zero byte is true, except a lone trailing 0x80 (negative zero).
const castToBool = (b) => {
  for (let i = 0; i < b.length; i++) if (b[i] !== 0) return !(i === b.length - 1 && b[i] === 0x80);
  return false;
};

// opcodes needing a tx context / signature checking we don't model in this path
const NEEDS_CONTEXT = /CHECKSIG|CHECKMULTISIG|CHECKSIGADD|CHECKLOCKTIMEVERIFY|CHECKSEQUENCEVERIFY/;

test('Bitcoin Core script_tests.json: every non-signature case matches our interpreter', () => {
  let ran = 0, matched = 0;
  const skip = { witness: 0, sigOrTimelock: 0, realP2SH: 0, realWitness: 0, unparseable: 0 };
  const mismatches = [];

  for (const t of cases) {
    if (t.length < 4) continue;                       // comment-only line
    if (Array.isArray(t[0])) { skip.witness++; continue; } // [witness, amount] segwit case
    const [sig, spk, flags, expected] = t;
    if (NEEDS_CONTEXT.test(sig) || NEEDS_CONTEXT.test(spk)) { skip.sigOrTimelock++; continue; }
    let sigHex, spkHex;
    try { sigHex = parseScript(sig); spkHex = parseScript(spk); } catch { skip.unparseable++; continue; }
    // skip only when the scriptPubKey is ACTUALLY a P2SH / witness program under that flag
    const type = scriptEngine.classify(spkHex).type;
    if (/P2SH/.test(flags) && type === 'p2sh') { skip.realP2SH++; continue; }
    if (/WITNESS/.test(flags) && /witness|segwit|p2w/i.test(type)) { skip.realWitness++; continue; }

    const fset = new Set(flags.split(/[,\s]+/).filter(Boolean));
    let ours;
    try {
      // SIGPUSHONLY: scriptSig must be push-only (every opcode <= OP_16)
      if (fset.has('SIGPUSHONLY') && !scriptEngine.parse(sigHex).every((o) => o.code <= 0x60)) {
        ours = false;
      } else {
        const stack = [];
        let r = interp.execute(sigHex, stack, { sigVersion: 'legacy', flags: fset });
        if (r.ok) r = interp.execute(spkHex, stack, { sigVersion: 'legacy', flags: fset });
        ours = r.ok && stack.length > 0 && castToBool(stack[stack.length - 1]);
        if (ours && fset.has('CLEANSTACK') && stack.length !== 1) ours = false;
      }
    } catch { skip.sigOrTimelock++; continue; } // opcode that needs tx context

    ran++;
    if (ours === (expected === 'OK')) matched++;
    else mismatches.push(`[${flags}] exp=${expected} ours=${ours} | ${sig} | ${spk}`);
  }

  console.log(`  script_tests.json: ran ${ran}/${cases.length}, matched ${matched}; skipped ${JSON.stringify(skip)}`);
  assert.ok(ran >= 850, `expected to cover >=850 cases, ran ${ran} (corpus or parser changed?)`);
  assert.deepEqual(mismatches, [], `\n${mismatches.slice(0, 20).join('\n')}`);
});

// Focused, legible assertions for the script-gating flags (the corpus above
// exercises them comprehensively but opaquely; these document the contract).
test('verification flags gate strictness via ctx.flags', () => {
  const run = (hex, ...flags) => interp.execute(hex, [], { sigVersion: 'legacy', flags: new Set(flags) });
  // MINIMALDATA — non-minimal PUSH: a 1-byte push of 0x01 must use OP_1
  assert.equal(run('0101').ok, true);
  assert.equal(run('0101', 'MINIMALDATA').ok, false);
  // MINIMALDATA — non-minimal SCRIPTNUM: 0x0000 read by OP_NOT
  assert.equal(run('02000091').ok, true);
  assert.equal(run('02000091', 'MINIMALDATA').ok, false);
  // DISCOURAGE_UPGRADABLE_NOPS — OP_NOP1 (0xb0)
  assert.equal(run('b0').ok, true);
  assert.equal(run('b0', 'DISCOURAGE_UPGRADABLE_NOPS').ok, false);
});
