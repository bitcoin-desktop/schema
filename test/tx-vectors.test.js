// Differential test against Bitcoin Core's transaction-level corpus
// (src/test/data, MIT, vendored verbatim into test/vectors):
//   tx_valid.json   — [[[prevout hash, index, scriptPubKey asm, amount?]…], tx hex, EXCLUDED flags]
//                     must verify with every known flag except the excluded ones
//   tx_invalid.json — same shape with flags to APPLY; must fail (BADTX = fails CheckTransaction)
//   sighash.json    — [raw tx, scriptCode, input index, hashType, expected legacy sighash]
// Unlike script_tests.json these drive verifyInput with a real transaction,
// real prevouts and per-case flags — the shape block validation uses.
//
// Mismatches are expected at first (schema#73): each maps to a known
// interpreter deviation (bitcoin-kernel/kernel#3). They are pinned in KNOWN
// below so the suite stays green, any *new* mismatch fails, and a fix that
// clears one must also remove it from the list.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { Codec } from '../codec/codec.js';
import { ScriptEngine } from '../codec/script.js';
import { ScriptInterpreter } from '../codec/interpreter.js';
import { BlockEngine, isCoinbase } from '../codec/blocks.js';
import { reverseHex } from '../codec/hash.js';
import { makeParseScript, ALL_FLAGS, parseFlags } from './helpers/core-asm.js';

const load = async (p) => JSON.parse(await readFile(new URL(p, import.meta.url), 'utf8'));
const core = await load('../schema/core.jsonld');
const codec = new Codec(core);
const scriptSchema = await load('../schema/script.jsonld');
const chainSchema = await load('../schema/chain.jsonld');
const validateSchema = await load('../schema/validate.jsonld');
const scriptEngine = ScriptEngine.fromSchemas(scriptSchema, chainSchema);
const limits = scriptSchema['@graph'].find((n) => n['@id'] === 'btc:scriptLimits');
const interp = new ScriptInterpreter(codec, scriptEngine, limits);
const blocks = BlockEngine.fromSchemas(codec, chainSchema, validateSchema, scriptSchema);
const parseScript = makeParseScript(scriptSchema);

// Known mismatches, keyed by "<file>#<case index>" (index counts cases, not
// comment lines), each with the interpreter deviation it pins. bitcoin-kernel/
// kernel#3 items are referenced by number; "new" means this corpus found it.
const FIND_AND_DELETE = 'FindAndDelete: legacy CHECKSIG/CHECKMULTISIG must delete the signature push(es) from scriptCode before hashing (new)';
const CONST_SCRIPTCODE = 'SCRIPT_VERIFY_CONST_SCRIPTCODE not implemented: must fail when FindAndDelete would alter scriptCode or scriptCode holds OP_CODESEPARATOR (new; needs FindAndDelete first)';
const WITNESS_LENGTH = 'v0 witness program must be 20 or 32 bytes, else WITNESS_PROGRAM_WRONG_LENGTH (kernel#3 item 4)';
const KNOWN = new Map([
  ...[5, 8, 32, 33, 34, 35, 36, 37, 38, 39, 116, 118].map((i) => [`tx_valid#${i}`, FIND_AND_DELETE]),
  ['tx_valid#84', 'CSV compares tx.version signed; Core casts to uint32 so 0xffffffff is >= 2 (kernel#3 note, real vector)'],
  ['tx_valid#108', 'witness-program detection must require a direct push (IsWitnessProgram); a PUSHDATA-encoded program is a bare script (kernel#3 item 4)'],
  ['tx_invalid#64', WITNESS_LENGTH], ['tx_invalid#71', WITNESS_LENGTH],
  ['tx_invalid#68', '520-byte cap on initial witness stack elements (kernel#3 item 2)'],
  ['tx_invalid#77', FIND_AND_DELETE], ['tx_invalid#79', FIND_AND_DELETE],
  ...[81, 82, 83, 87, 88, 89, 90, 92].map((i) => [`tx_invalid#${i}`, CONST_SCRIPTCODE]),
]);

// Run one corpus. `expectValid` selects the tx_valid vs tx_invalid semantics.
function runCorpus(name, cases, expectValid) {
  const stats = { ran: 0, matched: 0, skipped: [], mismatches: [], unexpectedPass: [] };
  let idx = -1;
  for (const t of cases) {
    if (t.length === 1) continue; // comment
    idx++;
    const [inputs, txHex, flagStr] = t;
    const key = `${name}#${idx}`;
    let ours, why = '';
    try {
      const tx = codec.decode('Transaction', txHex);
      // Core writes the coinbase prevout index as -1; the codec decodes it as 0xffffffff.
      const prevouts = new Map(inputs.map(([hash, vout, spk, amount]) =>
        [`${hash}:${vout === -1 ? 0xffffffff : vout}`, { scriptPubKey: parseScript(spk), value: amount ?? 0 }]));
      // Core's CheckTransaction knows a coinbase when it sees one; tell validateTransaction.
      const structure = blocks.validateTransaction(tx, isCoinbase(tx)).ok;
      if (flagStr === 'BADTX') { ours = structure; why = 'BADTX'; }
      else if (!structure) {
        // Core requires every non-BADTX vector to pass CheckTransaction; a structural
        // failure here is a harness/engine problem, never the expected verdict.
        ours = 'THROW:unexpected CheckTransaction failure';
      } else {
        const flags = expectValid
          ? new Set(ALL_FLAGS.filter((f) => !parseFlags(flagStr).has(f)))
          : parseFlags(flagStr);
        const all = tx.inputs.map((inp) => prevouts.get(`${inp.prevout.txid}:${inp.prevout.vout}`) ?? null);
        if (all.some((p) => p == null)) throw new Error('prevout not in vector');
        let verdict = true;
        for (let i = 0; i < tx.inputs.length && verdict; i++) {
          const r = interp.verifyInput(tx, i, all[i], all, flags);
          if (r.ok === null) { verdict = null; why = `input ${i}: ${r.reason}`; break; }
          if (!r.ok) { verdict = false; why = `input ${i}: ${r.error}`; }
        }
        ours = verdict;
      }
    } catch (e) { ours = `THROW:${e.message}`; }

    if (ours === null) { stats.skipped.push(`${key} (${why})`); continue; }
    stats.ran++;
    const agree = ours === expectValid;
    if (agree) { stats.matched++; if (KNOWN.has(key)) stats.unexpectedPass.push(key); }
    else if (!KNOWN.has(key)) stats.mismatches.push(`${key} [${flagStr}] ours=${ours} ${why} :: ${txHex.slice(0, 48)}…`);
  }
  return stats;
}

const txValid = await load('vectors/tx_valid.json');
const txInvalid = await load('vectors/tx_invalid.json');

test('Core tx_valid.json: every transaction verifies under all flags minus the excluded ones', () => {
  const s = runCorpus('tx_valid', txValid, true);
  console.log(`  tx_valid.json: ran ${s.ran}, matched ${s.matched}, known ${s.ran - s.matched}, skipped ${s.skipped.length} ${s.skipped.join('; ')}`);
  assert.deepEqual(s.unexpectedPass, [], 'now passing — remove from KNOWN');
  assert.deepEqual(s.mismatches, [], `\n${s.mismatches.join('\n')}`);
});

test('Core tx_invalid.json: every transaction fails under the listed flags', () => {
  const s = runCorpus('tx_invalid', txInvalid, false);
  console.log(`  tx_invalid.json: ran ${s.ran}, matched ${s.matched}, known ${s.ran - s.matched}, skipped ${s.skipped.length} ${s.skipped.join('; ')}`);
  assert.deepEqual(s.unexpectedPass, [], 'now passing — remove from KNOWN');
  assert.deepEqual(s.mismatches, [], `\n${s.mismatches.join('\n')}`);
});

test('Core sighash.json: legacy sighash digests match exactly (OP_CODESEPARATOR cases pinned)', async () => {
  const rows = (await load('vectors/sighash.json')).filter((r) => r.length === 5);
  // Known: Core's legacy sighash serializer drops every OP_CODESEPARATOR from
  // scriptCode; ours keeps them (kernel#3 item 7). Every scriptCode containing
  // one currently mismatches; none without one may.
  let matched = 0, knownSep = 0; const bad = [];
  for (const [i, [rawTx, scriptCode, inIndex, hashType, expected]] of rows.entries()) {
    const tx = codec.decode('Transaction', rawTx);
    const ours = reverseHex(interp.sighashLegacy(tx, Number(inIndex), scriptCode, Number(hashType) >>> 0));
    const hasSep = scriptEngine.parse(scriptCode).some((o) => o.code === 0xab);
    if (ours === expected) { matched++; if (hasSep) bad.push(`#${i} now matches with OP_CODESEPARATOR — update the pin`); }
    else if (hasSep) knownSep++;
    else bad.push(`#${i} hashType ${hashType} in ${inIndex}: ours ${ours} expected ${expected}`);
  }
  console.log(`  sighash.json: ${matched}/${rows.length} match, ${knownSep} known (OP_CODESEPARATOR in scriptCode)`);
  assert.deepEqual(bad.slice(0, 10), [], `${bad.length} unexpected:\n${bad.slice(0, 10).join('\n')}`);
});
