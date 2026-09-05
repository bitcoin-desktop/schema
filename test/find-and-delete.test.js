// Core's script_FindAndDelete unit cases (src/test/script_tests.cpp), ported
// verbatim, plus the legacy-sighash OP_CODESEPARATOR stripping. Both feed the
// legacy sighash path; the tx_valid/tx_invalid/sighash corpora exercise them
// end to end, this pins the helper semantics on their own.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { findAndDelete, stripCodeSeparators } from '../codec/interpreter.js';
import { bytesToHex, hexToBytes } from '../codec/hash.js';

const fad = (s, d) => { const r = findAndDelete(hexToBytes(s), hexToBytes(d)); return [bytesToHex(r.script), r.found]; };

test('FindAndDelete matches Core case for case', () => {
  const cases = [
    // [script, delete, expected, found]
    ['5152', '', '5152', 0],                          // delete nothing is a no-op
    ['515253', '52', '5153', 1],
    ['535153535453', '53', '5154', 4],
    ['0302ff03', '0302ff03', '', 1],                  // PUSH 0x02ff03
    ['0302ff030302ff03', '0302ff03', '', 2],
    ['0302ff030302ff03', '02', '0302ff030302ff03', 0], // matches entire opcodes only
    ['0302ff030302ff03', 'ff', '0302ff030302ff03', 0],
    ['0302ff030302ff03', '03', '02ff0302ff03', 2],    // odd edge: strips the push-three prefix
    ['02feed5169', 'feed51', '02feed5169', 0],        // does not match inside opcodes
    ['02feed5169', '02feed51', '69', 1],
    ['516902feed5169', 'feed51', '516902feed5169', 0],
    ['516902feed5169', '02feed51', '516969', 1],
    ['00005151', '0051', '0051', 1],                  // single-pass
    ['000051005151', '0051', '0051', 2],
    ['0003feed', '03feed', '00', 1],                  // can remove a trailing invalid push
    ['0003feed', '00', '03feed', 1],
  ];
  for (const [s, d, expect, found] of cases) {
    assert.deepEqual(fad(s, d), [expect, found], `FindAndDelete(${s}, ${d})`);
  }
});

test('legacy sighash scriptCode drops every OP_CODESEPARATOR', () => {
  const strip = (h) => bytesToHex(stripCodeSeparators(hexToBytes(h)));
  assert.equal(strip('ab51ab52ab'), '5152');
  assert.equal(strip('5152'), '5152');
  assert.equal(strip('02abab51'), '02abab51');       // 0xab inside a push is data, not an opcode
  assert.equal(strip('4c02abab'), '4c02abab');       // PUSHDATA1 payload likewise
  assert.equal(strip('ab'), '');
  assert.equal(strip('51ab0302'), '510302');         // truncated trailing push: remainder kept verbatim
});
