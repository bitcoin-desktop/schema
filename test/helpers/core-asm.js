// Bitcoin Core's script mini-language, as used by src/test/data/*.json
// (script_tests.json, tx_valid.json, tx_invalid.json): whitespace-separated
// decimal numbers, 0x-prefixed raw bytes, 'strings', and opcode names with or
// without the OP_ prefix. Mirrors ParseScript() in src/test/script_tests.cpp.
export function makeParseScript(scriptSchema) {
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
  return function parseScript(s) {
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
  };
}

// Every script_verify flag Core's harnesses know (mapFlagNames in
// src/test/transaction_tests.cpp). tx_valid.json lists flags to EXCLUDE from
// this set; tx_invalid.json lists flags to APPLY. Flags this interpreter does
// not model are carried along harmlessly (it only ever asks `flags.has(name)`).
export const ALL_FLAGS = [
  'P2SH', 'STRICTENC', 'DERSIG', 'LOW_S', 'SIGPUSHONLY', 'MINIMALDATA', 'NULLDUMMY',
  'DISCOURAGE_UPGRADABLE_NOPS', 'CLEANSTACK', 'MINIMALIF', 'NULLFAIL',
  'CHECKLOCKTIMEVERIFY', 'CHECKSEQUENCEVERIFY', 'WITNESS',
  'DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM', 'WITNESS_PUBKEYTYPE', 'CONST_SCRIPTCODE',
  'TAPROOT', 'DISCOURAGE_UPGRADABLE_TAPROOT_VERSION', 'DISCOURAGE_OP_SUCCESS',
  'DISCOURAGE_UPGRADABLE_PUBKEYTYPE',
];
export const parseFlags = (s) => new Set(s.split(/[,\s]+/).filter((f) => f && f !== 'NONE'));
