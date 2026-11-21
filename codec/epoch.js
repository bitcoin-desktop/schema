// Epoch packages (schema/epoch.jsonld) checked from the package alone. The rules are data in the
// schema; this file binds a pure check to each rule id, Hornet-style, the way headers.js does for
// btc:HeaderRules. btc:rule-epoch-product needs the epoch's blocks, so it is reported as not judged
// (ok: null): replaying the blocks against the side data is a verifier's job (blaketestnode's
// verifyEpoch), and a package that passes everything here can still fail it.
import { sha256, bytesToHex, hexToBytes } from './hash.js';

const HEX64 = /^[0-9a-f]{64}$/, HEX = /^([0-9a-f]{2})*$/;
const isU32 = (v) => Number.isInteger(v) && v >= 0 && v <= 0xffffffff;
const TYPES = {
  u32: isU32, hash: (v) => typeof v === 'string' && HEX64.test(v), hex: (v) => typeof v === 'string' && HEX.test(v),
  string: (v) => typeof v === 'string', bool: (v) => typeof v === 'boolean', array: (v) => Array.isArray(v) || (v && typeof v === 'object'),
};
const MUHASH_BYTES = 384;
const EMPTY_SET = '01' + '00'.repeat(MUHASH_BYTES - 1); // the value 1, little-endian

// Core's digest of a MuHash3072 value: SHA256 of its 384 little-endian bytes, shown reversed
export function muhashDigest(valueHex) {
  if (typeof valueHex !== 'string' || valueHex.length !== MUHASH_BYTES * 2) return null;
  return bytesToHex(sha256(hexToBytes(valueHex)).reverse());
}

function fromBase64(b64) {
  if (typeof b64 !== 'string') return null;
  try { const s = atob(b64); const out = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i); return out; } catch { return null; }
}
const popcount = (bytes) => { let n = 0; for (let b of bytes) for (; b; b &= b - 1) n++; return n; };

export class EpochChecker {
  // schema: the parsed schema/epoch.jsonld graph
  constructor(schema, { interval = 2016 } = {}) {
    this.interval = interval;
    this.nodes = new Map((schema['@graph'] ?? []).map((n) => [n['@id'], n]));
    this.rules = this.nodes.get('btc:EpochRules')?.rules ?? [];
    this.chainRules = this.nodes.get('btc:EpochChainRules')?.rules ?? [];
    if (!this.rules.length || !this.chainRules.length) throw new Error('epoch schema: btc:EpochRules / btc:EpochChainRules missing');
  }

  // the declared fields of a struct, checked recursively -> null or what is wrong
  conforms(obj, structId, path = '') {
    const s = this.nodes.get(structId); if (!s) return `${structId} is not declared`;
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) return `${path || 'package'} is not an object`;
    for (const f of s.fields) {
      const v = obj[f.label], at = path ? `${path}.${f.label}` : f.label;
      if (v === undefined) { if (f.optional) continue; return `${at} missing`; }
      if (f.valueType === 'struct') { const why = this.conforms(v, f.structType, at); if (why) return why; continue; }
      const ok = TYPES[f.valueType]; if (!ok) return `${at}: unknown valueType ${f.valueType}`;
      if (!ok(v)) return `${at} is not a ${f.valueType}`;
    }
    return null;
  }

  // -> { ok, results: [{ rule, label, errorCode, ok: true|false|null, why? }] }
  check(pkg) {
    const fieldsWhy = this.conforms(pkg, 'btc:Epoch');
    const run = (rule) => {
      if (rule['@id'] === 'btc:rule-epoch-fields') return fieldsWhy;
      if (fieldsWhy) return undefined; // the other rules read fields this one found missing or mistyped
      const s = pkg.start, e = pkg.end;
      switch (rule['@id']) {
        case 'btc:rule-epoch-span':
          if (e.height <= s.height) return `ends at ${e.height}, not after its start ${s.height}`;
          if ((e.height + 1) % this.interval) return `ends at ${e.height}, not on the last block of a ${this.interval}-block retarget period`;
          return pkg.blocks.count === e.height - s.height ? null : `blocks.count ${pkg.blocks.count} is not ${e.height - s.height}`;
        case 'btc:rule-epoch-empty-genesis':
          return s.height !== 0 || (s.coins === 0 && s.value === EMPTY_SET) ? null : 'an epoch from genesis starts from the empty set (0 coins, value 1)';
        case 'btc:rule-epoch-digest':
          for (const [end, st] of [['start', s], ['end', e]]) { const d = muhashDigest(st.value); if (d === null) return `${end}.value is not ${MUHASH_BYTES} bytes`; if (d !== st.muhash) return `${end}.muhash is not the digest of ${end}.value`; }
          return null;
        case 'btc:rule-epoch-hints': {
          const bits = fromBase64(pkg.hints); if (!bits) return 'hints is not base64';
          if (bits.length !== Math.ceil(pkg.outputs / 8)) return `hints is ${bits.length} bytes, not ${Math.ceil(pkg.outputs / 8)}`;
          if (pkg.outputs % 8 && bits[bits.length - 1] >> (pkg.outputs % 8)) return 'hints sets bits past the last output';
          const n = popcount(bits); return n === pkg.unspent ? null : `hints marks ${n} unspent, the package says ${pkg.unspent}`;
        }
        case 'btc:rule-epoch-side-data': {
          const seen = new Set();
          for (const r of pkg.spent) {
            if (!Array.isArray(r) || r.length !== 5) return 'a side-data record is not [key, height, coinbase, value, scriptPubKey]';
            const [key, height, coinbase, value, spk] = r;
            if (typeof key !== 'string' || !/^[0-9a-f]{64}:\d+$/.test(key) || !isU32(height) || (coinbase !== 0 && coinbase !== 1) || !Number.isSafeInteger(value) || value < 0 || typeof spk !== 'string' || !HEX.test(spk)) return `side-data record ${key} is malformed`;
            if (height > s.height) return `side-data coin ${key} was created at ${height}, inside the epoch`;
            if (seen.has(key)) return `side data lists ${key} twice`; seen.add(key);
          }
          return null;
        }
        case 'btc:rule-epoch-coin-count':
          return e.coins === s.coins + pkg.unspent - pkg.spent.length ? null : `${s.coins} + ${pkg.unspent} - ${pkg.spent.length} is not ${e.coins}`;
        case 'btc:rule-epoch-product': return undefined; // needs the blocks
        default: return undefined;
      }
    };
    return this.#report(this.rules, run);
  }

  // consecutive packages, in height order -> { ok, results } (each package's own rules not repeated)
  checkChain(pkgs) {
    const run = (rule) => {
      for (let i = 1; i < pkgs.length; i++) {
        const p = pkgs[i - 1], n = pkgs[i];
        if (rule['@id'] === 'btc:rule-epoch-chain-network' && (n.network !== p.network || n.chain !== p.chain)) return `package ${i} is ${n.network}/${n.chain}, package ${i - 1} ${p.network}/${p.chain}`;
        if (rule['@id'] === 'btc:rule-epoch-chain-link') {
          for (const k of ['height', 'hash', 'coins', 'muhash', 'value']) if (n.start?.[k] !== p.end?.[k]) return `package ${i} starts with ${k} ${String(n.start?.[k]).slice(0, 16)}, package ${i - 1} ended with ${String(p.end?.[k]).slice(0, 16)}`;
          if (n.start.hashSerialized3 !== undefined && p.end.hashSerialized3 !== undefined && n.start.hashSerialized3 !== p.end.hashSerialized3) return `package ${i} starts with a different hashSerialized3`;
        }
      }
      return null;
    };
    return this.#report(this.chainRules, run);
  }

  #report(rules, run) {
    const results = rules.map((rule) => {
      const why = run(rule), base = { rule: rule['@id'], label: rule.label, errorCode: rule.errorCode };
      return why === undefined ? { ...base, ok: null } : why === null ? { ...base, ok: true } : { ...base, ok: false, why };
    });
    return { ok: results.every((r) => r.ok !== false), results };
  }
}
