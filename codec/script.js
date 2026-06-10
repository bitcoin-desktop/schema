// Schema-driven script engine.
//
// Opcode names come from the Opcode enumeration and classification templates
// from the ScriptType enumeration in schema/script.jsonld; address encoding
// is parameterized by NetworkParams (schema/chain.jsonld). This file holds
// only the mechanics: byte walking, template matching, base58check and
// bech32/bech32m encoding.

import { dsha256, bytesToHex, hexToBytes } from './hash.js';

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const B32 = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function base58check(versionByte, payload) {
  const data = new Uint8Array(1 + payload.length + 4);
  data[0] = versionByte;
  data.set(payload, 1);
  data.set(dsha256(data.subarray(0, 1 + payload.length)).subarray(0, 4), 1 + payload.length);
  let n = 0n;
  for (const b of data) n = (n << 8n) | BigInt(b);
  let out = '';
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of data) { if (b !== 0) break; out = '1' + out; }
  return out;
}

function bech32Polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((top >>> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}

function bech32Encode(hrp, witnessVersion, program, constant) {
  const data = [witnessVersion];
  let acc = 0, bits = 0;
  for (const b of program) {
    acc = (acc << 8) | b; bits += 8;
    while (bits >= 5) { bits -= 5; data.push((acc >>> bits) & 31); }
  }
  if (bits > 0) data.push((acc << (5 - bits)) & 31);
  const hrpExp = [...[...hrp].map((c) => c.charCodeAt(0) >>> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31)];
  const polymod = bech32Polymod([...hrpExp, ...data, 0, 0, 0, 0, 0, 0]) ^ constant;
  const checksum = Array.from({ length: 6 }, (_, i) => (polymod >>> (5 * (5 - i))) & 31);
  return hrp + '1' + [...data, ...checksum].map((d) => B32[d]).join('');
}

export class ScriptEngine {
  constructor(opcodeEnum, scriptTypeEnum, params) {
    this.params = params;
    this.byCode = new Map(opcodeEnum.members.map((m) => [m.code, m.name]));
    this.byName = new Map(opcodeEnum.members.map((m) => [m.name, m.code]));
    this.scriptTypes = scriptTypeEnum.members;
  }

  static fromSchemas(scriptSchema, chainSchema, network = 'btc:mainnet') {
    const node = (id) => scriptSchema['@graph'].find((n) => n['@id'] === id);
    return new ScriptEngine(node('btc:Opcode'), node('btc:ScriptType'),
      chainSchema['@graph'].find((n) => n['@id'] === network));
  }

  // hex -> [{code, name, data?}]; data (hex) present for pushes.
  // A malformed tail yields a final op with `error` set rather than a throw.
  parse(hex) {
    const bytes = hexToBytes(hex);
    const ops = [];
    let i = 0;
    while (i < bytes.length) {
      const code = bytes[i++];
      let len = null;
      if (code >= 0x01 && code <= 0x4b) len = code;
      else if (code === 0x4c) { len = bytes[i]; i += 1; }
      else if (code === 0x4d) { len = bytes[i] | (bytes[i + 1] << 8); i += 2; }
      else if (code === 0x4e) { len = bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24); i += 4; }
      if (len === null) {
        ops.push({ code, name: this.byCode.get(code) ?? `OP_UNKNOWN_0x${code.toString(16).padStart(2, '0')}` });
        continue;
      }
      if (Number.isNaN(len) || i + len > bytes.length) {
        ops.push({ code, name: 'OP_PUSH', error: 'truncated push' });
        break;
      }
      const name = code <= 0x4b ? `OP_PUSHBYTES_${code}` : this.byCode.get(code);
      ops.push({ code, name, data: bytesToHex(bytes.subarray(i, i + len)) });
      i += len;
    }
    return ops;
  }

  asm(hex) {
    return this.parse(hex).map((op) => op.error ? `[${op.error}]` : op.data ?? op.name).join(' ');
  }

  // Match one ScriptType template ("OP_DUP OP_HASH160 <20> ..."): <n> matches
  // a push of exactly n bytes, <a|b> of either length.
  #matchTemplate(template, ops) {
    const tokens = template.split(' ');
    if (tokens.length !== ops.length) return false;
    return tokens.every((tok, i) => {
      const op = ops[i];
      if (tok.startsWith('<')) {
        if (op.data == null) return false;
        return tok.slice(1, -1).split('|').some((n) => op.data.length === 2 * Number(n));
      }
      return op.name === tok && op.data == null;
    });
  }

  #isSmallInt(op) { return op.code === 0x00 || (op.code >= 0x51 && op.code <= 0x60); }
  #smallInt(op) { return op.code === 0x00 ? 0 : op.code - 0x50; }

  #matchSpecial(kind, ops) {
    switch (kind) {
      case 'nulldata':
        return ops.length >= 1 && ops[0].name === 'OP_RETURN';
      case 'multisig': {
        if (ops.length < 4 || ops.at(-1).name !== 'OP_CHECKMULTISIG') return false;
        const [m, n] = [ops[0], ops.at(-2)];
        if (!this.#isSmallInt(m) || !this.#isSmallInt(n)) return false;
        const keys = ops.slice(1, -2);
        return keys.length === this.#smallInt(n) && this.#smallInt(m) >= 1
          && this.#smallInt(m) <= this.#smallInt(n)
          && keys.every((k) => k.data && (k.data.length === 66 || k.data.length === 130));
      }
      case 'witness-unknown': {
        if (ops.length !== 2 || !ops[1].data) return false;
        const v = ops[0].code;
        const len = ops[1].data.length / 2;
        return v >= 0x52 && v <= 0x60 && len >= 2 && len <= 40;
      }
      case 'fallback':
        return true;
      default:
        return false;
    }
  }

  address(type, ops) {
    const enc = type.addressEncoding;
    if (!enc) return null;
    const pushes = ops.filter((op) => op.data != null);
    const payload = hexToBytes(pushes[Number(enc.payload.split(':')[1])].data);
    if (enc.encoding === 'base58check') return base58check(this.params[enc.versionParam], payload);
    const witnessVersion = enc.witnessVersion ?? this.#smallInt(ops[0]);
    const constant = enc.encoding === 'bech32' ? 1 : 0x2bc830a3;
    return bech32Encode(this.params.bech32Hrp, witnessVersion, payload, constant);
  }

  // hex -> {type, address|null, asm}
  classify(hex) {
    const ops = this.parse(hex);
    const broken = ops.some((op) => op.error);
    for (const t of this.scriptTypes) {
      const matched = !broken && (t.template
        ? this.#matchTemplate(t.template, ops)
        : this.#matchSpecial(t.special, ops));
      if (matched || (broken && t.special === 'fallback')) {
        return { type: t.name, address: matched ? this.address(t, ops) : null, asm: this.asm(hex) };
      }
    }
    return { type: 'nonstandard', address: null, asm: this.asm(hex) };
  }
}
