// P2P message layer: the 24-byte envelope plus typed payloads, driven by
// the Command enumeration in schema/p2p.jsonld. Transport (TCP, BIP 324
// encryption) is a host-environment concern; this layer turns byte streams
// into messages and back.

import { dsha256, bytesToHex, hexToBytes } from './hash.js';

const HEADER_SIZE = 24;

export class P2pEngine {
  constructor(codec, params, commandEnum) {
    this.codec = codec;
    this.params = params;
    this.commands = new Map(commandEnum.members.map((m) => [m.name, m]));
  }

  // The p2p schema must be loaded into the codec (its structs reference the
  // core and proof modules for tx/block/merkleblock payloads).
  static fromSchemas(codec, p2pSchema, chainSchema, network = 'btc:mainnet') {
    const commandEnum = p2pSchema['@graph'].find((n) => n['@id'] === 'btc:Command');
    const params = chainSchema['@graph'].find((n) => n['@id'] === network);
    return new P2pEngine(codec, params, commandEnum);
  }

  #structFor(command) {
    const id = this.commands.get(command)?.structType;
    return id ? id.replace(/^btc:/, '') : null;
  }

  // Encode one message: envelope (magic from params, computed length and
  // checksum) + payload. `payload` may be a struct object (encoded via the
  // command's schema struct), a hex string (raw payload), or absent.
  encodeMessage(command, payload = null) {
    let payloadBytes;
    if (payload == null) payloadBytes = new Uint8Array(0);
    else if (typeof payload === 'string') payloadBytes = hexToBytes(payload);
    else {
      const structName = this.#structFor(command);
      if (!structName) throw new Error(`no payload struct for command: ${command}`);
      payloadBytes = this.codec.encode(structName, payload);
    }
    const header = this.codec.encode('MessageHeader', {
      magic: this.params.magic,
      command,
      length: payloadBytes.length,
      checksum: bytesToHex(dsha256(payloadBytes).subarray(0, 4)),
    });
    const out = new Uint8Array(header.length + payloadBytes.length);
    out.set(header); out.set(payloadBytes, HEADER_SIZE);
    return out;
  }

  encodeMessageHex(command, payload = null) { return bytesToHex(this.encodeMessage(command, payload)); }

  // Decode a single message starting at `offset`. Returns the envelope, the
  // decoded payload when the command's struct is known (raw hex otherwise),
  // and validity checks — never throws on unknown commands.
  decodeMessage(bytes, offset = 0) {
    if (bytes.length - offset < HEADER_SIZE) throw new Error('truncated message header');
    const header = this.codec.decode('MessageHeader', bytes.subarray(offset, offset + HEADER_SIZE));
    const start = offset + HEADER_SIZE;
    if (bytes.length - start < header.length) throw new Error(`truncated payload for ${header.command}`);
    const payloadBytes = bytes.subarray(start, start + header.length);
    const checksumOk = bytesToHex(dsha256(payloadBytes).subarray(0, 4)) === header.checksum;
    const magicOk = header.magic === this.params.magic;

    let payload = null, decoded = false;
    const structName = this.#structFor(header.command);
    if (structName && header.length > 0) {
      try {
        payload = this.codec.decode(structName, payloadBytes);
        decoded = true;
      } catch {
        payload = bytesToHex(payloadBytes); // malformed: keep raw
      }
    } else if (header.length > 0) {
      payload = bytesToHex(payloadBytes);
    }
    return {
      command: header.command,
      known: this.commands.has(header.command),
      magicOk, checksumOk, decoded,
      length: header.length,
      payload,
      next: start + header.length,
    };
  }

  // Split a raw stream into messages (stops at a trailing partial message).
  decodeStream(bytesOrHex) {
    const bytes = typeof bytesOrHex === 'string' ? hexToBytes(bytesOrHex) : bytesOrHex;
    const messages = [];
    let offset = 0;
    while (bytes.length - offset >= HEADER_SIZE) {
      const length = new DataView(bytes.buffer, bytes.byteOffset + offset + 16, 4).getUint32(0, true);
      if (bytes.length - offset - HEADER_SIZE < length) break;
      const msg = this.decodeMessage(bytes, offset);
      messages.push(msg);
      offset = msg.next;
    }
    return { messages, consumed: offset, remainder: bytes.length - offset };
  }

  // A well-formed version message with sensible defaults.
  buildVersion({ userAgent = '/bitcoin-schema:0.0.10/', startHeight = 0, nonce = Math.floor(Math.random() * 2 ** 53), services = 0, timestamp = Math.floor(Date.now() / 1000) } = {}) {
    const zeroAddr = { services: 0, ip: '0'.repeat(32), port: 0 };
    return {
      version: 70016,
      services,
      timestamp,
      addrRecv: zeroAddr,
      addrFrom: zeroAddr,
      nonce,
      userAgent,
      startHeight,
      relay: 1,
    };
  }
}
