// Zero-dependency WebSocket server framing (RFC 6455), enough for the
// bridge: the upgrade handshake (we already own a SHA-1), binary frames
// with client masking, fragmentation, ping/pong, and close.

import { sha1 } from './hash.js';

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

export function acceptKey(secWebSocketKey) {
  const digest = sha1(new TextEncoder().encode(secWebSocketKey + GUID));
  // base64 without Buffer, so this file stays environment-neutral
  let bin = '';
  for (const b of digest) bin += String.fromCharCode(b);
  return (typeof btoa !== 'undefined') ? btoa(bin)
    : globalThis.Buffer.from(digest).toString('base64');
}

// Server -> client frame (unmasked).
export function encodeFrame(payload, opcode = 0x2) {
  const n = payload.length;
  let header;
  if (n < 126) {
    header = Uint8Array.of(0x80 | opcode, n);
  } else if (n < 65536) {
    header = Uint8Array.of(0x80 | opcode, 126, n >> 8, n & 0xff);
  } else {
    header = new Uint8Array(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    new DataView(header.buffer).setBigUint64(2, BigInt(n));
  }
  const out = new Uint8Array(header.length + n);
  out.set(header);
  out.set(payload, header.length);
  return out;
}

// Incremental client -> server frame parser. feed(bytes) returns an array
// of {opcode, payload} for each complete message (fragments reassembled).
export class FrameParser {
  constructor() {
    this.buf = new Uint8Array(0);
    this.fragments = [];
    this.fragOpcode = null;
  }

  feed(bytes) {
    const merged = new Uint8Array(this.buf.length + bytes.length);
    merged.set(this.buf);
    merged.set(bytes, this.buf.length);
    this.buf = merged;

    const messages = [];
    for (;;) {
      const frame = this.#frame();
      if (!frame) break;
      const { fin, opcode, payload } = frame;
      if (opcode === 0x0) { // continuation
        this.fragments.push(payload);
        if (fin) {
          messages.push({ opcode: this.fragOpcode, payload: concat(this.fragments) });
          this.fragments = []; this.fragOpcode = null;
        }
      } else if (!fin) {
        this.fragOpcode = opcode;
        this.fragments = [payload];
      } else {
        messages.push({ opcode, payload });
      }
    }
    return messages;
  }

  #frame() {
    const b = this.buf;
    if (b.length < 2) return null;
    const fin = (b[0] & 0x80) !== 0;
    const opcode = b[0] & 0x0f;
    const masked = (b[1] & 0x80) !== 0;
    let len = b[1] & 0x7f;
    let off = 2;
    if (len === 126) {
      if (b.length < 4) return null;
      len = (b[2] << 8) | b[3];
      off = 4;
    } else if (len === 127) {
      if (b.length < 10) return null;
      len = Number(new DataView(b.buffer, b.byteOffset + 2, 8).getBigUint64(0));
      off = 10;
    }
    const maskLen = masked ? 4 : 0;
    if (b.length < off + maskLen + len) return null;
    let payload = b.slice(off + maskLen, off + maskLen + len);
    if (masked) {
      const mask = b.subarray(off, off + 4);
      for (let i = 0; i < payload.length; i++) payload[i] ^= mask[i & 3];
    }
    this.buf = b.slice(off + maskLen + len);
    return { fin, opcode, payload };
  }
}

function concat(arrays) {
  const out = new Uint8Array(arrays.reduce((s, a) => s + a.length, 0));
  let p = 0;
  for (const a of arrays) { out.set(a, p); p += a.length; }
  return out;
}

// Attach a WebSocket server to a node:http server. onConnection receives
// {send(bytes), close(), onMessage(cb), onClose(cb)} per client.
export function attachWsServer(httpServer, onConnection) {
  httpServer.on('upgrade', (req, socket) => {
    const key = req.headers['sec-websocket-key'];
    if (!key) { socket.destroy(); return; }
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n'
      + 'Upgrade: websocket\r\nConnection: Upgrade\r\n'
      + `Sec-WebSocket-Accept: ${acceptKey(key)}\r\n\r\n`);

    const parser = new FrameParser();
    let messageCb = null, closeCb = null;
    const client = {
      send: (bytes) => socket.write(encodeFrame(bytes, 0x2)),
      close: () => { socket.write(encodeFrame(new Uint8Array(0), 0x8)); socket.end(); },
      onMessage: (cb) => { messageCb = cb; },
      onClose: (cb) => { closeCb = cb; },
    };
    socket.on('data', (data) => {
      for (const { opcode, payload } of parser.feed(new Uint8Array(data))) {
        if (opcode === 0x2 || opcode === 0x1) messageCb?.(payload);
        else if (opcode === 0x9) socket.write(encodeFrame(payload, 0xa)); // ping -> pong
        else if (opcode === 0x8) { socket.end(); closeCb?.(); }
      }
    });
    socket.on('close', () => closeCb?.());
    socket.on('error', () => closeCb?.());
    onConnection(client, req);
  });
}
