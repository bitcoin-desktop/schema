// LightNode: a persistent, verifying light client. Syncs the header chain
// forward from a schema-defined checkpoint, validating every header through
// the schema ruleset (including testnet min-difficulty walk-backs and BIP 94
// retargets), cross-checks multiple sources, and verifies transaction
// inclusion against its OWN validated chain rather than a server's word.
//
// In Elementary Bitcoin §20.6 terms this is a Class-H verifier with
// on-demand Class-T proofs — the chassis the bridge and mesh bolt onto.

import { HeaderEngine } from './headers.js';
import { SpvEngine } from './spv.js';

export class MemoryStorage {
  constructor() { this.m = new Map(); }
  async get(k) { return this.m.get(k) ?? null; }
  async set(k, v) { this.m.set(k, v); }
}

// Minimal promise wrapper over IndexedDB (browser persistence).
export class IdbStorage {
  constructor(dbName = 'bitcoin-schema-node') { this.dbName = dbName; }
  async #db() {
    if (this._db) return this._db;
    this._db = await new Promise((resolve, reject) => {
      const req = indexedDB.open(this.dbName, 1);
      req.onupgradeneeded = () => req.result.createObjectStore('kv');
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return this._db;
  }
  async get(k) {
    const db = await this.#db();
    return new Promise((resolve, reject) => {
      const req = db.transaction('kv').objectStore('kv').get(k);
      req.onsuccess = () => resolve(req.result ?? null);
      req.onerror = () => reject(req.error);
    });
  }
  async set(k, v) {
    const db = await this.#db();
    return new Promise((resolve, reject) => {
      const tx = db.transaction('kv', 'readwrite');
      tx.objectStore('kv').put(v, k);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  }
}

// An esplora HTTP source. Headers are reconstructed from block JSON
// (10 per request) and verified against their own hashes — the source
// cannot lie about a header without changing its id.
export class EsploraSource {
  constructor(base, codec, fetchFn = globalThis.fetch) {
    this.base = base;
    this.codec = codec;
    // browsers require fetch to be invoked with the global as `this`
    this.fetch = fetchFn.bind(globalThis);
  }
  async #text(p) {
    const r = await this.fetch(this.base + p);
    if (!r.ok) throw new Error(`${this.base}${p}: HTTP ${r.status}`);
    return r.text();
  }
  async tipHeight() { return parseInt(await this.#text('/blocks/tip/height'), 10); }
  async tipHash() { return this.#text('/blocks/tip/hash'); }

  headerFromBlockJson(b) {
    const hex = this.codec.encodeHex('BlockHeader', {
      version: b.version,
      prevBlockHash: b.previousblockhash ?? '0'.repeat(64),
      merkleRoot: b.merkle_root,
      time: b.timestamp,
      bits: b.bits,
      nonce: b.nonce,
    });
    if (this.codec.blockHash(this.codec.decode('BlockHeader', hex)) !== b.id) {
      throw new Error(`source served inconsistent block JSON at height ${b.height}`);
    }
    return hex;
  }

  // Ascending 80-byte header hexes for [start, start+count).
  // /blocks/:h returns 10 blocks descending from height h.
  async headersRange(start, count) {
    const out = new Array(count);
    let topWanted = start + count - 1;
    while (topWanted >= start) {
      const batch = JSON.parse(await this.#text(`/blocks/${topWanted}`));
      for (const b of batch) {
        if (b.height >= start && b.height <= start + count - 1) {
          out[b.height - start] = this.headerFromBlockJson(b);
        }
      }
      topWanted -= batch.length;
      if (!batch.length) throw new Error('empty block batch');
    }
    return out;
  }

  async merkleProof(txid) {
    const [proofHex, status] = await Promise.all([
      this.#text(`/tx/${txid}/merkleblock-proof`),
      this.#text(`/tx/${txid}/status`).then(JSON.parse),
    ]);
    return { proofHex, blockHeight: status.block_height ?? null };
  }
}

export class LightNode {
  constructor({ codec, headerEngine, spvEngine = null, storage, sources, checkpoint, batchSize = 200 }) {
    this.codec = codec;
    this.engine = headerEngine;
    this.spv = spvEngine;
    this.storage = storage;
    this.sources = sources;
    this.checkpoint = checkpoint; // {height, hash, rawHeader}
    this.batchSize = batchSize;
    this.cache = new Map(); // height -> decoded header (current epoch + tail)
    this.divergence = null;
  }

  static fromSchemas(codec, chainSchema, validateSchema, network, { storage, sources, batchSize } = {}) {
    const engine = HeaderEngine.fromSchemas(codec, chainSchema, validateSchema, network);
    const spv = SpvEngine.fromSchemas(codec, validateSchema);
    const checkpoint = chainSchema['@graph'].find(
      (n) => n['@type'] === 'btc:Checkpoint' && n.network === network);
    if (!checkpoint) throw new Error(`no checkpoint for ${network}`);
    return new LightNode({
      codec, headerEngine: engine, spvEngine: spv,
      storage: storage ?? new MemoryStorage(), sources: sources ?? [],
      checkpoint, batchSize,
    });
  }

  async init() {
    let meta = await this.storage.get('meta');
    if (!meta) {
      const header = this.codec.decode('BlockHeader', this.checkpoint.rawHeader);
      const hash = this.codec.blockHash(header);
      if (this.checkpoint.hash && hash !== this.checkpoint.hash) {
        throw new Error('checkpoint header does not match its hash');
      }
      meta = {
        startHeight: this.checkpoint.height,
        tipHeight: this.checkpoint.height,
        tipHash: hash,
        chainWork: this.engine.work(header).toString(16), // work since checkpoint
      };
      await this.storage.set(`h:${this.checkpoint.height}`, this.checkpoint.rawHeader);
      await this.storage.set('meta', meta);
    }
    this.meta = meta;
    await this.#warmCache();
    return meta;
  }

  async headerAt(height) {
    if (this.cache.has(height)) return this.cache.get(height);
    const hex = await this.storage.get(`h:${height}`);
    if (!hex) return null;
    const h = this.codec.decode('BlockHeader', hex);
    this.cache.set(height, h);
    return h;
  }

  // Preload everything the difficulty rule may walk back to: the current
  // epoch from its boundary, plus an 11-header MTP tail.
  async #warmCache() {
    const epochStart = Math.floor(this.meta.tipHeight / this.engine.interval) * this.engine.interval;
    const from = Math.max(this.meta.startHeight, Math.min(epochStart, this.meta.tipHeight - 11));
    for (let h = from; h <= this.meta.tipHeight; h++) await this.headerAt(h);
  }

  status() {
    return {
      ...this.meta,
      headersStored: this.meta.tipHeight - this.meta.startHeight + 1,
      checkpoint: this.checkpoint.height,
      divergence: this.divergence,
    };
  }

  // Validate and append a contiguous ascending batch starting at tip+1.
  async #appendBatch(headerHexes, startHeight) {
    const headers = headerHexes.map((hex) => this.codec.decode('BlockHeader', hex));
    const prevContext = [];
    for (let h = Math.max(this.meta.startHeight, startHeight - 11); h < startHeight; h++) {
      prevContext.push(await this.headerAt(h));
    }
    const rows = this.engine.validateChain(headers, {
      startHeight, prevContext,
      now: Math.floor(Date.now() / 1000),
      chainAt: (h) => this.cache.get(h) ?? null,
    });
    for (const row of rows) {
      if (!row.ok) {
        const bad = row.results.filter((r) => r.ok === false).map((r) => r.error).join(',');
        throw new Error(`header ${row.height} rejected: ${bad}`);
      }
    }
    let work = BigInt('0x' + this.meta.chainWork);
    for (const [i, header] of headers.entries()) {
      const height = startHeight + i;
      await this.storage.set(`h:${height}`, headerHexes[i]);
      this.cache.set(height, header);
      work += this.engine.work(header);
    }
    this.meta = {
      ...this.meta,
      tipHeight: startHeight + headers.length - 1,
      tipHash: rows.at(-1).hash,
      chainWork: work.toString(16),
    };
    await this.storage.set('meta', this.meta);
    // bound the cache: keep the current epoch + tail
    const keep = Math.floor(this.meta.tipHeight / this.engine.interval) * this.engine.interval - 11;
    for (const h of this.cache.keys()) if (h < Math.min(keep, this.meta.tipHeight - 2048)) this.cache.delete(h);
  }

  // Sync forward to the sources' tip. onProgress(synced, target) is optional.
  async sync({ maxBatches = Infinity, onProgress = null } = {}) {
    const primary = this.sources[0];
    if (!primary) throw new Error('no sources configured');
    const target = await primary.tipHeight();
    let batches = 0;
    while (this.meta.tipHeight < target && batches < maxBatches) {
      const start = this.meta.tipHeight + 1;
      const count = Math.min(this.batchSize, target - this.meta.tipHeight);
      const hexes = await primary.headersRange(start, count);
      await this.#appendBatch(hexes, start);
      batches++;
      onProgress?.(this.meta.tipHeight, target);
    }
    await this.#crossCheck();
    return this.status();
  }

  // Compare our tip against every other source; record divergence rather
  // than trusting anyone silently.
  async #crossCheck() {
    this.divergence = null;
    for (const source of this.sources.slice(1)) {
      try {
        const theirHeight = await source.tipHeight();
        const h = Math.min(theirHeight, this.meta.tipHeight);
        const theirs = (await source.headersRange(h, 1))[0];
        const ours = await this.storage.get(`h:${h}`);
        if (ours && theirs !== ours) {
          this.divergence = { height: h, source: source.base };
        }
      } catch { /* unreachable source is not divergence */ }
    }
  }

  // Verify a transaction's inclusion against OUR chain: the proof's header
  // must equal the header we validated at that height.
  async verifyTx(txid, sourceIdx = 0) {
    if (!this.spv) throw new Error('no spv engine');
    const { proofHex, blockHeight } = await this.sources[sourceIdx].merkleProof(txid);
    if (blockHeight == null) return { ok: false, error: 'unconfirmed' };
    const stored = await this.headerAt(blockHeight);
    if (!stored) return { ok: null, reason: `height ${blockHeight} predates checkpoint ${this.checkpoint.height}` };
    const mb = this.codec.decode('MerkleBlock', proofHex);
    if (this.codec.blockHash(mb.header) !== this.codec.blockHash(stored)) {
      return { ok: false, error: 'proof header does not match our validated chain' };
    }
    const verdict = this.spv.verify(mb, { txid });
    return {
      ok: verdict.ok, results: verdict.results,
      height: blockHeight,
      confirmations: this.meta.tipHeight - blockHeight + 1,
    };
  }
}
