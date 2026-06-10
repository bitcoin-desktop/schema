// Schema-driven SPV engine.
//
// Executes the `spv` phase ruleset from schema/validate.jsonld against
// decoded MerkleBlock objects (schema/proof.jsonld). The partial merkle
// tree extraction follows BIP 37 / Bitcoin Core's CPartialMerkleTree:
// depth-first traversal driven by flag bits (LSB-first within each byte),
// consuming hashes for pruned subtrees and matched leaves.

import { dsha256, bytesToHex, hexToBytes, reverseHex } from './hash.js';

export class SpvEngine {
  constructor(codec, ruleSet) {
    this.codec = codec;
    this.ruleSet = ruleSet;

    this.checks = {
      'btc:rule-spv-pow': (ctx) => this.codec.checkProofOfWork(ctx.merkleBlock.header),
      'btc:rule-spv-tree': (ctx) => ctx.extracted.wellFormed,
      'btc:rule-spv-merkle-root': (ctx) =>
        ctx.extracted.wellFormed && ctx.extracted.root === ctx.merkleBlock.header.merkleRoot,
      'btc:rule-spv-inclusion': (ctx) =>
        ctx.txid == null ? null : ctx.extracted.matches.some((m) => m.txid === ctx.txid),
    };
  }

  static fromSchemas(codec, validateSchema) {
    const ruleSet = validateSchema['@graph'].find((n) => n['@type'] === 'RuleSet' && n.phase === 'spv');
    return new SpvEngine(codec, ruleSet);
  }

  // BIP 37 partial merkle tree extraction. Returns the reconstructed root,
  // the matched txids with their block positions, and whether the encoding
  // was well-formed (all hashes and flag bits consumed, no duplicated
  // branches — the CVE-2012-2459 check, non-zero tx count).
  extract(merkleBlock) {
    const nTx = merkleBlock.txCount;
    const hashes = merkleBlock.hashes.map((h) => hexToBytes(h).reverse());
    const flags = hexToBytes(merkleBlock.flags);
    const width = (h) => (nTx + (1 << h) - 1) >> h;
    let height = 0;
    while (width(height) > 1) height++;

    let bitsUsed = 0, hashesUsed = 0, bad = false;
    const matches = [];

    const traverse = (h, pos) => {
      if (bitsUsed >= flags.length * 8) { bad = true; return new Uint8Array(32); }
      const flag = (flags[bitsUsed >> 3] >>> (bitsUsed & 7)) & 1;
      bitsUsed++;
      if (h === 0 || !flag) {
        if (hashesUsed >= hashes.length) { bad = true; return new Uint8Array(32); }
        const hash = hashes[hashesUsed++];
        if (h === 0 && flag) matches.push({ txid: reverseHex(hash), index: pos });
        return hash;
      }
      const left = traverse(h - 1, pos * 2);
      let right = left;
      if (pos * 2 + 1 < width(h - 1)) {
        right = traverse(h - 1, pos * 2 + 1);
        if (bytesToHex(left) === bytesToHex(right)) bad = true;
      }
      const cat = new Uint8Array(64);
      cat.set(left); cat.set(right, 32);
      return dsha256(cat);
    };

    const root = nTx === 0 ? new Uint8Array(32) : traverse(height, 0);
    const wellFormed = !bad
      && nTx > 0
      && hashesUsed === hashes.length
      && Math.ceil(bitsUsed / 8) === flags.length;
    return { root: reverseHex(root), matches, wellFormed };
  }

  // Run the spv ruleset. txid (display-order hex) is the transaction whose
  // inclusion is being verified; pass null to skip the inclusion rule.
  verify(merkleBlock, { txid = null } = {}) {
    const ctx = { merkleBlock, txid, extracted: this.extract(merkleBlock) };
    const results = this.ruleSet.rules.map((rule) => {
      const outcome = this.checks[rule['@id']](ctx);
      return {
        rule: rule['@id'],
        label: rule.label,
        ok: outcome,
        error: outcome === false ? rule.errorCode : null,
      };
    });
    return {
      ok: results.every((r) => r.ok !== false),
      results,
      root: ctx.extracted.root,
      matches: ctx.extracted.matches,
    };
  }
}
