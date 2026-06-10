// Block construction: mining is validation run forward. The miner assembles
// consensus fields (coinbase, merkle root, header) so that every derived
// field satisfies every rule, then searches the nonce/extraNonce space for
// a header hash at or below the target.

import { dsha256, bytesToHex, hexToBytes } from './hash.js';
import { numEncode } from './interpreter.js';

const NULL_TXID = '0'.repeat(64);

export class Miner {
  constructor(codec, params) {
    this.codec = codec;
    this.params = params;
  }

  static fromSchemas(codec, chainSchema, network = 'btc:regtest') {
    return new Miner(codec, chainSchema['@graph'].find((n) => n['@id'] === network));
  }

  subsidy(height) {
    const halvings = Math.floor(height / this.params.halvingInterval);
    return halvings >= 64 ? 0 : Math.floor(this.params.initialSubsidy / 2 ** halvings);
  }

  // BIP 34 height push followed by extraNonce bytes, padded to the 2-byte
  // minimum coinbase script size.
  coinbaseScriptSig(height, extraNonce = 0) {
    const h = numEncode(height);
    const e = numEncode(extraNonce);
    let hex = h.length.toString(16).padStart(2, '0') + bytesToHex(h)
      + e.length.toString(16).padStart(2, '0') + bytesToHex(e);
    while (hex.length < 4) hex += '00';
    return hex;
  }

  // The witness commitment for a candidate block whose coinbase is not yet
  // final: coinbase wtxid is defined as zero, so only the other txids matter.
  witnessCommitment(transactions) {
    const wtxids = [NULL_TXID, ...transactions.map((tx) => this.codec.wtxid(tx))];
    const root = hexToBytes(this.codec.merkleRoot(wtxids)).reverse();
    const cat = new Uint8Array(64);
    cat.set(root); // witness reserved value: 32 zero bytes
    return bytesToHex(dsha256(cat));
  }

  buildCoinbase({ height, value, scriptPubKey, transactions = [], extraNonce = 0 }) {
    const segwit = transactions.some((tx) => tx.witness?.some((s) => s.length > 0));
    const outputs = [{ value, scriptPubKey }];
    const coinbase = {
      version: 2,
      inputs: [{
        prevout: { txid: NULL_TXID, vout: 0xffffffff },
        scriptSig: this.coinbaseScriptSig(height, extraNonce),
        sequence: 0xffffffff,
      }],
      outputs,
      lockTime: 0,
    };
    if (segwit) {
      outputs.push({ value: 0, scriptPubKey: '6a24aa21a9ed' + this.witnessCommitment(transactions) });
      coinbase.witness = [['0'.repeat(64)]];
    }
    return coinbase;
  }

  assemble({ prevHash, height, bits, time, scriptPubKey, transactions = [], fees = 0, version = 4, extraNonce = 0 }) {
    const coinbase = this.buildCoinbase({
      height, value: this.subsidy(height) + fees, scriptPubKey, transactions, extraNonce,
    });
    const all = [coinbase, ...transactions];
    return {
      header: {
        version,
        prevBlockHash: prevHash,
        merkleRoot: this.codec.merkleRoot(all.map((tx) => this.codec.txid(tx))),
        time,
        bits,
        nonce: 0,
      },
      transactions: all,
    };
  }

  // Search the nonce space (bumping extraNonce on wrap, which rebuilds the
  // coinbase and merkle root). Synchronous; pass maxAttempts to bound work.
  mine(template, { maxAttempts = 1 << 24 } = {}) {
    const target = this.codec.expandCompact(template.bits);
    let extraNonce = 0;
    let attempts = 0;
    while (attempts < maxAttempts) {
      const block = this.assemble({ ...template, extraNonce });
      for (let nonce = 0; nonce <= 0xffffffff && attempts < maxAttempts; nonce++, attempts++) {
        block.header.nonce = nonce;
        const hash = this.codec.blockHash(block.header);
        if (BigInt('0x' + hash) <= target) {
          return { block, hash, attempts: attempts + 1, extraNonce };
        }
      }
      extraNonce++;
    }
    return { block: null, attempts };
  }
}
