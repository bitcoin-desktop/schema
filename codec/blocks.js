// Schema-driven block engine: the `transaction`, `block`, and `block-context`
// phases from schema/validate.jsonld, plus UTXO window evolution — a pruned
// node in miniature.
//
// Outcomes follow the established convention: true (pass), false (fail with
// the rule's errorCode), null (skipped — context unavailable or, for rules
// with an activationParam, height below the deployment's activation).
// Skipping is the honest pruned-node tradeoff: an input spending a coin
// created before the window can only be checked if its transaction is
// supplied via `external`.
//
// Out of scope, deliberately: witness/signature script execution.

import { dsha256, bytesToHex, hexToBytes } from './hash.js';
import { ScriptEngine } from './script.js';

const NULL_TXID = '0'.repeat(64);
const keyOf = (prevout) => `${prevout.txid}:${prevout.vout}`;

export const isCoinbase = (tx) =>
  tx.inputs.length === 1
  && tx.inputs[0].prevout.txid === NULL_TXID
  && tx.inputs[0].prevout.vout === 0xffffffff;

export class BlockEngine {
  constructor(codec, params, ruleSets, scriptEngine = null) {
    this.codec = codec;
    this.params = params;
    this.ruleSets = ruleSets; // {transaction, block, blockContext}
    this.scriptEngine = scriptEngine; // needed by the sigop rule

    const sumOut = (tx) => tx.outputs.reduce((s, o) => s + o.value, 0);

    this.txChecks = {
      'btc:rule-tx-inputs-nonempty': ({ tx }) => tx.inputs.length > 0,
      'btc:rule-tx-outputs-nonempty': ({ tx }) => tx.outputs.length > 0,
      'btc:rule-tx-size': ({ tx }) => this.codec.txWeight(tx) <= params.maxBlockWeight,
      'btc:rule-tx-output-values': ({ tx }) =>
        tx.outputs.every((o) => o.value >= 0 && o.value <= params.maxMoney)
        && sumOut(tx) <= params.maxMoney,
      'btc:rule-tx-inputs-unique': ({ tx }) =>
        new Set(tx.inputs.map((i) => keyOf(i.prevout))).size === tx.inputs.length,
      'btc:rule-tx-prevouts': ({ tx, coinbase }) => coinbase
        ? isCoinbase(tx)
        : tx.inputs.every((i) => i.prevout.txid !== NULL_TXID),
      'btc:rule-tx-coinbase-script': ({ tx, coinbase }) => {
        if (!coinbase) return null;
        const len = tx.inputs[0].scriptSig.length / 2;
        return len >= 2 && len <= 100;
      },
    };

    this.blockChecks = {
      'btc:rule-block-coinbase-first': ({ block }) =>
        block.transactions.length > 0 && isCoinbase(block.transactions[0]),
      'btc:rule-block-coinbase-single': ({ block }) =>
        block.transactions.slice(1).every((tx) => !isCoinbase(tx)),
      'btc:rule-block-merkle-root': ({ block, txids }) =>
        this.codec.merkleRoot(txids) === block.header.merkleRoot,
      'btc:rule-block-tx-duplicates': ({ txids }) => new Set(txids).size === txids.length,
      'btc:rule-block-weight': ({ block }) => this.blockWeight(block) <= params.maxBlockWeight,
      'btc:rule-block-sigops': ({ block }) => {
        if (!this.scriptEngine) return null;
        const sigops = block.transactions.reduce((s, tx) =>
          s + tx.inputs.reduce((a, i) => a + this.legacySigOps(i.scriptSig), 0)
            + tx.outputs.reduce((a, o) => a + this.legacySigOps(o.scriptPubKey), 0), 0);
        return 4 * sigops <= params.maxBlockSigopsCost;
      },
      'btc:rule-block-transactions': ({ block }) =>
        block.transactions.every((tx, i) => this.validateTransaction(tx, i === 0).ok),
    };

    this.contextChecks = {
      'btc:rule-blockctx-bip34-height': ({ block, height }) =>
        this.bip34Height(block.transactions[0]) === height,
      // definite violations (double spend, nonexistent vout) fail even in a
      // pruned window; out-of-window coins whose unspent-ness can't be
      // verified make the rule skip — that is the pruning tradeoff
      'btc:rule-blockctx-inputs-available': ({ spending }) =>
        spending.missing.length > 0 ? false
          : spending.valueUnresolved > 0 || spending.unverified > 0 ? null : true,
      'btc:rule-blockctx-fees': ({ spending }) =>
        spending.deficits.length > 0 ? false
          : spending.valueUnresolved > 0 ? null : true,
      // lockTime 0 and the all-final-sequences escape need no context; a
      // time-based lockTime needs median-time-past, which a caller may lack
      'btc:rule-blockctx-finality': ({ block, height, mtp }) => {
        let unknown = false;
        for (const tx of block.transactions) {
          if (tx.lockTime === 0) continue;
          if (tx.inputs.every((i) => i.sequence === 0xffffffff)) continue;
          if (tx.lockTime < 500000000) {
            if (tx.lockTime >= height) return false;
          } else if (mtp == null) unknown = true;
          else if (tx.lockTime >= mtp) return false;
        }
        return unknown ? null : true;
      },
      'btc:rule-blockctx-coinbase-maturity': ({ spending }) =>
        spending.premature.length > 0 ? false
          : spending.maturityUnknown > 0 ? null : true,
      'btc:rule-blockctx-coinbase-amount': ({ block, height, spending }) =>
        spending.valueUnresolved > 0 ? null
          : block.transactions[0].outputs.reduce((s, o) => s + o.value, 0)
            <= this.subsidy(height) + spending.fees,
      'btc:rule-blockctx-witness-commitment': ({ block }) => {
        const hasWitness = block.transactions.some((tx) => tx.witness?.some((s) => s.length > 0));
        if (!hasWitness) return null;
        const commitment = this.witnessCommitment(block.transactions[0]);
        if (!commitment) return false;
        return commitment === this.witnessCommitmentHash(block);
      },
    };
  }

  static fromSchemas(codec, chainSchema, validateSchema, scriptSchema = null, network = 'btc:mainnet') {
    const params = chainSchema['@graph'].find((n) => n['@id'] === network);
    const set = (phase) => validateSchema['@graph'].find((n) => n['@type'] === 'RuleSet' && n.phase === phase);
    const scriptEngine = scriptSchema
      ? ScriptEngine.fromSchemas(scriptSchema, chainSchema, network)
      : null;
    return new BlockEngine(codec, params, {
      transaction: set('transaction'),
      block: set('block'),
      blockContext: set('block-context'),
    }, scriptEngine);
  }

  // Legacy signature-operation count (Bitcoin Core's GetSigOpCount with
  // fAccurate=false): CHECKSIG(VERIFY) counts 1, CHECKMULTISIG(VERIFY) 20.
  legacySigOps(scriptHex) {
    let n = 0;
    for (const op of this.scriptEngine.parse(scriptHex)) {
      if (op.name === 'OP_CHECKSIG' || op.name === 'OP_CHECKSIGVERIFY') n += 1;
      else if (op.name === 'OP_CHECKMULTISIG' || op.name === 'OP_CHECKMULTISIGVERIFY') n += 20;
    }
    return n;
  }

  // ---- consensus arithmetic ----

  subsidy(height) {
    const halvings = Math.floor(height / this.params.halvingInterval);
    return halvings >= 64 ? 0 : Math.floor(this.params.initialSubsidy / 2 ** halvings);
  }

  blockWeight(block) {
    const total = this.codec.encode('Block', block).length;
    const legacy = block.transactions.reduce(
      (s, tx) => s + this.codec.encode('Transaction', tx, { legacy: true }).length,
      80 + this.#varintSize(block.transactions.length));
    return 3 * legacy + total;
  }

  #varintSize(n) { return n < 0xfd ? 1 : n <= 0xffff ? 3 : n <= 0xffffffff ? 5 : 9; }

  // BIP 34: the height encoded as a script-number push at the start of the
  // coinbase scriptSig. Returns null if unparseable.
  bip34Height(coinbaseTx) {
    const script = hexToBytes(coinbaseTx.inputs[0].scriptSig);
    const len = script[0];
    if (len < 1 || len > 5 || script.length < 1 + len) return null;
    let n = 0;
    for (let i = len; i >= 1; i--) n = n * 256 + script[i];
    return n;
  }

  // The witness commitment carried in a coinbase output: the last output
  // whose scriptPubKey starts OP_RETURN 0x24 0xaa21a9ed; returns the 32-byte
  // commitment hex, or null.
  witnessCommitment(coinbaseTx) {
    for (let i = coinbaseTx.outputs.length - 1; i >= 0; i--) {
      const spk = coinbaseTx.outputs[i].scriptPubKey;
      if (spk.startsWith('6a24aa21a9ed') && spk.length >= 12 + 64) {
        return spk.slice(12, 12 + 64);
      }
    }
    return null;
  }

  // dsha256(witness merkle root || witness reserved value). The coinbase
  // wtxid is defined as all zeros; the reserved value comes from the
  // coinbase's own witness stack (usually 32 zero bytes).
  witnessCommitmentHash(block) {
    const wtxids = block.transactions.map((tx, i) =>
      i === 0 ? NULL_TXID : this.codec.wtxid(tx));
    const root = hexToBytes(this.codec.merkleRoot(wtxids)).reverse();
    const reserved = hexToBytes(block.transactions[0].witness?.[0]?.[0] ?? '00'.repeat(32));
    const cat = new Uint8Array(64);
    cat.set(root); cat.set(reserved, 32);
    return bytesToHex(dsha256(cat));
  }

  // ---- ruleset execution ----

  #run(ruleSet, checks, ctx) {
    const results = ruleSet.rules.map((rule) => {
      let outcome;
      if (rule.activationParam && ctx.height != null
          && ctx.height < this.params[rule.activationParam]) {
        outcome = null; // not yet activated at this height
      } else {
        outcome = checks[rule['@id']](ctx);
      }
      return {
        rule: rule['@id'],
        label: rule.label,
        ok: outcome,
        error: outcome === false ? rule.errorCode : null,
      };
    });
    return { ok: results.every((r) => r.ok !== false), results };
  }

  validateTransaction(tx, coinbase = false) {
    return this.#run(this.ruleSets.transaction, this.txChecks, { tx, coinbase });
  }

  validateBlockStructure(block) {
    const txids = block.transactions.map((tx) => this.codec.txid(tx));
    return this.#run(this.ruleSets.block, this.blockChecks, { block, txids });
  }

  // Walk the block's transactions in order, resolving each input against
  // (1) coins created earlier in the window or block — availability proven,
  // (2) externally supplied prevout transactions — value known, unspent-ness
  //     unverifiable in a pruned window ("unverified"),
  // (3) nothing — "valueUnresolved".
  // Definite violations land in `missing` (double spend within the window
  // or block, or a vout that does not exist on a known transaction).
  // Does not mutate utxo.
  #resolveSpending(block, utxo, external, height) {
    const spentHere = new Set();
    const createdHere = new Map();
    let fees = 0, valueUnresolved = 0, unverified = 0, maturityUnknown = 0;
    const missing = [], deficits = [], premature = [];

    block.transactions.forEach((tx, i) => {
      const txid = this.codec.txid(tx);
      if (i > 0) {
        let inSum = 0, valuesOk = true;
        for (const inp of tx.inputs) {
          const key = keyOf(inp.prevout);
          if (spentHere.has(key)) {
            missing.push(key); valuesOk = false;
          } else {
            const coin = createdHere.get(key) ?? utxo.get(key);
            if (coin) {
              inSum += coin.output.value;
              if (coin.coinbase && height - coin.height < this.params.coinbaseMaturity) {
                premature.push(key);
              }
            } else {
              const ext = external.get(inp.prevout.txid);
              const out = ext?.outputs[inp.prevout.vout];
              if (out) {
                inSum += out.value; unverified++;
                // an out-of-window coinbase coin's creation height is unknown
                if (isCoinbase(ext)) maturityUnknown++;
              } else if (ext) { missing.push(key); valuesOk = false; }
              else { valueUnresolved++; valuesOk = false; }
            }
          }
          spentHere.add(key);
        }
        const outSum = tx.outputs.reduce((s, o) => s + o.value, 0);
        if (valuesOk) {
          if (inSum < outSum) deficits.push(txid);
          else fees += inSum - outSum;
        }
      }
      tx.outputs.forEach((output, vout) => {
        if (!output.scriptPubKey.startsWith('6a')) {
          createdHere.set(`${txid}:${vout}`, { output, coinbase: i === 0, height });
        }
      });
    });
    return { fees, missing, deficits, premature, valueUnresolved, unverified, maturityUnknown };
  }

  validateBlockContext(block, { height, utxo = new Map(), external = new Map(), mtp = null }) {
    const spending = this.#resolveSpending(block, utxo, external, height);
    const verdict = this.#run(this.ruleSets.blockContext, this.contextChecks,
      { block, height, spending, mtp });
    return { ...verdict, spending };
  }

  // Apply a fully-validated block to the UTXO window map (mutates).
  // Returns {created, spent} counts.
  applyBlock(utxo, block, height) {
    let created = 0, spent = 0;
    block.transactions.forEach((tx, i) => {
      if (i > 0) {
        for (const inp of tx.inputs) {
          if (utxo.delete(keyOf(inp.prevout))) spent++;
        }
      }
      const txid = this.codec.txid(tx);
      tx.outputs.forEach((output, vout) => {
        if (!output.scriptPubKey.startsWith('6a')) { // unspendable: not a coin
          utxo.set(`${txid}:${vout}`, {
            outpoint: { txid, vout }, output, height, coinbase: i === 0,
          });
          created++;
        }
      });
    });
    return { created, spent };
  }
}
