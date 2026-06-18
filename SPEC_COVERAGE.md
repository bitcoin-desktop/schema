# Consensus coverage map

This maps the schema's validation coverage against an **independent enumeration** of
Bitcoin's consensus rules — the section tree of the BTCDecoded "Orange Paper"
(`PROTOCOL.md`), used here purely as a second-opinion completeness checklist.

Using an outside enumeration as the oracle keeps the audit honest: it lists rules someone
else thought were load-bearing, so a gap is visible even if we never thought to write the
rule. It is **not** an endorsement of that implementation — at the time of writing its
difficulty code shipped a public `get_next_work_required_corrected()` that forks off
mainnet and had no testnet4/BIP94 support, both of which the schema gets right (see
[§7.1](#71-difficulty-adjustment)).

The schema's rules live in [`schema/validate.jsonld`](schema/validate.jsonld) (executed by
[`codec/headers.js`](codec/headers.js) / [`codec/blocks.js`](codec/blocks.js)) with the
script system in [`codec/interpreter.js`](codec/interpreter.js). Error codes match Bitcoin
Core's.

## Legend

| Mark | Meaning |
|------|---------|
| ✅ | Covered — a rule, codec check, or engine enforces it |
| ◐ | Partial — the mechanism exists but not as a distinct enforced rule, or only part is modelled |
| ⬛ | Out of scope — relay/mempool **policy**, not block-validation consensus; the schema is a validation / light-client model, not a relay node |
| ○ | Future — in scope but not yet modelled |

## Scope boundary

The schema validates **headers, transactions, and blocks** — what a node must check to
accept a block. It deliberately does **not** model the mempool/relay layer (acceptance
policy, standardness, RBF, fee-market, peer gossip). Those are node *policy*, not consensus,
and a light client never runs them. Such sections are marked ⬛ with the reason, not left
as silent gaps.

## Coverage

| § | Section (reference) | Status | Schema rule / module | Note |
|---|---|---|---|---|
| 4 | Consensus Constants | ✅ | `chain.jsonld` NetworkParams | `maxMoney`, `maxBlockSigopsCost`, subsidy, difficulty interval, all per-network |
| 5.1 | Transaction Validation | ✅ | `inputs-nonempty`, `outputs-nonempty`, `size-limit`, `output-values`, `inputs-unique`, `prevouts` | `inputs-unique` is the CVE-2018-17144 duplicate-prevout check |
| 5.2 | Script Execution | ✅ | `codec/interpreter.js`, gated by `scripts` rule | full opcode set incl. `OP_CHECKLOCKTIMEVERIFY` / `OP_CHECKSEQUENCEVERIFY`; legacy + BIP143 + BIP341 sighash; **differentially tested against Core's `script_tests.json`** (flag-independent subset, 750 cases) |
| 5.3 | Block Validation | ✅ | `coinbase-script-size`/`-first`/`-single`, `merkle-root`, `no-duplicate-txids`, `sigop-limit`, `weight-limit`, `transactions-valid` | `no-duplicate-txids` = BIP30 |
| 5.4 | BIP Validation Rules | ✅ | `version` (BIP34/66/65 gating), `coinbase-height` (BIP34) | activation heights carried in NetworkParams |
| 5.5 | Sequence Locks (BIP68/112) | ✅ | `sequence-locks` rule + `OP_CHECKSEQUENCEVERIFY` opcode | height-based relative locks enforced at tx-context level; time-based and out-of-window locks skip honestly (no per-coin MTP in a light window) |
| 6.1 | Block Subsidy | ✅ | `codec/mine.js` subsidy + `coinbase-amount` rule | halving schedule |
| 6.2 | Total Supply | ◐ | derived from subsidy schedule | not asserted as a standalone supply invariant |
| 6.3 | Supply Limit Validation | ✅ | `output-values` [`bad-txns-vout-toolarge`] via `maxMoney`; `codec/blocks.js` `sumOut <= maxMoney` | |
| 6.4 | Coinbase Detection | ✅ | `coinbase-first`/`-single` + codec `isCoinbase` | |
| 6.5 | Fee Market | ⬛ | — | mempool/relay policy, not consensus |
| 7.1 | Difficulty Adjustment | ✅ | `difficulty` [`bad-diffbits`] + **`timewarp`** [`time-timewarp-attack`] | **exceeds the reference**: BIP94 timewarp + testnet4 min-difficulty modelled and validated from genesis |
| 7.2 | Proof of Work | ✅ | `proof-of-work` [`high-hash`] | header + block |
| 8 | Security Properties | ◐ | test suite | expressed as executable tests (golden BIP vectors, live-chain validation, reorg suite), not as in-band rules |
| 9.1 | Mempool Validation | ⬛ | — | relay node, out of scope |
| 9.2 | Standard Transaction Rules | ⬛ | — | policy, not consensus |
| 9.3 | Replace-By-Fee (RBF) | ⬛ | — | mempool policy |
| 10 | Network Protocol | ◐ | `codec/p2p.js`, `bridge/bridge.js`, `codec/ws.js` | handshake, `getheaders`, `inv`, block sync; not full relay / addr gossip / Dandelion |
| 11.1 | SegWit | ✅ | `witness-commitment` rule + BIP143 sighash + codec segwit (de)serialization | |
| 11.2 | Taproot | ✅ | `codec/interpreter.js` taproot (BIP341/342), key & script path | |
| 11.4 | UTXO Commitments | ○ | — | assumeUTXO not modelled; note the pruned-node design caps at 6 blocks |
| 11.5 | Signet (BIP325) | ◐ | signet NetworkParams present | **block-signature (signet challenge) validation not yet implemented** → candidate add |
| 12 | Mining Protocol | ✅ | `codec/mine.js` | block template, subsidy, witness commitment, nonce grind |
| 13 | Engineering Invariants | ◐ | test suite + `codec/node.js` reorg | analog: 127 tests + reorg walk-back |

## Where the schema exceeds the reference

- **Timewarp / BIP94 (§7.1).** The schema has an explicit `timewarp` rule and validates
  testnet4 from genesis (BIP94 + the 20-minute min-difficulty walk-back). The reference
  enumeration's difficulty implementation had neither.
- **Reorg recovery.** `codec/node.js` performs bounded fork-point walk-back with a
  more-work rule ([reorg test](test/reorg.test.js)); covered by golden + regtest-mined tests.

## Candidate additions (in scope, prioritised)

1. ~~**BIP68/112 sequence-lock context enforcement**~~ — **done** (`sequence-locks` rule,
   issue #45): height-based relative locks enforced; time-based and out-of-window locks
   skip honestly. *(§5.5)*
2. **Signet (BIP325) block-signature validation** — we already carry signet NetworkParams;
   the missing piece is validating the block signature committed in the coinbase. Natural
   extension of multi-network support. *(§11.5)*
3. **Explicit total-supply invariant** — a standalone assertion that cumulative issuance
   never exceeds `maxMoney`, complementing the per-output `output-values` check. *(§6.2)*

## Out of scope by design (documented, not gaps)

Mempool validation, standardness, RBF, fee-market, peer gossip / addr relay, Dandelion++,
and UTXO commitments / assumeUTXO. These are relay-node policy or bulk-state features
outside a header/transaction/block validation schema.
