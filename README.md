# Bitcoin Schema

**v0.0.1** · A canonical, machine-readable model of the Bitcoin protocol, written in JSON-LD.

One schema; many projections: byte-exact binary serialization, explorer views, RDF/linked data,
and (eventually) declarative validation rules in the spirit of
[Hornet Node](https://hornetnode.org/paper.html)'s formal consensus specification.

**Live:** https://bitcoin-desktop.github.io/schema/ · **Decoder app:** [apps/tx.html](https://bitcoin-desktop.github.io/schema/apps/tx.html)

> Independent community project; not affiliated with Bitcoin Core.

## The idea

Bitcoin's consensus rules and data structures are defined, in practice, by implementation code.
This repo takes the opposite approach: a **declarative schema** is the source of truth, and
code is a projection of it.

Every field of every structure is tagged with its epistemic class:

- **Consensus fields** exist in the canonical byte stream and are covered by proof-of-work.
  They carry wire annotations (`wireType`, ordering, conditional presence) sufficient for a
  generic codec to serialize and deserialize them with no per-type code.
- **Derived fields** (`txid`, `wtxid`, block `hash`, `weight`, merkle root, target, work…)
  are computed deterministically from consensus bytes and are **never serialized**.
  Their derivation formulas are part of the schema.
- **Contextual fields** (height, confirmations, fee, spent status) depend on chain state and
  will live in the `chain` module — never mixed into consensus structures.

The keystone test: the schema-driven [reference codec](codec/codec.js) must round-trip real
mainnet data **byte-exactly**. The [test suite](test/) does this for the genesis block and the
first segwit transaction, and verifies every derivation (txid, wtxid, block hash, merkle root,
proof-of-work, size/weight/vsize) against known mainnet values. If the schema can't reproduce
consensus bytes, it's documentation; because it can, it's canonical.

## Everything is JSON-LD

- The **schema itself** ([schema/core.jsonld](schema/core.jsonld)) is a JSON-LD graph —
  classes and properties get dereferenceable URIs under
  `https://bitcoin-desktop.github.io/schema/`.
- **Instances** (a decoded transaction, a block) are JSON-LD documents using
  [context.jsonld](context.jsonld).
- Hashes are hex strings in display order (byte-reversed, as in every explorer and RPC);
  amounts are satoshis as plain JSON numbers (max supply is well inside the float53 safe range).
- The only non-JSON projection is the consensus byte stream itself.

## Modules and layering

Strict one-way dependencies (Hornet-style): a module may only reference modules above it.

| module | status | contents |
|---|---|---|
| `core` | **v0.0.1** | Block, BlockHeader, Transaction, TransactionInput, TransactionOutput, OutPoint, Witness — full wire annotations + derivations |
| `script` | planned | opcodes, script types, addresses, taproot |
| `chain` | planned | UTXO set, mempool, network params, deployments |
| `proof` | planned | merkle proofs, compact filters (BIP 157/158), SPV |
| `validate` | planned | declarative rulesets as data: phase, context, error code, BIP, activation |
| `p2p` | planned | message envelope and the wire messages |
| `mine` | planned | block template, coinbase construction, targets |
| `wallet` | planned | BIP 32 keys, descriptors, PSBT, BIP 21 |

## Roadmap

Each milestone is a working artifact, not just more schema:

1. **Headers** — headers-only chain sync and verification (PoW, difficulty, chain work) in the
   browser, from `core` + `proof`. ✅ `core` structures and PoW check shipped in v0.0.1.
2. **SPV** — verify transaction inclusion with merkle proofs and compact filters.
3. **Pruned node** — full validation with UTXO set evolution, pruned storage.
4. **Full node** — `p2p` + `mine`: relay, mempool, block template construction.

## Using the codec

```js
import { Codec } from './codec/codec.js';

const core = await (await fetch('schema/core.jsonld')).json();
const codec = new Codec(core);

const tx = codec.decode('Transaction', rawHex); // JSON-LD-ready object
codec.txid(tx);                                  // derived: display-order txid
codec.encodeHex('Transaction', tx) === rawHex;   // byte-exact, always
```

Zero dependencies, browser and Node. Run the golden tests with `npm test`.

## Relationship to other work

- **[Hornet Node](https://hornetnode.org/)** specifies Bitcoin's *rules* as declarative,
  pure-function rulesets; this schema specifies the *structures, wire format, and derivations*
  those rules operate over. The planned `validate` module mirrors Hornet's four validation
  phases (header, transaction, block-structural, block-contextual) so rule IDs can be shared
  across implementations for differential testing.
- **[schema.org](https://schema.org/)** is the stylistic model: a pragmatic, web-native
  vocabulary where every term has a URI and a readable page.
- **ASN.1 / Kaitai Struct** are the precedents for byte-level encoding annotations; unlike
  them, this schema also carries semantics (derivations, BIP provenance, RDF projection).

## License

MIT
