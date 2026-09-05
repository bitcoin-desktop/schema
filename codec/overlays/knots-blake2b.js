// Code half of the Bitcoin Knots BLAKE2b overlay (data half:
// schema/overlays/knots-blake2b.jsonld). Installs the proof-of-work hash, the
// derived `time` of a v2 header, and the checks behind the overlay's rules.
// Semantics follow Knots v29.4.1 validation.cpp; error codes are Knots'.
import { registerKnotsBlake2b, headerTime, isHeaderV2 } from '../pow/knots-header-v2.js';
import { hexToBytes } from '../hash.js';

export const REDUCED_DATA_MAX_BLOCK_WEIGHT = 800000;

// RDTS applies to exactly the blocks from the fork height until the parent's
// median-time-past reaches the expiry (Consensus::Params::RdtsActiveAt).
export const rdtsActiveAt = (params, height, mtpPrev) =>
  height >= params.blake2bHeight && mtpPrev < params.rdtsExpiryTime;

const containsBytes = (hay, needle) => {
  if (!needle.length) return true;
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
};

export function headerChecks(params) {
  return {
    // CheckBlockHeader: a v2 header's committed height must be at/after the fork
    'knots:rule-header-v1-until-fork': ({ header }) => !isHeaderV2(header) || header.height >= params.blake2bHeight,
    // ContextualCheckBlockHeader: from the fork height every header is v2
    'knots:rule-header-v2-from-fork': ({ header, height }) => height == null ? null : (height < params.blake2bHeight || isHeaderV2(header)),
    'knots:rule-header-height': ({ header, height }) => !isHeaderV2(header) ? true : height == null ? null : header.height === height,
    'knots:rule-header-flags-reserved': ({ header }) => !isHeaderV2(header) || (header.flags & 0xc0) === 0,
  };
}

export function blockChecks(params, engine) {
  const headline = params.blake2bHeadline ? new TextEncoder().encode(params.blake2bHeadline) : new Uint8Array(0);
  return {
    block: {
      'knots:rule-block-txcount': ({ block }) => !isHeaderV2(block.header) || block.header.txCount === block.transactions.length,
      'knots:rule-block-headline': ({ block }) => {
        if (!isHeaderV2(block.header) || block.header.height !== params.blake2bHeight) return true;
        const cb = block.transactions[0];
        return !!cb && containsBytes(hexToBytes(cb.inputs[0].scriptSig), headline);
      },
    },
    blockContext: {
      'knots:rule-blockctx-weight-rdts': ({ block, height, mtp }) => {
        if (height == null || mtp == null) return null;
        return !rdtsActiveAt(params, height, mtp) || engine.blockWeight(block) <= REDUCED_DATA_MAX_BLOCK_WEIGHT;
      },
    },
  };
}

// createKernel overlay object; `graph` is supplied by the caller (the JSON-LD).
export const knotsBlake2b = (graph) => ({
  graph,
  install(codec) {
    registerKnotsBlake2b(codec);
    codec.registerDerived('knots:BlockHeaderV2', (h) => ({ time: headerTime(h) }));
  },
  installChecks({ headers, blocks, params }) {
    headers.registerChecks(headerChecks(params));
    blocks.registerChecks(blockChecks(params, blocks));
  },
});
