// Schema-driven header chain engine.
//
// Executes the `header` phase ruleset from schema/validate.jsonld against
// decoded BlockHeader objects, with network parameters from schema/chain.jsonld.
// Rule order, identity, and error codes come from the schema; this file holds
// only the pure check implementations the rule IDs bind to (Hornet-style:
// one invariant per rule, no side effects, typed errors).
//
// A check returns true (pass), false (fail -> the rule's errorCode), or
// null (insufficient context to evaluate; reported as skipped).

export class HeaderEngine {
  constructor(codec, params, ruleSet) {
    this.codec = codec;
    this.params = params;
    this.ruleSet = ruleSet;
    this.powLimit = BigInt('0x' + params.powLimit);
    this.interval = params.difficultyAdjustmentInterval;

    this.checks = {
      'btc:rule-header-prev-link': (ctx) =>
        ctx.prev == null ? null : ctx.header.prevBlockHash === this.codec.blockHash(ctx.prev),
      'btc:rule-header-pow': (ctx) =>
        this.codec.checkProofOfWork(ctx.header),
      'btc:rule-header-difficulty': (ctx) => {
        if (ctx.prev == null) return null;
        const expected = this.expectedBits(ctx.prev, ctx.height - 1, ctx.epochFirst,
          { header: ctx.header, chainAt: ctx.chainAt });
        return expected == null ? null : ctx.header.bits === expected;
      },
      'btc:rule-header-mtp': (ctx) => {
        // a window truncated by storage limits (e.g. just after a sync
        // checkpoint) yields a wrong median — skip rather than misjudge
        const need = Math.min(11, ctx.height ?? 11);
        if (!ctx.mtpWindow || ctx.mtpWindow.length < need) return null;
        return ctx.header.time > this.medianTimePast(ctx.mtpWindow);
      },
      'btc:rule-header-time-future': (ctx) =>
        ctx.now == null ? null : ctx.header.time <= ctx.now + this.params.maxFutureBlockTime,
      'btc:rule-header-timewarp': (ctx) => {
        if (!this.params.timewarpFix) return null;
        if (ctx.height == null || ctx.prev == null) return null;
        if (ctx.height % this.interval !== 0) return true; // only epoch-first blocks
        return ctx.header.time >= ctx.prev.time - this.params.maxTimewarp;
      },
      'btc:rule-header-version': (ctx) => {
        if (ctx.height == null) return null;
        const p = this.params;
        const min = ctx.height >= p.bip65Height ? 4
          : ctx.height >= p.bip66Height ? 3
          : ctx.height >= p.bip34Height ? 2 : 1;
        return ctx.header.version >= min;
      },
    };
  }

  static fromSchemas(codec, chainSchema, validateSchema, network = 'btc:mainnet') {
    const params = chainSchema['@graph'].find((n) => n['@id'] === network);
    if (!params) throw new Error(`unknown network: ${network}`);
    codec.setChainParams?.(params); // variants + PoW hash follow the chain
    const ruleSet = validateSchema['@graph'].find((n) => n['@type'] === 'RuleSet' && n.phase === 'header');
    return new HeaderEngine(codec, params, ruleSet);
  }

  // ---- consensus arithmetic ----

  // Expected work to find a block at this target: 2^256 / (target + 1).
  work(header) {
    return (1n << 256n) / (this.codec.expandCompact(header.bits) + 1n);
  }

  // Median of the last (up to) 11 block timestamps.
  medianTimePast(window) {
    const times = window.slice(-11).map((h) => h.time).sort((a, b) => a - b);
    return times[times.length >> 1];
  }

  // Compact-encode a 256-bit target (inverse of expandCompact), matching
  // Bitcoin Core's arith_uint256::GetCompact mantissa truncation.
  compactFromTarget(target) {
    let size = Math.ceil(target.toString(16).length / 2);
    let compact = size <= 3
      ? Number(target << (8n * BigInt(3 - size)))
      : Number(target >> (8n * BigInt(size - 3)));
    if (compact & 0x800000) { compact >>= 8; size++; }
    return (compact | (size << 24)) >>> 0;
  }

  // The bits required of the block following `prev` at height prevHeight.
  // Within an epoch: unchanged — except on min-difficulty networks, where a
  // 20-minute gap permits powLimit bits and otherwise the difficulty is that
  // of the last real-difficulty block (the walk-back needs opts.chainAt; if
  // unavailable, returns null to skip honestly). At a boundary: retargeted
  // from the previous epoch's timespan, based on the epoch-first block's
  // bits under BIP 94 (timewarpFix) and the last block's otherwise.
  expectedBits(prev, prevHeight, epochFirst, opts = {}) {
    if (this.params.powNoRetargeting) return prev.bits;
    const boundary = (prevHeight + 1) % this.interval === 0;
    if (!boundary && this.params.allowMinDifficultyBlocks) {
      const powBits = this.compactFromTarget(this.powLimit);
      if (opts.header && opts.header.time > prev.time + 2 * this.params.targetSpacing) {
        return powBits;
      }
      let h = prevHeight, hdr = prev;
      while (h % this.interval !== 0 && hdr.bits === powBits) {
        const back = opts.chainAt?.(h - 1);
        if (!back) return null; // walk-back context exhausted
        h--; hdr = back;
      }
      return hdr.bits;
    }
    if (!boundary) return prev.bits;
    if (epochFirst == null) return null;
    const base = this.params.timewarpFix ? epochFirst.bits : prev.bits;
    return this.retarget(epochFirst.time, prev.time, base);
  }

  retarget(firstTime, lastTime, baseBits) {
    const span = this.params.targetTimespan;
    const actual = Math.max(span / 4, Math.min(lastTime - firstTime, span * 4));
    let target = this.codec.expandCompact(baseBits) * BigInt(actual) / BigInt(span);
    if (target > this.powLimit) target = this.powLimit;
    return this.compactFromTarget(target);
  }

  // ---- ruleset execution ----

  // Overlay rules bind their checks here, keyed by rule @id.
  registerChecks(map) { Object.assign(this.checks, map); }

  validateHeader(ctx) {
    const results = this.ruleSet.rules.map((rule) => {
      const check = this.checks[rule['@id']];
      if (!check) throw new Error(`no check registered for ${rule['@id']}`);
      const gated = rule.activationParam && ctx.height != null && ctx.height < this.params[rule.activationParam];
      const outcome = gated ? null : check(ctx);
      return {
        rule: rule['@id'],
        label: rule.label,
        ok: outcome,
        error: outcome === false ? rule.errorCode : null,
      };
    });
    return { ok: results.every((r) => r.ok !== false), results };
  }

  // Validate consecutive headers starting at startHeight.
  //   prevContext: up to 11 decoded headers immediately preceding headers[0]
  //   epochFirsts: {height: header} for epoch-first headers needed at
  //                retarget boundaries that fall before the window
  //   now: unix time for the future-time rule (null to skip)
  validateChain(headers, { startHeight, prevContext = [], epochFirsts = {}, now = null, ...extra }) {
    const all = [...prevContext, ...headers];
    const firstIndex = prevContext.length;
    const heightOf = (i) => startHeight - prevContext.length + i;
    let chainWork = 0n;

    return headers.map((header, k) => {
      const i = firstIndex + k;
      const height = startHeight + k;
      const boundaryFirst = height % this.interval === 0 ? height - this.interval : null;
      const inWindow = boundaryFirst != null && boundaryFirst >= heightOf(0)
        ? all[boundaryFirst - heightOf(0)]
        : null;
      const chainAt = (h) => {
        const idx = h - heightOf(0);
        if (idx >= 0 && idx < i) return all[idx];
        return epochFirsts[h] ?? extra.chainAt?.(h) ?? null;
      };
      const ctx = {
        header,
        height,
        prev: i > 0 ? all[i - 1] : null,
        mtpWindow: all.slice(Math.max(0, i - 11), i),
        epochFirst: inWindow ?? epochFirsts[boundaryFirst]
          ?? (boundaryFirst != null ? extra.chainAt?.(boundaryFirst) : null) ?? null,
        chainAt,
        now,
      };
      const verdict = this.validateHeader(ctx);
      chainWork += this.work(header);
      return {
        height,
        hash: this.codec.blockHash(header),
        time: header.time,
        bits: header.bits,
        chainWork,
        ...verdict,
      };
    });
  }
}
