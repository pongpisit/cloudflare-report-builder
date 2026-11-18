/**
 * Rate limiting can be configured two ways, and a zone can use either or both:
 *   - the legacy zone rate_limits API, and
 *   - rules in the "http_ratelimit" phase of the Rulesets engine (the current way).
 * Counting only the legacy list reported "no rate limiting" for a zone with 43 active rules.
 */
export interface RateLimitSources {
  /** Legacy rate_limits entries. */
  legacy: { enabled: boolean }[];
  /** Custom rules from the zone's rulesets; rate limiting rules have phase "http_ratelimit". */
  rules: { phase?: string; enabled: boolean; action?: string }[];
}

export interface RateLimitCoverage {
  /** Enabled rules across both sources. */
  active: number;
  /** All rules across both sources, enabled or not. */
  total: number;
  legacyActive: number;
  rulesetActive: number;
  /** Enabled rules that block or challenge (log-only rules observe but do not stop traffic). */
  enforcing: number;
  logOnly: number;
}

const ENFORCING = new Set(["block", "challenge", "managed_challenge", "js_challenge", "legacy_challenge", "drop"]);

export function rateLimitCoverage(sources: RateLimitSources): RateLimitCoverage {
  const rulesetRules = sources.rules.filter(r => r.phase === "http_ratelimit");
  const legacyActive = sources.legacy.filter(r => r.enabled).length;
  const activeRules = rulesetRules.filter(r => r.enabled);
  return {
    active: legacyActive + activeRules.length,
    total: sources.legacy.length + rulesetRules.length,
    legacyActive,
    rulesetActive: activeRules.length,
    enforcing: activeRules.filter(r => ENFORCING.has(String(r.action))).length + legacyActive,
    logOnly: activeRules.filter(r => String(r.action) === "log").length,
  };
}
