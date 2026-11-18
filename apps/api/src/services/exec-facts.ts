/**
 * Fact packs for the scheduled-email executive summary.
 *
 * Every statement the AI may repeat is built here, in code, from the generated
 * report data. Customer-controlled names go through cleanText(). Nothing here
 * calls a model.
 *
 * The "changes" section is built ONLY when the caller passes a comparison
 * (schedule opted in). Without it the section does not exist at all.
 */

import type { AppSecData, ZeroTrustData } from "../types";
import type { MagicTransitData } from "../../../../shared/magic-transit";
import { cleanText, type Fact, type FactPack, type SectionFacts, type Severity } from "./exec-summary";

// ─── Formatting ───────────────────────────────────────────────────────────────

export function fmt(n: number): string {
  if (!Number.isFinite(n)) return "0";
  const a = Math.abs(n);
  if (a >= 1e9) return `${(n / 1e9).toFixed(1)}B`;
  if (a >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (a >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return String(Math.round(n));
}
export function fmtBytes(bytes: number): string {
  if (bytes >= 1e12) return `${(bytes / 1e12).toFixed(1)} TB`;
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(1)} KB`;
  return `${Math.round(bytes)} B`;
}
const pct = (part: number, total: number): number => total > 0 ? Math.round(part / total * 100) : 0;
const num = (v: unknown): number => typeof v === "number" && Number.isFinite(v) ? v : 0;
const arr = <T>(v: unknown): T[] => Array.isArray(v) ? v as T[] : [];
const plural = (n: number, one: string, many = `${one}s`): string => n === 1 ? one : many;

// ─── Comparison (opt-in) ──────────────────────────────────────────────────────

export interface Snapshot { metrics: Record<string, number>; risks: string[]; days: number; generatedAt: string }
export interface Comparison { previous: Snapshot | null }

/** Human labels for stable metric keys and risk codes (also used for risks that no longer apply). */
const METRIC_LABELS: Record<string, string> = {
  aiCrawlerRequests: "AI crawler requests", wafAttackRated: "Requests rated attack or likely attack by the WAF score",
  totalRequests: "Total requests", threatsBlocked: "Threats blocked", ddosMitigated: "DDoS-mitigated requests",
  botTrafficPct: "Automated traffic share (%)", cacheHitRatePct: "Cache hit rate (%)", accountTakeover: "Account-takeover signals",
  dnsProxiedPct: "Proxied DNS records (%)", expiringCerts: "Certificates expiring within 30 days", zombieApis: "Zombie API endpoints",
  riskyApis: "API endpoints with BOLA risk", highRecommendations: "High-priority recommendations",
  authEvents: "Access login events", blockedAuth: "Blocked Access login events", gatewayDnsBlocked: "Gateway DNS queries blocked",
  gatewayHttpBlocked: "Gateway HTTP requests blocked", warpOfflinePct: "WARP devices offline (%)", unhealthyTunnels: "Unhealthy tunnels",
  casbFindings: "CASB findings", shadowIt: "Shadow IT applications discovered", seatsNeverLoggedIn: "Seats that never logged in",
  trafficBytes: "Ingress traffic (bytes)", droppedBytes: "Dropped traffic (bytes)", attackEvents: "Attack events",
  probeSuccessPct: "Tunnel probe success (%)", tunnels: "Configured tunnels",
};
const RISK_LABELS: Record<string, string> = {
  ato: "Account-takeover signals were detected", bola: "API endpoints flagged for BOLA risk", noauth: "API endpoints with missing or inconsistent authentication",
  certs: "Certificates expiring within 30 days", ratelimit: "No rate limiting rules are configured", dmarc: "DMARC policy does not enforce", spf: "SPF uses softfail",
  leaked: "Leaked Credential Check is not enabled", scripts: "Page Shield flagged suspicious scripts", zombie: "Zombie API endpoints are present",
  dnsproxy: "Fewer than 60% of DNS records are proxied", tls13: "TLS 1.3 is not enabled", https: "Always HTTPS is not enforced", upload: "Malicious upload scanning is not enabled",
  bots: "Automated traffic is above 30% of requests", casb: "Critical or high CASB findings exist", tunnels: "Tunnels are degraded, down or inactive",
  offline: "Many enrolled WARP devices are offline", neverlogged: "Licensed seats have never logged in", dlp: "DLP matches were recorded",
  mttunnels: "Tunnel health or routing problems were observed", mtprobe: "Tunnel probe success is below 99%", mtunavailable: "Some report sections were unavailable",
  mtattack: "An attack event is still ongoing", mtprefix: "A prefix is not currently advertised",
};

export function snapshotFromFacts(metrics: Record<string, number>, risks: string[], days: number, generatedAt: string): Snapshot {
  return { metrics, risks: [...new Set(risks)].sort(), days, generatedAt };
}

function changeFacts(current: Snapshot, comparison: Comparison): Fact[] {
  const prev = comparison.previous;
  if (!prev) return [{ id: "ch-first", text: "This is the first report with comparison enabled, so there is no earlier report to compare against." }];
  const date = prev.generatedAt.slice(0, 10);
  if (prev.days !== current.days) {
    return [{ id: "ch-days", text: `The previous report (sent on ${date}) covered ${prev.days} ${plural(prev.days, "day")} and this one covers ${current.days} ${plural(current.days, "day")}, so their figures are not compared.` }];
  }
  const facts: Fact[] = [];
  for (const [key, now] of Object.entries(current.metrics)) {
    const before = prev.metrics[key];
    if (typeof before !== "number" || before === now) continue;
    const label = METRIC_LABELS[key] ?? key;
    const change = before === 0 ? null : Math.round((now - before) / Math.abs(before) * 1000) / 10;
    if (change !== null && Math.abs(change) < 10) continue;
    const isBytes = key.endsWith("Bytes");
    const f = (n: number) => isBytes ? fmtBytes(n) : fmt(n);
    facts.push({
      id: `ch-${key}`, severity: "info",
      text: change === null
        ? `${label} went from ${f(before)} in the previous report to ${f(now)}.`
        : `${label} ${now > before ? "rose" : "fell"} by ${Math.abs(change)}% from ${f(before)} to ${f(now)}.`,
    });
  }
  const prevRisks = new Set(prev.risks), nowRisks = new Set(current.risks);
  for (const code of nowRisks) if (!prevRisks.has(code)) facts.push({ id: `ch-new-${code}`, severity: "high", text: `New since the previous report: ${RISK_LABELS[code] ?? code}.` });
  for (const code of prevRisks) if (!nowRisks.has(code)) facts.push({ id: `ch-gone-${code}`, severity: "info", text: `No longer present since the previous report: ${RISK_LABELS[code] ?? code}.` });
  if (!facts.length) facts.push({ id: "ch-none", text: `Compared with the previous report sent on ${date}, no tracked figure moved by 10% or more and no risk appeared or cleared.` });
  else facts.unshift({ id: "ch-ref", text: `Compared with the previous report sent on ${date} (same ${current.days}-day length).` });
  return facts;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function section(id: SectionFacts["id"], title: string, facts: Fact[], empty: string): SectionFacts {
  return { id, title, facts, empty };
}

const TITLES = {
  posture: "Overall protected attack surface and security posture",
  risks: "High-priority exposures, threats and material risks",
  changes: "Changes since the previous report",
  trends: "Key attack trends and notable security events",
  actions: "Recommended actions requiring your attention",
} as const;

interface Risk { code: string; severity: Severity; text: string }

function riskFacts(risks: Risk[], unavailable: number, scope: string): Fact[] {
  const facts: Fact[] = risks.map(r => ({ id: `risk-${r.code}`, severity: r.severity, text: r.text }));
  if (unavailable > 0) facts.push({ id: "risk-unavailable", severity: "info", text: `${unavailable} report ${plural(unavailable, "section")} could not be retrieved, so ${scope} in ${unavailable === 1 ? "it" : "them"} could not be assessed.` });
  if (!risks.length) facts.unshift({ id: "risk-none", severity: "info", text: `No high-priority exposure was identified by the checks this report performs${unavailable ? ", although some sections were unavailable" : ""}.` });
  return facts;
}

function recommendationFacts(recs: { priority: string; title: string; benefit?: string }[]): Fact[] {
  const order = { high: 0, medium: 1, low: 2 } as Record<string, number>;
  return [...recs].sort((a, b) => (order[a.priority] ?? 3) - (order[b.priority] ?? 3)).slice(0, 6).map((r, i) => ({
    id: `act-${i}`,
    severity: (r.priority === "high" ? "high" : r.priority === "medium" ? "medium" : "low") as Severity,
    text: `${r.priority === "high" ? "High priority" : r.priority === "medium" ? "Medium priority" : "Low priority"}: ${cleanText(r.title, 150)}${r.benefit ? `. ${cleanText(r.benefit, 170)}` : ""}`,
  }));
}

function finish(product: FactPack["product"], subject: string, period: string, parts: Record<"posture" | "risks" | "trends" | "actions", SectionFacts>, metrics: Record<string, number>, riskCodes: string[], days: number, generatedAt: string, comparison: Comparison | undefined): { pack: FactPack; snapshot: Snapshot } {
  // Recommendation-derived risks carry free text, so only fixed codes are stored for comparison.
  const snapshot = snapshotFromFacts(metrics, riskCodes.filter(c => !c.startsWith("rec-") && c in RISK_LABELS), days, generatedAt);
  const sections = [parts.posture, parts.risks];
  if (comparison) sections.push(section("changes", TITLES.changes, changeFacts(snapshot, comparison), "No comparison with a previous report is available."));
  sections.push(parts.trends, parts.actions);
  return { pack: { product, subject: cleanText(subject, 120), period: cleanText(period, 120), sections }, snapshot };
}


// ─── Threat insight (bots, AI, WAF score, rules, sources) ─────────────────────

const OUTCOME_ACTIONS = new Set(["block", "challenge", "managed_challenge", "js_challenge", "legacy_challenge", "interactive_challenge", "challenge_solved"]);
const pctOf = (part: number, total: number): string => total > 0 ? `${Math.round(part / total * 1000) / 10}%` : "0%";
const clean = (v: unknown, n = 60): string => cleanText(v, n);

/** Extra, precisely worded threat context. Every sentence states what the metric does and does not mean. */
function threatInsight(ap: Record<string, unknown>, totalReqs: number): Fact[] {
  const facts: Fact[] = [];

  // Bots: the score bands are Cloudflare's own (1 automated, 2-29 likely automated, 30-99 likely human).
  const bands = arr<{ scoreRange: string; requests: number }>(ap.botScoreBreakdown);
  const s = ap.summary as { automatedPct?: number; likelyAutomatedPct?: number; humanPct?: number } | undefined;
  const automated = bands.find(b => /Score 1\)/.test(b.scoreRange)), likely = bands.find(b => /Score 2/.test(b.scoreRange)), human = bands.find(b => /Score 30/.test(b.scoreRange));
  if (automated && likely && human) {
    facts.push({ id: "in-bots", tag: "Bots", severity: num(s?.automatedPct) + num(s?.likelyAutomatedPct) > 30 ? "medium" : "info",
      text: `By bot score, ${fmt(num(automated.requests))} requests (${Math.round(num(s?.automatedPct))}%) were definitely automated, ${fmt(num(likely.requests))} (${Math.round(num(s?.likelyAutomatedPct))}%) were likely automated and ${fmt(num(human.requests))} (${Math.round(num(s?.humanPct))}%) were likely human.` });
  }
  const verified = arr<{ category: string; count: number }>(ap.verifiedBotCategories).slice(0, 4);
  const verifiedTotal = arr<{ count: number }>(ap.verifiedBotCategories).reduce((t, v) => t + num(v.count), 0);
  if (verified.length) facts.push({ id: "in-verified", tag: "Bots", severity: "info",
    text: `Verified bots made ${fmt(verifiedTotal)} requests; the largest categories were ${verified.map(v => `${clean(v.category, 40)} (${fmt(num(v.count))})`).join(", ")}. Verified bots are known, identified crawlers and are not attacks by themselves.` });

  // AI crawlers: allowed vs blocked, using the AI Crawl Control split of response status.
  const ai = ap.aiCrawlerSummary as { totalRequests: number; pctOfTotal: number; uniqueBots: number; topBot: string | null; allowedRequests: number; blockedRequests: number; paymentRequiredRequests: number; otherErrorRequests: number; categoryBreakdown?: { category: string; requests: number }[] } | undefined;
  if (ai && ai.totalRequests > 0) {
    const cats = (ai.categoryBreakdown ?? []).slice(0, 3).map(c => `${clean(c.category, 30)} (${fmt(num(c.requests))})`).join(", ");
    facts.push({ id: "in-ai", tag: "AI crawlers", severity: ai.pctOfTotal > 5 && ai.blockedRequests < ai.allowedRequests ? "medium" : "info",
      text: `${ai.uniqueBots} generative AI crawlers made ${fmt(ai.totalRequests)} requests (${ai.pctOfTotal}% of traffic)${ai.topBot ? `, led by ${clean(ai.topBot, 40)}` : ""}${cats ? `; by type: ${cats}` : ""}. Of these, ${fmt(ai.allowedRequests)} received a successful response, ${fmt(ai.blockedRequests)} were blocked with a 403${ai.paymentRequiredRequests ? `, ${fmt(ai.paymentRequiredRequests)} were asked to pay with a 402` : ""} and ${fmt(ai.otherErrorRequests)} ended in another error.` });
  }

  // WAF attack score: ML classification of ALL traffic, separate from rule-based events.
  const score = arr<{ scoreClass: string; count: number }>(ap.wafScoreAllTraffic);
  const byClass = (c: string) => score.filter(r => r.scoreClass === c).reduce((t, r) => t + num(r.count), 0);
  const attack = byClass("attack"), likelyAttack = byClass("likely_attack"), scoredTotal = score.filter(r => r.scoreClass !== "not_scored").reduce((t, r) => t + num(r.count), 0);
  if (scoredTotal > 0) facts.push({ id: "in-wafscore", tag: "WAF score", severity: attack > 0 ? "medium" : "info",
    text: `The WAF attack score rated ${fmt(attack)} requests as attacks and ${fmt(likelyAttack)} as likely attacks out of ${fmt(scoredTotal)} scored requests (${pctOf(attack + likelyAttack, scoredTotal)}). This is a machine-learning rating of all traffic, separate from the rule-based security events.` });
  const events = arr<{ scoreClass: string; action: string; count: number }>(ap.wafAttackScoreBreakdown);
  const evAttack = events.filter(r => r.scoreClass === "attack" || r.scoreClass === "likely_attack");
  const evTotal = evAttack.reduce((t, r) => t + num(r.count), 0);
  const evBlocked = evAttack.filter(r => r.action === "block").reduce((t, r) => t + num(r.count), 0);
  if (evTotal > 0) facts.push({ id: "in-wafscore-actions", tag: "WAF score", severity: "info",
    text: `Of ${fmt(evTotal)} security events on attack or likely-attack requests, ${fmt(evBlocked)} (${pctOf(evBlocked, evTotal)}) were blocked; the rest were logged, skipped or handled by other actions.` });
  const vec = ap.wafPerVectorScore as { scoredCount: number; avgSqliScore: number | null; avgXssScore: number | null; avgRceScore: number | null; avgPathTraversalScore: number | null } | undefined;
  if (vec && vec.scoredCount > 0) {
    const parts = [["SQL injection", vec.avgSqliScore], ["cross-site scripting", vec.avgXssScore], ["remote code execution", vec.avgRceScore], ["path traversal", vec.avgPathTraversalScore]]
      .filter((p): p is [string, number] => typeof p[1] === "number").map(([k, v]) => `${k} ${v}`);
    if (parts.length) facts.push({ id: "in-wafvector", tag: "WAF score", severity: "info",
      text: `Average per-attack-type scores across the ${fmt(vec.scoredCount)} requests that were not rated clean: ${parts.join(", ")}. A lower score means the request looks more like that attack, and 99 means it looks clean.` });
  }

  // Rules: what the zone's own rules did.
  const rules = arr<{ description: string; totalHits: number; blocks: number; challenges: number; blockRate: number }>(ap.wafRuleEffectiveness).slice(0, 3);
  if (rules.length) facts.push({ id: "in-rules", tag: "WAF rules", severity: "info",
    text: `The most active rules were ${rules.map(r => `"${clean(r.description, 70)}" (${fmt(num(r.totalHits))} hits, ${Math.round(num(r.blockRate))}% blocked)`).join("; ")}.` });

  // Sources: where the unwanted traffic came from.
  const asns = arr<{ asnName: string; count: number }>(ap.topThreatAsns).slice(0, 3);
  if (asns.length) facts.push({ id: "in-asns", tag: "Sources", severity: "info",
    text: `The networks behind the most blocked or challenged requests were ${asns.map(a => `${clean(a.asnName, 40)} (${fmt(num(a.count))})`).join(", ")}. A network appearing here does not mean the whole network is malicious.` });

  // Outcome mix: how the edge dealt with the unwanted traffic.
  const svc = arr<{ action: string; count: number }>(ap.securityEventsByService);
  const outcomeTotal = svc.reduce((t, e) => t + num(e.count), 0);
  const act = (name: string) => svc.filter(e => e.action === name).reduce((t, e) => t + num(e.count), 0);
  const blocked = act("block"), challenged = act("managed_challenge") + act("challenge") + act("js_challenge");
  if (outcomeTotal > 0 && blocked + challenged > 0) facts.push({ id: "in-outcomes", tag: "Edge actions", severity: "info",
    text: `Of ${fmt(outcomeTotal)} security events, ${fmt(blocked)} were blocks and ${fmt(challenged)} were challenges; the remainder were logged, skipped or other actions.` });

  // Origin health seen from the edge.
  const st = ap.httpStatusSummary as { e4xx: number; e5xx: number; total: number } | undefined;
  if (st && st.total > 0) facts.push({ id: "in-status", tag: "Responses", severity: num(st.e5xx) / st.total > 0.02 ? "medium" : "info",
    text: `Of ${fmt(st.total)} responses, ${fmt(num(st.e4xx))} (${pctOf(num(st.e4xx), st.total)}) were client errors and ${fmt(num(st.e5xx))} (${pctOf(num(st.e5xx), st.total)}) were server errors.` });

  void totalReqs; void OUTCOME_ACTIONS;
  return facts;
}

// ─── AppSec ───────────────────────────────────────────────────────────────────

export function appsecFactPack(a: AppSecData, comparison?: Comparison): { pack: FactPack; snapshot: Snapshot } {
  const ap = a as AppSecData & Record<string, unknown>;
  const s = a.summary;
  const meta = a.meta;
  const totalReqs = num(s.totalRequests);
  const certs = arr<{ daysUntilExpiry: number }>(ap.certificates);
  const expiring = certs.filter(c => c.daysUntilExpiry >= 0 && c.daysUntilExpiry < 30).length;
  const dns = ap.dnsRecordSummary as { totalRecords: number; proxiedCount: number } | undefined;
  const dnsProxiedPct = dns ? pct(dns.proxiedCount, dns.totalRecords) : 100;
  const email = ap.emailSecurity as { grade?: string; dmarcPolicy?: string; spfPolicy?: string } | null | undefined;
  const takeover = num((ap.accountTakeover as { totalRequests?: number } | undefined)?.totalRequests);
  const leaked = (ap.leakedCredentialCheck as { enabled?: boolean } | undefined)?.enabled === true;
  const aiSec = (ap.aiSecurityForApps as { enabled?: boolean } | undefined)?.enabled === true;
  const scanning = (ap.contentScanning as { enabled?: boolean } | undefined)?.enabled === true;
  const tls13 = ap.tls13Enabled as boolean | undefined, alwaysHttps = ap.alwaysHttps as boolean | undefined;
  const risky = arr<{ labels: string[] }>(ap.apiRiskyEndpoints).filter(e => e.labels.some(l => l.startsWith("cf-risk-bola"))).length;
  const riskLabels = arr<{ label: string; operationCount: number }>(ap.apiRiskLabels);
  const noAuth = num(riskLabels.find(r => r.label === "cf-risk-missing-auth")?.operationCount) + num(riskLabels.find(r => r.label === "cf-risk-mixed-auth")?.operationCount);
  const zombies = num(ap.apiZombieEndpointsTotalCount) || arr(ap.apiZombieEndpoints).length;
  const flagged = arr<{ js_integrity_score?: number; malware_score?: number }>(ap.pageShieldScripts).filter(x => (x.js_integrity_score ?? 100) < 30 || (x.malware_score ?? 100) < 30).length;
  const rateRules = arr(ap.rateLimitRules).length, wafRulesets = arr(ap.wafManagedRules).length;
  const botPct = num(s.botTrafficPct);
  const recs = arr<{ priority: "high" | "medium" | "low"; title: string; benefit: string }>(ap.recommendations);
  const unavailable = Object.keys((ap.errors as Record<string, string> | undefined) ?? {}).length;
  const ddos = arr<{ mitigated: number }>(ap.ddosTimeSeries).reduce((t, d) => t + num(d.mitigated), 0);

  const posture: Fact[] = [
    { id: "p-traffic", text: `${cleanText(meta.zoneName)} handled ${fmt(totalReqs)} requests and ${fmtBytes(num(s.totalBandwidthBytes))} of traffic through Cloudflare during the period, from ${fmt(num(s.uniqueVisitors))} unique visitors.` },
    { id: "p-blocked", text: `Cloudflare blocked or mitigated ${fmt(num(s.totalThreatsBlocked))} threats, which is ${pct(num(s.totalThreatsBlocked), totalReqs)}% of requests.` },
    { id: "p-rules", text: `${wafRulesets} WAF ${plural(wafRulesets, "ruleset")} and ${rateRules} rate limiting ${plural(rateRules, "rule")} are configured.` },
  ];
  if (dns && dns.totalRecords > 0) posture.push({ id: "p-dns", text: `${dns.proxiedCount} of ${dns.totalRecords} DNS records are proxied through Cloudflare (${dnsProxiedPct}%).` });
  if (certs.length) posture.push({ id: "p-certs", text: `${certs.length} ${plural(certs.length, "certificate")} ${plural(certs.length, "is", "are")} managed and ${expiring} expire within 30 days.` });
  if (tls13 !== undefined || alwaysHttps !== undefined) posture.push({ id: "p-tls", text: `TLS 1.3 is ${tls13 ? "enabled" : "not enabled"} and Always HTTPS is ${alwaysHttps ? "enforced" : "not enforced"}.` });
  posture.push({ id: "p-features", text: `Leaked Credential Check is ${leaked ? "enabled" : "not enabled"}, AI Security for Apps is ${aiSec ? "enabled" : "not enabled"}, and malicious upload scanning is ${scanning ? "enabled" : "not enabled"}.` });
  posture.push({ id: "p-cache", text: `The cache hit rate was ${Math.round(num(s.cacheHitRatePct))}%.` });
  if (email?.grade) posture.push({ id: "p-email", text: `The email security grade for the domain is ${cleanText(email.grade, 3)}.` });

  const risks: Risk[] = [];
  if (takeover > 0) risks.push({ code: "ato", severity: "critical", text: `${fmt(takeover)} account-takeover signals were detected on login endpoints.` });
  if (risky > 0) risks.push({ code: "bola", severity: "critical", text: `${risky} API ${plural(risky, "endpoint")} ${plural(risky, "is", "are")} flagged for Broken Object Level Authorization risk.` });
  if (noAuth > 0) risks.push({ code: "noauth", severity: "high", text: `${noAuth} API ${plural(noAuth, "endpoint")} ${plural(noAuth, "has", "have")} missing or inconsistent authentication on successful requests.` });
  if (expiring > 0) risks.push({ code: "certs", severity: "high", text: `${expiring} ${plural(expiring, "certificate")} will expire within 30 days.` });
  if (flagged > 0) risks.push({ code: "scripts", severity: "high", text: `Page Shield flagged ${flagged} suspicious ${plural(flagged, "script")}.` });
  if (rateRules === 0) risks.push({ code: "ratelimit", severity: "medium", text: "No rate limiting rules are configured, so login and API endpoints have no request-rate protection." });
  if (email && (email.dmarcPolicy === "none" || email.dmarcPolicy === "")) risks.push({ code: "dmarc", severity: "medium", text: "The DMARC policy is set to none, which does not stop email spoofing of the domain." });
  if (!leaked) risks.push({ code: "leaked", severity: "medium", text: "Leaked Credential Check is not enabled, so logins using breached passwords are not flagged." });
  if (zombies > 0) risks.push({ code: "zombie", severity: "medium", text: `${zombies} zombie API ${plural(zombies, "endpoint")} with no recent traffic ${plural(zombies, "remains", "remain")} exposed.` });
  if (dns && dns.totalRecords > 0 && dnsProxiedPct < 60) risks.push({ code: "dnsproxy", severity: "medium", text: `Only ${dnsProxiedPct}% of DNS records are proxied, which leaves the rest exposed directly.` });
  if (tls13 === false) risks.push({ code: "tls13", severity: "low", text: "TLS 1.3 is not enabled." });
  if (alwaysHttps === false) risks.push({ code: "https", severity: "medium", text: "Always HTTPS is not enforced, so plain HTTP connections are possible." });
  if (!scanning) risks.push({ code: "upload", severity: "low", text: "Malicious upload scanning is not enabled for file uploads." });
  if (botPct > 30) risks.push({ code: "bots", severity: "medium", text: `${Math.round(botPct)}% of requests came from automated clients.` });

  const topRule = a.wafTopRules?.[0];
  const classes = arr<{ category: string; count: number }>(ap.wafAttackClassification).slice(0, 3);
  const vectors = arr<{ vector: string; count: number }>(ap.ddosAttackVectors);
  const bySource = new Map<string, number>();
  for (const e of arr<{ source: string; count: number }>(ap.securityEventsByService)) if (e.source && !["dlp", "sanitycheck", "unknown"].includes(e.source)) bySource.set(e.source, (bySource.get(e.source) ?? 0) + num(e.count));
  const services = [...bySource.entries()].sort((x, y) => y[1] - x[1]).slice(0, 3);
  const countries = arr<{ countryName: string; count: number }>(ap.wafTopCountries).slice(0, 3);
  const days = arr<{ date: string; block: number; challenge: number; managed_challenge: number }>(ap.wafTimeSeries).map(d => ({ date: d.date, n: num(d.block) + num(d.challenge) + num(d.managed_challenge) }));
  const peak = days.reduce<{ date: string; n: number } | null>((best, d) => !best || d.n > best.n ? d : best, null);
  const scored = arr<{ scoreClass: string; count: number }>(ap.wafScoreAllTraffic).filter(r => r.scoreClass === "attack").reduce((t, r) => t + num(r.count), 0);
  const crawler = ap.aiCrawlerSummary as { totalRequests: number; pctOfTotal: number; topBot: string | null } | undefined;

  const trends: Fact[] = [];
  if (topRule) trends.push({ id: "t-rule", tag: "WAF rules", text: `The most active WAF rule was "${cleanText(topRule.ruleName ?? topRule.description ?? topRule.ruleId)}" with ${fmt(num(topRule.count))} events, action ${cleanText(topRule.action, 24)}.` });
  if (classes.length) trends.push({ id: "t-classes", tag: "Attack types", text: `Top attack categories: ${classes.map(c => `${cleanText(c.category, 40)} (${fmt(num(c.count))})`).join(", ")}.` });
  if (ddos > 0) trends.push({ id: "t-ddos", tag: "DDoS", text: `${fmt(ddos)} layer 7 DDoS requests were mitigated${vectors[0] ? `, led by ${cleanText(vectors[0].vector, 50)} (${fmt(num(vectors[0].count))})` : ""}.` });
  if (services.length) trends.push({ id: "t-services", tag: "Security events", text: `Security events by service: ${services.map(([k, v]) => `${cleanText(k, 40)} (${fmt(v)})`).join(", ")}.` });
  if (countries.length) trends.push({ id: "t-countries", tag: "Countries", text: `Most blocked traffic originated from ${countries.map(c => `${cleanText(c.countryName, 40)} (${fmt(num(c.count))})`).join(", ")}.` });
  if (peak && peak.n > 0 && days.length > 1) trends.push({ id: "t-peak", tag: "Peak day", text: `The busiest day for blocked or challenged requests was ${peak.date} with ${fmt(peak.n)} events.` });
  // The AI-crawler and ML-score headlines now live in the insight facts below, with full context.
  void crawler; void scored;
  // Bot, AI crawler and WAF score insight leads, then the general attack facts.
  trends.unshift(...threatInsight(ap, totalReqs));

  const metrics = { totalRequests: totalReqs, threatsBlocked: num(s.totalThreatsBlocked), ddosMitigated: ddos, botTrafficPct: Math.round(botPct), cacheHitRatePct: Math.round(num(s.cacheHitRatePct)), accountTakeover: takeover, aiCrawlerRequests: num(crawler?.totalRequests), wafAttackRated: arr<{ scoreClass: string; count: number }>(ap.wafScoreAllTraffic).filter(r => r.scoreClass === "attack" || r.scoreClass === "likely_attack").reduce((t, r) => t + num(r.count), 0), dnsProxiedPct, expiringCerts: expiring, zombieApis: zombies, riskyApis: risky, highRecommendations: recs.filter(r => r.priority === "high").length };
  return finish("appsec", meta.zoneName, `${meta.periodLabel} (${meta.since} to ${meta.until})`, {
    posture: section("posture", TITLES.posture, posture, "No posture data was available."),
    risks: section("risks", TITLES.risks, riskFacts(risks, unavailable, "risks"), "No risk data was available."),
    trends: section("trends", TITLES.trends, trends, "No attack activity or notable security events were recorded in the data retrieved for this period."),
    actions: section("actions", TITLES.actions, recs.length ? recommendationFacts(recs) : [], "No recommended actions were generated for this period."),
  }, metrics, risks.map(r => r.code), num(meta.days), meta.generatedAt, comparison);
}

// ─── Zero Trust ───────────────────────────────────────────────────────────────

export function zeroTrustFactPack(z: ZeroTrustData, comparison?: Comparison): { pack: FactPack; snapshot: Snapshot } {
  const s = z.summary, meta = z.meta;
  const unhealthy = arr<{ status: string }>(z.tunnels).filter(t => t.status !== "healthy").length;
  const offlinePct = pct(num(s.warpOfflineDevices), num(s.warpEnrolledDevices));
  const critHigh = arr<{ severity: string }>(z.casbFindingsDetail).filter(f => ["critical", "high"].includes(String(f.severity).toLowerCase())).length;
  const dlpHits = num(z.dlpActivitySummary?.hitCount);
  const recs = arr<{ priority: "high" | "medium" | "low"; title: string; benefit: string }>(z.recommendations);
  const unavailable = Object.keys((z as unknown as { errors?: Record<string, string> }).errors ?? {}).length;
  const mfa = arr<{ requireMfa: boolean }>(z.accessPolicies);
  const dnsBlockedPct = pct(num(s.gatewayDnsBlocked), num(s.gatewayDnsQueries));
  const httpBlockedPct = pct(num(s.gatewayHttpBlocked), num(s.gatewayHttpRequests));

  const posture: Fact[] = [
    { id: "p-access", text: `${cleanText(meta.accountName)} protects ${arr(z.accessApps).length} Access ${plural(arr(z.accessApps).length, "application")} with ${mfa.length} ${plural(mfa.length, "policy", "policies")}, of which ${mfa.filter(p => p.requireMfa).length} require MFA.` },
    { id: "p-auth", text: `${fmt(num(s.totalAuthEvents))} Access login events were recorded with a ${Math.round(num(s.authSuccessRate))}% success rate.` },
    { id: "p-gateway", text: `Gateway evaluated ${fmt(num(s.gatewayDnsQueries))} DNS queries and ${fmt(num(s.gatewayHttpRequests))} HTTP requests, with ${arr(z.gatewayPolicies).length} filtering ${plural(arr(z.gatewayPolicies).length, "policy", "policies")}.` },
    { id: "p-warp", text: `${num(s.warpEnrolledDevices)} WARP devices are enrolled and ${num(s.warpOnlineDevices)} were online at their latest status.` },
    { id: "p-tunnels", text: `${num(s.tunnelsHealthy)} of ${num(s.tunnelsTotal)} tunnels are healthy.` },
    { id: "p-seats", text: `${num(s.seatsActiveInPeriod)} of ${num(s.seatsTotal)} licensed seats were active in the period.` },
  ];

  const risks: Risk[] = [];
  if (critHigh > 0) risks.push({ code: "casb", severity: "high", text: `${critHigh} CASB ${plural(critHigh, "finding")} ${plural(critHigh, "is", "are")} rated critical or high.` });
  if (unhealthy > 0) risks.push({ code: "tunnels", severity: "high", text: `${unhealthy} of ${arr(z.tunnels).length} tunnels are degraded, down or inactive.` });
  if (num(s.warpEnrolledDevices) >= 5 && offlinePct >= 40) risks.push({ code: "offline", severity: "medium", text: `${offlinePct}% of enrolled WARP devices were offline at their latest status.` });
  if (num(s.seatsNeverLoggedIn) > 0) risks.push({ code: "neverlogged", severity: "low", text: `${num(s.seatsNeverLoggedIn)} licensed ${plural(num(s.seatsNeverLoggedIn), "seat has", "seats have")} never logged in.` });
  if (dlpHits > 0) risks.push({ code: "dlp", severity: "medium", text: `DLP recorded ${fmt(dlpHits)} matches on sensitive data.` });
  for (const r of recs.filter(r => r.priority === "high").slice(0, 3)) risks.push({ code: `rec-${cleanText(r.title, 40).toLowerCase().replace(/[^a-z0-9]+/g, "-")}`, severity: "high", text: cleanText(r.title, 150) + "." });

  const cats = arr<{ category: string; count: number }>(z.gatewayDnsTopBlockedCategories).slice(0, 3);
  const apps = arr<{ name: string; count: number }>(z.shadowItApps).slice(0, 3);
  const trends: Fact[] = [];
  if (num(s.gatewayDnsBlocked) > 0) trends.push({ id: "t-dns", text: `Gateway blocked ${fmt(num(s.gatewayDnsBlocked))} DNS queries (${dnsBlockedPct}% of queries)${cats.length ? `, mostly ${cats.map(c => `${cleanText(c.category, 40)} (${fmt(num(c.count))})`).join(", ")}` : ""}.` });
  if (num(s.gatewayHttpBlocked) > 0) trends.push({ id: "t-http", text: `Gateway blocked ${fmt(num(s.gatewayHttpBlocked))} HTTP requests (${httpBlockedPct}% of requests).` });
  if (num(s.blockedAuthEvents) > 0) trends.push({ id: "t-auth", text: `${fmt(num(s.blockedAuthEvents))} Access login attempts were blocked.` });
  if (num(s.shadowItAppsDiscovered) > 0) trends.push({ id: "t-shadow", text: `${num(s.shadowItAppsDiscovered)} shadow IT applications were discovered${apps.length ? `, led by ${apps.map(a => `${cleanText(a.name, 40)} (${fmt(num(a.count))})`).join(", ")}` : ""}.` });
  if (dlpHits > 0) trends.push({ id: "t-dlp", text: `DLP matched ${fmt(dlpHits)} items across ${fmt(num(z.dlpActivitySummary?.scanCount))} scanned requests or files.` });
  const blockedUsers = arr<{ count: number }>(z.accessTopBlockedUsers);
  if (blockedUsers.length) trends.push({ id: "in-blockedusers", tag: "Access", severity: "info", text: `${blockedUsers.length} users had blocked Access attempts, together ${fmt(blockedUsers.reduce((t, u) => t + num(u.count), 0))} attempts.` });
  const gen = z.aiAppUsage;
  if (gen && gen.totalRequests > 0) {
    const top = gen.apps.slice(0, 3).map(a => `${cleanText(a.name, 40)} (${fmt(num(a.count))})`).join(", ");
    trends.push({ id: "in-genai", tag: "Generative AI", severity: gen.hasGovernancePolicy ? "info" : "medium",
      text: `${gen.uniqueUsers} users made ${fmt(gen.totalRequests)} requests to ${gen.uniqueApps} generative AI applications${top ? `, led by ${top}` : ""}. ${gen.hasGovernancePolicy ? "A Gateway policy governs this use." : "No Gateway policy governs this use."}` });
  }
  const catHigh = arr<{ severity: string; count: number }>(z.casbFindingsBySeverity).filter(c => ["critical", "high"].includes(String(c.severity).toLowerCase())).reduce((t, c) => t + num(c.count), 0);
  if (catHigh > 0) trends.push({ id: "in-casb", tag: "CASB", severity: "medium", text: `${catHigh} SaaS posture findings were rated critical or high.` });
  const changes = arr(z.configChanges).length;
  if (changes > 0) trends.push({ id: "t-config", text: `${changes} Zero Trust configuration ${plural(changes, "change was", "changes were")} recorded in the audit log.` });

  const metrics = { authEvents: num(s.totalAuthEvents), blockedAuth: num(s.blockedAuthEvents), gatewayDnsBlocked: num(s.gatewayDnsBlocked), gatewayHttpBlocked: num(s.gatewayHttpBlocked), warpOfflinePct: offlinePct, unhealthyTunnels: unhealthy, casbFindings: num(s.casbFindingsCount), shadowIt: num(s.shadowItAppsDiscovered), seatsNeverLoggedIn: num(s.seatsNeverLoggedIn), highRecommendations: recs.filter(r => r.priority === "high").length };
  return finish("zero-trust", meta.accountName, `${meta.periodLabel} (${meta.since} to ${meta.until})`, {
    posture: section("posture", TITLES.posture, posture, "No posture data was available."),
    risks: section("risks", TITLES.risks, riskFacts(risks, unavailable, "risks"), "No risk data was available."),
    trends: section("trends", TITLES.trends, trends, "No notable security events were recorded in the data retrieved for this period."),
    actions: section("actions", TITLES.actions, recs.length ? recommendationFacts(recs) : [], "No recommended actions were generated for this period."),
  }, metrics, risks.map(r => r.code), num(meta.days), meta.generatedAt, comparison);
}

// ─── Magic Transit ────────────────────────────────────────────────────────────

const MT_ACTIONS: Record<string, string> = {
  mtattack: "Review the ongoing attack event with your network team and confirm mitigation is holding.",
  mtprobe: "Investigate tunnel health probe failures and confirm the tunnels and their endpoints are stable.",
  mttunnels: "Check the BGP state of the affected tunnels and the routers at the tunnel endpoints.",
  mtprefix: "Confirm that each prefix that is not advertised is intentionally withdrawn.",
};
function mtActions(risks: Risk[], unavailable: number): Fact[] {
  const facts: Fact[] = risks.filter(r => MT_ACTIONS[r.code]).map(r => ({ id: `act-${r.code}`, severity: r.severity, text: MT_ACTIONS[r.code] }));
  if (unavailable > 0) facts.push({ id: "act-unavailable", severity: "low", text: "Review the sections of the attached report that could not be retrieved and check the API token permissions." });
  return facts;
}

export function magicTransitFactPack(m: MagicTransitData, comparison?: Comparison): { pack: FactPack; snapshot: Snapshot } {
  const s = m.summary;
  const bytes = (bits: number | null | undefined) => bits === null || bits === undefined ? null : bits / 8;
  const traffic = bytes(s.traffic?.bits), dropped = bytes(s.dropped?.bits), passed = bytes(s.passed?.bits);
  const unavailable = Object.keys(m.errors ?? {}).length;
  const badTunnels = m.tunnels.filter(t => t.bgpState !== null && t.bgpState !== "BGP_UP").length;
  const ongoing = m.attacks.filter(a => a.end === null).length;
  const notAdvertised = m.prefixes.filter(p => p.advertised === false).length;
  const probe = s.probeSuccessPct;

  const posture: Fact[] = [];
  if (traffic !== null) posture.push({ id: "p-traffic", text: `${cleanText(m.meta.accountName)} received an estimated ${fmtBytes(traffic)} of ingress traffic through Magic Transit in the period (sampled estimate).` });
  if (dropped !== null && traffic) posture.push({ id: "p-dropped", text: `An estimated ${fmtBytes(dropped)} was dropped by mitigation, which is ${pct(dropped, traffic)}% of ingress traffic. Dropped traffic is not necessarily DDoS.` });
  if (passed !== null) posture.push({ id: "p-passed", text: `An estimated ${fmtBytes(passed)} was passed to the network.` });
  posture.push({ id: "p-config", text: `${m.tunnels.length} ${plural(m.tunnels.length, "tunnel")}, ${m.routes.length} ${plural(m.routes.length, "route")} and ${m.prefixes.length} ${plural(m.prefixes.length, "prefix", "prefixes")} are currently configured.` });
  const active = m.protections.filter(p => p.rules.length > 0).length;
  if (m.protections.length) posture.push({ id: "p-protect", text: `${active} of ${m.protections.length} protection ${plural(m.protections.length, "system")} have rules configured.` });
  if (probe !== null && probe !== undefined) posture.push({ id: "p-probe", text: `Tunnel health probes succeeded ${Math.round(probe * 10) / 10}% of the time. This is probe success, not SLA uptime.` });

  const risks: Risk[] = [];
  if (ongoing > 0) risks.push({ code: "mtattack", severity: "high", text: `${ongoing} attack ${plural(ongoing, "event is", "events are")} still ongoing at the end of the report window.` });
  if (probe !== null && probe !== undefined && probe < 99) risks.push({ code: "mtprobe", severity: probe < 90 ? "high" : "medium", text: `Tunnel probe success was ${Math.round(probe * 10) / 10}%, below 99%.` });
  if (badTunnels > 0) risks.push({ code: "mttunnels", severity: "high", text: `${badTunnels} ${plural(badTunnels, "tunnel")} did not report a BGP up state.` });
  if (notAdvertised > 0) risks.push({ code: "mtprefix", severity: "medium", text: `${notAdvertised} ${plural(notAdvertised, "prefix", "prefixes")} ${plural(notAdvertised, "is", "are")} not currently advertised.` });

  const attackCount = s.attackCount;
  const vectors = new Map<string, number>();
  for (const a of m.attacks) vectors.set(a.vector, (vectors.get(a.vector) ?? 0) + 1);
  const topVectors = [...vectors.entries()].sort((x, y) => y[1] - x[1]).slice(0, 3);
  const countries = (m.attackRankings?.sourceCountries ?? []).slice(0, 3);
  const systems = [...m.mitigationSystems].sort((x, y) => y.bits - x.bits).slice(0, 3);
  const trends: Fact[] = [];
  if (attackCount !== null && attackCount > 0) trends.push({ id: "t-attacks", text: `${attackCount} layer 3 and 4 attack ${plural(attackCount, "event")} overlapped the period${topVectors.length ? `, most often ${topVectors.map(([v, n]) => `${cleanText(v, 40)} (${n})`).join(", ")}` : ""}.` });
  if (countries.length) trends.push({ id: "t-countries", text: `Mitigated attack traffic came mostly from ${countries.map(c => `${cleanText(c.name, 30)} (${fmtBytes(c.bits / 8)})`).join(", ")}.` });
  if (systems.length) trends.push({ id: "t-systems", text: `Dropped traffic by mitigation system: ${systems.map(x => `${cleanText(x.name, 40)} (${fmtBytes(x.bits / 8)})`).join(", ")}.` });
  if (s.peakBps !== null) trends.push({ id: "t-peak", text: `Peak ingress was ${fmt(s.peakBps)} bits per second, measured as an average over each ${m.meta.bucketSeconds}-second bucket.` });
  const protoTotal = m.protocolPorts.reduce((t, p) => t + p.bits, 0);
  const topProto = new Map<string, number>();
  for (const p of m.protocolPorts) topProto.set(p.protocol, (topProto.get(p.protocol) ?? 0) + p.bits);
  const protoRank = [...topProto.entries()].sort((x, y) => y[1] - x[1]).slice(0, 3);
  if (protoTotal > 0 && protoRank.length) trends.push({ id: "in-protocols", tag: "Protocols", severity: "info", text: `By protocol, ${protoRank.map(([name, bits]) => `${cleanText(name, 20)} carried ${pct(bits, protoTotal)}%`).join(", ")} of the measured ingress volume.` });
  const prev = bytes(s.previousTraffic?.bits);
  if (traffic !== null && prev !== null && prev > 0) trends.push({ id: "t-prior", text: `Ingress traffic was ${fmtBytes(traffic)} against ${fmtBytes(prev)} in the immediately preceding period of equal length.` });

  const metrics: Record<string, number> = { tunnels: m.tunnels.length };
  if (traffic !== null) metrics.trafficBytes = Math.round(traffic);
  if (dropped !== null) metrics.droppedBytes = Math.round(dropped);
  if (attackCount !== null) metrics.attackEvents = attackCount;
  if (probe !== null && probe !== undefined) metrics.probeSuccessPct = Math.round(probe * 10) / 10;
  const codes = risks.map(r => r.code);
  if (unavailable > 0) codes.push("mtunavailable");
  return finish("magic-transit", m.meta.accountName, `${m.meta.periodLabel} (${m.meta.since} to ${m.meta.until})`, {
    posture: section("posture", TITLES.posture, posture, "No posture data was available."),
    risks: section("risks", TITLES.risks, riskFacts(risks, unavailable, "risks"), "No risk data was available."),
    trends: section("trends", TITLES.trends, trends, "No attack events or notable security events were recorded in the data retrieved for this period."),
    actions: section("actions", TITLES.actions, mtActions(risks, unavailable), "No action is indicated by the checks this report performs."),
  }, metrics, codes, m.meta.days, m.meta.generatedAt, comparison);
}
