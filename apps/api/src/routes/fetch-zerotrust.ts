/**
 * POST /api/zerotrust
 * Cloudflare One (Zero Trust) POC report data aggregation.
 * Account-level only — no zoneId required.
 * Returns ZeroTrustData.
 */

import type { Context } from "hono";
import type { Env, ZeroTrustData } from "../types";
import {
  getAccessApps, getAccessPolicies, getAccessIdps,
  getGatewayRules, getGatewayLocations, getGatewayCategories, buildGatewayCategoryMap,
  getWarpDevices, getWarpPostureRules,
  getCloudflaredTunnels, getTunnelRoutes,
  getDlpProfiles, getMcpPortals,
  getAccessUsers, getCasbFindings, getAlertsHistory,
  type CfAccessApp, type CfGatewayRule,
} from "../services/cf-rest";
import {
  fetchAccessAuthTimeSeries, fetchAccessLogs,
  deriveAccessTopApps, deriveAccessTopUsers, deriveAccessGeoDistribution,
  deriveAccessTopSourceIps, deriveAccessAuthMethodBreakdown,
  fetchAccessDailyActiveUsers,
  fetchAccessIdentityProviderBreakdown, fetchAccessAppBreakdown,
  fetchAccessFailedLoginDetails, detectAccessAnomalies,
  fetchGatewayDnsTimeSeries, fetchGatewayDnsTopBlocked, fetchGatewayDnsTopAllowed,
  fetchGatewayDnsTopBlockedCategories, fetchGatewayDnsSummary,
  fetchGatewayDnsTopByPolicy, fetchGatewayDnsResolverBreakdown,
  fetchGatewayHttpTimeSeries, fetchGatewayHttpTopBlocked, fetchGatewayHttpTopAllowed,
  fetchGatewayHttpTopBlockedCategories, fetchGatewayHttpSummary, fetchGatewayHttpStatusCodes,
  fetchGatewayL4Data,
  fetchShadowItData,
  fetchWarpDeviceStatusBreakdown, fetchWarpDeviceStatusTimeSeries, fetchWarpDeviceLatestStatus,
  fetchGatewayNetworkAnalytics, fetchPrivateNetworkOrigins,
  fetchGenAiUsage,
} from "../services/cf-zerotrust-graphql";

import { last30Days as l30 } from "../services/cf-graphql";

const ALLOWED_DAYS = [1, 3, 5, 7, 14, 30] as const;

function safeGet<T>(
  r: PromiseSettledResult<T>,
  key: string,
  fallback: T,
  errors: Record<string, string>
): T {
  if (r.status === "rejected") errors[key] = String(r.reason);
  return r.status === "fulfilled" ? r.value : fallback;
}

export async function handleFetchZeroTrust(c: Context<{ Bindings: Env }>) {
  let body: unknown;
  try { body = await c.req.json(); }
  catch { return c.json({ error: "Invalid JSON body" }, 400); }

  const { token, accountId, days: rawDays, tzOffset = 0 } =
    body as { token?: string; accountId?: string; days?: number; tzOffset?: number };

  if (!token || typeof token !== "string" || token.length < 10)
    return c.json({ error: "Missing or invalid token" }, 400);
  if (!accountId || !/^[a-f0-9]{32}$/i.test(accountId))
    return c.json({ error: "Missing or invalid accountId (32-char hex)" }, 400);

  const days = ALLOWED_DAYS.includes(rawDays as typeof ALLOWED_DAYS[number])
    ? (rawDays as typeof ALLOWED_DAYS[number]) : 30;

  const zerotrust = await generateZerotrustData({ token, accountId, days, tzOffset });
  return c.json({ ok: true, zerotrust });
}

// ─── Report Generation ────────────────────────────────────────────────────────
// Shared by the POST /api/zerotrust route and the scheduled report email runner.

export async function generateZerotrustData(input: {
  token: string;
  accountId: string;
  days: number;
  tzOffset: number;
}): Promise<ZeroTrustData> {
  const { token, accountId, days, tzOffset } = input;

  const { since, until, sinceTs, untilTs } = l30(days, tzOffset);

  // Use ISO timestamps for Gateway GraphQL queries.
  const adSince = sinceTs;  // e.g. "2026-03-02T10:36:42Z" = now - 30d
  const adUntil = untilTs;  // e.g. "2026-04-01T10:36:42Z" = now

  // IMPORTANT: gatewayResolverQueriesAdaptiveGroups does NOT support datetime_lt.
  // It only supports datetime_gt (open-ended upper bound = "now at Cloudflare").
  // The 30-day quota means "now - 30 days → now" must stay within 4w2d.
  // Since adSince = now - 30d, by the time Cloudflare processes the query the
  // effective range is 30d + network latency → quota exceeded → silent empty response.
  // Fix: add 2h buffer so DNS range is ~29d 22h (safely under the limit).
  const gwAdSince = new Date(new Date(adSince).getTime() + 2 * 60 * 60 * 1000).toISOString();

  const fetchErrors: Record<string, string> = {};
  const sg = <T>(r: PromiseSettledResult<T>, key: string, fallback: T): T =>
    safeGet(r, key, fallback, fetchErrors);

  // ── REST: config data (apps, rules, devices, tunnels) ─────────────────────
  const config = await Promise.allSettled([
    getAccessApps(token, accountId),
    getAccessIdps(token, accountId),
    getGatewayRules(token, accountId),
    getGatewayLocations(token, accountId),
    getGatewayCategories(token, accountId),
    getWarpDevices(token, accountId),
    getWarpPostureRules(token, accountId),
    getCloudflaredTunnels(token, accountId),
    getTunnelRoutes(token, accountId),
    getDlpProfiles(token, accountId),
    getMcpPortals(token, accountId),
    getAccessUsers(token, accountId),
    getCasbFindings(token, accountId),
    getAlertsHistory(token, accountId, 25),
    fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}`, {
      headers: { Authorization: `Bearer ${token}` },
    }).then((r) => r.json() as Promise<{ result?: { name?: string } }>),
  ]);

  const [
    appsR, idpsR, gatewayRulesR, locationsR, gwCategoriesR,
    warpDevicesR, postureRulesR, tunnelsR, tunnelRoutesR, dlpProfilesR,
    mcpPortalsR,
    accessUsersR, casbFindingsR, alertsHistoryR,
    accountInfoR,
  ] = config;

  const rawApps      = sg(appsR,         "apps",      []) as CfAccessApp[];
  const idps         = sg(idpsR,         "idps",      []);
  const gatewayRules = sg(gatewayRulesR, "gwRules",   []) as CfGatewayRule[];
  const gwLocations  = sg(locationsR,    "gwLoc",     []);
  const gwCategories = sg(gwCategoriesR, "gwCats",    []);
  const gwCategoryMap = buildGatewayCategoryMap(gwCategories as Parameters<typeof buildGatewayCategoryMap>[0]);
  const rawDevices   = sg(warpDevicesR,  "devices",   []);
  const postureRules = sg(postureRulesR, "posture",   []);
  const rawTunnels   = sg(tunnelsR,      "tunnels",   []);
  const rawRoutes    = sg(tunnelRoutesR, "routes",    []);
  const rawDlpProfs  = sg(dlpProfilesR,  "dlp",       []);
  const rawMcpPortals = sg(mcpPortalsR,  "mcpPortals",[]) as Array<{ id: string; name: string; hostname: string }>;
  const rawAccessUsers = sg(accessUsersR, "accessUsers", []) as Array<{
    id: string; uid: string; name?: string; email: string;
    last_successful_login?: string; access_seat?: boolean; gateway_seat?: boolean;
  }>;
  const rawCasbFindings = sg(casbFindingsR, "casbFindings", []) as Array<{ severity?: string; type?: string; resource_name?: string }>;
  const rawAlertsHistory = sg(alertsHistoryR, "alertsHistory", []) as Array<{
    id: string; name: string; alert_type: string; sent: string; silenced?: boolean;
  }>;
  const accountName = (accountInfoR.status === "fulfilled"
    ? (accountInfoR.value as { result?: { name?: string } })?.result?.name
    : undefined) ?? accountId;

  // Access policies per app (cap at 10 apps)
  const policyResults = await Promise.allSettled(
    rawApps.slice(0, 10).map((app) => getAccessPolicies(token, accountId, app.id))
  );

  // ── GraphQL analytics (all parallel) ──────────────────────────────────────
  const [
    authSeriesR, accessLogsR, dailyActiveR,
    idpBreakdownR, appBreakdownR, failedDetailsR,
    dnsSummaryR, dnsDailyR, dnsBreakdownR, dnsTopDomsR, dnsTopAllowedR, dnsCatsR, dnsTopPoliciesR,
    httpSummaryR, httpDailyR, httpTopDomsR, httpTopAllowedR, httpCatsR, httpStatusCodesR,
    l4DataR,
    shadowItR,
    warpStatusBreakdownR, warpStatusSeriesR, warpLatestStatusR,
    networkAnalyticsR, privateNetOriginsR,
    genAiR,
  ] = await Promise.allSettled([
    // Access
    fetchAccessAuthTimeSeries(token, accountId, adSince, adUntil),
    fetchAccessLogs(token, accountId), // single fetch — reused below for top apps/users/geo/IPs/auth method
    fetchAccessDailyActiveUsers(token, accountId, adSince, adUntil),
    // Access Audit enrichment (cf-reporting patterns)
    fetchAccessIdentityProviderBreakdown(token, accountId, adSince, adUntil),
    fetchAccessAppBreakdown(token, accountId, adSince, adUntil),
    fetchAccessFailedLoginDetails(token, accountId, adSince, adUntil),
    // Gateway DNS — gwAdSince has +2h buffer to stay within 30-day quota
    // (datetime_gt only; datetime_lt is NOT supported on gatewayResolverQueriesAdaptiveGroups)
    fetchGatewayDnsSummary(token, accountId, gwAdSince, adUntil),
    fetchGatewayDnsTimeSeries(token, accountId, gwAdSince, adUntil),
    fetchGatewayDnsResolverBreakdown(token, accountId, gwAdSince, adUntil),
    fetchGatewayDnsTopBlocked(token, accountId, gwAdSince, adUntil, 15),
    fetchGatewayDnsTopAllowed(token, accountId, gwAdSince, adUntil, 15),
    fetchGatewayDnsTopBlockedCategories(token, accountId, gwAdSince, adUntil, 10, gwCategoryMap),
    fetchGatewayDnsTopByPolicy(token, accountId, gwAdSince, adUntil, 10),
    // Gateway HTTP
    fetchGatewayHttpSummary(token, accountId, adSince, adUntil),
    fetchGatewayHttpTimeSeries(token, accountId, adSince, adUntil),
    fetchGatewayHttpTopBlocked(token, accountId, adSince, adUntil, 15),
    fetchGatewayHttpTopAllowed(token, accountId, adSince, adUntil, 15),
    fetchGatewayHttpTopBlockedCategories(token, accountId, adSince, adUntil, 10),
    fetchGatewayHttpStatusCodes(token, accountId, adSince, adUntil),
    // Gateway L4
    fetchGatewayL4Data(token, accountId, adSince, adUntil),
    // Shadow IT
    fetchShadowItData(token, accountId, adSince, adUntil),
    // WARP device connection status (real online/offline — see cf-zerotrust-graphql.ts)
    fetchWarpDeviceStatusBreakdown(token, accountId, adSince, adUntil),
    fetchWarpDeviceStatusTimeSeries(token, accountId, adSince, adUntil),
    fetchWarpDeviceLatestStatus(token, accountId, adSince, adUntil),
    // Gateway network-layer bandwidth + session health/location analytics
    // (account-wide only, see fetchGatewayNetworkAnalytics in cf-zerotrust-graphql.ts)
    fetchGatewayNetworkAnalytics(token, accountId, adSince, adUntil),
    // Real "Shadow IT: Private Network" origins (WARP-routed internal traffic)
    fetchPrivateNetworkOrigins(token, accountId, adSince, adUntil, 15),
    // Generative AI usage — real Cloudflare category classification (id 184 "Artificial Intelligence")
    fetchGenAiUsage(token, accountId, gwAdSince, adUntil),
  ]);

  // Unwrap results
  const authSeries     = sg(authSeriesR,    "authSeries",    []);
  const accessLogs     = sg(accessLogsR,    "accessLogs",    []);
  // Derived synchronously from the single accessLogs fetch above.
  const topApps        = deriveAccessTopApps(accessLogs, adSince, adUntil, 10);
  const topUsers        = deriveAccessTopUsers(accessLogs, adSince, adUntil, 15);
  const geoDistrib      = deriveAccessGeoDistribution(accessLogs, adSince, adUntil, 20);
  const topSourceIps    = deriveAccessTopSourceIps(accessLogs, adSince, adUntil, 20);
  const authMethodBreak = deriveAccessAuthMethodBreakdown(accessLogs, adSince, adUntil);
  const dailyActive    = sg(dailyActiveR,   "dailyActive",   []);
  const idpBreakdown   = sg(idpBreakdownR,  "idpBreakdown",  []);
  const appBreakdown   = sg(appBreakdownR,  "appBreakdown",  []);
  const failedDetails  = sg(failedDetailsR, "failedDetails", []);
  const rawDnsSummary  = sg(dnsSummaryR,    "dnsSummary",  null);
  const dnsSeries      = sg(dnsDailyR,      "dnsSeries",   []);
  const dnsBreakdown   = sg(dnsBreakdownR,  "dnsBreakdown",[]);
  const dnsTopDoms     = sg(dnsTopDomsR,    "dnsTopDoms",  []);
  const dnsTopAllowed  = sg(dnsTopAllowedR, "dnsTopAllowed", []);
  const dnsCats        = sg(dnsCatsR,       "dnsCats",     []);
  const dnsTopPolics   = sg(dnsTopPoliciesR,"dnsTopPol",   []) as Array<{ policyId: string; queriesTotal: number }>;
  const rawHttpSummary = sg(httpSummaryR,   "httpSummary", null);
  const httpSeries     = sg(httpDailyR,     "httpSeries",  []);
  const httpTopDoms    = sg(httpTopDomsR,   "httpTopDoms", []);
  const httpTopAllowed = sg(httpTopAllowedR,"httpTopAllowed", []);
  const httpCats       = sg(httpCatsR,      "httpCats",    []);
  const httpStatusCodes = sg(httpStatusCodesR, "httpStatusCodes", []);
  const l4Data         = sg(l4DataR,        "l4Data",      { timeSeries: [], blockedDestinations: [], protocols: [], sourceCountries: [], portBreakdown: [] });
  const shadowIt       = sg(shadowItR,      "shadowIt",    { discoveredApps: [], categoryBreakdown: [], userAppMappings: [], appStatuses: {} });
  const warpStatusBreakdown = sg(warpStatusBreakdownR, "warpStatusBreakdown", []);
  const warpStatusSeries   = sg(warpStatusSeriesR,     "warpStatusSeries",    []);
  const warpLatestStatus   = sg(warpLatestStatusR,     "warpLatestStatus",    { online: 0, offline: 0, total: 0 });
  const networkAnalytics   = sg(networkAnalyticsR, "networkAnalytics", {
    bytesSent: 0, bytesRecvd: 0, packetsSent: 0, packetsRecvd: 0, sessionCount: 0,
    retransmittedBytes: 0, transportStatusBreakdown: [], tokenAuthStatusBreakdown: [], topColos: [],
  });
  const privateNetOrigins  = sg(privateNetOriginsR, "privateNetOrigins", []);
  const genAi               = sg(genAiR,     "genAi",     { totalRequests: 0, uniqueApps: 0, uniqueUsers: 0, apps: [], users: [] });

  // ── Derived KPIs ──────────────────────────────────────────────────────────
  const totalAuth   = authSeries.reduce((s: number, d: { allow: number; block: number; mfa: number }) => s + d.allow + d.block + d.mfa, 0);
  const totalBlock  = authSeries.reduce((s: number, d: { block: number }) => s + d.block, 0);
  const totalMfa    = authSeries.reduce((s: number, d: { mfa: number }) => s + d.mfa, 0);
  const successRate = totalAuth > 0 ? Math.round(((totalAuth - totalBlock) / totalAuth) * 100) : 100;

  const uniqueUsersSet = new Set((topUsers as Array<{ email: string }>).map((u) => u.email));
  const uniqueAppsSet  = new Set((topApps  as Array<{ name: string }>).map((a) => a.name));

  const totalDnsQ   = (rawDnsSummary as { queriesTotal?: number } | null)?.queriesTotal
    ?? dnsSeries.reduce((s: number, d: { total: number }) => s + d.total, 0);
  const totalDnsBlk = (rawDnsSummary as { queriesBlocked?: number } | null)?.queriesBlocked
    ?? dnsSeries.reduce((s: number, d: { blocked: number }) => s + d.blocked, 0);
  const totalHttpQ   = (rawHttpSummary as { requestsTotal?: number } | null)?.requestsTotal
    ?? httpSeries.reduce((s: number, d: { total: number }) => s + d.total, 0);
  const totalHttpBlk = (rawHttpSummary as { requestsBlocked?: number } | null)?.requestsBlocked
    ?? httpSeries.reduce((s: number, d: { blocked: number }) => s + d.blocked, 0);
  const totalHttpRbi = (rawHttpSummary as { rbiSessions?: number } | null)?.rbiSessions ?? 0;
  const totalHttpQuarantined = (rawHttpSummary as { quarantinedRequests?: number } | null)?.quarantinedRequests ?? 0;
  const totalMcpHttp = (rawHttpSummary as { mcpRequests?: number } | null)?.mcpRequests ?? 0;

  const l4DataObj = l4Data as { timeSeries: Array<{ date: string; total: number; blocked: number }>; blockedDestinations: unknown[]; protocols: unknown[]; sourceCountries: unknown[]; portBreakdown: unknown[] };
  const totalL4    = l4DataObj.timeSeries.reduce((s, d) => s + d.total,   0);
  const totalL4Blk = l4DataObj.timeSeries.reduce((s, d) => s + d.blocked, 0);

  const shadowItObj = shadowIt as {
    discoveredApps: unknown[]; categoryBreakdown: unknown[]; userAppMappings: unknown[];
    appStatuses: Record<string, string>;
  };

  // REST /accounts/{id}/devices and the GraphQL warpDeviceAdaptiveGroups
  // dataset can disagree on device count in practice (confirmed live on a
  // real account: REST returned 0 while GraphQL analytics showed 5 distinct
  // deviceIds with real connection events in the period — GraphQL tracks
  // historical connection events for any device that connected during the
  // window, while the REST list reflects current MDM/registration state).
  // Both are real signals; take the larger (more complete) one rather than
  // showing an inconsistent "0 enrolled, 5 offline" combination.
  const warpCount = Math.max((rawDevices as Array<unknown>).length, (warpLatestStatus as { total: number }).total);

  // ── Users & seats (real, from REST /access/users) ──────────────────────────
  // access_seat / gateway_seat are real per-user license flags; last_successful_login
  // is a real timestamp used to compute "active in this report period" honestly
  // (no fabricated MAU estimate — a user only counts as active if they actually
  // logged in within [since, until]).
  const sinceMs = new Date(since).getTime();
  const untilMs = new Date(until).getTime();
  const seatsAccessTotal  = rawAccessUsers.filter((u) => u.access_seat).length;
  const seatsGatewayTotal = rawAccessUsers.filter((u) => u.gateway_seat).length;
  const seatsTotal        = new Set(rawAccessUsers.map((u) => u.email)).size;
  const seatsActiveInPeriod = rawAccessUsers.filter((u) => {
    if (!u.last_successful_login) return false;
    const t = new Date(u.last_successful_login).getTime();
    return t >= sinceMs && t <= untilMs;
  }).length;
  const seatsNeverLoggedIn = rawAccessUsers.filter((u) => !u.last_successful_login).length;

  // ── WARP device online/offline (real, from warpDeviceAdaptiveGroups.status) ─
  const warpOnlineDevices  = (warpLatestStatus as { online: number }).online;
  const warpOfflineDevices = (warpLatestStatus as { offline: number }).offline;

  // ── Gateway network-layer bandwidth (real, account-wide only) ──────────────
  const networkAnalyticsObj = networkAnalytics as {
    bytesSent: number; bytesRecvd: number; packetsSent: number; packetsRecvd: number; sessionCount: number;
    retransmittedBytes: number;
    transportStatusBreakdown: { status: string; count: number }[];
    tokenAuthStatusBreakdown: { status: string; count: number }[];
    topColos: { colo: string; country: string; count: number }[];
  };

  // ── CASB findings (real; empty array = no findings/no CASB integration, honest) ─
  const casbFindingsCount = rawCasbFindings.length;
  const casbFindingsBySeverity = new Map<string, number>();
  for (const f of rawCasbFindings) {
    const sev = f.severity || "unknown";
    casbFindingsBySeverity.set(sev, (casbFindingsBySeverity.get(sev) ?? 0) + 1);
  }

  // ── Recent account-wide alerts (real, from /alerting/v3/history) ───────────
  const recentAlerts = rawAlertsHistory
    .slice()
    .sort((a, b) => new Date(b.sent).getTime() - new Date(a.sent).getTime())
    .slice(0, 15)
    .map((a) => ({ id: a.id, name: a.name, alertType: a.alert_type, sentAt: a.sent, silenced: !!a.silenced }));

  const tunnelList = (rawTunnels as Array<{ id: string; name: string; status: string; created_at?: string; connections?: Array<unknown> }>)
    .map((t) => ({
      id: t.id, name: t.name,
      status: (["healthy","degraded","down","inactive"].includes(t.status) ? t.status : "inactive") as "healthy"|"degraded"|"down"|"inactive",
      createdAt: t.created_at ?? "",
      connections: (t.connections ?? []).length,
      routeCount: (rawRoutes as Array<{ tunnel_id?: string }>).filter((r) => r.tunnel_id === t.id).length,
    }));
  const tunnelsHealthy = tunnelList.filter((t) => t.status === "healthy").length;

  // ── Access apps/policies ──────────────────────────────────────────────────
  const accessApps = rawApps.slice(0, 50).map((app, i) => {
    const appPolicies = policyResults[i]?.status === "fulfilled" ? policyResults[i].value : [];
    return {
      id: app.id, name: app.name,
      domain: app.domain ?? "",
      type: app.type ?? "self_hosted",
      sessionDuration: app.session_duration ?? "24h",
      allowedIdps: app.allowed_idps ?? [],
      policyCount: (appPolicies as Array<unknown>).length,
      enabled: app.enabled !== false,
    };
  });

  const accessPolicies = rawApps.slice(0, 10).flatMap((app, i) => {
    const pols = policyResults[i]?.status === "fulfilled" ? policyResults[i].value as Array<{ id: string; name: string; decision: string; require?: Array<{ mfa?: unknown }>; precedence?: number }> : [];
    return pols.map((p) => ({
      id: p.id, appId: app.id, appName: app.name, name: p.name,
      decision: p.decision,
      requireMfa: Array.isArray(p.require) && p.require.some((r: { mfa?: unknown }) => r.mfa),
      precedence: p.precedence ?? 0,
    }));
  });

  // ── Access policy action breakdown ─────────────────────────────────────────
  // Mirrors "Access admin metrics — Policies configured" in the Application
  // Access Report (Allow / Block / Bypass / Service Auth / Non-Identity).
  const DECISION_LABELS: Record<string, string> = {
    allow: "Allow", block: "Block", bypass: "Bypass",
    non_identity: "Service Auth", service_auth: "Service Auth",
  };
  const policyActionCounts = new Map<string, number>();
  for (const p of accessPolicies) {
    const label = DECISION_LABELS[p.decision] ?? p.decision;
    policyActionCounts.set(label, (policyActionCounts.get(label) ?? 0) + 1);
  }
  const accessPolicyActionBreakdown = Array.from(policyActionCounts.entries())
    .map(([action, count]) => ({ action, count }))
    .sort((a, b) => b.count - a.count);

  // ── Access app-type breakdown ──────────────────────────────────────────────
  // Mirrors the "Access applications by event count" panel in the Application
  // Access Report (Self-hosted / SaaS / Private Network / Infrastructure / MCP
  // Portal). Uses the FULL app list (not the 50-item display cap) for accuracy.
  const APP_TYPE_LABELS: Record<string, string> = {
    self_hosted: "Self-hosted", saas: "SaaS", ssh: "SSH", vnc: "VNC",
    app_launcher: "App Launcher", warp: "WARP", biso: "Browser Isolation",
    bookmark: "Bookmark", dash_sso: "Dashboard SSO", infrastructure: "Infrastructure",
    mcp: "MCP Server",
  };
  const appTypeCounts = new Map<string, number>();
  for (const app of rawApps) {
    const type = app.type || "self_hosted";
    appTypeCounts.set(type, (appTypeCounts.get(type) ?? 0) + 1);
  }
  const accessAppTypeBreakdown = Array.from(appTypeCounts.entries())
    .map(([type, count]) => ({ type: APP_TYPE_LABELS[type] ?? type, count }))
    .sort((a, b) => b.count - a.count);

  // ── MCP visibility ──────────────────────────────────────────────────────────
  // Individual MCP server Access apps (type: "mcp") + MCP server portals
  // (separate resource under /access/ai-controls/mcp/portals).
  const mcpApps = rawApps.filter((a) => a.type === "mcp");
  const mcpAppIdentifiers = new Set(mcpApps.flatMap((a) => [a.id, a.domain].filter(Boolean)));
  const mcpServersCount = mcpApps.length;
  const mcpPortalsCount = rawMcpPortals.length;
  const mcpServerLoginEvents = topApps
    .filter((a) => mcpAppIdentifiers.has(a.name))
    .reduce((s, a) => s + a.requests, 0);

  // Map policyId → queriesTotal from DNS analytics
  const policyQueryMap = new Map<string, number>();
  for (const p of dnsTopPolics) policyQueryMap.set(p.policyId, p.queriesTotal);

  const gtwPolicies = (gatewayRules as CfGatewayRule[]).map((r) => ({
    id: r.id, name: r.name,
    ruleType: (r.rule_type as "dns"|"http"|"l4") ?? "dns",
    action: r.action, enabled: r.enabled !== false,
    filters: r.filters ?? [],
    expression: r.description
      ? `${r.description}${policyQueryMap.has(r.id) ? ` [${policyQueryMap.get(r.id)!.toLocaleString()} queries]` : ""}`
      : policyQueryMap.has(r.id) ? `${policyQueryMap.get(r.id)!.toLocaleString()} queries in period` : "",
  }));

  // ── Generative AI / Shadow AI usage ────────────────────────────────────────
  // Real Cloudflare category classification (DNS + HTTP Gateway traffic
  // tagged with category id 184 "Artificial Intelligence", confirmed live
  // via /gateway/categories) — see fetchGenAiUsage() in cf-zerotrust-graphql.ts.
  // Replaces the previous keyword/substring app-name guessing heuristic
  // entirely: this now reflects Cloudflare's own real per-request
  // classification instead of a manually maintained app-name list.
  const shadowItAppsTyped  = shadowItObj.discoveredApps  as Array<{ name: string; category: string; count: number }>;
  const appStatuses        = shadowItObj.appStatuses ?? {};
  const genAiObj = genAi as { totalRequests: number; uniqueApps: number; uniqueUsers: number; apps: { name: string; count: number }[]; users: { email: string; count: number }[] };

  // Governance check: inspect the admin's OWN real Gateway policy names/
  // descriptions/filters for AI-related terms. This is a heuristic, but it
  // inspects real policy metadata text (not traffic) so it never fabricates
  // a number — worst case it under/over-detects an admin-authored label.
  const AI_POLICY_TERMS = ["generative ai", "artificial intelligence", "genai", "chatgpt", "openai", "claude", "gemini", "copilot"];
  const hasAiGovernancePolicy = gtwPolicies.some((p) => {
    const text = `${p.name} ${p.expression ?? ""} ${(p.filters ?? []).join(" ")}`.toLowerCase();
    return AI_POLICY_TERMS.some((k) => text.includes(k));
  });

  const aiAppUsage: ZeroTrustData["aiAppUsage"] = {
    apps: genAiObj.apps.map((a) => ({
      name: a.name,
      category: "Artificial Intelligence",
      count: a.count,
      status: appStatuses[a.name],
    })),
    users: genAiObj.users.slice(0, 15),
    totalRequests: genAiObj.totalRequests,
    uniqueApps: genAiObj.uniqueApps,
    uniqueUsers: genAiObj.uniqueUsers,
    hasGovernancePolicy: hasAiGovernancePolicy,
  };

  // ── Recommendations ───────────────────────────────────────────────────────
  const recommendations: ZeroTrustData["recommendations"] = [];
  if (accessPolicies.filter((p) => p.requireMfa).length === 0)
    recommendations.push({ priority: "high", title: "Enforce MFA on All Access Applications", description: "No Access policies require MFA. Add a 'Require' rule with your IdP's MFA method to all applications.", benefit: "Prevents credential stuffing and account takeover — MFA blocks 99.9% of automated attacks" });
  if (gtwPolicies.filter((p) => p.ruleType === "dns" && p.action === "block").length < 3)
    recommendations.push({ priority: "high", title: "Add Gateway DNS Blocking Policies for Malware & Phishing", description: "Less than 3 DNS blocking policies configured. Add policies blocking 'Malware', 'Phishing', and 'Command and Control' categories.", benefit: "DNS filtering stops threats before connections are established — zero latency impact" });
  if (warpCount === 0)
    recommendations.push({ priority: "medium", title: "Deploy WARP Client for Device-Level Security", description: "No WARP-enrolled devices detected. Deploy the WARP client to route all device traffic through Cloudflare Gateway for full visibility.", benefit: "Enables device posture checks, split tunneling, and egress filtering for all managed devices" });
  if (gtwPolicies.filter((p) => p.ruleType === "http").length === 0)
    recommendations.push({ priority: "medium", title: "Enable HTTP Gateway Filtering", description: "No HTTP filtering policies configured. Add policies to inspect and block malicious web content, shadow IT, and data exfiltration.", benefit: "HTTP inspection provides full visibility into SaaS usage and can detect data loss attempts" });
  if ((rawDlpProfs as Array<unknown>).length === 0)
    recommendations.push({ priority: "medium", title: "Configure DLP Profiles to Prevent Data Loss", description: "No DLP profiles configured. Add predefined profiles for PII, credit cards, and custom sensitive data patterns.", benefit: "Prevents accidental or malicious exfiltration of sensitive customer and company data" });
  if (tunnelList.length === 0)
    recommendations.push({ priority: "low", title: "Replace VPN with Cloudflare Tunnel", description: "No Cloudflare Tunnels configured. Replace your VPN with Tunnel + Access for zero-trust network access to internal applications.", benefit: "Eliminates VPN attack surface — no inbound firewall rules needed, connections are outbound-only" });
  if (aiAppUsage.uniqueApps > 0 && !aiAppUsage.hasGovernancePolicy)
    recommendations.push({ priority: "medium", title: `Govern Generative AI (Shadow AI) Usage — ${aiAppUsage.uniqueApps} App${aiAppUsage.uniqueApps === 1 ? "" : "s"} Discovered`, description: `Users are accessing generative AI tools (e.g. ${genAiObj.apps.slice(0,3).map((a) => a.name).join(", ") || "ChatGPT, Claude"}) with no Gateway policy specifically governing GenAI traffic. Add DNS/HTTP categories or app-based policies for "Generative AI" plus a DLP profile to inspect prompts for sensitive data.`, benefit: "Prevents accidental leakage of confidential data into public AI models and gives visibility/audit trail into GenAI adoption across the organization" });
  if (warpLatestStatus.total > 0 && warpLatestStatus.offline > warpLatestStatus.online)
    recommendations.push({ priority: "medium", title: `${warpLatestStatus.offline} of ${warpLatestStatus.total} WARP Devices Not Connected`, description: `More than half of enrolled WARP devices had a non-connected status (disconnected, no network, or a connectivity check failure) most recently in this period. Investigate client health, captive-portal issues, or expired device certificates.`, benefit: "Devices that are not connected to WARP are not protected by Gateway policies or posture checks" });
  if (seatsTotal > 0 && seatsNeverLoggedIn / seatsTotal > 0.3)
    recommendations.push({ priority: "low", title: `${seatsNeverLoggedIn} Provisioned Users Have Never Logged In`, description: `${seatsNeverLoggedIn} of ${seatsTotal} provisioned Access/Gateway seats have no recorded successful login. Review whether these are stale accounts consuming licensed seats.`, benefit: "Reduces licensing cost and shrinks the attack surface from unused/orphaned accounts" });

  // ── Assemble response ─────────────────────────────────────────────────────
  const zerotrust: ZeroTrustData = {
    meta: {
      accountId, accountName,
      since, until,
      generatedAt: new Date().toISOString(),
      days, periodLabel: days === 1 ? "1-Day" : `${days}-Day`,
    },
    summary: {
      totalAuthEvents: totalAuth, authSuccessRate: successRate,
      uniqueUsers: uniqueUsersSet.size, uniqueApps: uniqueAppsSet.size,
      blockedAuthEvents: totalBlock, mfaChallenges: totalMfa,
      gatewayDnsQueries: totalDnsQ, gatewayDnsBlocked: totalDnsBlk,
      gatewayHttpRequests: totalHttpQ, gatewayHttpBlocked: totalHttpBlk,
      httpRbiSessions: totalHttpRbi,
      httpQuarantinedRequests: totalHttpQuarantined, gatewayMcpHttpRequests: totalMcpHttp,
      gatewayL4Sessions: totalL4, gatewayL4Blocked: totalL4Blk,
      shadowItAppsDiscovered: shadowItObj.discoveredApps.length,
      warpEnrolledDevices: warpCount,
      warpOnlineDevices: warpOnlineDevices, warpOfflineDevices: warpOfflineDevices,
      tunnelsHealthy, tunnelsTotal: tunnelList.length,
      seatsTotal, seatsAccessTotal, seatsGatewayTotal, seatsActiveInPeriod, seatsNeverLoggedIn,
      gatewayBandwidthBytesSent: networkAnalyticsObj.bytesSent, gatewayBandwidthBytesRecvd: networkAnalyticsObj.bytesRecvd,
      gatewayRetransmittedBytes: networkAnalyticsObj.retransmittedBytes,
      casbFindingsCount,
      mcpServersCount, mcpPortalsCount, mcpServerLoginEvents,
    },
    // Access
    accessApps,
    accessPolicies,
    accessIdps: (idps as Array<{ id: string; name: string; type: string }>).map((i) => ({ id: i.id, name: i.name, type: i.type })),
    accessAuthTimeSeries: authSeries,
    accessTopApps: topApps,
    accessTopUsers: topUsers,
    accessTopBlockedUsers: (topUsers as Array<{ email: string; requests: number; blocked: number; country: string }>).filter((u) => u.blocked > 0).sort((a, b) => b.blocked - a.blocked).map((u) => ({ email: u.email, count: u.blocked, country: u.country })),
    accessGeoDistribution: geoDistrib,
    accessTopSourceIps: topSourceIps,
    accessAuthMethodBreakdown: authMethodBreak,
    accessAppTypeBreakdown,
    accessPolicyActionBreakdown,
    accessDailyActiveUsers: dailyActive,
    accessIdpBreakdown: idpBreakdown,
    accessAppBreakdown: appBreakdown,
    accessFailedLoginDetails: failedDetails,
    accessAnomalies: detectAccessAnomalies(
      appBreakdown as Parameters<typeof detectAccessAnomalies>[0],
      failedDetails as Parameters<typeof detectAccessAnomalies>[1],
      (geoDistrib as Array<{ country: string }>).map((g) => g.country),
      dailyActive as Parameters<typeof detectAccessAnomalies>[3]
    ),
    // Gateway DNS
    gatewayDnsTimeSeries: dnsSeries,
    gatewayDnsResolverBreakdown: dnsBreakdown,
    gatewayDnsTopBlockedDomains: dnsTopDoms,
    gatewayDnsTopAllowedDomains: dnsTopAllowed,
    gatewayDnsTopBlockedCategories: dnsCats,
    // Gateway HTTP
    gatewayHttpTimeSeries: httpSeries,
    gatewayHttpTopBlockedDomains: httpTopDoms,
    gatewayHttpTopAllowedDomains: httpTopAllowed,
    gatewayHttpTopBlockedCategories: httpCats,
    gatewayHttpStatusCodes: httpStatusCodes as ZeroTrustData["gatewayHttpStatusCodes"],
    // Gateway L4 / Network Session Analytics
    gatewayL4TimeSeries: l4DataObj.timeSeries,
    gatewayL4BlockedDestinations: l4DataObj.blockedDestinations as ZeroTrustData["gatewayL4BlockedDestinations"],
    gatewayL4Protocols: l4DataObj.protocols as ZeroTrustData["gatewayL4Protocols"],
    gatewayL4SourceCountries: l4DataObj.sourceCountries as ZeroTrustData["gatewayL4SourceCountries"],
    gatewayL4PortBreakdown: l4DataObj.portBreakdown as ZeroTrustData["gatewayL4PortBreakdown"],
    gatewayTransportStatusBreakdown: networkAnalyticsObj.transportStatusBreakdown,
    gatewayTokenAuthStatusBreakdown: networkAnalyticsObj.tokenAuthStatusBreakdown,
    gatewayTopColos: networkAnalyticsObj.topColos,
    privateNetworkOrigins: privateNetOrigins as ZeroTrustData["privateNetworkOrigins"],
    // Shadow IT
    shadowItApps: shadowItAppsTyped.map((a) => ({
      name: a.name, category: a.category, count: a.count,
      status: appStatuses[a.name],
    })),
    shadowItCategoryBreakdown: shadowItObj.categoryBreakdown as ZeroTrustData["shadowItCategoryBreakdown"],
    shadowItUserMappings: shadowItObj.userAppMappings as ZeroTrustData["shadowItUserMappings"],
    // Generative AI / Shadow AI usage — real Cloudflare category classification
    aiAppUsage,
    // Gateway config
    gatewayPolicies: gtwPolicies,
    gatewayLocations: (gwLocations as Array<{ id: string; name: string; doh_subdomain?: string; ip?: string[] }>).map((l) => ({ id: l.id, name: l.name, dnsOverHttps: !!l.doh_subdomain, ipv4Destination: l.ip?.[0] })),
    // WARP
    warpDevices: (rawDevices as Array<{ id: string; name: string; user?: { email?: string }; os?: string; device_type?: string; created?: string; last_seen?: string }>).slice(0, 100).map((d) => ({
      id: d.id, name: d.name,
      user: d.user?.email ?? "unknown",
      os: d.os ?? d.device_type ?? "Unknown",
      enrolledAt: d.created ?? "", lastSeen: d.last_seen ?? "",
      postureStatus: "unknown" as const,
    })),
    warpPostureRules: (postureRules as Array<{ id: string; name: string; type: string; enabled?: boolean }>).map((r) => ({ id: r.id, name: r.name, type: r.type, enabled: r.enabled !== false })),
    warpOsBreakdown: (() => {
      const byOs = new Map<string, number>();
      for (const d of rawDevices as Array<{ os?: string; device_type?: string }>) {
        const os = d.os ?? d.device_type ?? "Unknown";
        byOs.set(os, (byOs.get(os) ?? 0) + 1);
      }
      return Array.from(byOs.entries()).map(([os, count]) => ({ os, count })).sort((a, b) => b.count - a.count);
    })(),
    warpDeviceStatusBreakdown: warpStatusBreakdown as ZeroTrustData["warpDeviceStatusBreakdown"],
    warpDeviceStatusTimeSeries: warpStatusSeries as ZeroTrustData["warpDeviceStatusTimeSeries"],
    // Tunnels
    tunnels: tunnelList,
    tunnelRoutes: (rawRoutes as Array<{ network: string; tunnel_id?: string; tunnel_name?: string; comment?: string }>).map((r) => ({ network: r.network, tunnelId: r.tunnel_id ?? "", tunnelName: r.tunnel_name ?? "", comment: r.comment })),
    // DLP — real configuration only (see type/comment in types.ts for why
    // match-count time series were removed rather than kept as fake stubs)
    dlpProfiles: (rawDlpProfs as Array<{ id: string; name: string; type: "custom"|"predefined" }>).map((p) => ({ id: p.id, name: p.name, type: p.type, matchCount: 0 })),
    // CASB
    casbFindingsBySeverity: Array.from(casbFindingsBySeverity.entries()).map(([severity, count]) => ({ severity, count })),
    // Alerts
    recentAlerts,
    recommendations,
    errors: fetchErrors,
  };

  return zerotrust;
}
