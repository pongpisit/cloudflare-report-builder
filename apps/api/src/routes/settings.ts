/**
 * Backend settings — dashboard-facing routes.
 *
 *   GET  /api/settings      — current state (token NEVER returned in full,
 *                             only a masked hint + which source is active)
 *   PUT  /api/settings       — update (null clears a value → env fallback)
 *   POST /api/settings/test — validate the effective token + account against
 *                             the Cloudflare API (lightweight calls)
 *
 * Values set here override the Worker's env secret/vars and take effect on
 * the next scheduled run or zone-picker fetch — no redeploy needed.
 */

import type { Context } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import type { Env } from "../types";
import { getEffectiveBackendConfig, getStoredSettings, saveSetting, SETTING_KEYS, type SettingKey } from "../services/settings";
import { cfGet, cfGetPaged } from "../services/cf-rest";

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ─── GET /api/settings ────────────────────────────────────────────────────────

export async function handleGetSettings(c: Context<{ Bindings: Env }>) {
  const stored = await getStoredSettings(c.env);
  const effective = await getEffectiveBackendConfig(c.env);

  return c.json({
    ok: true,
    settings: {
      tokenSet: effective.token.length > 0,
      tokenSource: effective.tokenSource,
      tokenHint: stored.cfApiToken ? maskToken(stored.cfApiToken) : null,
      accountId: effective.accountId || null,
      accountSource: effective.accountSource,
      emailFrom: effective.emailFrom,
      emailSource: effective.emailSource,
    },
  });
}

// ─── PUT /api/settings ────────────────────────────────────────────────────────
// Body: { cfApiToken?: string | null, cfAccountId?: string | null, emailFrom?: string | null }
// - Omitted field → left unchanged
// - null or ""    → cleared (falls back to the Worker's env value)

export async function handleUpdateSettings(c: Context<{ Bindings: Env }>) {
  let body: unknown;
  try { body = await c.req.json(); } catch { return c.json({ error: "Invalid JSON body" }, 400); }
  if (!body || typeof body !== "object") return c.json({ error: "Missing request body" }, 400);

  const b = body as Record<string, unknown>;

  // Normalise: absent = skip; null or "" = clear
  const read = (key: string): string | null | undefined => {
    if (!(key in b)) return undefined;
    const v = b[key];
    if (v === null) return null;
    if (typeof v !== "string") return undefined; // invalid type → ignored
    const t = v.trim();
    return t === "" ? null : t;
  };

  const token = read("cfApiToken");
  if (token !== undefined && token !== null && token.length < 10) {
    return c.json({ error: "API token looks too short to be valid (min 10 chars)" }, 400);
  }
  const accountId = read("cfAccountId");
  if (accountId !== undefined && accountId !== null && !/^[a-f0-9]{32}$/i.test(accountId)) {
    return c.json({ error: "Account ID must be a 32-character hex string" }, 400);
  }
  const emailFrom = read("emailFrom");
  if (emailFrom !== undefined && emailFrom !== null) {
    if (!EMAIL_RE.test(emailFrom) || emailFrom.length > 254) {
      return c.json({ error: `Invalid sender address: ${emailFrom}` }, 400);
    }
    // The from domain must be onboarded to Cloudflare Email Sending
    const domain = emailFrom.split("@")[1];
    if (domain === "workers.dev" || emailFrom.endsWith(".workers.dev")) {
      return c.json({ error: "workers.dev addresses cannot send email — use a domain onboarded to Cloudflare Email Sending" }, 400);
    }
  }

  const updates: [SettingKey, string | null][] = [];
  if (token !== undefined) updates.push([SETTING_KEYS.cfApiToken, token]);
  if (accountId !== undefined) updates.push([SETTING_KEYS.cfAccountId, accountId]);
  if (emailFrom !== undefined) updates.push([SETTING_KEYS.emailFrom, emailFrom]);

  for (const [key, value] of updates) {
    await saveSetting(c.env, key, value);
  }

  // Return the fresh state (same shape as GET)
  return handleGetSettings(c);
}

// ─── POST /api/settings/test ──────────────────────────────────────────────────

export async function handleTestSettings(c: Context<{ Bindings: Env }>) {
  const { token, accountId } = await getEffectiveBackendConfig(c.env);

  if (!token || !accountId) {
    return c.json(
      { error: "No API token / account configured — set them in Settings or via the Worker's secret/var" },
      400
    );
  }

  // 1. Token validity (independent of permissions)
  const verify = await cfGet<{ status: string; id: string }>(token, "/user/tokens/verify");
  if (!verify.ok) {
    const status = (verify.status || 502) as ContentfulStatusCode;
    return c.json(
      { error: `Token verification failed: ${verify.error ?? "unknown error"}` },
      status
    );
  }

  // 2. Account accessibility (needs Account Settings: Read)
  const account = await cfGet<{ name?: string }>(token, `/accounts/${accountId}`);
  if (!account.ok) {
    return c.json(
      { error: `Token is valid, but account lookup failed (${account.error ?? "unknown"}). Check the Account ID and the "Account Settings: Read" permission.` },
      400
    );
  }

  // 3. Zone visibility (what the schedule zone picker needs)
  const zones = await cfGetPaged<unknown[]>(
    token,
    `/zones?account.id=${accountId}&per_page=1&page=1&status=active`
  );

  return c.json({
    ok: true,
    result: {
      tokenValid: true,
      accountName: account.data?.name ?? accountId,
      zonesVisible: zones.ok ? (zones.totalCount ?? 0) : null,
      zonesWarning: zones.ok
        ? null
        : `Token cannot list zones (${zones.error ?? "unknown"}) — "Zone: Read" permission is required for AppSec schedules`,
    },
  });
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function maskToken(token: string): string {
  const tail = token.slice(-4);
  return `••••••••${tail}`;
}
