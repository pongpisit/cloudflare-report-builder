import type {
  AppSecData, ZeroTrustData, ReportInput, ZoneOption,
  ScheduleConfig, ScheduleInput, ScheduleHistoryEntry,
  BackendSettingsState, BackendSettingsUpdate,
  RemediationItem, RemediationStatus,
  CasbFindingItem, CasbFindingStatus,
  AlertTrackingItem, AlertTrackingStatus,
} from "../types";

// In production, the Pages Function at /functions/api/[[path]].ts proxies
// all /api/* requests to the Worker — same origin, no CORS, no hardcoded URL.
// In dev, Vite's proxy (vite.config.ts) forwards /api → wrangler dev on :8787.
const API_BASE = import.meta.env.VITE_API_URL ?? "";

async function post<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    throw new Error((err as { error?: string }).error ?? `HTTP ${res.status}`);
  }

  return res.json() as Promise<T>;
}

async function request<T>(path: string, method: "GET" | "PUT" | "PATCH" | "DELETE", body?: unknown): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: body !== undefined ? { "Content-Type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
    throw new Error((err as { error?: string }).error ?? `HTTP ${res.status}`);
  }

  return res.json() as Promise<T>;
}

export async function fetchZones(token: string, accountId: string): Promise<ZoneOption[]> {
  const result = await post<{ ok: boolean; zones: ZoneOption[] }>("/api/zones", {
    token,
    accountId,
  });
  return result.zones;
}

export async function fetchAppsecData(input: ReportInput): Promise<AppSecData> {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { clientLogo: _logo, ...apiInput } = input;
  const result = await post<{ ok: boolean; appsec: AppSecData }>("/api/appsec", apiInput);
  return result.appsec;
}

export async function fetchZeroTrustData(input: ReportInput): Promise<ZeroTrustData> {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { clientLogo: _logo, zoneId: _zone, ...apiInput } = input;
  const result = await post<{ ok: boolean; zerotrust: ZeroTrustData }>("/api/zerotrust", apiInput);
  return result.zerotrust;
}

export async function fetchAiSummary(appsec: AppSecData, isPoc = true): Promise<string> {
  const result = await post<{ ok: boolean; summary: string }>("/api/summary", { appsec, isPoc });
  return result.summary;
}

/**
 * Returns the email of the logged-in user from Cloudflare Access.
 * The Pages Function reads the CF_Authorization JWT (Warp/Gateway policy)
 * or the Cf-Access-Authenticated-User-Email header (identity policy).
 */
export async function fetchUserEmail(): Promise<string | null> {
  try {
    const res = await fetch(`${API_BASE}/api/me`);
    if (!res.ok) return null;
    const data = await res.json() as { ok: boolean; email: string | null };
    return data.email ?? null;
  } catch {
    return null;
  }
}

/**
 * Save a rendered HTML report to the R2 audit bucket.
 * Key format: {email}_{hostname}_{timestamp}.html
 */
export interface AuditReportMeta {
  key: string;
  size: number;
  uploaded: string;
  email: string;
  hostname: string;
  zoneName: string;
  days: string;
  generatedAt: string;
}

/**
 * List all saved audit reports from R2.
 */
export async function fetchAuditList(): Promise<AuditReportMeta[]> {
  try {
    const res = await fetch(`${API_BASE}/api/audit`);
    if (!res.ok) return [];
    const data = await res.json() as { ok: boolean; reports: AuditReportMeta[] };
    return data.reports ?? [];
  } catch {
    return [];
  }
}

export async function saveAuditReport(params: {
  email: string;
  hostname: string;
  zoneName: string;
  days: number;
  generatedAt: string;
  html: string;
}): Promise<{ key: string } | null> {
  try {
    const res = await fetch(`${API_BASE}/api/audit`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(params),
    });
    if (!res.ok) return null;
    const data = await res.json() as { ok: boolean; key: string };
    return { key: data.key };
  } catch {
    return null;
  }
}

// ─── Scheduled Reports ────────────────────────────────────────────────────────

/**
 * Zone list for the schedule dashboard's picker. Uses the backend-bound
 * CF_API_TOKEN + CF_ACCOUNT_ID — the client sends no credentials.
 */
export async function fetchScheduleZones(): Promise<ZoneOption[]> {
  const result = await request<{ ok: boolean; zones: ZoneOption[]; accountId: string }>(
    "/api/schedule/zones",
    "GET"
  );
  return result.zones;
}

export async function listSchedules(): Promise<ScheduleConfig[]> {
  const result = await request<{ ok: boolean; schedules: ScheduleConfig[] }>("/api/schedules", "GET");
  return result.schedules;
}

export async function createSchedule(input: ScheduleInput): Promise<ScheduleConfig> {
  const result = await post<{ ok: boolean; schedule: ScheduleConfig }>("/api/schedules", input);
  return result.schedule;
}

export async function updateSchedule(id: string, input: ScheduleInput): Promise<ScheduleConfig> {
  const result = await request<{ ok: boolean; schedule: ScheduleConfig }>(
    `/api/schedules/${id}`,
    "PUT",
    input
  );
  return result.schedule;
}

export async function deleteSchedule(id: string): Promise<void> {
  await request<{ ok: boolean }>(`/api/schedules/${id}`, "DELETE");
}

/** Trigger an immediate generation + send (full report — heavy). */
export async function sendScheduleNow(id: string): Promise<void> {
  await post<{ ok: boolean }>(`/api/schedules/${id}/send`, {});
}

export async function fetchScheduleHistory(id: string): Promise<ScheduleHistoryEntry[]> {
  const result = await request<{ ok: boolean; history: ScheduleHistoryEntry[] }>(
    `/api/schedules/${id}/history`,
    "GET"
  );
  return result.history;
}

// ─── Backend Settings ─────────────────────────────────────────────────────────

/** Current backend config state — the token itself is never returned. */
export async function fetchBackendSettings(): Promise<BackendSettingsState> {
  const result = await request<{ ok: boolean; settings: BackendSettingsState }>("/api/settings", "GET");
  return result.settings;
}

/**
 * Update backend settings. Omitted fields are left unchanged; null clears a
 * value so the Worker's env secret/var becomes the active fallback again.
 */
export async function saveBackendSettings(
  update: BackendSettingsUpdate
): Promise<BackendSettingsState> {
  const result = await request<{ ok: boolean; settings: BackendSettingsState }>("/api/settings", "PUT", update);
  return result.settings;
}

export interface ConnectionTestResult {
  tokenValid: boolean;
  accountName?: string;
  zonesVisible?: number | null;
  zonesWarning?: string | null;
}

/** Validates the effective token + account against the Cloudflare API. */
export async function testBackendConnection(): Promise<ConnectionTestResult> {
  const result = await post<{ ok: boolean; result: ConnectionTestResult }>("/api/settings/test", {});
  return result.result;
}

// ─── Zero Trust Remediation Register ──────────────────────────────────────────

/** Re-fetches the current register for an account — used after a status/owner
 *  change so the report reflects the persisted state without a full re-run. */
export async function fetchRemediationRegister(accountId: string): Promise<RemediationItem[]> {
  const result = await request<{ ok: boolean; items: RemediationItem[] }>(
    `/api/remediation?accountId=${encodeURIComponent(accountId)}`,
    "GET"
  );
  return result.items;
}

export async function updateRemediationItem(
  id: string,
  update: { status?: RemediationStatus; ownerEmail?: string | null; dueDate?: string | null }
): Promise<RemediationItem> {
  const result = await request<{ ok: boolean; item: RemediationItem }>(
    `/api/remediation/${id}`,
    "PATCH",
    update
  );
  return result.item;
}

// ─── CASB Finding Register ─────────────────────────────────────────────────────

export async function fetchCasbFindingRegister(accountId: string): Promise<CasbFindingItem[]> {
  const result = await request<{ ok: boolean; items: CasbFindingItem[] }>(
    `/api/casb-findings?accountId=${encodeURIComponent(accountId)}`,
    "GET"
  );
  return result.items;
}

export async function updateCasbFindingItem(
  id: string,
  update: { status?: CasbFindingStatus; ownerEmail?: string | null; dueDate?: string | null }
): Promise<CasbFindingItem> {
  const result = await request<{ ok: boolean; item: CasbFindingItem }>(
    `/api/casb-findings/${id}`,
    "PATCH",
    update
  );
  return result.item;
}

// ─── Alert Investigation Register ──────────────────────────────────────────────

export async function fetchAlertRegister(accountId: string): Promise<AlertTrackingItem[]> {
  const result = await request<{ ok: boolean; items: AlertTrackingItem[] }>(
    `/api/alert-register?accountId=${encodeURIComponent(accountId)}`,
    "GET"
  );
  return result.items;
}

export async function updateAlertItem(
  id: string,
  update: { status?: AlertTrackingStatus; ownerEmail?: string | null; dueDate?: string | null }
): Promise<AlertTrackingItem> {
  const result = await request<{ ok: boolean; item: AlertTrackingItem }>(
    `/api/alert-register/${id}`,
    "PATCH",
    update
  );
  return result.item;
}
