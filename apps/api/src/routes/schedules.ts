/**
 * Scheduled report configuration — CRUD + manual test send + history.
 *
 *   GET    /api/schedules             — list all schedules
 *   POST   /api/schedules             — create a schedule
 *   PUT    /api/schedules/:id         — update a schedule (full replacement)
 *   DELETE /api/schedules/:id         — delete a schedule
 *   POST   /api/schedules/:id/send    — generate + send now (test)
 *   GET    /api/schedules/:id/history — recent runs
 *
 * The dashboard only manages configuration — the Cloudflare API token used
 * for generation is bound on the backend (CF_API_TOKEN secret), never sent
 * from the client.
 */

import type { Context } from "hono";
import type { Env, ScheduleRow, ScheduleConfig, ScheduleReportType, ScheduleFrequency } from "../types";
import { runSchedule } from "../scheduler";

const ALLOWED_DAYS = [1, 3, 5, 7, 14, 30];
const MAX_RECIPIENTS = 50; // Cloudflare Email Sending limit (to + cc + bcc)
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ─── Row → API shape ──────────────────────────────────────────────────────────

function rowToConfig(row: ScheduleRow): ScheduleConfig {
  let recipients: string[] = [];
  try {
    const parsed = JSON.parse(row.recipients) as unknown;
    if (Array.isArray(parsed)) recipients = parsed.filter((r): r is string => typeof r === "string");
  } catch { /* keep [] */ }

  return {
    id: row.id,
    name: row.name,
    reportType: row.report_type,
    zoneId: row.zone_id,
    zoneName: row.zone_name,
    days: row.days,
    tzOffset: row.tz_offset,
    frequency: row.frequency,
    dayOfWeek: row.day_of_week,
    dayOfMonth: row.day_of_month,
    sendHourUtc: row.send_hour_utc,
    recipients,
    subject: row.subject,
    message: row.message,
    isPoc: row.is_poc === 1,
    clientName: row.client_name,
    enabled: row.enabled === 1,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    lastRunAt: row.last_run_at,
    lastStatus: row.last_status,
    lastError: row.last_error,
  };
}

// ─── Input validation (create + update) ────────────────────────────────────────

interface ValidatedSchedule {
  name: string;
  reportType: ScheduleReportType;
  zoneId: string | null;
  zoneName: string | null;
  days: number;
  tzOffset: number;
  frequency: ScheduleFrequency;
  dayOfWeek: number | null;
  dayOfMonth: number | null;
  sendHourUtc: number;
  recipients: string;
  subject: string;
  message: string;
  isPoc: number;
  clientName: string | null;
  enabled: number;
}

function validateSchedule(body: unknown): { data?: ValidatedSchedule; error?: string } {
  if (!body || typeof body !== "object") return { error: "Missing request body" };
  const b = body as Record<string, unknown>;

  const name = typeof b.name === "string" ? b.name.trim() : "";
  if (!name || name.length > 120) return { error: "name is required (max 120 chars)" };

  const reportType = b.reportType;
  if (reportType !== "appsec" && reportType !== "zero-trust")
    return { error: "reportType must be 'appsec' or 'zero-trust'" };

  let zoneId: string | null = null;
  let zoneName: string | null = null;
  if (reportType === "appsec") {
    if (typeof b.zoneId !== "string" || !/^[a-f0-9]{32}$/i.test(b.zoneId))
      return { error: "zoneId (32-char hex) is required for appsec schedules" };
    zoneId = b.zoneId.toLowerCase();
    if (b.zoneName !== undefined && b.zoneName !== null) {
      if (typeof b.zoneName !== "string" || b.zoneName.length > 255)
        return { error: "zoneName must be a string (max 255 chars)" };
      zoneName = b.zoneName.trim() || null;
    }
  }

  const days = b.days;
  if (typeof days !== "number" || !ALLOWED_DAYS.includes(days))
    return { error: `days must be one of ${ALLOWED_DAYS.join(", ")}` };

  let tzOffset = 0;
  if (b.tzOffset !== undefined) {
    if (typeof b.tzOffset !== "number" || !isFinite(b.tzOffset)) return { error: "tzOffset must be a number" };
    tzOffset = Math.max(-840, Math.min(840, Math.round(b.tzOffset)));
  }

  const frequency = b.frequency;
  if (frequency !== "daily" && frequency !== "weekly" && frequency !== "monthly")
    return { error: "frequency must be 'daily', 'weekly' or 'monthly'" };

  let dayOfWeek: number | null = null;
  let dayOfMonth: number | null = null;
  if (frequency === "weekly") {
    if (typeof b.dayOfWeek !== "number" || b.dayOfWeek < 0 || b.dayOfWeek > 6 || !Number.isInteger(b.dayOfWeek))
      return { error: "dayOfWeek (0-6, Sunday=0) is required for weekly schedules" };
    dayOfWeek = b.dayOfWeek;
  } else if (frequency === "monthly") {
    if (typeof b.dayOfMonth !== "number" || b.dayOfMonth < 1 || b.dayOfMonth > 28 || !Number.isInteger(b.dayOfMonth))
      return { error: "dayOfMonth (1-28) is required for monthly schedules" };
    dayOfMonth = b.dayOfMonth;
  }

  if (typeof b.sendHourUtc !== "number" || b.sendHourUtc < 0 || b.sendHourUtc > 23 || !Number.isInteger(b.sendHourUtc))
    return { error: "sendHourUtc must be an integer 0-23" };
  const sendHourUtc = b.sendHourUtc;

  if (!Array.isArray(b.recipients) || b.recipients.length === 0)
    return { error: "recipients must be a non-empty array" };
  if (b.recipients.length > MAX_RECIPIENTS)
    return { error: `maximum ${MAX_RECIPIENTS} recipients per schedule` };
  const seen = new Set<string>();
  for (const r of b.recipients) {
    if (typeof r !== "string") return { error: "recipients must be strings" };
    const email = r.trim().toLowerCase();
    if (!EMAIL_RE.test(email)) return { error: `invalid recipient address: ${r}` };
    seen.add(email);
  }
  const recipients = JSON.stringify(Array.from(seen));

  const subject = typeof b.subject === "string" ? b.subject.trim() : "";
  if (!subject || subject.length > 200) return { error: "subject is required (max 200 chars)" };

  const message = typeof b.message === "string" ? b.message : "";
  if (message.length > 5000) return { error: "message must be max 5000 chars" };

  let clientName: string | null = null;
  if (b.clientName !== undefined && b.clientName !== null) {
    if (typeof b.clientName !== "string" || b.clientName.length > 200)
      return { error: "clientName must be a string (max 200 chars)" };
    clientName = b.clientName.trim() || null;
  }

  const isPoc = b.isPoc === undefined ? true : b.isPoc !== false;
  const enabled = b.enabled === undefined ? true : b.enabled !== false;

  return {
    data: {
      name, reportType, zoneId, zoneName, days, tzOffset, frequency,
      dayOfWeek, dayOfMonth, sendHourUtc, recipients, subject, message,
      isPoc: isPoc ? 1 : 0, clientName, enabled: enabled ? 1 : 0,
    },
  };
}

// ─── GET /api/schedules ────────────────────────────────────────────────────────

export async function handleListSchedules(c: Context<{ Bindings: Env }>) {
  const { results } = await c.env.DB.prepare(
    "SELECT * FROM schedules ORDER BY created_at DESC"
  ).all<ScheduleRow>();

  const schedules = (results ?? []).map(rowToConfig);
  return c.json({ ok: true, schedules });
}

// ─── POST /api/schedules ───────────────────────────────────────────────────────

export async function handleCreateSchedule(c: Context<{ Bindings: Env }>) {
  let body: unknown;
  try { body = await c.req.json(); } catch { return c.json({ error: "Invalid JSON body" }, 400); }

  const { data, error } = validateSchedule(body);
  if (!data) return c.json({ error }, 400);

  const now = new Date().toISOString();
  const id = crypto.randomUUID();

  await c.env.DB.prepare(
    `INSERT INTO schedules
       (id, name, report_type, zone_id, zone_name, days, tz_offset, frequency,
        day_of_week, day_of_month, send_hour_utc, recipients, subject, message,
        is_poc, client_name, enabled, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      id, data.name, data.reportType, data.zoneId, data.zoneName, data.days,
      data.tzOffset, data.frequency, data.dayOfWeek, data.dayOfMonth,
      data.sendHourUtc, data.recipients, data.subject, data.message,
      data.isPoc, data.clientName, data.enabled, now, now
    )
    .run();

  const row = await getScheduleRow(c.env, id);
  if (!row) return c.json({ error: "Failed to create schedule" }, 500);
  return c.json({ ok: true, schedule: rowToConfig(row) }, 201);
}

// ─── PUT /api/schedules/:id ────────────────────────────────────────────────────

export async function handleUpdateSchedule(c: Context<{ Bindings: Env }>) {
  const id = c.req.param("id") ?? "";
  const existing = await getScheduleRow(c.env, id);
  if (!existing) return c.json({ error: "Schedule not found" }, 404);

  let body: unknown;
  try { body = await c.req.json(); } catch { return c.json({ error: "Invalid JSON body" }, 400); }

  const { data, error } = validateSchedule(body);
  if (!data) return c.json({ error }, 400);

  const now = new Date().toISOString();
  await c.env.DB.prepare(
    `UPDATE schedules SET
       name = ?, report_type = ?, zone_id = ?, zone_name = ?, days = ?, tz_offset = ?,
       frequency = ?, day_of_week = ?, day_of_month = ?, send_hour_utc = ?,
       recipients = ?, subject = ?, message = ?, is_poc = ?, client_name = ?,
       enabled = ?, updated_at = ?
     WHERE id = ?`
  )
    .bind(
      data.name, data.reportType, data.zoneId, data.zoneName, data.days, data.tzOffset,
      data.frequency, data.dayOfWeek, data.dayOfMonth, data.sendHourUtc,
      data.recipients, data.subject, data.message, data.isPoc, data.clientName,
      data.enabled, now, id
    )
    .run();

  const row = await getScheduleRow(c.env, id);
  if (!row) return c.json({ error: "Schedule not found" }, 404);
  return c.json({ ok: true, schedule: rowToConfig(row) });
}

// ─── DELETE /api/schedules/:id ─────────────────────────────────────────────────

export async function handleDeleteSchedule(c: Context<{ Bindings: Env }>) {
  const id = c.req.param("id") ?? "";
  const res = await c.env.DB.prepare("DELETE FROM schedules WHERE id = ?").bind(id).run();
  if ((res.meta.changes ?? 0) === 0) return c.json({ error: "Schedule not found" }, 404);
  // Keep send_history rows as an audit trail; they reference schedule_id only.
  return c.json({ ok: true });
}

// ─── POST /api/schedules/:id/send — generate + send immediately ─────────────────

export async function handleSendNow(c: Context<{ Bindings: Env }>) {
  const id = c.req.param("id") ?? "";
  const row = await getScheduleRow(c.env, id);
  if (!row) return c.json({ error: "Schedule not found" }, 404);

  const result = await runSchedule(c.env, row, "manual");
  if (!result.ok) return c.json({ ok: false, error: result.error ?? "Send failed" }, 502);
  return c.json({ ok: true, messageId: result.messageId, finishedAt: result.finishedAt });
}

// ─── GET /api/schedules/:id/history ────────────────────────────────────────────

export async function handleScheduleHistory(c: Context<{ Bindings: Env }>) {
  const id = c.req.param("id") ?? "";
  const { results } = await c.env.DB.prepare(
    "SELECT * FROM send_history WHERE schedule_id = ? ORDER BY started_at DESC LIMIT 20"
  )
    .bind(id)
    .all();

  const history = (results ?? []).map((r) => ({
    id: r.id as string,
    scheduleId: r.schedule_id as string,
    startedAt: r.started_at as string,
    finishedAt: (r.finished_at ?? null) as string | null,
    status: r.status as string,
    trigger: r.trigger as string,
    error: (r.error ?? null) as string | null,
    messageId: (r.message_id ?? null) as string | null,
  }));

  return c.json({ ok: true, history });
}

// ─── Shared ────────────────────────────────────────────────────────────────────

async function getScheduleRow(env: Env, id: string): Promise<ScheduleRow | null> {
  const row = await env.DB.prepare("SELECT * FROM schedules WHERE id = ?")
    .bind(id)
    .first<ScheduleRow>();
  return row ?? null;
}
