/**
 * Scheduled report email runner.
 *
 * A cron trigger fires hourly (see [triggers] in wrangler.toml). The handler
 * finds schedules whose most recent intended occurrence is within GRACE_MS of
 * now, claims each one atomically (double-send guard), then for each: generates
 * the report with the backend-bound CF_API_TOKEN, produces the Workers AI
 * executive summary, renders an email-safe HTML digest, sends it via the EMAIL
 * binding (Cloudflare Email Sending), snapshots the HTML to R2, and records
 * the run in send_history.
 *
 * The grace window also acts as catch-up: if a cron event is delayed or
 * missed entirely, the next hourly fire still triggers the run (up to 90
 * minutes after the intended send time).
 */

import type { Env, ScheduleRow } from "./types";
import { generateAppsecData } from "./routes/fetch-appsec";
import { generateZerotrustData } from "./routes/fetch-zerotrust";
import { generateAiSummary } from "./routes/ai-summary";
import { generateZtSummary } from "./routes/ai-zt-summary";
import {
  applySubjectTokens,
  renderAppsecEmail,
  renderZtEmail,
  type ReportEmailParams,
  type RenderedEmail,
} from "./services/email-template";
import { sendReportEmail } from "./services/send-report-email";
import { getEffectiveBackendConfig } from "./services/settings";

export interface ScheduleRunResult {
  ok: boolean;
  error?: string;
  messageId?: string;
  startedAt: string;
  finishedAt: string;
  recipients: string[];
}

// ─── Cron entrypoint ───────────────────────────────────────────────────────────

export async function scheduled(
  controller: ScheduledController,
  env: Env,
  ctx: ExecutionContext
): Promise<void> {
  const now = new Date();

  let due: ScheduleRow[] = [];
  try {
    const { results } = await env.DB.prepare(
      "SELECT * FROM schedules WHERE enabled = 1"
    ).all<ScheduleRow>();
    due = (results ?? []).filter((row) => isDue(row, now));
  } catch (e) {
    console.error("[scheduler] failed to query schedules:", String(e));
    return;
  }

  // Sequential — each run fans out ~60 Cloudflare API calls.
  for (const row of due) {
    const claimed = await claimSchedule(env, row, now);
    if (!claimed) continue;
    await runSchedule(env, row, "cron");
  }
}

// ─── Due determination ─────────────────────────────────────────────────────────
// A schedule is due when now is within GRACE_MS after its most recent intended
// occurrence. The claim then requires last_run_at < that occurrence — which
// prevents double sends AND lets a delayed/missed cron event still fire on the
// next hourly pass (catch-up).

/** How long after the intended send time a schedule may still fire (catch-up). */
export const GRACE_MS = 90 * 60 * 1000;

/**
 * The most recent intended occurrence of this schedule as a UTC ms timestamp
 * (e.g. weekly "Monday 03:00" with tz GMT+7 → the most recent Monday 03:00
 * in that zone, which is Sunday 20:00 UTC). Returns null for unknown cadences.
 *
 * Weekday / day-of-month are LOCAL days in the schedule's timezone
 * (tz_offset uses the Date#getTimezoneOffset convention: minutes,
 * negative = ahead of UTC).
 */
export function mostRecentOccurrenceMs(row: ScheduleRow, nowMs: number): number | null {
  const tzMin = row.tz_offset ?? 0;
  const tzMs = tzMin * 60 * 1000;

  // Work in the schedule's local wall clock: shift "now" by -tz_offset and
  // read calendar parts through the getUTC* accessors.
  const local = new Date(nowMs - tzMs);
  const nowLocalMs = local.getTime();
  const sendLocalHour = ((row.send_hour_utc - tzMin / 60) % 24 + 24) % 24;
  const atSendHour = (dayStartMs: number): number => dayStartMs + sendLocalHour * 60 * 60 * 1000;
  const daysInMonth = (year: number, month: number): number =>
    new Date(Date.UTC(year, month + 1, 0)).getUTCDate();

  let candidateLocalMs: number;

  switch (row.frequency) {
    case "daily": {
      const todayStart = Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate());
      candidateLocalMs = atSendHour(todayStart);
      if (candidateLocalMs > nowLocalMs) candidateLocalMs -= 24 * 60 * 60 * 1000;
      break;
    }
    case "weekly": {
      const daysBack = (local.getUTCDay() - (row.day_of_week ?? 0) + 7) % 7;
      const dayStart = Date.UTC(local.getUTCFullYear(), local.getUTCMonth(), local.getUTCDate() - daysBack);
      candidateLocalMs = atSendHour(dayStart);
      if (candidateLocalMs > nowLocalMs) candidateLocalMs -= 7 * 24 * 60 * 60 * 1000;
      break;
    }
    case "monthly": {
      const dom = row.day_of_month ?? 1;
      let year = local.getUTCFullYear();
      let month = local.getUTCMonth();
      candidateLocalMs = atSendHour(Date.UTC(year, month, Math.min(dom, daysInMonth(year, month))));
      if (candidateLocalMs > nowLocalMs) {
        // This month's occurrence hasn't happened yet — use last month's
        // (day_of_month clamped to that month's length).
        month -= 1;
        if (month < 0) { month = 11; year -= 1; }
        candidateLocalMs = atSendHour(Date.UTC(year, month, Math.min(dom, daysInMonth(year, month))));
      }
      break;
    }
    default:
      return null;
  }

  // Convert the local wall-clock occurrence back to a real UTC timestamp.
  return candidateLocalMs + tzMs;
}

export function isDue(row: ScheduleRow, now: Date): boolean {
  if (row.enabled !== 1) return false;
  const occ = mostRecentOccurrenceMs(row, now.getTime());
  if (occ === null) return false;
  const elapsed = now.getTime() - occ;
  return elapsed >= 0 && elapsed <= GRACE_MS;
}

// ─── Double-send guard ─────────────────────────────────────────────────────────
// Claims the schedule for its current occurrence: last_run_at is set before the
// run so a retried cron event, an overlapping isolate, or a late catch-up fire
// cannot send twice for the same occurrence.

async function claimSchedule(env: Env, row: ScheduleRow, now: Date): Promise<boolean> {
  const occ = mostRecentOccurrenceMs(row, now.getTime());
  if (occ === null) return false;

  const res = await env.DB.prepare(
    `UPDATE schedules
        SET last_run_at = ?, last_status = 'sending', updated_at = ?
      WHERE id = ? AND (last_run_at IS NULL OR last_run_at < ?)`
  )
    .bind(now.toISOString(), now.toISOString(), row.id, new Date(occ).toISOString())
    .run();

  return (res.meta.changes ?? 0) > 0;
}

// ─── Run one schedule (cron or manual "send test now") ────────────────────────

export async function runSchedule(
  env: Env,
  row: ScheduleRow,
  trigger: "cron" | "manual"
): Promise<ScheduleRunResult> {
  const startedAt = new Date().toISOString();
  const recipients = safeParseRecipients(row.recipients);

  let ok = false;
  let error: string | undefined;
  let messageId: string | undefined;

  try {
    // Credentials resolve dashboard settings (D1) first, then the Worker's
    // env secret/var — a token rotated in Settings applies on the next run.
    const { token, accountId, emailFrom } = await getEffectiveBackendConfig(env);
    if (!token || !accountId) {
      throw new Error(
        "No API token / account configured — set them in Scheduled Reports → Settings, or via the CF_API_TOKEN secret + CF_ACCOUNT_ID var"
      );
    }

    const isPoc = row.is_poc === 1;
    const tzOffset = row.tz_offset ?? 0;

    let rendered: RenderedEmail;
    let subject: string;

    if (row.report_type === "appsec") {
      if (!row.zone_id) throw new Error("AppSec schedule has no zone configured");
      const appsec = await generateAppsecData({
        token,
        zoneId: row.zone_id,
        accountId,
        days: row.days,
        tzOffset,
      });
      const aiSummary = await generateAiSummary(env, appsec, isPoc).catch((e) => {
        console.warn("[scheduler] AI summary failed, sending without it:", String(e));
        return "";
      });
      const params: ReportEmailParams = {
        scheduleName: row.name,
        message: row.message ?? "",
        isPoc,
        clientName: row.client_name,
        aiSummary,
      };
      rendered = renderAppsecEmail(appsec, params);
      subject = applySubjectTokens(row.subject, { zone: appsec.meta?.zoneName });
    } else {
      const zt = await generateZerotrustData({ token, accountId, days: row.days, tzOffset });
      const aiSummary = await generateZtSummary(env, zt, isPoc).catch((e) => {
        console.warn("[scheduler] AI summary failed, sending without it:", String(e));
        return "";
      });
      const params: ReportEmailParams = {
        scheduleName: row.name,
        message: row.message ?? "",
        isPoc,
        clientName: row.client_name,
        aiSummary,
      };
      rendered = renderZtEmail(zt, params);
      subject = applySubjectTokens(row.subject, { account: zt.meta?.accountName });
    }

    const sendResult = await sendReportEmail(env, {
      to: recipients,
      subject,
      html: rendered.html,
      text: rendered.text,
      from: emailFrom,
    });
    ok = sendResult.ok;
    error = sendResult.error;
    messageId = sendResult.messageId;

    // Archive what was generated (even if the send failed — useful for debugging)
    await saveSnapshot(env, row, rendered.html).catch((e) => {
      console.warn("[scheduler] snapshot save failed:", String(e));
    });
  } catch (e) {
    ok = false;
    error = e instanceof Error ? e.message : String(e);
    console.error(`[scheduler] run failed for "${row.name}":`, error);
  }

  const finishedAt = new Date().toISOString();

  await env.DB.prepare(
    `INSERT INTO send_history (id, schedule_id, started_at, finished_at, status, trigger, error, recipients, message_id)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(
      crypto.randomUUID(),
      row.id,
      startedAt,
      finishedAt,
      ok ? "success" : "error",
      trigger,
      error ?? null,
      JSON.stringify(recipients),
      messageId ?? null
    )
    .run();

  // Record the outcome on the schedule row for BOTH triggers (cron and
  // manual) — the dashboard card shows the latest status either way.
  // last_run_at is used by the claim as "already ran for this occurrence":
  // a manual run before the occurrence doesn't block the scheduled one
  // (08:55 < 09:00), a manual run after it suppresses a redundant catch-up.
  await env.DB.prepare(
    `UPDATE schedules SET last_run_at = ?, last_status = ?, last_error = ? WHERE id = ?`
  )
    .bind(finishedAt, ok ? "success" : "error", error ?? null, row.id)
    .run();

  return { ok, error, messageId, startedAt, finishedAt, recipients };
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function safeParseRecipients(json: string): string[] {
  try {
    const parsed = JSON.parse(json) as unknown;
    return Array.isArray(parsed) ? parsed.filter((r): r is string => typeof r === "string") : [];
  } catch {
    return [];
  }
}

async function saveSnapshot(env: Env, row: ScheduleRow, html: string): Promise<void> {
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const key = `scheduled/${row.id}/${ts}.html`;
  await env.AUDIT_BUCKET.put(key, html, {
    httpMetadata: { contentType: "text/html; charset=utf-8" },
    customMetadata: {
      // Compatible with the /api/audit listing fields
      email: "scheduled",
      hostname: `scheduled-${row.report_type}`,
      zoneName: row.zone_name ?? "",
      days: String(row.days),
      generatedAt: ts,
    },
  });
}
