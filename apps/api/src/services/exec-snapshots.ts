/**
 * Opt-in comparison snapshots for scheduled executive summaries.
 *
 * Used ONLY when a schedule has compare_previous = 1. Stores counts and fixed
 * risk codes (no names, hostnames, IPs, emails or tokens). Failures never block
 * a report: the comparison is simply reported as unavailable.
 */

import type { Snapshot } from "./exec-facts";

const KEEP_PER_SCHEDULE = 12;

export async function loadPreviousSnapshot(db: D1Database | undefined, scheduleId: string, product: string): Promise<{ ok: boolean; previous: Snapshot | null }> {
  if (!db) return { ok: false, previous: null };
  try {
    const row = await db.prepare(
      `SELECT generated_at, days, metrics_json, risks_json, period FROM exec_report_snapshots
        WHERE schedule_id = ? AND product = ? ORDER BY generated_at DESC LIMIT 1`
    ).bind(scheduleId, product).first<{ generated_at: string; days: number; metrics_json: string; risks_json: string; period: string | null }>();
    if (!row) return { ok: true, previous: null };
    const metrics = JSON.parse(row.metrics_json) as Record<string, unknown>;
    const risks = JSON.parse(row.risks_json) as unknown;
    const clean: Record<string, number> = {};
    for (const [k, v] of Object.entries(metrics)) if (typeof v === "number" && Number.isFinite(v)) clean[k] = v;
    return { ok: true, previous: { generatedAt: row.generated_at, days: row.days, metrics: clean, risks: Array.isArray(risks) ? risks.filter((r): r is string => typeof r === "string") : [], period: row.period ?? undefined } };
  } catch (e) {
    console.warn("[exec-snapshots] load failed:", e instanceof Error ? e.name : "error");
    return { ok: false, previous: null };
  }
}

/** Call only after a SUCCESSFUL send, so a failed run is never used as the baseline. */
export async function saveSnapshot(db: D1Database | undefined, scheduleId: string, product: string, snapshot: Snapshot): Promise<void> {
  if (!db) return;
  try {
    await db.prepare(
      `INSERT INTO exec_report_snapshots (id, schedule_id, product, generated_at, days, metrics_json, risks_json, period)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(crypto.randomUUID(), scheduleId, product, snapshot.generatedAt, snapshot.days, JSON.stringify(snapshot.metrics), JSON.stringify(snapshot.risks), snapshot.period ?? null).run();
    await db.prepare(
      `DELETE FROM exec_report_snapshots WHERE schedule_id = ? AND id NOT IN (
         SELECT id FROM exec_report_snapshots WHERE schedule_id = ? ORDER BY generated_at DESC LIMIT ?)`
    ).bind(scheduleId, scheduleId, KEEP_PER_SCHEDULE).run();
  } catch (e) {
    console.warn("[exec-snapshots] save failed:", e instanceof Error ? e.name : "error");
  }
}

/** Removes comparison data when a schedule is deleted or opts out. */
export async function deleteSnapshots(db: D1Database | undefined, scheduleId: string): Promise<void> {
  if (!db) return;
  try { await db.prepare("DELETE FROM exec_report_snapshots WHERE schedule_id = ?").bind(scheduleId).run(); }
  catch (e) { console.warn("[exec-snapshots] delete failed:", e instanceof Error ? e.name : "error"); }
}
