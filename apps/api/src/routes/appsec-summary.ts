/**
 * POST /api/appsec-summary
 *
 * The same structured executive summary the scheduled email uses (five sections, topic notes, model credit)
 * plus Cloudflare Radar Zero Wire news, for the on-demand AppSec HTML report. AppSec only for now.
 *
 * The facts are built in code from the report data the browser already has; the models only write wording, and
 * every number is checked against those facts before it is returned.
 */

import type { Context } from "hono";
import type { Env, AppSecData } from "../types";
import { buildExecutiveSummary, creditLine, type ExecutiveSummary } from "../services/exec-summary";
import { appsecFactPack } from "../services/exec-facts";
import { fetchRadarBriefings } from "../services/radar-news";

export interface AppsecSummaryResponse {
  ok: true;
  sections: ExecutiveSummary["sections"];
  credit: string;
  radar: Awaited<ReturnType<typeof fetchRadarBriefings>>;
  generatedAt: string;
}

export async function handleAppsecSummary(c: Context<{ Bindings: Env }>) {
  let body: { appsec?: AppSecData; isPoc?: boolean };
  try { body = await c.req.json(); } catch { return c.json({ error: "Invalid JSON" }, 400); }
  const appsec = body?.appsec;
  if (!appsec?.meta?.zoneName || !appsec.summary) return c.json({ error: "Missing appsec report data" }, 400);

  try {
    const { pack } = appsecFactPack(appsec);
    const [summary, radar] = await Promise.all([
      buildExecutiveSummary(c.env, pack, body.isPoc !== false),
      fetchRadarBriefings().catch(() => ({ ok: false as const, reason: "Radar could not be reached" })),
    ]);
    const response: AppsecSummaryResponse = {
      ok: true,
      sections: summary.sections,
      credit: creditLine(summary),
      radar,
      generatedAt: new Date().toISOString(),
    };
    return c.json(response);
  } catch {
    // Never echo model or upstream detail to the browser.
    return c.json({ error: "The executive summary could not be generated. The report data below is unaffected." }, 502);
  }
}
