/**
 * GET /api/schedule/zones
 * Lists zones for the schedule dashboard's zone picker using the backend-bound
 * CF_API_TOKEN + CF_ACCOUNT_ID — the client never supplies (or sees) the token.
 */

import type { Context } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import type { Env } from "../types";
import { cfGet } from "../services/cf-rest";
import { getEffectiveBackendConfig } from "../services/settings";

interface CfZone {
  id: string;
  name: string;
  status: string;
  plan: { name: string };
}

export async function handleScheduleZones(c: Context<{ Bindings: Env }>) {
  const { token, accountId } = await getEffectiveBackendConfig(c.env);

  if (!token || !accountId) {
    return c.json(
      {
        error:
          "Backend credentials not configured. Set the API token and account in Scheduled Reports → Settings (or the CF_API_TOKEN secret + CF_ACCOUNT_ID var on the Worker).",
      },
      503
    );
  }

  const res = await cfGet<CfZone[]>(
    token,
    `/zones?account.id=${accountId}&per_page=200&page=1&status=active`
  );

  if (!res.ok) {
    const status = (res.status || 502) as ContentfulStatusCode;
    return c.json({ error: res.error ?? "Failed to list zones" }, status);
  }

  const zones = (res.data ?? []).map((z) => ({
    id: z.id,
    name: z.name,
    status: z.status,
    plan: z.plan?.name ?? "Unknown",
  }));

  return c.json({ ok: true, zones, accountId });
}
