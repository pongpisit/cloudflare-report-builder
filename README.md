# Cloudflare POC Report Builder

Generate polished, data-rich PDF/HTML reports straight from live Cloudflare
analytics — either a **Security (AppSec) report** for a single zone, or a
**Zero Trust / Cloudflare One report** for an account — complete with an
AI-written executive summary, charts, and prioritized recommendations. Built
entirely as a Cloudflare Worker + static frontend: no external servers, no
database to manage beyond Cloudflare's own D1/R2.

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/pongpisit/cf-poc-report-builder)

> Built for Cloudflare partners, SEs, and customers who want a Proof-of-Concept
> or recurring security assessment report generated from *real* Cloudflare
> data — not a mock-up. Every metric in every report traces back to a live
> GraphQL Analytics or REST API call.

---

## What it does

Paste in a Cloudflare API token (yours, scoped read-only, never stored) and
generate:

- **AppSec report** (per zone) — WAF, DDoS, Bot Management, DNS, Cache/CDN,
  SSL/TLS, Rate Limiting, API Shield, Page Shield, Email Security (SPF/DKIM/DMARC),
  AI Crawl Control, AI Security for Apps (prompt injection / PII / unsafe
  topics), Leaked Credential Check, Content Scanning, and a computed Security
  Posture Score — 20+ sections in total.
- **Zero Trust / Cloudflare One report** (per account) — Access apps &
  policies, authentication events & anomalies, Gateway DNS/HTTP/Network (L4)
  filtering with real session health & top Cloudflare locations, Shadow IT
  discovery (SaaS + Private Network), Generative AI usage (via Cloudflare's
  own category classification, not keyword guessing), WARP device posture
  with real online/offline status, Tunnel health, DLP & CASB findings, and a
  Zero Trust posture score. Mirrors the layout of Cloudflare's own **Zero
  Trust → Insights → Dashboards** catalog.
- An **AI executive summary** (Workers AI) for both report types, with
  distinct wording for a "Proof-of-Concept" pitch vs. a neutral recurring
  "Assessment" report.
- Optional **scheduled email delivery** (daily/weekly/monthly) of either
  report type via Cloudflare Email Sending, with a full run history.
- An **audit archive** of every generated report (R2), listable and
  re-viewable later.

**No mock data, ever.** Every chart is backed by a real Cloudflare GraphQL
Analytics dataset or REST endpoint (documented inline in the source next to
every fetcher). Where a metric genuinely can't be sourced from a real
Cloudflare API, the report shows an honest empty state instead of a
fabricated number — see the extensive comments throughout `apps/api/src/services/`.

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │   Cloudflare Worker (Hono)               │
   User's browser   │   apps/api/src/index.ts                  │
  ───────────────── │                                          │
  GET  /            │   [assets] → serves apps/web/dist (SPA)  │
  GET  /api/*  ──────►  REST + GraphQL fetchers → Cloudflare API│
  GET  /health       │   D1 (schedules/settings)  R2 (audit)   │
                    │   Workers AI (executive summary)         │
                    │   Cron (hourly) → scheduled email digest │
                    └─────────────────────────────────────────┘
```

By default the **same Worker serves both the API and the built frontend**
(via [Workers static assets](https://developers.cloudflare.com/workers/static-assets/)) —
one deploy, one URL, no CORS to configure. A separate-Pages-project topology
is also supported; see [Alternative: separate Pages frontend](#alternative-separate-pages-frontend).

**Stack:** Hono (API), React + Vite + Tailwind + Recharts (frontend), D1
(schedule config + history), R2 (audit archive), Workers AI (summaries),
Cloudflare Email Sending (scheduled digests), cron triggers.

---

## Quick start — Deploy to Cloudflare

Click the button above. Cloudflare will fork this repo into your GitHub
account, provision a D1 database + R2 bucket, bind Workers AI, and deploy
the Worker (which also serves the frontend). That's the whole report
builder — interactive AppSec + Zero Trust reports work immediately with no
further setup, since you supply your own Cloudflare API token directly in
the UI for those.

### Post-deploy steps (optional — only for scheduled email reports)

Scheduled reports need a backend-bound token and sender email, since the
cron job runs with nobody in the browser to supply a token interactively.

```bash
# 1. Bind a Cloudflare API token the scheduler will use to generate reports
#    (same permissions as the interactive report builder — see tables below).
#    The dashboard's Settings page can also set/rotate this without a redeploy.
npx wrangler secret put CF_API_TOKEN

# 2. Set the account the scheduled reports are generated from, and onboard a
#    sending domain for Cloudflare Email Sending.
npx wrangler email sending enable yourdomain.com
```

Then set `CF_ACCOUNT_ID` and `EMAIL_FROM` either in `wrangler.toml`'s
`[vars]` (requires a redeploy) or in the app's **Settings** dashboard
(applies instantly, no redeploy — see `apps/api/src/services/settings.ts`).

### ⚠️ Protect the dashboard before going further

The **Scheduled Reports** and **Settings** pages are **not authenticated by
design** — anyone who can reach your Worker's URL can view/change schedule
configuration and the masked settings state (never the raw token — see
[Security](#security)). Put this Worker behind
[Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
before sharing the URL with anyone but yourself. `/api/me` already reads the
Access-authenticated user's email for you once Access is in front.

---

## Manual deployment (alternative to the button)

```bash
git clone https://github.com/<you>/cf-poc-report-builder.git
cd cf-poc-report-builder
npm install

# One-time: create the D1 database and record its ID locally (never committed)
npx wrangler d1 create poc-report-schedules
cp wrangler.local.example.toml wrangler.local.toml
# → paste the returned database_id into wrangler.local.toml

npm run deploy   # builds the frontend, runs D1 migrations, deploys the Worker
```

`npm run deploy` (see `scripts/deploy.sh`) automatically uses
`wrangler.local.toml` instead of the committed `wrangler.toml` template when
present — this is how you can keep redeploying to your own already-provisioned
resources without ever committing their IDs to git.

---

## Local development

```bash
npm install

# Terminal 1 — Worker API + assets (uses wrangler.local.toml if present)
npm run dev:api          # wrangler dev, http://localhost:8787

# Terminal 2 — Vite dev server with hot reload (proxies /api → :8787)
npm run dev:web          # http://localhost:5173
```

Regenerate `worker-configuration.d.ts` (ambient `Env` types) after editing
`wrangler.toml`:

```bash
npm run cf-typegen
```

---

## Security

- **Interactive reports**: your API token is sent once per report-generation
  request, held only in memory for that request, and never written to D1,
  R2, or logs. Nothing is stored server-side unless you explicitly click
  "Save to Audit Archive" (which stores the *rendered report HTML*, not the
  token).
- **Scheduled reports**: the token used by the cron job is either a Worker
  secret (`CF_API_TOKEN`, set via `wrangler secret put`, never readable back
  out) or stored in D1 via the Settings dashboard (masked in every API
  response — only a `••••1234`-style hint is ever returned, never the full
  value).
- **Unauthenticated by design, protect it yourself**: `/api/schedules/*` and
  `/api/settings/*` have no built-in auth check — they're meant to sit behind
  [Cloudflare Access](https://developers.cloudflare.com/cloudflare-one/access-controls/policies/)
  (or an equivalent) in front of the Worker. `/api/me` reads the
  `Cf-Access-Authenticated-User-Email` header / `CF_Authorization` JWT cookie
  if Access is configured, purely for attribution in the audit archive — it
  is **not** an authorization check.
- **Rate limiting**: the expensive routes (`/api/appsec`, `/api/zerotrust`,
  `/api/summary`, `/api/zt-summary`, `/api/schedules/:id/send`,
  `/api/settings/test`) are capped at 50 requests / 5 minutes per source IP
  (in-memory, per-isolate — a coarse guard, not a substitute for Access).

---

## Cloudflare API token permissions

Create a token at **My Profile → API Tokens → Create Token → Custom Token**.
"Optional" permissions unlock specific sections; the report renders fine
without them (that section just shows an honest empty state).

### AppSec report

| Permission | Required | Unlocks |
|---|---|---|
| Zone · Zone · Read | ✅ | Zone info, plan, status |
| Zone · Zone Settings · Read | ✅ | All zone settings |
| Zone · Analytics · Read | ✅ | GraphQL Analytics API (most of the report) |
| Zone · Zone Rulesets · Read | ✅ | WAF managed rules |
| Zone · WAF · Read | ✅ | Legacy firewall rules |
| Zone · Bot Management · Read | ✅ | Bot Management config |
| Zone · DDoS Protection · Read | ✅ | DDoS protection ruleset |
| Zone · Firewall Services · Read | ✅ | Firewall rules |
| Zone · DNS · Read | ✅ | DNS record inventory |
| Zone · SSL and Certificates · Read | ✅ | Certificate packs |
| Zone · Cache Rules · Read | ✅ | Cache rules |
| Zone · API Gateway · Read | optional | API Shield section |
| Zone · Page Shield · Read | optional | Page Shield section |
| Account · Account Settings · Read | ✅ | Account info |
| Account · Account Analytics · Read | optional | DNS analytics enrichment |

### Zero Trust report

| Permission | Required | Unlocks |
|---|---|---|
| Account · Zero Trust Read | ✅ | Access apps, policies, auth events |
| Account · Access: Apps and Policies · Read | ✅ | Access application inventory |
| Account · Access: Apps and Policies · Read | ✅ | Per-app policy rules |
| Account · Access: Audit Logs · Read | optional | Real seat counts + last-login (`/access/users`) |
| Account · Gateway · Read | ✅ | DNS/HTTP/Network filtering stats, WARP device status |
| Account · Zero Trust Analytics | ✅ | GraphQL: auth events, Gateway, WARP status, bandwidth |
| Account · WARP · Read | optional | Enrolled devices |
| Account · Tunnels · Read | optional | Tunnel status |
| Account · DLP · Read | optional | DLP profiles |
| Account · Zero Trust Read/Write | optional | CASB findings (`/data-security/posture/findings`) |
| Account · Notifications · Read | optional | Recent alert history |
| Account · Account Settings · Read | ✅ | Account name |

---

## Scheduled email reports

An hourly cron (`[triggers]` in `wrangler.toml`) checks for due schedules,
generates the report with the backend-bound token, writes a Workers AI
executive summary, renders an email-safe HTML digest, and sends it via the
Email Sending binding. Everything is configured from the **Scheduled
Reports** dashboard — report type, zone/account, timeframe, cadence,
recipients, subject, and an optional custom message.

- **Cadence**: daily / weekly / monthly, evaluated in the schedule's
  captured timezone. A 90-minute grace window after the intended send time
  doubles as catch-up if a cron event is missed.
- **Double-send guard**: an atomic `last_run_at` claim (compared against the
  intended occurrence, not wall-clock time) prevents duplicate sends.
- **"Send test now"**: generates and sends immediately, recorded as a
  `manual` run in history — use this to verify recipients/formatting before
  trusting the cron.
- **Archive**: every scheduled send's rendered HTML is snapshotted to the
  R2 audit bucket under `scheduled/`.
- See `apps/api/src/scheduler.ts` for the full implementation.

---

## AI models

Executive summaries use a three-tier Workers AI fallback chain, since large
reasoning models can occasionally exhaust their token budget mid-thought
before writing any output (`finish_reason: "length"`, empty content) —
confirmed live in testing, non-deterministically, on prompts built from
larger real reports:

1. `@cf/zai-org/glm-5.3-flash` (primary)
2. `@cf/openai/gpt-oss-120b` (fallback)
3. `@cf/meta/llama-3.3-70b-instruct-fp8-fast` (final fallback)

A response shorter than a real 5-paragraph summary is treated as a failure
and the next model is tried — see `MIN_VALID_SUMMARY_LENGTH` in
`apps/api/src/routes/ai-summary.ts` / `ai-zt-summary.ts`. In the rare case
all three models fail, report generation still succeeds — only the
executive summary is omitted (or, for the interactive UI, shown as an
explicit "AI summary unavailable" error rather than silently blank).
Because of this fallback chain, summary generation can occasionally take
up to ~60-120 seconds on a bad run; this is expected, not a hang.

---

## Alternative: separate Pages frontend

If you'd rather deploy the frontend as its own Cloudflare Pages project
(e.g. to put it on a different custom domain than the Worker), the
`apps/web/functions/api/[[path]].ts` reverse-proxy Function is included for
exactly that:

```bash
cd apps/web
npm run build
npx wrangler pages deploy dist --project-name=your-project-name
```

Then set `API_WORKER_URL` as a **Pages environment variable** (dashboard →
Settings → Environment variables) pointing at your deployed Worker's URL. In
this topology, also set `ALLOWED_ORIGIN` in the Worker's `wrangler.toml` to
your Pages URL so CORS allows it.

---

## Project structure

```
apps/api/            Cloudflare Worker (Hono) — all report generation logic
  src/routes/         HTTP handlers (appsec, zerotrust, summaries, schedules, settings, audit)
  src/services/        GraphQL/REST fetchers per Cloudflare product area
  src/scheduler.ts     Cron entrypoint + email digest runner
apps/web/             React + Vite frontend
  src/pages/            Report pages + input forms
  src/pages/sections/   AppSec report sections
  src/pages/zt-sections/  Zero Trust report sections
  functions/            Optional Pages Function (see Alternative topology above)
migrations/           D1 schema (schedules, settings, send_history)
wrangler.toml         Public deploy template (no resource IDs — auto-provisioned)
wrangler.local.example.toml   Template for your own local wrangler.local.toml
scripts/deploy.sh     Build → migrate → deploy
```

---

## Testing

```bash
npm run typecheck     # tsc --noEmit across both apps
npm run test:e2e       # Playwright — see tests/e2e/
```

Live/browser E2E tests need real credentials in `.env.test` (copy from
`.env.test.example` — never committed).

---

## License

MIT — see [LICENSE](LICENSE). Contributions and forks welcome.
