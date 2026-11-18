/**
 * Cloudflare Radar "Zero Wire" briefings for the scheduled email.
 *
 * Zero Wire is a public vulnerability feed (https://radar.cloudflare.com/zero-wire). It is GENERAL security
 * news: it says nothing about whether a particular customer runs the affected software, and the email says so.
 *
 * Third-party text is treated as untrusted data:
 *   - only the fixed feed URL is fetched (no redirects, short timeout, bounded size);
 *   - only a few plain-text fields are kept, never HTML, scripts or the agent prompts the briefings contain;
 *   - links must be https links on radar.cloudflare.com;
 *   - any failure returns an explicit "unavailable" result and never blocks the report.
 */

export const ZERO_WIRE_FEED = "https://radar.cloudflare.com/zero-wire/feed";
const MAX_FEED_BYTES = 1_500_000;
const TIMEOUT_MS = 8_000;
const MAX_ITEMS = 3;
const CACHE_TTL_MS = 5 * 60_000; // the feed itself is served with max-age=300

export interface RadarBriefing {
  title: string;
  /** The feed's own severity label, e.g. "Prioritize patching". */
  label: string;
  /** Plain-text summary of the threat. */
  summary: string;
  /** What Cloudflare says to do. */
  action: string;
  /** Cloudflare's own statement about product coverage, when the briefing has one. */
  coverage: string;
  cves: string[];
  tags: string[];
  /** ISO date (YYYY-MM-DD) the briefing was published. */
  published: string;
  /** ISO date (YYYY-MM-DD) of the last review, when stated. */
  reviewed: string | null;
  url: string;
}

export type RadarResult =
  | { ok: true; briefings: RadarBriefing[]; fetchedAt: string }
  | { ok: false; reason: string };

// ─── Minimal, strict text helpers ─────────────────────────────────────────────

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };

export function decodeEntities(text: string): string {
  return text.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (match, body: string) => {
    if (body[0] === "#") {
      const code = body[1].toLowerCase() === "x" ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      return Number.isFinite(code) && code > 31 && code < 0x10ffff ? String.fromCodePoint(code) : " ";
    }
    return ENTITIES[body.toLowerCase()] ?? match;
  });
}

/** Strips every tag and control character, collapses whitespace and bounds the length. */
export function plain(html: string, max: number): string {
  const text = decodeEntities(html.replace(/<(script|style|pre)[\s\S]*?<\/\1>/gi, " ").replace(/<[^>]*>/g, " "))
    .replace(/[\u0000-\u001f\u007f<>`{}\[\]\\]/g, " ").replace(/\s+/g, " ").trim();
  return text.length > max ? `${text.slice(0, max - 1).trimEnd()}…` : text;
}

const tag = (xml: string, name: string): string => xml.match(new RegExp(`<${name}(?:\\s[^>]*)?>([\\s\\S]*?)</${name}>`, "i"))?.[1] ?? "";
const cdata = (value: string): string => value.match(/<!\[CDATA\[([\s\S]*?)\]\]>/)?.[1] ?? value;

/** Section body: the HTML between <h2>{heading}</h2> and the next <h2>. */
function section(body: string, heading: string): string {
  const match = body.match(new RegExp(`<h2>${heading}</h2>([\\s\\S]*?)(?=<h2>|$)`, "i"));
  return match?.[1] ?? "";
}

function isoDate(value: string): string | null {
  const ms = Date.parse(value);
  return Number.isFinite(ms) ? new Date(ms).toISOString().slice(0, 10) : null;
}

function safeRadarLink(value: string): string | null {
  try {
    const url = new URL(decodeEntities(value).trim());
    if (url.protocol !== "https:" || url.hostname !== "radar.cloudflare.com" || url.username || url.password || url.port) return null;
    url.search = ""; url.hash = "";
    return url.toString();
  } catch { return null; }
}

const CVE = /CVE-\d{4}-\d{4,}/g;

/** Parses the RSS feed. Pure and synchronous so it can be tested without a network. */
export function parseZeroWire(xml: string): RadarBriefing[] {
  const items = [...xml.matchAll(/<item>([\s\S]*?)<\/item>/g)].map(m => m[1]);
  const out: RadarBriefing[] = [];
  for (const item of items) {
    const title = plain(cdata(tag(item, "title")), 140);
    const url = safeRadarLink(cdata(tag(item, "link")));
    const published = isoDate(tag(item, "pubDate"));
    if (!title || !url || !published) continue;
    const body = cdata(tag(item, "content:encoded"));
    const label = plain(body.match(/<p><strong>([\s\S]*?)<\/strong>/)?.[1] ?? "", 60);
    const reviewed = body.match(/Last reviewed <time datetime="(\d{4}-\d{2}-\d{2})"/)?.[1] ?? null;
    const lead = body.match(/<\/p><p>([\s\S]*?)<\/p>/)?.[1] ?? "";
    const risk = plain(section(body, "Risk"), 420);
    const action = plain(section(body, "Recommended action").match(/^\s*<p>([\s\S]*?)<\/p>/)?.[1] ?? section(body, "Recommended action"), 380);
    // The coverage section has a "Service status" part (about Cloudflare's own systems) and a "Product coverage"
    // part (what Cloudflare products do for a customer). Only the second is useful here.
    const productCoverage = section(body, "Cloudflare coverage").match(/<h3>Product coverage<\/h3>\s*<p>([\s\S]*?)<\/p>/i)?.[1] ?? "";
    const coverage = plain(productCoverage, 380);
    const tags = [...item.matchAll(/<category[^>]*>([\s\S]*?)<\/category>/g)].map(m => plain(m[1], 30)).filter(Boolean).slice(0, 6);
    // The briefing's own "CVE records" list is the precise answer. The body also mentions related flaws (the React
    // briefing cites a separate Next.js image CVE), so the body alone would mislabel the briefing.
    const records = body.match(/<h3>CVE records?<\/h3>([\s\S]*?)(?=<h3>|<p><a href="https:\/\/radar)/i)?.[1] ?? "";
    const cves = [...new Set((records || `${title} ${plain(cdata(tag(item, "description")), 600)}`).match(CVE) ?? [])].slice(0, 4);
    out.push({ title, label, summary: plain(lead, 300) || risk, action, coverage, cves, tags, published, reviewed, url });
  }
  return out.sort((a, b) => b.published.localeCompare(a.published));
}

// ─── Fetch (cached per isolate) ───────────────────────────────────────────────

let cache: { at: number; result: RadarResult } | null = null;

export async function fetchRadarBriefings(now = Date.now(), fetcher: typeof fetch = fetch): Promise<RadarResult> {
  if (cache && now - cache.at < CACHE_TTL_MS && cache.result.ok) return cache.result;
  try {
    const response = await fetcher(ZERO_WIRE_FEED, { redirect: "manual", signal: AbortSignal.timeout(TIMEOUT_MS), headers: { Accept: "application/rss+xml" } });
    if (!response.ok) return { ok: false, reason: `Radar returned HTTP ${response.status}` };
    const type = response.headers.get("content-type") ?? "";
    if (!/xml/i.test(type)) return { ok: false, reason: "Radar did not return a feed" };
    const reader = response.body?.getReader();
    if (!reader) return { ok: false, reason: "Radar returned an empty feed" };
    const chunks: Uint8Array[] = []; let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.length;
      if (size > MAX_FEED_BYTES) { await reader.cancel(); return { ok: false, reason: "Radar feed exceeded the size limit" }; }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
    const briefings = parseZeroWire(new TextDecoder().decode(bytes)).slice(0, MAX_ITEMS);
    if (!briefings.length) return { ok: false, reason: "Radar feed contained no briefings" };
    const result: RadarResult = { ok: true, briefings, fetchedAt: new Date(now).toISOString() };
    cache = { at: now, result };
    return result;
  } catch (e) {
    return { ok: false, reason: e instanceof Error && e.name === "TimeoutError" ? "Radar did not respond in time" : "Radar could not be reached" };
  }
}

export function resetRadarCacheForTest(): void { cache = null; }
