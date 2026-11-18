/** General Cloudflare Radar Zero Wire news, shown after the report summary. Not site-specific. */
export interface RadarNewsPayload {
  ok: boolean;
  reason?: string;
  fetchedAt?: string;
  briefings?: { title: string; label: string; summary: string; action: string; coverage: string; cves: string[]; tags: string[]; published: string; reviewed: string | null; url: string }[];
}

export default function RadarNews({ radar }: { radar: RadarNewsPayload | undefined }) {
  if (!radar) return null;
  return <div data-testid="radar-news" className="mt-8 rounded-xl border border-cf-gray-200 bg-white p-5 print:break-inside-avoid">
    <p className="text-[10px] font-black uppercase tracking-widest text-cf-gray-500 mb-1">General security news</p>
    <p className="text-xs text-cf-gray-500 mb-4">Cloudflare Radar Zero Wire. These briefings are not specific to your environment: check whether you run the affected software before acting.</p>
    {!radar.ok ? <p className="text-sm text-cf-gray-600">Cloudflare Radar Zero Wire could not be reached for this report ({radar.reason}). Your report data is unaffected.</p>
      : <div className="space-y-4">{(radar.briefings ?? []).map(b => <article key={b.url}>
          <a href={b.url} target="_blank" rel="noreferrer" className="text-sm font-semibold text-cf-navy underline">{b.title}</a>
          <p className="text-[11px] text-cf-orange mt-0.5">{[b.label, `Published ${b.published}`, b.reviewed && b.reviewed !== b.published ? `reviewed ${b.reviewed}` : "", ...b.cves].filter(Boolean).join(" · ")}</p>
          <p className="text-[13px] text-cf-gray-700 mt-1">{b.summary}</p>
          <p className="text-[13px] text-cf-gray-700 mt-1"><strong>What to do:</strong> {b.action}</p>
          {b.coverage && <p className="text-[12px] text-cf-gray-500 mt-1"><strong>Cloudflare coverage:</strong> {b.coverage}</p>}
        </article>)}</div>}
  </div>;
}
