import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { Printer, FileText, RefreshCw, Loader2, CheckCircle } from "lucide-react";
import type { ReportInput } from "../types";
import type { MagicTransitData, MtRank, MtTrafficPoint } from "../../../../shared/magic-transit";
import { consolidateMtTunnels } from "../../../../shared/magic-transit-tunnels";
import { fetchMtSummary, saveAuditReport } from "../services/api";
import { captureReportHtml, saveToHtml, saveToPdf } from "../utils/pdf-export";
import cfLogo from "../assets/cf-logo";
import AreaTimeSeriesChart from "../components/charts/AreaTimeSeriesChart";
import HorizonChart from "../components/charts/HorizonChart";
import StackedBarChart from "../components/charts/StackedBarChart";
import PieBreakdownChart from "../components/charts/PieBreakdownChart";
import HorizontalBarChart from "../components/charts/HorizontalBarChart";
import ParallelCoordinates from "../components/charts/ParallelCoordinates";
import WorldMap from "../components/charts/WorldMap";
import SankeyFlowChart from "../components/charts/SankeyFlowChart";
import SecurityRadarChart from "../components/charts/SecurityRadarChart";
import NetworkGlobe from "../components/magic-transit/NetworkGlobe";
import { HealthHeatmap, AttackTimeline, ProtocolPortMatrix, RouteTopology, mtNumber, mtBytes, mtRate, mtDate } from "../components/magic-transit/NetworkVisuals";
import "./magic-transit.css";

const BLUE = "#078dad", ORANGE = "#f6821f", RED = "#d75267", GREEN = "#109b8d";
function Panel({ title, subtitle, children, id }: { title: string; subtitle?: string; children: ReactNode; id?: string }) {
  return <section className="mt-panel" id={id}><header><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</header>{children}</section>;
}
function EvidenceTable({ headers, rows }: { headers: string[]; rows: ReactNode[][] }) {
  return <div className="mt-table-wrap"><table><thead><tr>{headers.map(h => <th key={h}>{h}</th>)}</tr></thead><tbody>{rows.map((row, i) => <tr key={i}>{row.map((cell, j) => <td key={j}>{cell}</td>)}</tr>)}</tbody></table>{!rows.length && <p className="mt-empty">No records returned. See data availability for query errors.</p>}</div>;
}
function Rank({ title, rows = [] }: { title: string; rows?: MtRank[] }) {
  return <div><HorizontalBarChart title={title} data={rows.slice(0, 10).map(r => ({ name: r.name, value: r.bits / 8 }))} color={BLUE} xTickFormatter={v => mtNumber(v, "B")} subtitle="Ranked by bytes · top categories" />
    <EvidenceTable headers={["Category", "Bytes", "Packets"]} rows={rows.map(r => [r.name, mtBytes(r.bits), mtNumber(r.packets)])} /></div>;
}
function Distribution({ title, rows }: { title: string; rows: MtRank[] }) {
  const total = rows.reduce((v, r) => v + r.packets, 0);
  return <PieBreakdownChart title={title} subtitle="Packet share within returned categories" legendPosition="bottom" data={rows.map(r => ({ name: r.name, value: r.packets, pct: total ? Number((r.packets / total * 100).toFixed(1)) : 0 }))} colors={[BLUE, ORANGE, GREEN, RED, "#4862a6", "#93b6c8"]} />;
}
function pivot(points: MtTrafficPoint[], tz: number) {
  const byTime = new Map<string, Record<string, string | number>>();
  for (const p of points) {
    const row = byTime.get(p.timestamp) ?? { date: p.timestamp, label: mtDate(p.timestamp, tz), bps: 0, pps: 0, bits: 0 };
    row[p.outcome] = Number(row[p.outcome] ?? 0) + p.packets;
    row.bps = Number(row.bps) + p.bps; row.pps = Number(row.pps) + p.pps; row.bits = Number(row.bits) + p.bits;
    byTime.set(p.timestamp, row);
  }
  return [...byTime.values()].sort((a, b) => String(a.date).localeCompare(String(b.date)));
}
function change(value: number | null | undefined, baseline: number | null | undefined): string {
  if (value == null || baseline == null || baseline === 0) return "Baseline unavailable";
  const delta = (value / baseline - 1) * 100;
  return `${delta > 0 ? "+" : ""}${delta.toFixed(1)}% vs preceding equivalent period`;
}

export default function MagicTransitReportPage({ data, input, onReset, userEmail }: { data: MagicTransitData; input: ReportInput; onReset: () => void; userEmail?: string | null }) {
  const embedded = (window as { __EMBEDDED_REPORT__?: { aiSummary?: string } }).__EMBEDDED_REPORT__;
  const [summary, setSummary] = useState(embedded?.aiSummary ?? "");
  const [busy, setBusy] = useState(!embedded);
  const [summaryError, setSummaryError] = useState("");
  const [exporting, setExporting] = useState(false);
  const [saved, setSaved] = useState(false);
  const [geoView, setGeoView] = useState<"sourceCountries" | "processingCountries">("sourceCountries");
  const { meta, summary: metrics } = data;
  const tz = meta.tzOffset;
  useEffect(() => {
    if (embedded) return;
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    void fetchMtSummary(data, input.isPoc !== false).then(text => { if (!cancelled) setSummary(text); }).catch(() => { if (!cancelled) setSummaryError("Executive summary unavailable. The measurements below remain available."); }).finally(() => {
      if (cancelled) return;
      setBusy(false);
      timer = setTimeout(() => { if (!cancelled) void captureReportHtml().then(html => saveAuditReport({ email: userEmail ?? "anonymous", hostname: `magic-transit-${meta.accountId}`, zoneName: meta.accountName, days: meta.days, generatedAt: meta.generatedAt, html })).then(r => { if (!cancelled && r) setSaved(true); }).catch(() => {}); }, 1500);
    });
    return () => { cancelled = true; if (timer) clearTimeout(timer); };
  }, [data, input.isPoc, meta.accountId, meta.accountName, meta.days, meta.generatedAt, userEmail, embedded]);
  const times = useMemo(() => pivot(data.traffic, tz), [data.traffic, tz]);
  const outcomeKeys = [...new Set(data.traffic.map(p => p.outcome))];
  const timeSeries = [{ key: "bps", label: "Ingress bandwidth", color: BLUE }];
  const horizon = [
    { key: "bandwidth", label: "Ingress bandwidth", color: BLUE, data: times.map(p => ({ date: String(p.date), value: Number(p.bps) })), formatter: mtRate },
    { key: "packets", label: "Ingress packet rate", color: GREEN, data: times.map(p => ({ date: String(p.date), value: Number(p.pps) })), formatter: (v: number) => mtNumber(v, "pps") },
    { key: "dropped", label: "Dropped packets", color: ORANGE, data: times.map(p => ({ date: String(p.date), value: Number(p.drop ?? 0) })), formatter: (v: number) => mtNumber(v, "packets") },
  ];
  const probes = data.tunnels.filter(t => t.healthChecksEnabled !== null);
  const coverage = [
    ...(metrics.probeSuccessPct !== null ? [{ subject: "Probe success", score: metrics.probeSuccessPct, fullMark: 100, description: "Successful observed probes / all observed probes" }] : []),
    ...(probes.length ? [{ subject: "Checks enabled", score: probes.filter(t => t.healthChecksEnabled).length / probes.length * 100, fullMark: 100, description: "Health-check enabled tunnels / tunnels with known configuration" }] : []),
    ...(data.rules.length ? [{ subject: "Rules enabled", score: data.rules.filter(r => r.enabled).length / data.rules.length * 100, fullMark: 100, description: "Enabled rules / returned rules; not an efficacy score" }] : []),
  ];
  const flowRows = data.outcomes.filter(r => r.packets > 0);
  const flow = { nodes: [{ name: "Ingress packets", color: BLUE }, ...flowRows.map(r => ({ name: r.name === "drop" ? "Dropped" : r.name === "pass" ? "Passed" : r.name, color: r.name === "drop" ? ORANGE : GREEN }))], links: flowRows.map((r, i) => ({ source: 0, target: i + 1, value: r.packets })) };
  const tunnelRollup = useMemo(() => consolidateMtTunnels(data), [data]);
  const tunnelNames = [...new Set([...data.tunnels.map(t => t.name), ...tunnelRollup.totals.map(p => p.tunnel), ...tunnelRollup.traffic.map(p => p.tunnel)])].sort();
  const tunnelCadence = tunnelRollup.interval === "hour" ? "Hourly" : "Daily";
  const tunnelTimeLabel = (t: string) => mtDate(t, tz);
  return <div className="mt-report">
    <nav className="mt-toolbar print:hidden"><img src={cfLogo} alt="Cloudflare" /><span>Magic Transit · {meta.accountName}</span>{saved && <small><CheckCircle size={13} /> Archived</small>}
      {!embedded && <button onClick={onReset}><RefreshCw size={14} /> New report</button>}
      <button disabled={exporting} onClick={async () => { setExporting(true); try { await saveToHtml(`magic-transit-${meta.accountName}`); } finally { setExporting(false); } }}>{exporting ? <Loader2 size={14} /> : <FileText size={14} />} HTML</button>
      <button onClick={saveToPdf}><Printer size={14} /> PDF</button>
    </nav>
    <main id="report-content" className="mt-content">
      <section className="mt-hero">
        <div className="mt-hero-brand"><img src={cfLogo} alt="Cloudflare" /><span>NETWORK PROTECTION / {input.isPoc !== false ? "POC" : "ASSESSMENT"} / CONFIDENTIAL</span></div>
        <div className="mt-hero-layout"><div className="mt-hero-copy">
          {input.clientLogo && <img className="mt-client-logo" src={input.clientLogo} alt={input.clientName ?? "Client logo"} />}
          <p className="mt-eyebrow">{input.clientName || meta.accountName}</p>
          <h1>Magic<br /><span>Transit.</span></h1>
          <p className="mt-hero-thesis">Your network.<br />Its traffic. Its protection.</p>
          <p className="mt-hero-period">{meta.periodLabel}<br />{mtDate(meta.sinceTs, tz)} — {mtDate(meta.untilTs, tz)}</p>
          <div className="mt-hero-ledger"><div><strong>{mtBytes(metrics.traffic?.bits)}</strong><span>Ingress processed</span></div><div><strong>{mtNumber(metrics.attackCount)}</strong><span>Overlapping attack events</span></div></div>
        </div><NetworkGlobe data={data.rankings.sourceCountries ?? []} /></div>
        <div className="mt-hero-footer"><span>Cloudflare Network Analytics + configuration APIs</span><span>{input.partnerName || "Cloudflare"} · generated {mtDate(meta.generatedAt, tz)}</span></div>
      </section>
      <nav className="mt-jump print:hidden" aria-label="Report sections">{[["traffic", "Traffic"], ["geography", "Geography"], ["attacks", "Attacks"], ["tunnels", "Tunnels"], ["policy", "Policy"], ["configuration", "Configuration"], ["quality", "Data quality"]].map(([id, label]) => <a key={id} href={`#mt-${id}`}>{label}</a>)}</nav>
      <div className="mt-kpis">
        {[
          ["Ingress traffic", mtBytes(metrics.traffic?.bits), change(metrics.traffic?.bits, metrics.previousTraffic?.bits)],
          ["Dropped traffic", mtBytes(metrics.dropped?.bits), change(metrics.dropped?.bits, metrics.previousDropped?.bits)],
          ["Peak bucket bandwidth", metrics.peakBps == null ? "Unavailable" : mtRate(metrics.peakBps), `${meta.bucketSeconds / 60}-minute averages`],
          ["Peak bucket packet rate", mtNumber(metrics.peakPps, "pps"), "Ingress only"],
          ["Probe success", metrics.probeSuccessPct == null ? "Unavailable" : `${metrics.probeSuccessPct.toFixed(1)}%`, "Observed samples · not SLA uptime"],
           ["Configured tunnels", Object.keys(data.errors).some(k => k.startsWith("tunnels:")) ? data.tunnels.length ? `${data.tunnels.length} (partial)` : "Unavailable" : mtNumber(data.tunnels.length), "Current inventory · see collection errors"],
        ].map(([label, value, note]) => <article key={label}><span>{label}</span><strong>{value}</strong><small>{note}</small></article>)}
      </div>
      <Panel title="Executive assessment" subtitle="AI narrative grounded in the report measurements">
        {busy ? <p className="mt-empty">Preparing the executive assessment…</p> : summary ? <div className="mt-summary">{summary.split(/\n\s*\n/).filter(Boolean).map((p, i) => <p key={i}>{p}</p>)}</div> : <p className="mt-empty">{summaryError || "No AI narrative was included. Use the measurements and evidence below."}</p>}
      </Panel>
      <Panel id="mt-traffic" title="Traffic pulse" subtitle="Aligned ingress measurements · estimates from sampled network analytics">
        {times.length ? <><HorizonChart series={horizon} title="Network pulse" dateFormat={meta.days === 1 ? "MMM d HH:mm" : "MMM d"} />
          <div className="mt-grid"><AreaTimeSeriesChart data={times} series={timeSeries} title="Ingress bandwidth" xDataKey="label" tickFormatter={mtRate} /><AreaTimeSeriesChart data={times} series={[{ key: "pps", label: "Packets per second", color: GREEN }]} title="Ingress packet rate" xDataKey="label" tickFormatter={v => mtNumber(v, "pps")} /></div>
          <StackedBarChart data={times} series={outcomeKeys.map((key, i) => ({ key, label: `${key} packets`, color: key === "drop" ? ORANGE : [GREEN, BLUE, RED][i % 3] }))} title="Traffic outcomes" xKey="date" labelFormatter={t => mtDate(t, tz)} />
        </> : <p className="mt-empty">Traffic time series unavailable for the selected period.</p>}
        <div className="mt-grid"><Distribution title="Traffic outcomes" rows={data.outcomes} /><Distribution title="Dropped traffic by mitigation system" rows={data.mitigationSystems} /></div>
        {flow.links.length > 0 && <><h3>Ingress traffic disposition</h3><SankeyFlowChart data={flow} unit="packets" height={300} /><EvidenceTable headers={["Outcome", "Packets", "Bytes"]} rows={data.outcomes.map(r => [r.name, mtNumber(r.packets), mtBytes(r.bits)])} /></>}
      </Panel>
      <Panel id="mt-geography" title="Where the traffic comes from" subtitle="Source countries are distinct from Cloudflare processing locations">
        <div className="mt-switch print:hidden"><button aria-pressed={geoView === "sourceCountries"} onClick={() => setGeoView("sourceCountries")}>Source countries</button><button aria-pressed={geoView === "processingCountries"} onClick={() => setGeoView("processingCountries")}>Processing countries</button></div>
        <h3>{geoView === "sourceCountries" ? "Source-country packet distribution" : "Cloudflare processing-country packet distribution"}</h3>
        <WorldMap unit="packets" data={(data.rankings[geoView] ?? []).map(r => ({ clientCountryName: r.name, requests: r.packets, bytes: r.bits / 8, threats: 0 }))} />
        <div className="mt-grid"><Rank title="Source countries" rows={data.rankings.sourceCountries} /><Rank title="Source ASNs" rows={data.rankings.sourceAsns} /></div>
        <div className="mt-grid"><Rank title="Processing countries" rows={data.rankings.processingCountries} /><Rank title="Cloudflare locations" rows={data.rankings.colos} /></div>
      </Panel>
      <Panel title="Traffic fingerprint" subtitle="Protocols, destinations and measured joint protocol/port combinations">
        <div className="mt-grid"><Distribution title="Protocols" rows={data.rankings.protocols ?? []} /><Distribution title="TCP flags" rows={data.rankings.tcpFlags ?? []} /></div>
        <ProtocolPortMatrix data={data.protocolPorts} />
        <div className="mt-grid"><Rank title="Destination prefixes" rows={data.rankings.prefixes} /><Rank title="Destination ports" rows={data.rankings.ports} /><Rank title="Source IPs" rows={data.rankings.sourceIps} /><Rank title="Destination IPs" rows={data.rankings.destinationIps} /></div>
        <Rank title="Packet-size buckets" rows={data.rankings.packetSizes} />
      </Panel>
      <Panel id="mt-attacks" title="Attack activity" subtitle="Network-layer events overlapping the selected period · event volumes are lifetime totals">
        <AttackTimeline attacks={data.attacks} start={meta.sinceTs} end={meta.untilTs} tzOffset={tz} />
         {data.attacks.some(a => a.packets !== null && a.droppedBits !== null) && <ParallelCoordinates title="Attack profiles" subtitle="Top 30 with available packet and dropped-volume measurements · each line is one event" dimensions={[{ key: "duration", label: "Overlap seconds", log: true }, { key: "packets", label: "Lifetime packets", log: true }, { key: "dropped", label: "Lifetime dropped bytes", log: true }]} rows={data.attacks.filter(a => a.packets !== null && a.droppedBits !== null).sort((a, b) => b.droppedBits! - a.droppedBits!).slice(0, 30).map(a => ({ id: a.id, label: `${a.vector} · ${a.destination}`, color: a.end ? ORANGE : RED, values: { duration: Math.max(0, (Math.min(Date.parse(a.end ?? meta.untilTs), Date.parse(meta.untilTs)) - Math.max(Date.parse(a.start), Date.parse(meta.sinceTs))) / 1000), packets: a.packets!, dropped: a.droppedBits! / 8 } }))} />}
         <EvidenceTable headers={["Vector / ID", "Start", "End", "Target", "Lifetime dropped"]} rows={data.attacks.map(a => [`${a.vector} · ${a.id}`, mtDate(a.start, tz), a.end ? mtDate(a.end, tz) : "Ongoing", `${a.destination || "Unavailable"}:${a.port ?? "unknown port"} (${a.protocol || "unknown protocol"})`, mtBytes(a.droppedBits)])} />
      </Panel>
      <Panel id="mt-tunnels" title="Tunnel health & throughput" subtitle={`${tunnelCadence} summaries · probe success, routing state and bandwidth remain separate`}>
        <HealthHeatmap health={tunnelRollup.health} tzOffset={tz} timestamps={tunnelRollup.timestamps} />
        <div className="mt-grid">
          {tunnelRollup.health.length > 0 && <StackedBarChart title={`${tunnelCadence} probe outcomes`} subtitle="Counts summed across measured tunnels; gaps have no returned samples" height={200} data={tunnelRollup.probeSeries} series={[{ key: "ok", label: "OK", color: GREEN }, { key: "timeout", label: "Timeout", color: RED }, { key: "other", label: "Other", color: ORANGE }]} labelFormatter={tunnelTimeLabel} />}
          {tunnelRollup.traffic.length > 0 ? <AreaTimeSeriesChart title={`${tunnelCadence} tunnel bandwidth`} subtitle="Average over returned source buckets · ingress and egress are separate" height={200} data={tunnelRollup.bandwidthSeries.map(p => ({ ...p, label: tunnelTimeLabel(String(p.date)) }))} series={tunnelRollup.directionKeys.map((key, i) => ({ key, label: key, color: i ? ORANGE : BLUE }))} xDataKey="label" tickFormatter={mtRate} /> : <div><h3>Tunnel bandwidth</h3><p className="mt-empty">{data.errors.tunnelTraffic ? "Tunnel throughput measurements are unavailable. See collection errors." : "No tunnel throughput measurements returned for this period. This is not measured zero traffic."}</p></div>}
        </div>
        <h3>Period summary by tunnel</h3>
        <EvidenceTable headers={["Tunnel / type", "Endpoint", "Checks / BGP", "Probes", "Success", "Timeouts", "Mean routing state (0–1)"]} rows={tunnelNames.map(name => {
          const t = data.tunnels.find(t => t.name === name), p = tunnelRollup.totals.find(p => p.tunnel === name), total = p ? p.ok + p.timeout + p.other : 0;
          return [`${name} · ${t?.type ?? "Unknown type"}`, t?.endpoint || "Unavailable", <div>{t?.healthChecksEnabled == null ? "Checks unknown" : t.healthChecksEnabled ? "Checks enabled" : "Checks disabled"}<br />{t?.bgpState ?? "BGP unavailable"}</div>, total ? total.toLocaleString() : "No samples", total ? `${(p!.ok / total * 100).toFixed(1)}%` : "Unavailable", p ? p.timeout.toLocaleString() : "Unavailable", p?.state == null ? "Unavailable" : p.state.toFixed(3)];
        })} />
        <p className="mt-caption">Probe counts are summed; success and routing-state means are sample-weighted. Bandwidth is bits divided by the duration of returned source buckets, not the sum of rates. Gaps remain unavailable.{tunnelRollup.utcAligned && " Daily buckets retain UTC source alignment; labels use the report timezone."}</p>
        {(tunnelRollup.health.length > 0 || tunnelRollup.traffic.length > 0) && <details className="mt-tunnel-evidence"><summary>{tunnelCadence} evidence · {tunnelRollup.health.length.toLocaleString()} health rows / {tunnelRollup.traffic.length.toLocaleString()} throughput rows</summary>
          {tunnelRollup.health.length > 0 && <EvidenceTable headers={["Period start", "Tunnel", "OK", "Timeout", "Other", "Mean routing state (0–1)"]} rows={tunnelRollup.health.map(p => [tunnelTimeLabel(p.timestamp), p.tunnel, p.ok.toLocaleString(), p.timeout.toLocaleString(), p.other.toLocaleString(), p.state == null ? "Unavailable" : p.state.toFixed(3)])} />}
          {tunnelRollup.traffic.length > 0 && <EvidenceTable headers={["Period start", "Tunnel", "Direction", "Bytes", "Mean bandwidth"]} rows={tunnelRollup.traffic.map(p => [tunnelTimeLabel(p.timestamp), p.tunnel, p.direction, mtBytes(p.bits), mtRate(p.bps)])} />}
        </details>}
      </Panel>
      <Panel id="mt-policy" title="Protection layers & policy activity" subtitle="DDoS, firewall and advanced protection measurements are kept separate">
        {data.protections.map(p => <div key={p.key} className="mt-protection"><h3>{p.name}</h3><p className="mt-caption">Dropped volume: {mtBytes(p.volume?.bits)} · {mtNumber(p.volume?.packets, "packets")}</p>
          <div className="mt-grid"><Rank title={`${p.name} breakdown`} rows={p.breakdown} />{p.series.length > 0 ? <AreaTimeSeriesChart title={`${p.name} bandwidth`} data={pivot(p.series, tz)} series={timeSeries} xDataKey="label" tickFormatter={mtRate} /> : <p className="mt-empty">No time series available for this layer.</p>}</div>
          {p.rules.length > 0 && <EvidenceTable headers={["Configuration rule", "Mode"]} rows={p.rules.map(r => [r.name, r.mode])} />}</div>)}
        <Rank title="Network Firewall rule activity" rows={data.ruleActivity.map(r => ({ ...r, name: data.rules.find(rule => rule.id === r.name)?.name || r.name }))} />
        <EvidenceTable headers={["Rule", "Phase", "Action", "Status", "Expression / rate limit"]} rows={data.rules.map(r => [r.name, r.phase, r.action, r.enabled ? "Enabled" : "Disabled", <div><code>{r.expression}</code>{r.rateLimit && <p><code>{r.rateLimit}</code></p>}</div>])} />
      </Panel>
      <Panel id="mt-configuration" title="Configured network" subtitle={`Current snapshot collected ${mtDate(meta.configurationAt, tz)}; not the configuration throughout the reporting period`}>
        <RouteTopology routes={data.routes} tunnels={data.tunnels} />
        {coverage.length >= 3 && <SecurityRadarChart title="Observed health & configuration ratios" subtitle="Percentages with different denominators · not a security grade or composite score" data={coverage} color={BLUE} />}
        <EvidenceTable headers={["Metric", "Percent", "Definition"]} rows={coverage.map(c => [c.subject, `${c.score.toFixed(1)}%`, c.description])} />
        <EvidenceTable headers={["Prefix", "ASN", "Advertisement snapshot", "RPKI"]} rows={data.prefixes.map(p => [p.cidr, p.asn ?? "Unavailable", p.advertised == null ? "Unavailable" : p.advertised ? "Advertised" : "Not advertised", p.rpki || "Unavailable"])} />
        <EvidenceTable headers={["Route prefix", "Next hop", "Priority"]} rows={data.routes.map(r => [r.prefix, r.nextHop, r.priority])} />
      </Panel>
      <Panel id="mt-quality" title="Data quality & collection status" subtitle="Unavailable measurements are not substituted with zero">
        <ul className="mt-notes">{data.notes.map(note => <li key={note}>{note}</li>)}</ul>
        <EvidenceTable headers={["Unavailable section", "Reason"]} rows={Object.entries(data.errors).map(([key, value]) => [key, value])} />
        <p className="mt-caption">Account: {meta.accountId} · UTC window: {meta.sinceTs} → {meta.untilTs}. Display timezone: UTC{tz <= 0 ? "+" : "−"}{Math.abs(tz / 60)}.</p>
      </Panel>
      <footer className="mt-footer">Magic Transit network assessment · Confidential · {input.clientName || meta.accountName}</footer>
    </main>
  </div>;
}
