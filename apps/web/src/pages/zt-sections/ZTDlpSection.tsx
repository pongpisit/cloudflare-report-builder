import { AlertTriangle, Shield, Info } from "lucide-react";
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip } from "recharts";
import type { ZeroTrustData } from "../../types";
import { formatNumber } from "../../utils/formatters";
import SectionHeader from "../../components/SectionHeader";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#EF4444", high: "#F97316", medium: "#F59E0B", low: "#3B82F6", unknown: "#9CA3AF",
};

export default function ZTDlpSection({ data }: { data: ZeroTrustData }) {
  const profiles = data.dlpProfiles;
  const casbBySeverity = data.casbFindingsBySeverity ?? [];
  const casbDetail = data.casbFindingsDetail ?? [];
  const quarantineSeries = data.gatewayDlpQuarantineTimeSeries ?? [];
  const s = data.summary;
  const dlpNote = data.dataConfidence?.dlpProfiles;

  if (profiles.length === 0 && (s.casbFindingsCount ?? 0) === 0) return (
    <section className="report-section">
      <SectionHeader icon={<Shield size={20}/>} title="Data Loss Prevention (DLP) & CASB" subtitle="Sensitive data detection and SaaS security posture" />
      <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-6 text-center">
        <AlertTriangle size={28} className="text-yellow-500 mx-auto mb-2"/>
        <p className="text-sm font-semibold text-yellow-700">No DLP profiles or CASB findings configured</p>
        <p className="text-xs text-yellow-600 mt-1">Configure DLP profiles to detect PII, credit cards, and sensitive data before it leaves your organization, and connect SaaS integrations for CASB posture monitoring.</p>
      </div>
    </section>
  );

  return (
    <section className="report-section">
      <SectionHeader icon={<Shield size={20}/>} title="Data Loss Prevention (DLP) & CASB"
        subtitle="DLP profile configuration and real CASB (Data Security Posture) findings" />
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-5">
        {[
          { label: "DLP Profiles",     value: profiles.length, color: "#8B5CF6" },
          { label: "Predefined",       value: profiles.filter((p) => p.type === "predefined").length, color: "#3B82F6" },
          { label: "CASB Findings",    value: formatNumber(s.casbFindingsCount ?? 0), color: (s.casbFindingsCount ?? 0) > 0 ? "#EF4444" : "#10B981" },
        ].map((k) => (
          <div key={k.label} className="bg-white rounded-xl shadow-sm border border-cf-gray-200 p-4">
            <p className="text-[10px] font-semibold text-cf-gray-500 uppercase tracking-wide mb-1">{k.label}</p>
            <p className="text-2xl font-black" style={{ color: k.color }}>{k.value}</p>
          </div>
        ))}
      </div>
      <div className={`grid gap-5 items-start ${casbBySeverity.length > 0 && profiles.length > 0 ? "grid-cols-1 lg:grid-cols-2" : "grid-cols-1"}`}>
        {casbBySeverity.length > 0 && (
          <div className="bg-white rounded-xl shadow-sm border border-cf-gray-200 p-4">
            <h3 className="text-sm font-semibold text-cf-navy mb-3">CASB Findings by Severity</h3>
            <div className="space-y-2">
              {casbBySeverity.map((f) => {
                const maxVal = Math.max(...casbBySeverity.map((x) => x.count), 1);
                const pct = Math.round((f.count / maxVal) * 100);
                return (
                  <div key={f.severity}>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="font-medium text-cf-navy capitalize">{f.severity}</span>
                      <span className="font-mono text-red-600">{formatNumber(f.count)}</span>
                    </div>
                    <div className="h-1.5 bg-cf-gray-100 rounded-full overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: SEVERITY_COLORS[f.severity.toLowerCase()] ?? SEVERITY_COLORS.unknown }}/>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
        {profiles.length > 0 && (
          <div className="bg-white rounded-xl shadow-sm border border-cf-gray-200 p-4">
            <h3 className="text-sm font-semibold text-cf-navy mb-3">Configured DLP Profiles ({profiles.length})</h3>
            <div className={`gap-x-4 ${casbBySeverity.length > 0 ? "" : "grid grid-cols-1 sm:grid-cols-2"}`}>
              {profiles.map((p) => (
                <div key={p.id} className="flex items-center justify-between gap-2 py-1 border-b border-cf-gray-50 last:border-0">
                  <span className="text-xs text-cf-navy font-medium truncate">{p.name}</span>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full font-medium flex-shrink-0 ${p.type === "predefined" ? "bg-blue-50 text-blue-600" : "bg-purple-50 text-purple-600"}`}>{p.type}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Real DLP outcome signal: HTTP requests quarantined by a DLP action
          over time — an indirect but genuinely measured trend (Cloudflare
          exposes no per-match/per-profile dataset via GraphQL). */}
      {quarantineSeries.some((d) => d.count > 0) && (
        <div className="bg-white rounded-xl shadow-sm border border-cf-gray-200 p-4 mt-5">
          <h3 className="text-sm font-semibold text-cf-navy mb-3">DLP Quarantine Actions Over Time</h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={quarantineSeries} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9"/>
              <XAxis dataKey="date" tick={{ fontSize: 10 }} tickFormatter={(v) => v.slice(5)}/>
              <YAxis tick={{ fontSize: 10 }}/>
              <Tooltip contentStyle={{ fontSize: 11, borderRadius: 8 }} formatter={(v: number) => formatNumber(v)}/>
              <Bar dataKey="count" name="Quarantined requests" fill="#8B5CF6" radius={[3,3,0,0]}/>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* CASB finding detail — the REST API already returns type/resource/
          integration per finding; previously only tallied into severity
          counts and discarded. */}
      {casbDetail.length > 0 && (
        <div className="bg-white rounded-xl shadow-sm border border-cf-gray-200 p-4 mt-5">
          <h3 className="text-sm font-semibold text-cf-navy mb-3">CASB Findings ({casbDetail.length}{casbDetail.length === 50 ? "+" : ""})</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left text-[10px] uppercase tracking-wide text-cf-gray-400 border-b border-cf-gray-100">
                  <th className="py-1.5 pr-3">Severity</th>
                  <th className="py-1.5 pr-3">Type</th>
                  <th className="py-1.5">Resource</th>
                </tr>
              </thead>
              <tbody>
                {casbDetail.slice(0, 25).map((f, i) => (
                  <tr key={f.id ?? i} className="border-b border-cf-gray-50 last:border-0">
                    <td className="py-1.5 pr-3">
                      <span className="text-[10px] px-2 py-0.5 rounded-full font-medium capitalize"
                        style={{ color: SEVERITY_COLORS[f.severity.toLowerCase()] ?? SEVERITY_COLORS.unknown, backgroundColor: `${SEVERITY_COLORS[f.severity.toLowerCase()] ?? SEVERITY_COLORS.unknown}14` }}>
                        {f.severity}
                      </span>
                    </td>
                    <td className="py-1.5 pr-3 text-cf-navy">{f.type}</td>
                    <td className="py-1.5 text-cf-gray-500 font-mono truncate max-w-xs">{f.resourceName}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {dlpNote && profiles.length > 0 && (
        <div className="print:hidden flex items-start gap-2 bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 mt-5">
          <Info size={13} className="text-slate-400 flex-shrink-0 mt-0.5"/>
          <p className="text-[11px] text-slate-500 leading-relaxed">{dlpNote}</p>
        </div>
      )}
    </section>
  );
}
