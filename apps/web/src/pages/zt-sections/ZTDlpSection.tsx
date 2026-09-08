import { AlertTriangle, Shield } from "lucide-react";
import type { ZeroTrustData } from "../../types";
import { formatNumber } from "../../utils/formatters";
import SectionHeader from "../../components/SectionHeader";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#EF4444", high: "#F97316", medium: "#F59E0B", low: "#3B82F6", unknown: "#9CA3AF",
};

export default function ZTDlpSection({ data }: { data: ZeroTrustData }) {
  const profiles = data.dlpProfiles;
  const casbBySeverity = data.casbFindingsBySeverity ?? [];
  const s = data.summary;

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
    </section>
  );
}
