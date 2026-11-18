import { CheckCircle } from "lucide-react";

/** Structured scheduled-email summary, carried inside the embedded report payload. */
export interface ExecSummaryPayload {
  sections: { id: string; title: string; body: string; items: { text: string; severity?: string }[] }[];
  credit: string;
}

const ACCENT: Record<string, { color: string; bg: string }> = {
  posture: { color: "#2563EB", bg: "#EFF6FF" },
  risks: { color: "#DC2626", bg: "#FEF2F2" },
  changes: { color: "#0E7490", bg: "#ECFEFF" },
  trends: { color: "#D97706", bg: "#FFFBEB" },
  actions: { color: "#7C3AED", bg: "#F5F3FF" },
};
const SEVERITY: Record<string, { label: string; color: string }> = {
  critical: { label: "Critical", color: "#ba0816" }, high: { label: "High", color: "#d1570f" },
  medium: { label: "Medium", color: "#8a6d00" }, low: { label: "Low", color: "#5d5e65" }, info: { label: "Note", color: "#5d5e65" },
};

/** The real section title is shown for each paragraph, never a position-based label. */
export default function ExecSummarySections({ summary, compact = false }: { summary: ExecSummaryPayload; compact?: boolean }) {
  return <div data-testid="exec-summary">
    <div className="space-y-5 print:space-y-6">
      {summary.sections.map((section, i) => {
        const accent = ACCENT[section.id] ?? ACCENT.posture;
        return <div key={section.id} data-section={section.id} className="rounded-xl border-l-4 px-4 py-3 print:rounded-none print:border-l-4 print:px-5 print:py-4" style={{ borderColor: accent.color, backgroundColor: accent.bg, breakInside: "avoid" }}>
          <p className="text-[10px] font-black uppercase tracking-widest mb-1.5 print:text-[8pt] print:mb-2" style={{ color: accent.color }}>{i + 1}. {section.title}</p>
          <p className={`leading-relaxed ${compact ? "text-[13px]" : "text-sm"} print:text-[10.5pt] print:leading-relaxed`} style={{ color: "#374151" }}>{section.body}</p>
          {section.items.length > 0 && <ul className="mt-2 space-y-1" style={{ listStyle: "none", padding: 0 }}>
            {section.items.map((item, k) => {
              const sev = SEVERITY[item.severity ?? "info"] ?? SEVERITY.info;
              return <li key={k} className="text-xs print:text-[9pt]" style={{ display: "flex", gap: 8 }}>
                <strong style={{ color: sev.color, textTransform: "uppercase", letterSpacing: ".06em", fontSize: 10, minWidth: 54 }}>{sev.label}</strong>
                <span style={{ color: "#374151" }}>{item.text}</span>
              </li>;
            })}
          </ul>}
        </div>;
      })}
    </div>
    {summary.credit && <div className="flex items-start gap-1.5 mt-5 text-xs text-green-700"><CheckCircle size={12} style={{ marginTop: 2, flexShrink: 0 }} /> <span>{summary.credit}</span></div>}
  </div>;
}

export function embeddedExecSummary(): ExecSummaryPayload | undefined {
  const raw = (window as { __EMBEDDED_REPORT__?: { execSummary?: ExecSummaryPayload } }).__EMBEDDED_REPORT__?.execSummary;
  return raw && Array.isArray(raw.sections) && raw.sections.length ? raw : undefined;
}
