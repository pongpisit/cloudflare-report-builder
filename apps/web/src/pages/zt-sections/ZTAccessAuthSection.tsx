import { Lock } from "lucide-react";
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from "recharts";
import type { ZeroTrustData } from "../../types";
import { formatNumber } from "../../utils/formatters";
import SectionHeader from "../../components/SectionHeader";

export default function ZTAccessAuthSection({ data }: { data: ZeroTrustData }) {
  const series = data.accessAuthTimeSeries;
  if (series.length === 0) return null;

  const totalAllow = series.reduce((s, d) => s + d.allow, 0);
  const totalBlock = series.reduce((s, d) => s + d.block, 0);
  const totalMfa   = series.reduce((s, d) => s + d.mfa, 0);

  return (
    <section className="report-section">
      <SectionHeader icon={<Lock size={20}/>} title="Access — Authentication Events"
        subtitle="Daily authentication activity — allowed, blocked, and MFA-challenged requests" />
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-5">
        {[
          { label: "Allowed",  value: totalAllow, color: "#10B981" },
          { label: "Blocked",  value: totalBlock, color: "#EF4444" },
          { label: "MFA Challenged", value: totalMfa, color: "#F59E0B" },
        ].map((k) => (
          <div key={k.label} className="bg-white rounded-xl shadow-sm border border-cf-gray-200 p-4">
            <p className="text-[10px] font-semibold text-cf-gray-500 uppercase tracking-wide mb-1">{k.label}</p>
            <p className="text-2xl font-black" style={{ color: k.color }}>{formatNumber(k.value)}</p>
          </div>
        ))}
      </div>
      <div className="bg-white rounded-xl shadow-sm border border-cf-gray-200 p-4">
        <h3 className="text-sm font-semibold text-cf-navy mb-3">Daily Authentication Breakdown</h3>
        <ResponsiveContainer width="100%" height={260}>
          <AreaChart data={series} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
            <defs>
              {[["allow","#10B981"],["block","#EF4444"],["mfa","#F59E0B"]].map(([k,c]) => (
                <linearGradient key={k} id={`ztAuth-${k}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor={c} stopOpacity={0.25}/>
                  <stop offset="95%" stopColor={c} stopOpacity={0.02}/>
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#F1F5F9"/>
            <XAxis dataKey="date" tick={{ fontSize: 10 }} tickFormatter={(v) => v.slice(5)}/>
            <YAxis tick={{ fontSize: 10 }} tickFormatter={(v) => v >= 1e3 ? `${(v/1e3).toFixed(0)}K` : String(v)}/>
            <Tooltip contentStyle={{ fontSize: 11, borderRadius: 8 }} formatter={(v: number) => formatNumber(v)}/>
            <Legend wrapperStyle={{ fontSize: 11 }}/>
            <Area type="monotone" dataKey="allow" name="Allowed"   stroke="#10B981" fill="url(#ztAuth-allow)" strokeWidth={2} dot={false}/>
            <Area type="monotone" dataKey="block" name="Blocked"   stroke="#EF4444" fill="url(#ztAuth-block)" strokeWidth={2} dot={false}/>
            <Area type="monotone" dataKey="mfa"   name="MFA Challenged" stroke="#F59E0B" fill="url(#ztAuth-mfa)" strokeWidth={2} dot={false}/>
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}
