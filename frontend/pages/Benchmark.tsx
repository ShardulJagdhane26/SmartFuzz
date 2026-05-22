import React, { useEffect, useState } from 'react';
import { CheckCircle2, XCircle, Minus, BarChart2, Bug, Globe, Clock, Zap } from 'lucide-react';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';

interface BenchmarkStats {
  total_scans: number;
  total_findings: number;
  top_vuln_type: string;
  avg_duration_seconds: number;
}

type Advantage = true | false | null;

interface Row {
  feature: string;
  smartfuzz: { text: string; advantage: true };
  zap: { text: string; advantage: Advantage };
}

const TABLE_ROWS: Row[] = [
  { feature: 'AI-Powered Payloads',        smartfuzz: { text: 'Yes — dynamically generated via Gemini 2.5 Flash-Lite', advantage: true },   zap: { text: 'No — relies on static wordlists only', advantage: false } },
  { feature: 'Context-Aware Generation',   smartfuzz: { text: 'Yes — adapts payloads to field names and page context', advantage: true },   zap: { text: 'No — fixed rules, no contextual awareness', advantage: false } },
  { feature: 'Adaptive Feedback Loop',     smartfuzz: { text: 'Yes — second-pass refinement on confirmed findings', advantage: true },      zap: { text: 'No — single-pass scan with no feedback loop', advantage: false } },
  { feature: 'Vulnerability Coverage',     smartfuzz: { text: '11 classes — SQLi, XSS, RCE, SSRF, CMDi, Auth Bypass, IDOR, NoSQL, XXE, SSTI, Open Redirect', advantage: true }, zap: { text: 'SQLi, XSS, SSRF and many passive checks', advantage: null } },
  { feature: 'Report Format',              smartfuzz: { text: 'PDF with per-finding severity breakdown', advantage: true },                  zap: { text: 'HTML, XML, and JSON exports', advantage: null } },
  { feature: 'Ease of Use',                smartfuzz: { text: 'Browser-based — no installation required', advantage: true },                zap: { text: 'Desktop app — requires Java and manual configuration', advantage: false } },
  { feature: 'False Positive Rate',        smartfuzz: { text: 'Low — differential baseline comparison', advantage: true },                  zap: { text: 'Medium — relies on signature matching only', advantage: false } },
  { feature: 'Scan Speed',                 smartfuzz: { text: 'Async with configurable concurrency', advantage: true },                     zap: { text: 'Threaded with passive and active modes', advantage: null } },
];

const glassPanel = {
  backdropFilter: 'blur(20px)',
  background: 'linear-gradient(160deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%)',
};

function SmartFuzzCell({ text }: { text: string }) {
  return (
    <div className="px-8 py-6 flex items-start gap-3">
      <CheckCircle2 size={15} strokeWidth={2} className="text-emerald-400 shrink-0 mt-0.5" />
      <span className="text-emerald-300 text-sm leading-relaxed">{text}</span>
    </div>
  );
}

function ZapCell({ text, advantage }: { text: string; advantage: Advantage }) {
  if (advantage === false) {
    return (
      <div className="px-8 py-6 flex items-start gap-3">
        <XCircle size={15} strokeWidth={2} className="text-rose-400 shrink-0 mt-0.5" />
        <span className="text-rose-300/70 text-sm leading-relaxed">{text}</span>
      </div>
    );
  }
  return (
    <div className="px-8 py-6 flex items-start gap-3">
      <Minus size={15} strokeWidth={2} className="text-slate-600 shrink-0 mt-0.5" />
      <span className="text-slate-500 text-sm leading-relaxed">{text}</span>
    </div>
  );
}

function StatTile({ icon, label, value, sub }: { icon: React.ReactNode; label: string; value: string | number; sub?: string }) {
  return (
    <div
      className="rounded-2xl p-7 flex flex-col items-center text-center border border-emerald-500/15 shadow-[0_0_25px_rgba(16,185,129,0.07)]"
      style={{ backdropFilter: 'blur(16px)', background: 'linear-gradient(135deg, rgba(16,185,129,0.09) 0%, rgba(16,185,129,0.03) 100%)' }}
    >
      <div className="text-emerald-400 mb-3">
        {React.isValidElement(icon)
          ? React.cloneElement(icon as React.ReactElement<any>, { size: 22, strokeWidth: 1.5 })
          : icon}
      </div>
      <p
        className="text-2xl font-black mb-1 tabular-nums"
        style={{ background: 'linear-gradient(90deg, #34d399, #22d3ee)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}
      >
        {value}
      </p>
      <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">{label}</p>
      {sub && <p className="text-xs text-slate-600 mt-1">{sub}</p>}
    </div>
  );
}

const Benchmark: React.FC = () => {
  const [stats, setStats]     = useState<BenchmarkStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState<string | null>(null);

  useEffect(() => {
    fetch(`${BASE_URL}/api/benchmark`)
      .then((r) => { if (!r.ok) throw new Error(`HTTP ${r.status}`); return r.json(); })
      .then((d: BenchmarkStats) => { setStats(d); setLoading(false); })
      .catch((e) => { setError(e.message); setLoading(false); });
  }, []);

  function formatDuration(secs: number): string {
    if (!secs || secs < 1) return '< 1s';
    if (secs < 60) return `${Math.round(secs)}s`;
    return `${Math.round(secs / 60)}m ${Math.round(secs % 60)}s`;
  }

  return (
    <div className="animate-in fade-in duration-700 space-y-8 pb-12">

      {/* Header */}
      <div className="border-b border-white/[0.06] pb-7">
        <div className="flex items-center gap-3 mb-2">
          <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/15 rounded-xl">
            <BarChart2 size={22} className="text-emerald-400" strokeWidth={1.5} />
          </div>
          <h1 className="text-3xl sm:text-4xl font-black text-white tracking-tight">
            SmartFuzz{' '}
            <span style={{ background: 'linear-gradient(90deg, #34d399, #22d3ee)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              vs
            </span>{' '}
            OWASP ZAP
          </h1>
        </div>
        <p className="text-slate-500 text-sm mt-1">
          Feature by feature comparison. AI powered fuzzing against the industry standard.
        </p>
      </div>

      {/* Comparison table — scrolls horizontally on mobile instead of crushing */}
      <div className="overflow-x-auto -mx-4 px-4 sm:mx-0 sm:px-0">
      <div className="rounded-2xl overflow-hidden border border-white/[0.08] min-w-[640px]" style={glassPanel}>

        {/* Column headers */}
        <div className="grid grid-cols-3 border-b border-white/[0.06]">

          {/* Feature column label */}
          <div className="px-8 py-7 flex items-center" style={{ backgroundColor: 'rgba(255,255,255,0.02)' }}>
            <p className="text-sm font-black text-slate-400 uppercase tracking-widest">Feature</p>
          </div>

          {/* SmartFuzz header */}
          <div
            className="px-8 py-7 border-l border-emerald-500/20"
            style={{ background: 'linear-gradient(180deg, rgba(16,185,129,0.14) 0%, rgba(16,185,129,0.06) 100%)' }}
          >
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2 rounded-xl shadow-[0_0_16px_rgba(16,185,129,0.5)]" style={{ background: 'linear-gradient(135deg, #10b981, #059669)' }}>
                <Zap size={14} className="text-white" strokeWidth={2.5} fill="currentColor" />
              </div>
              <span className="font-black text-white text-base tracking-tight">SmartFuzz</span>
            </div>
            <span className="inline-block text-[9px] font-bold bg-emerald-500/15 text-emerald-400 px-2.5 py-1 rounded-full border border-emerald-500/25 uppercase tracking-widest">
              Our Tool
            </span>
          </div>

          {/* ZAP header */}
          <div className="px-8 py-7 border-l border-white/[0.06]" style={{ backgroundColor: 'rgba(255,255,255,0.02)' }}>
            <div className="flex items-center gap-3 mb-2">
              <div className="w-9 h-9 flex items-center justify-center bg-slate-700/70 rounded-xl border border-white/[0.08]">
                <span className="text-slate-200 text-[11px] font-black tracking-wider">ZAP</span>
              </div>
              <span className="font-black text-slate-300 text-base tracking-tight">OWASP ZAP</span>
            </div>
            <span className="text-[9px] font-bold text-slate-600 uppercase tracking-widest">Industry Baseline</span>
          </div>
        </div>

        {/* Data rows — pure CSS grid divs for gap-free column backgrounds */}
        {TABLE_ROWS.map((row) => (
          <div key={row.feature} className="grid grid-cols-3 border-b border-white/[0.04] last:border-0 group">

            {/* Feature name */}
            <div
              className="px-8 py-6 flex items-center border-r border-white/[0.04] group-hover:bg-white/[0.015] transition-colors"
            >
              <span className="font-bold text-white text-base">{row.feature}</span>
            </div>

            {/* SmartFuzz value — consistent green column */}
            <div
              className="border-r border-emerald-500/10 group-hover:brightness-110 transition-all"
              style={{ background: 'rgba(16,185,129,0.05)' }}
            >
              <SmartFuzzCell text={row.smartfuzz.text} />
            </div>

            {/* ZAP value */}
            <div className="group-hover:bg-white/[0.01] transition-colors">
              <ZapCell text={row.zap.text} advantage={row.zap.advantage} />
            </div>
          </div>
        ))}
      </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-6">
        {[
          { icon: <CheckCircle2 size={14} className="text-emerald-400" strokeWidth={2} />, label: 'Advantage' },
          { icon: <XCircle size={14} className="text-rose-400" strokeWidth={2} />,         label: 'Disadvantage' },
          { icon: <Minus size={14} className="text-slate-600" strokeWidth={2} />,          label: 'Neutral' },
        ].map((item) => (
          <div key={item.label} className="flex items-center gap-1.5">
            {item.icon}
            <span className="text-xs font-bold text-slate-600 uppercase tracking-wider">{item.label}</span>
          </div>
        ))}
      </div>

      {/* Live stats */}
      <div className="rounded-2xl border border-white/[0.08] p-8" style={glassPanel}>
        <h2 className="text-xl font-black text-white mb-1 flex items-center gap-3">
          <span className="w-1 h-6 rounded-full bg-emerald-500 shrink-0" />
          Live Stats from Our Scans
        </h2>
        <p className="text-slate-500 text-sm mb-8 ml-4">Real data from SmartFuzz's SQLite scan history.</p>

        {error && (
          <div className="flex items-center gap-3 p-4 bg-rose-500/[0.08] border border-rose-500/20 rounded-xl text-rose-400 mb-6">
            <XCircle size={16} strokeWidth={2} className="shrink-0" />
            <p className="text-sm">Could not load live stats — {error}</p>
          </div>
        )}

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {loading ? (
            [...Array(4)].map((_, i) => (
              <div key={i} className="rounded-2xl h-32 animate-pulse border border-white/[0.06]" style={{ backgroundColor: 'rgba(255,255,255,0.04)' }} />
            ))
          ) : (
            <>
              <StatTile icon={<Globe />} label="Total Scans Run"   value={stats?.total_scans ?? 0} />
              <StatTile icon={<Bug />}   label="Total Findings"    value={stats?.total_findings ?? 0} />
              <StatTile icon={<BarChart2 />} label="Top Vuln Type" value={stats?.top_vuln_type ?? '—'} />
              <StatTile icon={<Clock />} label="Avg Scan Duration" value={formatDuration(stats?.avg_duration_seconds ?? 0)} sub="completed scans" />
            </>
          )}
        </div>
      </div>

    </div>
  );
};

export default Benchmark;
