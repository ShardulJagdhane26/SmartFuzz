import React from 'react';
import { Zap, Shield, Activity, FileText, Search, Target, ArrowRight, Download, Sparkles } from 'lucide-react';

interface LandingProps {
  onStartScan: () => void;
}

const features = [
  { icon: <Sparkles />, title: 'AI Payload Synthesis',     desc: 'Gemini generates context-aware attack vectors from your target URL, field names, and page structure.' },
  { icon: <Search />,   title: 'Intelligent Fuzzing',      desc: 'Async engine with differential baselines covering 11 vuln classes — SQLi, XSS, RCE, SSRF, CMDi, Auth, IDOR, NoSQL, XXE, SSTI, Open Redirect.' },
  { icon: <Shield />,   title: 'Evidence Validation',      desc: 'Real response snippets for every finding. Zero guesswork — every alert is verified.' },
  { icon: <Zap />,      title: 'Live Runtime Stream',       desc: 'High-fidelity terminal view with step-by-step progress and live findings counter.' },
  { icon: <FileText />, title: 'Remediation Intelligence', desc: 'Every vulnerability ships with a tailored fix recommendation for your engineering team.' },
  { icon: <Activity />, title: 'Threat Surface Mapping',   desc: 'Severity breakdown, scan history, and top threat analytics — all on one dashboard.' },
  { icon: <Target />,   title: 'Adaptive Feedback Loop',   desc: 'First-pass findings are fed back to Gemini for a second-pass with escalated, WAF-bypassing payloads.' },
  { icon: <Download />, title: 'Audit-Ready PDF Reports',  desc: 'One-click PDF export with severity breakdowns, evidence, and remediation for stakeholders.' },
];

const stats = [
  { value: '11',        label: 'Vuln Classes'      },
  { value: 'Async',     label: 'Parallel Engine'   },
  { value: 'CVSS v3.1', label: 'Per-Finding Score' },
  { value: '2×',    label: 'Adaptive Passes'   },
];

const Landing: React.FC<LandingProps> = ({ onStartScan }) => {
  return (
    <div className="min-h-full">

      {/* ── Hero ── */}
      <section className="max-w-screen-2xl mx-auto px-4 md:px-10 lg:px-16 pt-24 pb-20">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-start">

          {/* Left */}
          <div className="space-y-8">
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-emerald-500/25 bg-emerald-500/[0.08] text-emerald-400 text-xs font-bold uppercase tracking-widest">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              AI-Powered Security Testing
            </div>

            <h1 className="text-5xl sm:text-6xl xl:text-7xl font-black leading-[0.95] tracking-tighter">
              <span className="text-white">Intelligent</span><br />
              <span style={{ background: 'linear-gradient(90deg, #34d399, #22d3ee)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Fuzzing</span><br />
              <span className="text-white">for Modern</span><br />
              <span className="text-slate-400">Web Security</span>
            </h1>

            <p className="text-base text-slate-400 leading-relaxed max-w-md">
              Detect vulnerabilities with precision using AI-enhanced payload generation.
              SmartFuzz combines intelligent fuzzing with real-time analysis.
            </p>

            <div className="pt-1">
              <button
                onClick={onStartScan}
                className="flex items-center gap-3 px-9 py-4 text-white font-black text-base rounded-xl transition-all active:scale-95 shadow-[0_0_40px_rgba(16,185,129,0.45)]"
                style={{ background: 'linear-gradient(135deg, #10b981, #059669)' }}
              >
                Start Scan
                <ArrowRight size={18} strokeWidth={2.5} />
              </button>
            </div>
          </div>

          {/* Right — terminal mock */}
          <div className="lg:mt-16">
            <div
              className="rounded-2xl overflow-hidden border border-white/[0.1] shadow-[0_0_60px_rgba(0,0,0,0.6),0_0_40px_rgba(16,185,129,0.05)]"
              style={{ backdropFilter: 'blur(24px)', background: 'linear-gradient(160deg, rgba(255,255,255,0.06) 0%, rgba(255,255,255,0.02) 100%)', backgroundColor: 'rgba(8,13,26,0.9)' }}
            >
              <div className="px-5 py-3 flex items-center justify-between border-b border-white/[0.06]" style={{ backgroundColor: 'rgba(255,255,255,0.03)' }}>
                <div className="flex gap-1.5">
                  <div className="w-2.5 h-2.5 rounded-full bg-rose-500/60" />
                  <div className="w-2.5 h-2.5 rounded-full bg-amber-500/60" />
                  <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/60" />
                </div>
                <span className="text-[10px] text-slate-500 font-bold tracking-widest uppercase">smartfuzz — active</span>
                <div className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                  <span className="text-[10px] text-emerald-400 font-bold">LIVE</span>
                </div>
              </div>
              <div className="p-6 space-y-3.5 font-mono text-sm">
                <div className="flex gap-3 text-slate-400">
                  <Target size={14} className="text-emerald-400 shrink-0 mt-0.5" />
                  <span>Target: <span className="text-cyan-400">https://example.com/api</span></span>
                </div>
                <div className="flex gap-3 text-emerald-400 text-xs">
                  <span className="text-slate-600">▸</span>
                  Crawling attack surface…
                </div>
                <div className="flex gap-3 text-emerald-400 text-xs">
                  <span className="text-slate-600">▸</span>
                  Generating AI payloads via Gemini…
                </div>
                <div className="flex gap-3 text-cyan-400 text-xs">
                  <span className="text-slate-600">▸</span>
                  Fuzzing — 8 concurrent workers…
                </div>
                <div className="mt-4 pt-4 border-t border-white/[0.06]">
                  <div className="bg-rose-500/[0.08] border border-rose-500/[0.2] rounded-xl p-4 space-y-2">
                    <div className="flex items-center gap-2 text-rose-400 font-bold text-[10px] uppercase tracking-widest">
                      <Shield size={11} fill="currentColor" />
                      Vulnerability Confirmed
                    </div>
                    <p className="text-white font-bold text-sm">SQLi detected — /api/users?id=</p>
                    <p className="text-slate-500 text-xs">
                      Payload: <span className="text-rose-300 font-mono">{"' OR 1=1 --"}</span>
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Stats */}
        <div className="mt-20 grid grid-cols-2 md:grid-cols-4 gap-4">
          {stats.map((s) => (
            <div
              key={s.label}
              className="rounded-xl p-6 text-center border border-white/[0.08]"
              style={{ backdropFilter: 'blur(16px)', background: 'rgba(255,255,255,0.04)' }}
            >
              <p className="text-3xl font-black mb-1.5 tabular-nums" style={{ background: 'linear-gradient(90deg, #34d399, #22d3ee)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                {s.value}
              </p>
              <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">{s.label}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ── Features ── */}
      <section className="py-20 border-t border-white/[0.06]">
        <div className="max-w-screen-2xl mx-auto px-4 md:px-10 lg:px-16">

          <div className="mb-12">
            <p className="text-xs font-bold uppercase tracking-widest text-emerald-400 mb-4">Capabilities</p>
            <h2 className="text-5xl font-black text-white tracking-tighter">
              Security Testing,{' '}
              <span style={{ background: 'linear-gradient(90deg, #34d399, #22d3ee)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
                Reimagined.
              </span>
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {features.map((f, i) => (
              <div
                key={i}
                className="group rounded-2xl p-6 border border-white/[0.08] hover:border-emerald-500/25 transition-all duration-300 hover:shadow-[0_0_30px_rgba(16,185,129,0.08)] cursor-default"
                style={{ backdropFilter: 'blur(16px)', background: 'rgba(255,255,255,0.04)' }}
              >
                <div className="w-10 h-10 bg-emerald-500/10 border border-emerald-500/20 rounded-xl flex items-center justify-center mb-5 group-hover:bg-emerald-500/15 group-hover:border-emerald-500/30 transition-all">
                  {React.isValidElement(f.icon)
                    ? React.cloneElement(f.icon as React.ReactElement<any>, { size: 17, strokeWidth: 2, className: 'text-emerald-400' })
                    : f.icon}
                </div>
                <h3 className="text-lg font-bold text-white mb-2 leading-snug">{f.title}</h3>
                <p className="text-slate-400 text-sm leading-relaxed">{f.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── CTA ── */}
      <section className="border-t border-white/[0.06] py-20">
        <div className="max-w-screen-2xl mx-auto px-4 md:px-10 lg:px-16">
          <div
            className="rounded-2xl p-12 border border-white/[0.1] flex flex-col md:flex-row items-center justify-between gap-8 shadow-[0_0_60px_rgba(16,185,129,0.08)]"
            style={{ backdropFilter: 'blur(24px)', background: 'linear-gradient(135deg, rgba(16,185,129,0.08) 0%, rgba(255,255,255,0.03) 100%)' }}
          >
            <div>
              <h3 className="text-3xl font-black text-white tracking-tight mb-2">
                Ready to find your vulnerabilities?
              </h3>
              <p className="text-slate-400">Start a scan in under 30 seconds. No setup required.</p>
            </div>
            <button
              onClick={onStartScan}
              className="flex items-center gap-2.5 px-8 py-4 text-white font-bold rounded-xl transition-all active:scale-95 shadow-[0_0_30px_rgba(16,185,129,0.4)] shrink-0"
              style={{ background: 'linear-gradient(135deg, #10b981, #059669)' }}
            >
              Launch SmartFuzz
              <ArrowRight size={18} strokeWidth={2.5} />
            </button>
          </div>
        </div>
      </section>

      {/* ── Team ── */}
      <section className="border-t border-white/[0.06] py-16">
        <div className="max-w-screen-2xl mx-auto px-4 md:px-10 lg:px-16">
          <div className="flex flex-col items-center gap-10">
            <div className="text-center">
              <p className="text-xs uppercase tracking-widest text-emerald-500 font-bold mb-2">Built by</p>
              <h3 className="text-2xl font-black text-white tracking-tight">The Team</h3>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-6 w-full max-w-3xl">
              {[
                { name: 'Nazish Ansari',   github: 'Nazish0508'      },
                { name: 'Suhani Parkhi',   github: 'suhani-90'       },
                { name: 'Sejal Bhole',     github: 'SejalBhole'      },
                { name: 'Shardul Jagdhane',github: 'ShardulJagdhane26'},
              ].map(({ name, github }) => (
                <a
                  key={github}
                  href={`https://github.com/${github}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex flex-col items-center gap-3 p-5 rounded-2xl border border-white/[0.07] hover:border-emerald-500/40 hover:bg-emerald-500/[0.04] transition-all group"
                >
                  <img
                    src={`https://github.com/${github}.png?size=80`}
                    alt={name}
                    width={64}
                    height={64}
                    className="rounded-full ring-2 ring-white/10 group-hover:ring-emerald-500/50 transition-all"
                  />
                  <div className="text-center">
                    <p className="text-sm font-semibold text-slate-200 group-hover:text-white transition-colors leading-tight">{name}</p>
                    <p className="text-xs text-slate-500 group-hover:text-emerald-400 transition-colors mt-0.5">@{github}</p>
                  </div>
                </a>
              ))}
            </div>
            <a
              href="https://github.com/ShardulJagdhane26/SmartFuzz"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl border border-white/[0.1] hover:border-emerald-500/40 hover:bg-emerald-500/[0.05] text-slate-400 hover:text-white text-sm font-medium transition-all"
            >
              <svg viewBox="0 0 24 24" className="w-4 h-4 fill-current" aria-hidden="true">
                <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
              </svg>
              ShardulJagdhane26 / SmartFuzz
            </a>
          </div>
        </div>
      </section>

      {/* ── Footer ── */}
      <footer className="border-t border-white/[0.05] py-6">
        <div className="max-w-screen-2xl mx-auto px-4 md:px-10 lg:px-16 flex flex-col md:flex-row justify-between items-center gap-2">
          <span className="text-slate-600 text-sm">© 2026 SmartFuzz. All rights reserved.</span>
          <span className="text-slate-700 text-xs uppercase tracking-widest font-bold">SmartFuzz by 4 bits</span>
        </div>
      </footer>

    </div>
  );
};

export default Landing;
