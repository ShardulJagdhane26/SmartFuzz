import React, { useEffect, useState, useCallback } from 'react';
import {
  Globe, Bug, Database, Play,
  RefreshCw, AlertTriangle, TrendingUp, Shield,
  CheckCircle2, Clock, XCircle, Loader2, Ban, Radio,
} from 'lucide-react';
import StatCard from '../components/StatCard';

interface RecentScan {
  id: string;
  target_url: string;
  status: string;
  created_at: string;
  completed_at: string | null;
  total_findings: number;
}

interface DashboardStats {
  total_scans: number;
  completed_scans: number;
  total_vulns: number;
  by_severity: { Critical: number; High: number; Medium: number; Low: number };
  by_owasp?: Record<string, number>;
  top_vuln_type: string;
  recent_scans: RecentScan[];
}

const OWASP_TOP_10: { code: string; name: string }[] = [
  { code: "A01:2021", name: "Broken Access Control" },
  { code: "A02:2021", name: "Cryptographic Failures" },
  { code: "A03:2021", name: "Injection" },
  { code: "A04:2021", name: "Insecure Design" },
  { code: "A05:2021", name: "Security Misconfiguration" },
  { code: "A06:2021", name: "Vulnerable and Outdated Components" },
  { code: "A07:2021", name: "Identification and Authentication Failures" },
  { code: "A08:2021", name: "Software and Data Integrity Failures" },
  { code: "A09:2021", name: "Security Logging and Monitoring Failures" },
  { code: "A10:2021", name: "Server-Side Request Forgery" },
];

interface DashboardProps {
  progress: number;
  onNewScan: () => void;
  onViewLiveScan: () => void;
  isScanning: boolean;
  vulnerabilities: any[];
  totalRequests: number;
  totalEndpoints: number;
}

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';

const STATUS_CONFIG: Record<string, { icon: React.ReactNode; pill: string }> = {
  completed: { icon: <CheckCircle2 size={13} strokeWidth={2} />, pill: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' },
  running:   { icon: <Loader2 size={13} strokeWidth={2} className="animate-spin" />, pill: 'bg-blue-500/10 text-blue-400 border-blue-500/20' },
  queued:    { icon: <Clock size={13} strokeWidth={2} />, pill: 'bg-slate-500/10 text-slate-400 border-slate-500/20' },
  failed:    { icon: <XCircle size={13} strokeWidth={2} />, pill: 'bg-rose-500/10 text-rose-400 border-rose-500/20' },
  cancelled: { icon: <XCircle size={13} strokeWidth={2} />, pill: 'bg-amber-500/10 text-amber-400 border-amber-500/20' },
};

function formatDate(iso: string | null): string {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  } catch { return iso; }
}

const glassCard = {
  backdropFilter: 'blur(20px)',
  background: 'linear-gradient(160deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%)',
};

const Dashboard: React.FC<DashboardProps> = ({ progress, onNewScan, onViewLiveScan, isScanning }) => {
  const [stats, setStats]           = useState<DashboardStats | null>(null);
  const [loading, setLoading]       = useState(true);
  const [error, setError]           = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [cancelling, setCancelling] = useState<string | null>(null);

  const fetchStats = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    else setRefreshing(true);
    setError(null);
    try {
      const res = await fetch(`${BASE_URL}/api/dashboard/stats`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setStats(await res.json());
    } catch (err: any) {
      setError(err.message || 'Could not reach backend.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  const handleCancel = async (scanId: string) => {
    setCancelling(scanId);
    try {
      await fetch(`${BASE_URL}/api/scan/${scanId}/cancel`, { method: 'POST' });
      await fetchStats(true);
    } finally {
      setCancelling(null);
    }
  };

  useEffect(() => { fetchStats(); }, [fetchStats]);

  // Derive live state from what the DB actually says, not from ephemeral React
  // prop — this stays correct after page navigation or a hard refresh.
  const hasActiveScan = stats?.recent_scans?.some(
    s => s.status === 'running' || s.status === 'queued'
  ) ?? false;

  useEffect(() => {
    if (!hasActiveScan) return;
    const t = setInterval(() => fetchStats(true), 5_000);
    return () => clearInterval(t);
  }, [hasActiveScan, fetchStats]);

  const sev    = stats?.by_severity ?? { Critical: 0, High: 0, Medium: 0, Low: 0 };
  const total  = stats?.total_vulns ?? 0;
  const maxSev = Math.max(sev.Critical, sev.High, sev.Medium, sev.Low, 1);

  const sevBars = [
    { label: 'Critical', count: sev.Critical, color: 'bg-rose-500',    track: 'bg-rose-500/10',    text: 'text-rose-400'    },
    { label: 'High',     count: sev.High,     color: 'bg-orange-400',  track: 'bg-orange-500/10',  text: 'text-orange-400'  },
    { label: 'Medium',   count: sev.Medium,   color: 'bg-amber-400',   track: 'bg-amber-500/10',   text: 'text-amber-400'   },
    { label: 'Low',      count: sev.Low,      color: 'bg-emerald-400', track: 'bg-emerald-500/10', text: 'text-emerald-400' },
  ];


  if (loading) {
    return (
      <div className="space-y-10 animate-in fade-in duration-700">
        <div className="flex items-center justify-between border-b border-white/[0.06] pb-10">
          <div>
            <div className="h-12 w-64 bg-white/[0.06] rounded-xl animate-pulse mb-3" />
            <div className="h-4 w-48 bg-white/[0.04] rounded-lg animate-pulse" />
          </div>
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-5">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="rounded-2xl h-40 animate-pulse" style={{ background: 'rgba(255,255,255,0.04)' }} />
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8 animate-in fade-in duration-700 pb-16">

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-5 border-b border-white/[0.06] pb-8">
        <div>
          <h1 className="text-3xl sm:text-4xl font-black text-white tracking-tight">
            Security{' '}
            <span style={{ background: 'linear-gradient(90deg, #34d399, #22d3ee)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              Suite
            </span>
          </h1>
          <p className="text-slate-500 mt-2 text-sm">Real-time intelligence from your scan history.</p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <button
            onClick={() => fetchStats(true)}
            disabled={refreshing}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-bold text-slate-400 hover:text-white text-sm transition-all border border-white/[0.1] hover:border-white/[0.2] disabled:opacity-50"
            style={{ backdropFilter: 'blur(12px)', backgroundColor: 'rgba(255,255,255,0.05)' }}
          >
            <RefreshCw size={15} strokeWidth={2} className={refreshing ? 'animate-spin' : ''} />
            Refresh
          </button>
          <button
            onClick={onNewScan}
            disabled={hasActiveScan}
            className="flex items-center gap-2 px-6 py-2.5 text-white font-bold text-sm rounded-xl transition-all shadow-[0_0_20px_rgba(16,185,129,0.3)] disabled:opacity-50 active:scale-95"
            style={{ background: 'linear-gradient(135deg, #10b981, #059669)' }}
          >
            <Play size={14} fill="currentColor" />
            {hasActiveScan ? 'Scan Active' : 'New Scan'}
          </button>
        </div>
      </div>

      {/* Active scan banner — driven by DB state so it survives page navigation */}
      {hasActiveScan && (
        <button
          onClick={onViewLiveScan}
          className="w-full flex items-center gap-4 px-6 py-4 rounded-2xl border text-left transition-all hover:scale-[1.005] active:scale-[0.998]"
          style={{
            background: 'linear-gradient(135deg, rgba(16,185,129,0.1) 0%, rgba(8,145,178,0.06) 100%)',
            borderColor: 'rgba(52,211,153,0.25)',
            boxShadow: '0 0 30px rgba(16,185,129,0.08)',
          }}
        >
          <div className="p-2.5 rounded-xl shrink-0" style={{ background: 'rgba(16,185,129,0.15)', border: '1px solid rgba(52,211,153,0.2)' }}>
            <Radio size={18} className="text-emerald-400" strokeWidth={2} />
          </div>
          <div className="flex-1 min-w-0">
            <p className="font-bold text-white text-sm">Scan in progress</p>
            <p className="text-emerald-400/70 text-xs mt-0.5">Click to open Live Stream and monitor real-time activity</p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-emerald-400 font-bold text-sm">{progress}%</span>
          </div>
        </button>
      )}

      {/* Error banner */}
      {error && (
        <div className="flex items-center gap-3 p-4 bg-rose-500/[0.08] border border-rose-500/20 rounded-xl text-rose-400 text-sm">
          <AlertTriangle size={17} strokeWidth={2} className="shrink-0" />
          <p className="flex-1">{error}</p>
          <button onClick={() => fetchStats()} className="font-bold underline shrink-0 text-xs">Retry</button>
        </div>
      )}

      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-5">
        <StatCard label="Total Scans"     value={stats?.total_scans ?? 0}          icon={<Globe />} />
        <StatCard label="Vulnerabilities" value={total}                             icon={<Bug />} />
        <StatCard label="Critical / High" value={`${sev.Critical} / ${sev.High}`}  icon={<Shield />} />
        <StatCard label="Top Threat"      value={stats?.top_vuln_type ?? '—'}       icon={<TrendingUp />} />
      </div>


      {/* Severity breakdown + Recent scans */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">

        {/* Severity breakdown */}
        <div className="rounded-2xl p-8 border border-white/[0.08]" style={glassCard}>
          <h2 className="font-black text-white text-xl mb-8 flex items-center gap-3">
            <span className="w-1 h-6 rounded-full bg-emerald-500 shrink-0" />
            Severity Breakdown
          </h2>

          {total === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <div className="w-16 h-16 bg-emerald-500/[0.08] rounded-2xl flex items-center justify-center mb-5 border border-emerald-500/15">
                <Shield size={28} className="text-emerald-400" strokeWidth={1.5} />
              </div>
              <p className="font-bold text-slate-300 mb-1.5">No Vulnerabilities Yet</p>
              <p className="text-slate-500 text-sm">Run a scan to populate this chart.</p>
            </div>
          ) : (
            <div className="space-y-5">
              {sevBars.map((bar) => (
                <div key={bar.label}>
                  <div className="flex justify-between items-center mb-2">
                    <span className={`text-xs font-bold uppercase tracking-widest ${bar.text}`}>{bar.label}</span>
                    <span className="text-slate-400 text-sm font-black tabular-nums">{bar.count}</span>
                  </div>
                  <div className={`w-full ${bar.track} h-2 rounded-full overflow-hidden`}>
                    <div
                      className={`h-full ${bar.color} rounded-full transition-all duration-700`}
                      style={{ width: `${(bar.count / maxSev) * 100}%` }}
                    />
                  </div>
                </div>
              ))}

              <div className="pt-5 border-t border-white/[0.06] grid grid-cols-4 gap-3">
                {sevBars.map((bar) => (
                  <div key={bar.label} className="text-center">
                    <p className={`text-2xl font-black tabular-nums ${bar.text}`}>{bar.count}</p>
                    <p className="text-[10px] font-bold text-slate-600 uppercase tracking-widest mt-1">{bar.label}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Recent scans */}
        <div className="rounded-2xl p-8 border border-white/[0.08]" style={glassCard}>
          <h2 className="font-black text-white text-xl mb-8 flex items-center gap-3">
            <span className="w-1 h-6 rounded-full bg-emerald-500 shrink-0" />
            Recent Scans
          </h2>

          {!stats?.recent_scans?.length ? (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <div className="w-16 h-16 bg-white/[0.04] rounded-2xl flex items-center justify-center mb-5 border border-white/[0.08]">
                <Database size={28} className="text-slate-600" strokeWidth={1.5} />
              </div>
              <p className="font-bold text-slate-300 mb-1.5">No Scans Yet</p>
              <p className="text-slate-500 text-sm">Your history will appear here.</p>
            </div>
          ) : (
            <div className="space-y-2.5">
              {stats.recent_scans.map((scan) => {
                const cfg = STATUS_CONFIG[scan.status] ?? STATUS_CONFIG.failed;
                const isActive = scan.status === 'running' || scan.status === 'queued';
                return (
                  <div
                    key={scan.id}
                    className="flex items-center gap-3 p-4 rounded-xl border border-white/[0.06] hover:border-white/[0.1] transition-colors"
                    style={{ backgroundColor: 'rgba(255,255,255,0.03)' }}
                  >
                    <span className={`inline-flex items-center justify-center gap-1.5 px-3 py-1 rounded-full border text-[11px] font-bold uppercase tracking-wider shrink-0 w-28 ${cfg.pill}`}>
                      {cfg.icon}
                      {scan.status}
                    </span>

                    <div className="flex-1 min-w-0">
                      <p className="font-bold text-white text-sm truncate" title={scan.target_url}>
                        {scan.target_url}
                      </p>
                      <p className="text-[11px] text-slate-500 mt-0.5">{formatDate(scan.created_at)}</p>
                    </div>

                    {isActive ? (
                      <button
                        onClick={() => handleCancel(scan.id)}
                        disabled={cancelling === scan.id}
                        className="flex items-center gap-1.5 px-3 py-1.5 bg-rose-500/[0.08] hover:bg-rose-500/15 border border-rose-500/20 text-rose-400 rounded-lg font-bold text-xs transition-all disabled:opacity-50 shrink-0"
                      >
                        {cancelling === scan.id ? <Loader2 size={11} className="animate-spin" /> : <Ban size={11} />}
                        Cancel
                      </button>
                    ) : (
                      <span className={`font-black text-sm shrink-0 tabular-nums ${scan.total_findings > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                        {scan.total_findings}
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* OWASP Top 10 Coverage */}
      <div className="rounded-2xl p-8 border border-white/[0.08]" style={glassCard}>
        <h2 className="font-black text-white text-xl mb-2 flex items-center gap-3">
          <span className="w-1 h-6 rounded-full bg-emerald-500 shrink-0" />
          OWASP Top 10 Coverage
        </h2>
        <p className="text-slate-500 text-sm mb-7 ml-4">
          Findings across all scans, categorised against OWASP 2021. Categories at 0 are still tracked but not yet detected.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
          {OWASP_TOP_10.map(({ code, name }) => {
            const count = stats?.by_owasp?.[code] ?? 0;
            const hit   = count > 0;
            return (
              <div
                key={code}
                className={`flex items-center gap-4 p-4 rounded-xl border transition-colors ${
                  hit
                    ? 'border-emerald-500/20 bg-emerald-500/[0.04]'
                    : 'border-white/[0.06] bg-white/[0.015] opacity-60'
                }`}
              >
                <span
                  className={`shrink-0 px-2.5 py-1 rounded-md text-[10px] font-bold tracking-wider border ${
                    hit
                      ? 'bg-emerald-500/15 border-emerald-500/30 text-emerald-300'
                      : 'bg-white/[0.04] border-white/[0.08] text-slate-500'
                  }`}
                >
                  {code}
                </span>
                <span className={`flex-1 text-sm font-medium truncate ${hit ? 'text-slate-200' : 'text-slate-500'}`} title={name}>
                  {name}
                </span>
                <span
                  className={`shrink-0 font-black text-sm tabular-nums min-w-[2ch] text-right ${
                    hit ? 'text-emerald-400' : 'text-slate-600'
                  }`}
                >
                  {count}
                </span>
              </div>
            );
          })}
        </div>
      </div>

    </div>
  );
};

export default Dashboard;
