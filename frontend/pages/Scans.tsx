import React, { useEffect, useState, useCallback } from "react";
import {
  History, RefreshCw, ExternalLink, FileText, AlertCircle,
  CheckCircle2, Clock, XCircle, Loader2, Search, Shield,
} from "lucide-react";
import { getAllScans, downloadPdfReport, ScanHistoryItem } from "../api";

interface ScansProps {
  onViewResults: (scanId: string) => void;
}

const STATUS_CONFIG: Record<ScanHistoryItem["status"], { label: string; icon: React.ReactNode; pill: string }> = {
  completed: { label: "Completed", icon: <CheckCircle2 size={12} strokeWidth={2} />, pill: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" },
  running:   { label: "Running",   icon: <Loader2 size={12} strokeWidth={2} className="animate-spin" />, pill: "bg-blue-500/10 text-blue-400 border-blue-500/20" },
  queued:    { label: "Queued",    icon: <Clock size={12} strokeWidth={2} />, pill: "bg-slate-500/10 text-slate-400 border-slate-500/20" },
  failed:    { label: "Failed",    icon: <XCircle size={12} strokeWidth={2} />, pill: "bg-rose-500/10 text-rose-400 border-rose-500/20" },
  cancelled: { label: "Cancelled", icon: <XCircle size={12} strokeWidth={2} />, pill: "bg-amber-500/10 text-amber-400 border-amber-500/20" },
};

function findingsDot(count: number): string {
  if (!count || count === 0) return "bg-emerald-400";
  if (count <= 2)            return "bg-amber-400";
  return "bg-rose-400";
}

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: "short", day: "numeric", year: "numeric",
      hour: "2-digit", minute: "2-digit",
    });
  } catch { return iso; }
}

function shortId(id: string): string {
  return id.slice(0, 8).toUpperCase();
}

const glassPanel = {
  backdropFilter: 'blur(20px)',
  background: 'linear-gradient(160deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%)',
};

const Scans: React.FC<ScansProps> = ({ onViewResults }) => {
  const [scans, setScans]               = useState<ScanHistoryItem[]>([]);
  const [loading, setLoading]           = useState(true);
  const [error, setError]               = useState<string | null>(null);
  const [search, setSearch]             = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [refreshing, setRefreshing]     = useState(false);

  const fetchScans = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    else setRefreshing(true);
    setError(null);
    try {
      const data = await getAllScans();
      setScans(data);
    } catch (err: any) {
      setError(err.message || "Failed to load scan history.");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { fetchScans(); }, [fetchScans]);

  useEffect(() => {
    const hasActive = scans.some((s) => s.status === "running" || s.status === "queued");
    if (!hasActive) return;
    const timer = setInterval(() => fetchScans(true), 8000);
    return () => clearInterval(timer);
  }, [scans, fetchScans]);

  const isSearching = search.trim() !== "" || statusFilter !== "all";

  const filtered = scans
    .filter((s) => {
      const matchSearch = s.target_url.toLowerCase().includes(search.toLowerCase()) || s.id.toLowerCase().includes(search.toLowerCase());
      const matchStatus = statusFilter === "all" || s.status === statusFilter;
      return matchSearch && matchStatus;
    })
    .slice(0, isSearching ? undefined : 10);

  const totalFindings  = scans.reduce((acc, s) => acc + (s.findings_count ?? 0), 0);
  const completedCount = scans.filter((s) => s.status === "completed").length;

  return (
    <div className="space-y-7 animate-in fade-in duration-700 pb-16">

      {/* Header */}
      <div className="flex flex-col items-start gap-4 sm:flex-row sm:items-end sm:justify-between border-b border-white/[0.06] pb-7">
        <div>
          <h1 className="text-3xl sm:text-4xl font-black text-white tracking-tight">
            Scan{' '}
            <span style={{ background: 'linear-gradient(90deg, #34d399, #22d3ee)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              History
            </span>
          </h1>
          <p className="text-slate-500 mt-2 text-sm">All past and active security scans.</p>
        </div>
        <button
          onClick={() => fetchScans(true)}
          disabled={refreshing}
          className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-bold text-slate-400 hover:text-white text-sm border border-white/[0.1] hover:border-white/[0.2] transition-all disabled:opacity-50"
          style={{ backdropFilter: 'blur(12px)', backgroundColor: 'rgba(255,255,255,0.05)' }}
        >
          <RefreshCw size={15} strokeWidth={2} className={refreshing ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: "Total Scans",    value: scans.length    },
          { label: "Completed",      value: completedCount  },
          { label: "Total Findings", value: totalFindings   },
        ].map((card) => (
          <div
            key={card.label}
            className="rounded-2xl p-4 sm:p-7 flex flex-col items-center text-center gap-2 border border-emerald-500/15"
            style={{ backdropFilter: 'blur(16px)', background: 'linear-gradient(135deg, rgba(16,185,129,0.08) 0%, rgba(16,185,129,0.03) 100%)' }}
          >
            <p className="text-2xl sm:text-3xl font-black text-white tabular-nums">{card.value}</p>
            <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">{card.label}</p>
          </div>
        ))}
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-600" size={17} strokeWidth={2} />
        <input
          type="text"
          placeholder="Search by URL or scan ID…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full pl-11 pr-5 py-3 rounded-xl border border-white/[0.1] focus:border-emerald-500/40 focus:outline-none transition-all text-white placeholder:text-slate-600 text-sm"
          style={{ backdropFilter: 'blur(12px)', backgroundColor: 'rgba(255,255,255,0.05)' }}
        />
      </div>

      {/* Status filter pills */}
      <div className="flex justify-start sm:justify-center overflow-x-auto -mx-4 px-4 sm:mx-0 sm:px-0">
        <div
          className="flex items-center gap-1.5 p-1.5 rounded-xl shrink-0"
          style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)' }}
        >
          {([
            { value: 'all',       label: 'All'       },
            { value: 'completed', label: 'Completed' },
            { value: 'running',   label: 'Running'   },
            { value: 'queued',    label: 'Queued'    },
            { value: 'failed',    label: 'Failed'    },
            { value: 'cancelled', label: 'Cancelled' },
          ] as const).map((opt) => {
            const isActive = statusFilter === opt.value;
            return (
              <button
                key={opt.value}
                onClick={() => setStatusFilter(opt.value)}
                className="px-4 py-2 rounded-lg font-bold text-sm transition-all duration-200 whitespace-nowrap"
                style={
                  isActive
                    ? { color: '#fff', background: 'linear-gradient(135deg, rgba(16,185,129,0.2), rgba(8,145,178,0.12))', boxShadow: '0 0 14px rgba(16,185,129,0.12), inset 0 1px 0 rgba(255,255,255,0.08)', border: '1px solid rgba(52,211,153,0.25)' }
                    : { color: 'rgba(148,163,184,0.7)', border: '1px solid transparent' }
                }
              >
                {opt.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-center gap-3 p-4 bg-rose-500/[0.08] border border-rose-500/20 rounded-xl text-rose-400 text-sm">
          <AlertCircle size={17} strokeWidth={2} className="shrink-0" />
          <p>{error}</p>
        </div>
      )}

      {/* Loading skeleton */}
      {loading && (
        <div className="rounded-2xl overflow-hidden border border-white/[0.08]" style={glassPanel}>
          {[...Array(4)].map((_, i) => (
            <div key={i} className="flex items-center gap-5 px-7 py-5 border-b border-white/[0.04] last:border-0 animate-pulse">
              <div className="h-3 bg-white/[0.06] rounded-full w-40" />
              <div className="h-3 bg-white/[0.04] rounded-full w-24 ml-auto" />
              <div className="h-3 bg-white/[0.04] rounded-full w-16" />
              <div className="h-7 bg-white/[0.04] rounded-xl w-24" />
            </div>
          ))}
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && filtered.length === 0 && (
        <div className="rounded-2xl p-16 text-center border border-white/[0.08]" style={glassPanel}>
          <div className="w-16 h-16 bg-white/[0.04] border border-white/[0.08] rounded-2xl flex items-center justify-center mx-auto mb-6">
            <Shield size={28} className="text-slate-600" strokeWidth={1.5} />
          </div>
          <h3 className="text-xl font-black text-white mb-2">
            {search || statusFilter !== "all" ? "No matching scans" : "No scans yet"}
          </h3>
          <p className="text-slate-500 text-sm">
            {search || statusFilter !== "all" ? "Try adjusting your search or filter." : "Start a new scan from Mission Config."}
          </p>
        </div>
      )}

      {/* Table */}
      {!loading && filtered.length > 0 && (
        <div className="rounded-2xl overflow-hidden border border-white/[0.08]" style={glassPanel}>
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-white/[0.06]" style={{ backgroundColor: 'rgba(255,255,255,0.03)' }}>
                  {["ID", "Target", "Status", "Findings", "Date", "Actions"].map((h) => (
                    <th key={h} className="px-6 py-4 text-[10px] font-bold text-slate-500 uppercase tracking-widest whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04]">
                {filtered.map((scan) => {
                  const cfg = STATUS_CONFIG[scan.status] ?? STATUS_CONFIG.failed;
                  return (
                    <tr key={scan.id} className="hover:bg-white/[0.03] transition-colors group">

                      <td className="px-6 py-4">
                        <span className="font-mono text-[11px] text-slate-500 bg-white/[0.05] px-2.5 py-1 rounded-lg border border-white/[0.06]">
                          {shortId(scan.id)}
                        </span>
                      </td>

                      <td className="px-6 py-4 max-w-[220px]">
                        <p className="font-bold text-white text-sm truncate" title={scan.target_url}>{scan.target_url}</p>
                        <p className="text-[10px] text-slate-600 mt-0.5 uppercase tracking-wider truncate">{scan.vuln_classes.join(" · ")}</p>
                      </td>

                      <td className="px-6 py-4">
                        <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full border text-[11px] font-bold uppercase tracking-wider ${cfg.pill}`}>
                          {cfg.icon} {cfg.label}
                        </span>
                        {(scan.status === "running" || scan.status === "queued") && (
                          <div className="mt-1.5 w-20 h-1 rounded-full overflow-hidden" style={{ backgroundColor: 'rgba(255,255,255,0.06)' }}>
                            <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${scan.progress}%` }} />
                          </div>
                        )}
                      </td>

                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          <div className={`w-2 h-2 rounded-full ${findingsDot(scan.findings_count ?? 0)}`} />
                          <span className={`font-black text-base tabular-nums ${(scan.findings_count ?? 0) > 0 ? "text-rose-400" : "text-emerald-400"}`}>
                            {scan.findings_count ?? 0}
                          </span>
                        </div>
                      </td>

                      <td className="px-6 py-4 whitespace-nowrap">
                        <p className="text-slate-300 text-sm">{formatDate(scan.created_at)}</p>
                        {scan.completed_at && (
                          <p className="text-slate-600 text-[11px] mt-0.5">Done: {formatDate(scan.completed_at)}</p>
                        )}
                      </td>

                      <td className="px-6 py-4">
                        <div className="flex items-center gap-2">
                          {scan.status === "completed" && (
                            <button
                              onClick={() => onViewResults(scan.id)}
                              className="flex items-center gap-1.5 px-3.5 py-2 text-white font-bold text-xs rounded-lg transition-all active:scale-95 shadow-[0_0_12px_rgba(16,185,129,0.25)]"
                              style={{ background: 'linear-gradient(135deg, #10b981, #059669)' }}
                            >
                              <ExternalLink size={12} strokeWidth={2} />
                              Results
                            </button>
                          )}
                          {scan.status === "completed" && (
                            <button
                              onClick={() => downloadPdfReport(scan.id)}
                              className="flex items-center gap-1.5 px-3.5 py-2 bg-white/[0.06] hover:bg-white/[0.1] border border-white/[0.1] text-slate-300 rounded-lg font-bold text-xs transition-all"
                            >
                              <FileText size={12} strokeWidth={2} className="text-emerald-400" />
                              PDF
                            </button>
                          )}
                          {(scan.status === "running" || scan.status === "queued") && (
                            <span className="flex items-center gap-1.5 px-3.5 py-2 bg-blue-500/10 border border-blue-500/20 text-blue-400 rounded-lg font-bold text-xs">
                              <span className="w-1.5 h-1.5 bg-blue-400 rounded-full animate-ping" />
                              {scan.progress}%
                            </span>
                          )}
                          {(scan.status === "failed" || scan.status === "cancelled") && (
                            <span className="text-slate-600 text-xs font-bold">—</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="px-7 py-3.5 border-t border-white/[0.04]" style={{ backgroundColor: 'rgba(255,255,255,0.02)' }}>
            <p className="text-[11px] font-bold text-slate-600 uppercase tracking-widest">
              {isSearching
                ? `${filtered.length} of ${scans.length} scan${scans.length !== 1 ? "s" : ""}`
                : `Showing ${filtered.length} most recent · ${scans.length} total — search to find older scans`}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

export default Scans;
