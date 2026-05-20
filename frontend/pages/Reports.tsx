import React, { useEffect, useState, useCallback } from "react";
import {
  FileText, Download, ExternalLink, Loader2,
  AlertCircle, RefreshCw, PlusCircle, ShieldAlert,
  CheckCircle2, Clock,
} from "lucide-react";

const BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:5000";

interface ReportRow {
  scan_id: string;
  target_url: string;
  completed_at: string | null;
  total_findings: number;
  generated_at?: string;
  has_pdf: boolean;
  overall_risk: "Critical" | "High" | "Medium" | "Low" | "Clean";
}

interface ReportsProps {
  onViewResults: (scanId: string) => void;
  onNewScan: () => void;
}

function fmtDate(iso: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString("en-IN", {
    day: "2-digit", month: "short", year: "numeric",
    hour: "2-digit", minute: "2-digit",
  });
}

const RISK_STYLE: Record<string, string> = {
  Critical: "bg-rose-500/10 text-rose-400 border-rose-500/20",
  High:     "bg-orange-500/10 text-orange-400 border-orange-500/20",
  Medium:   "bg-amber-500/10 text-amber-400 border-amber-500/20",
  Low:      "bg-sky-500/10 text-sky-400 border-sky-500/20",
  Clean:    "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
};

const glassPanel = {
  backdropFilter: 'blur(20px)',
  background: 'linear-gradient(160deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%)',
};

const Reports: React.FC<ReportsProps> = ({ onViewResults, onNewScan }) => {
  const [rows, setRows]               = useState<ReportRow[]>([]);
  const [isLoading, setLoading]       = useState(true);
  const [error, setError]             = useState<string | null>(null);
  const [downloading, setDownloading] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [reportsRes, scansRes] = await Promise.all([
        fetch(`${BASE_URL}/api/reports`),
        fetch(`${BASE_URL}/api/scans`),
      ]);
      const reportsData = await reportsRes.json();
      const scansData   = await scansRes.json();

      const reportMap: Record<string, { generated_at: string }> = {};
      for (const r of (reportsData.reports ?? [])) {
        reportMap[r.scan_id] = { generated_at: r.generated_at };
      }

      const completedScans = (scansData.scans ?? []).filter((s: any) => s.status === "completed");
      const built: ReportRow[] = completedScans.map((s: any) => ({
        scan_id:        s.id,
        target_url:     s.target_url,
        completed_at:   s.completed_at,
        total_findings: s.total_findings ?? 0,
        generated_at:   reportMap[s.id]?.generated_at,
        has_pdf:        !!reportMap[s.id],
        overall_risk:   (s.total_findings ?? 0) > 0 ? "High" : "Clean",
      }));

      built.sort((a, b) => new Date(b.completed_at ?? 0).getTime() - new Date(a.completed_at ?? 0).getTime());
      setRows(built);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load reports.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleDownload = async (scanId: string) => {
    setDownloading(scanId);
    try {
      const link = document.createElement("a");
      link.href = `${BASE_URL}/api/report/${scanId}/pdf`;
      link.target = "_blank";
      link.click();
      setTimeout(fetchData, 1500);
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="space-y-7 animate-in fade-in duration-700 pb-12">

      {/* Header */}
      <div className="flex items-end justify-between border-b border-white/[0.06] pb-7">
        <div>
          <h1 className="text-4xl font-black text-white tracking-tight">
            Security{' '}
            <span style={{ background: 'linear-gradient(90deg, #34d399, #22d3ee)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              Reports
            </span>
          </h1>
          <p className="text-slate-500 mt-2 text-sm">Download PDF reports for all completed scans.</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchData}
            disabled={isLoading}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-bold text-slate-400 hover:text-white text-sm border border-white/[0.1] hover:border-white/[0.2] transition-all disabled:opacity-50"
            style={{ backdropFilter: 'blur(12px)', backgroundColor: 'rgba(255,255,255,0.05)' }}
          >
            <RefreshCw size={15} strokeWidth={2} className={isLoading ? "animate-spin" : ""} />
            Refresh
          </button>
          <button
            onClick={onNewScan}
            className="flex items-center gap-2 px-5 py-2.5 text-white font-bold text-sm rounded-xl transition-all shadow-[0_0_20px_rgba(16,185,129,0.3)] active:scale-95"
            style={{ background: 'linear-gradient(135deg, #10b981, #059669)' }}
          >
            <PlusCircle size={15} strokeWidth={2} />
            New Scan
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="flex items-start gap-3 bg-rose-500/[0.08] border border-rose-500/20 text-rose-400 rounded-xl px-5 py-4">
          <AlertCircle size={17} className="shrink-0 mt-0.5" strokeWidth={2} />
          <div>
            <p className="font-bold text-sm">Failed to load reports</p>
            <p className="text-sm mt-0.5 text-rose-300/80">{error}</p>
          </div>
        </div>
      )}

      {/* Summary cards */}
      {!isLoading && rows.length > 0 && (
        <div className="grid grid-cols-3 gap-4">
          {[
            { label: "Total Reports",  value: rows.length                                     },
            { label: "PDFs Generated", value: rows.filter(r => r.has_pdf).length             },
            { label: "Total Findings", value: rows.reduce((s, r) => s + (r.total_findings ?? 0), 0) },
          ].map((s) => (
            <div
              key={s.label}
              className="rounded-2xl p-7 flex flex-col items-center text-center gap-2 border border-emerald-500/15"
              style={{ backdropFilter: 'blur(16px)', background: 'linear-gradient(135deg, rgba(16,185,129,0.08) 0%, rgba(16,185,129,0.03) 100%)' }}
            >
              <p className="text-3xl font-black text-white tabular-nums">{s.value}</p>
              <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">{s.label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Loading */}
      {isLoading && (
        <div className="flex items-center justify-center py-20 gap-3 text-slate-500">
          <Loader2 size={28} className="animate-spin text-emerald-400" strokeWidth={1.5} />
          <span className="font-bold text-xs uppercase tracking-widest">Loading reports…</span>
        </div>
      )}

      {/* Empty state */}
      {!isLoading && rows.length === 0 && !error && (
        <div className="flex flex-col items-center justify-center py-24 gap-5">
          <div className="p-7 bg-white/[0.04] rounded-2xl border border-white/[0.08]">
            <FileText size={40} className="text-slate-600" strokeWidth={1.5} />
          </div>
          <h3 className="text-xl font-black text-white">No completed scans yet</h3>
          <p className="text-slate-500 text-sm">Run a scan to completion to generate a report.</p>
          <button
            onClick={onNewScan}
            className="flex items-center gap-2 px-6 py-3 text-white font-bold text-sm rounded-xl transition-all shadow-[0_0_20px_rgba(16,185,129,0.3)] active:scale-95"
            style={{ background: 'linear-gradient(135deg, #10b981, #059669)' }}
          >
            <PlusCircle size={15} strokeWidth={2} />
            Start First Scan
          </button>
        </div>
      )}

      {/* Table */}
      {!isLoading && rows.length > 0 && (
        <div className="rounded-2xl overflow-hidden border border-white/[0.08]" style={glassPanel}>
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-white/[0.06]" style={{ backgroundColor: 'rgba(255,255,255,0.03)' }}>
                  {["Target", "Completed", "Findings", "Risk", "PDF Status", "Actions"].map((h) => (
                    <th key={h} className="px-6 py-4 text-[10px] font-bold text-slate-500 uppercase tracking-widest">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.04]">
                {rows.map((row) => (
                  <tr key={row.scan_id} className="hover:bg-white/[0.03] transition-colors group">

                    <td className="px-6 py-4 max-w-[180px]">
                      <p className="font-bold text-white text-sm truncate" title={row.target_url}>
                        {row.target_url.replace(/^https?:\/\//, "")}
                      </p>
                      <p className="text-slate-600 font-mono text-[11px] mt-0.5">{row.scan_id.slice(0, 8)}…</p>
                    </td>

                    <td className="px-6 py-4">
                      <span className="text-slate-300 text-sm">{fmtDate(row.completed_at)}</span>
                    </td>

                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <ShieldAlert size={15} className={(row.total_findings ?? 0) > 0 ? "text-rose-400" : "text-slate-600"} strokeWidth={2} />
                        <span className={`text-lg font-black tabular-nums ${(row.total_findings ?? 0) > 0 ? "text-rose-400" : "text-slate-600"}`}>
                          {row.total_findings ?? 0}
                        </span>
                      </div>
                    </td>

                    <td className="px-6 py-4">
                      <span className={`px-3 py-1.5 rounded-full border text-[11px] font-bold uppercase tracking-wider ${RISK_STYLE[row.overall_risk] ?? RISK_STYLE.Clean}`}>
                        {row.overall_risk}
                      </span>
                    </td>

                    <td className="px-6 py-4">
                      {row.has_pdf ? (
                        <div className="flex items-center gap-1.5 text-emerald-400">
                          <CheckCircle2 size={14} strokeWidth={2} />
                          <span className="text-xs font-bold">Generated</span>
                        </div>
                      ) : (
                        <div className="flex items-center gap-1.5 text-slate-600">
                          <Clock size={14} strokeWidth={2} />
                          <span className="text-xs font-bold">Not yet</span>
                        </div>
                      )}
                    </td>

                    <td className="px-6 py-4">
                      <div className="flex items-center gap-2">
                        <button
                          onClick={() => handleDownload(row.scan_id)}
                          disabled={downloading === row.scan_id}
                          className="flex items-center gap-1.5 px-3.5 py-2 bg-white/[0.06] hover:bg-white/[0.1] border border-white/[0.1] text-white rounded-lg font-bold text-xs transition-all active:scale-95 disabled:opacity-50"
                        >
                          {downloading === row.scan_id
                            ? <Loader2 size={12} className="animate-spin" />
                            : <Download size={12} strokeWidth={2} />}
                          PDF
                        </button>
                        <button
                          onClick={() => onViewResults(row.scan_id)}
                          className="flex items-center gap-1.5 px-3.5 py-2 bg-emerald-500/10 hover:bg-emerald-500/15 border border-emerald-500/20 text-emerald-400 rounded-lg font-bold text-xs transition-all active:scale-95"
                        >
                          <ExternalLink size={12} strokeWidth={2} />
                          Results
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <div className="px-7 py-3.5 border-t border-white/[0.04]" style={{ backgroundColor: 'rgba(255,255,255,0.02)' }}>
            <p className="text-[11px] font-bold text-slate-600 uppercase tracking-widest">
              {rows.length} completed scan{rows.length !== 1 ? "s" : ""}
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

export default Reports;
