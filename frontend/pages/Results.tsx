import React, { useEffect, useState } from "react";
import {
  Search, AlertCircle, ChevronDown, ChevronRight, Bug, Download,
  Loader2, FileText, Globe, Calendar, Timer, ShieldCheck,
} from "lucide-react";
import { Vulnerability } from "../types";
import { getScanResults, downloadPdfReport, getAllScans, BackendFinding } from "../api";

interface ResultsProps {
  scanId: string | null;
}

function toVulnerability(f: BackendFinding): Vulnerability {
  return {
    id:                f.id ?? crypto.randomUUID(),
    url:               f.url,
    parameter:         f.parameter,
    payload:           f.payload,
    type:              f.vuln_type,
    severity:          f.severity as "Critical" | "High" | "Medium" | "Low",
    responseSnippet:   f.evidence ?? f.response_snippet ?? "",
    fixRecommendation: f.remediation,
    cvssScore:         f.cvss_score ?? null,
    cvssVector:        f.cvss_vector ?? null,
    owaspCategory:     f.owasp_category ?? null,
    owaspName:         f.owasp_name ?? null,
  };
}

function cvssBadgeColors(score: number): { bg: string; border: string; text: string; ring: string } {
  if (score >= 9.0)      return { bg: 'rgba(244,63,94,0.12)',  border: 'rgba(244,63,94,0.35)',  text: '#fb7185', ring: 'rgba(244,63,94,0.25)'  }; // rose
  if (score >= 7.0)      return { bg: 'rgba(249,115,22,0.12)', border: 'rgba(249,115,22,0.35)', text: '#fb923c', ring: 'rgba(249,115,22,0.25)' }; // orange
  if (score >= 4.0)      return { bg: 'rgba(245,158,11,0.12)', border: 'rgba(245,158,11,0.35)', text: '#fbbf24', ring: 'rgba(245,158,11,0.25)' }; // amber
  return                       { bg: 'rgba(16,185,129,0.12)', border: 'rgba(16,185,129,0.35)', text: '#34d399', ring: 'rgba(16,185,129,0.25)' }; // emerald
}

function formatDuration(start: string, end: string | null): string {
  if (!end) return '—';
  const secs = Math.round((new Date(end).getTime() - new Date(start).getTime()) / 1000);
  if (secs < 60) return `${secs}s`;
  return `${Math.floor(secs / 60)}m ${secs % 60}s`;
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString(undefined, {
    month: 'short', day: 'numeric', year: 'numeric',
    hour: '2-digit', minute: '2-digit',
  });
}

const SEVERITY_STYLES: Record<string, string> = {
  Critical: "bg-rose-500/10 text-rose-400 border-rose-500/20",
  High:     "bg-orange-500/10 text-orange-400 border-orange-500/20",
  Medium:   "bg-amber-500/10 text-amber-400 border-amber-500/20",
  Low:      "bg-sky-500/10 text-sky-400 border-sky-500/20",
};

const glassPanel = {
  backdropFilter: 'blur(20px)',
  background: 'linear-gradient(160deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%)',
};

const Results: React.FC<ResultsProps> = ({ scanId }) => {
  const [resolvedId, setResolvedId]           = useState<string | null>(scanId);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [stats, setStats]                     = useState<Record<string, number>>({});
  const [scanMeta, setScanMeta]               = useState<{ target_url: string; created_at: string; completed_at: string | null } | null>(null);
  const [isLoading, setIsLoading]             = useState(false);
  const [error, setError]                     = useState<string | null>(null);
  const [searchQuery, setSearchQuery]         = useState("");
  const [expandedId, setExpandedId]           = useState<string | null>(null);

  // If no scanId provided, resolve to the latest completed scan
  useEffect(() => {
    if (scanId) { setResolvedId(scanId); return; }
    getAllScans()
      .then((scans) => {
        const latest = scans.find((s) => s.status === "completed");
        setResolvedId(latest?.id ?? null);
      })
      .catch(() => setResolvedId(null));
  }, [scanId]);

  useEffect(() => {
    if (!resolvedId) return;
    let cancelled = false;
    setIsLoading(true);
    setError(null);
    getScanResults(resolvedId)
      .then((data) => {
        if (cancelled) return;
        setVulnerabilities(data.findings.map(toVulnerability));
        setStats(data.stats ?? {});
        setScanMeta({ target_url: data.target_url, created_at: data.created_at, completed_at: data.completed_at });
      })
      .catch((err) => {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Failed to load results.");
      })
      .finally(() => { if (!cancelled) setIsLoading(false); });
    return () => { cancelled = true; };
  }, [resolvedId]);

  const filteredVulns = vulnerabilities.filter(
    (v) =>
      v.type.toLowerCase().includes(searchQuery.toLowerCase()) ||
      v.url.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const handleExportCSV = () => {
    if (vulnerabilities.length === 0) return;
    const headers = ["ID", "Vulnerability Type", "Severity", "URL", "Parameter", "Payload", "Recommendation"];
    const rows = vulnerabilities.map((v) => [
      v.id,
      `"${v.type.replace(/"/g, '""')}"`,
      v.severity,
      `"${v.url}"`,
      `"${v.parameter}"`,
      `"${v.payload.replace(/"/g, '""')}"`,
      `"${v.fixRecommendation.replace(/"/g, '""')}"`,
    ]);
    const csvContent = [headers, ...rows].map((r) => r.join(",")).join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url  = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `security_audit_${resolvedId ?? "export"}_${Date.now()}.csv`;
    link.style.visibility = "hidden";
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="space-y-7 animate-in fade-in duration-700 pb-16">

      {/* Header */}
      <div className="flex items-end justify-between border-b border-white/[0.06] pb-7">
        <div>
          <h1 className="text-4xl font-black text-white tracking-tight">
            Audit{' '}
            <span style={{ background: 'linear-gradient(90deg, #34d399, #22d3ee)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              Inventory
            </span>
          </h1>
          <p className="text-slate-500 mt-2 text-sm">Verified findings from your security scan.</p>
        </div>
        <div className="flex items-center gap-3">
          {resolvedId && (
            <button
              onClick={() => downloadPdfReport(resolvedId)}
              disabled={isLoading || vulnerabilities.length === 0}
              className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-bold text-sm text-slate-300 hover:text-white border border-white/[0.1] hover:border-white/[0.2] transition-all disabled:opacity-40"
              style={{ backdropFilter: 'blur(12px)', backgroundColor: 'rgba(255,255,255,0.05)' }}
            >
              <FileText size={15} className="text-emerald-400" strokeWidth={2} />
              PDF Report
            </button>
          )}
          <button
            onClick={handleExportCSV}
            disabled={vulnerabilities.length === 0}
            className="flex items-center gap-2 px-5 py-2.5 rounded-xl font-bold text-sm text-slate-300 hover:text-white border border-white/[0.1] hover:border-white/[0.2] transition-all disabled:opacity-40"
            style={{ backdropFilter: 'blur(12px)', backgroundColor: 'rgba(255,255,255,0.05)' }}
          >
            <Download size={15} className="text-emerald-400" strokeWidth={2} />
            Export CSV
          </button>
        </div>
      </div>

      {/* Scan meta cards */}
      {scanMeta && (
        <div className="grid grid-cols-3 gap-4">
          {[
            { icon: <Globe size={20} strokeWidth={1.5} className="text-emerald-400" />, label: 'Target', value: scanMeta.target_url, truncate: true },
            { icon: <Calendar size={20} strokeWidth={1.5} className="text-emerald-400" />, label: 'Scanned', value: formatDate(scanMeta.created_at) },
            { icon: <Timer size={20} strokeWidth={1.5} className="text-emerald-400" />, label: 'Duration', value: formatDuration(scanMeta.created_at, scanMeta.completed_at), accent: true },
          ].map((card) => (
            <div key={card.label} className="rounded-2xl p-5 border border-white/[0.08] flex items-center gap-4" style={glassPanel}>
              <div className="p-2.5 bg-emerald-500/10 border border-emerald-500/15 rounded-xl shrink-0">
                {card.icon}
              </div>
              <div className="min-w-0">
                <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1">{card.label}</p>
                <p className={`font-bold text-sm ${card.accent ? 'text-emerald-400 text-lg font-black' : 'text-white'} ${card.truncate ? 'truncate' : ''}`} title={card.value}>
                  {card.value}
                </p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="flex items-start gap-3 bg-rose-500/[0.08] border border-rose-500/20 text-rose-400 rounded-xl px-5 py-4">
          <AlertCircle size={17} className="shrink-0 mt-0.5" strokeWidth={2} />
          <div>
            <p className="font-bold text-sm">Failed to load results</p>
            <p className="text-sm mt-0.5 text-rose-300/80">{error}</p>
          </div>
        </div>
      )}

      {/* Stats strip */}
      {!isLoading && Object.keys(stats).length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            { label: "Total Findings",  value: stats.total_findings ?? 0                         },
            { label: "Critical / High", value: (stats.critical ?? 0) + (stats.high ?? 0)        },
            { label: "Medium / Low",    value: (stats.medium ?? 0) + (stats.low ?? 0)           },
            { label: "Payloads Tested", value: stats.total_payloads_generated ?? 0              },
          ].map((s) => (
            <div
              key={s.label}
              className="rounded-2xl p-7 flex flex-col items-center text-center gap-2 border border-emerald-500/15 shadow-[0_0_20px_rgba(16,185,129,0.06)]"
              style={{ backdropFilter: 'blur(16px)', background: 'linear-gradient(135deg, rgba(16,185,129,0.08) 0%, rgba(16,185,129,0.03) 100%)' }}
            >
              <p className="text-3xl font-black text-white tabular-nums">{s.value}</p>
              <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">{s.label}</p>
            </div>
          ))}
        </div>
      )}

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-5 top-1/2 -translate-y-1/2 text-slate-600" size={18} strokeWidth={2} />
        <input
          type="text"
          placeholder="Search by vulnerability type or URL…"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full pl-12 pr-5 py-3.5 rounded-xl border border-white/[0.1] focus:border-emerald-500/40 focus:outline-none transition-all text-white placeholder:text-slate-600 text-sm"
          style={{ backdropFilter: 'blur(12px)', backgroundColor: 'rgba(255,255,255,0.05)' }}
        />
      </div>

      {/* Loading */}
      {isLoading && (
        <div className="flex flex-col items-center justify-center py-24 gap-4 text-slate-500">
          <Loader2 size={36} className="animate-spin text-emerald-400" strokeWidth={1.5} />
          <p className="font-bold text-xs uppercase tracking-widest">Loading findings…</p>
        </div>
      )}

      {/* No scan */}
      {!resolvedId && !isLoading && (
        <div className="flex flex-col items-center justify-center py-24 gap-4 text-slate-600">
          <Bug size={48} strokeWidth={1} />
          <p className="font-bold text-sm uppercase tracking-widest">No scan run yet</p>
          <p className="text-slate-500 text-sm">Start a scan from Mission Config.</p>
        </div>
      )}

      {/* Results table */}
      {!isLoading && vulnerabilities.length > 0 && (
        <div className="rounded-2xl overflow-hidden border border-white/[0.08]" style={glassPanel}>
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-white/[0.06]" style={{ backgroundColor: 'rgba(255,255,255,0.03)' }}>
                  {["Threat Class", "Severity", "Resource", "Parameter", ""].map((h) => (
                    <th key={h} className="px-7 py-5 text-[10px] font-bold text-slate-500 uppercase tracking-widest">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredVulns.map((vuln) => {
                  const isOpen = expandedId === vuln.id;
                  return (
                    <React.Fragment key={vuln.id}>
                      {/* Main row */}
                      <tr
                        onClick={() => setExpandedId(isOpen ? null : vuln.id)}
                        className="border-b border-white/[0.04] hover:bg-white/[0.04] cursor-pointer transition-colors group"
                      >
                        <td className="px-7 py-5">
                          <div className="flex items-center gap-3">
                            <div className="p-2 bg-rose-500/10 rounded-lg border border-rose-500/15">
                              <Bug size={15} className="text-rose-400" strokeWidth={2} />
                            </div>
                            <span className="font-bold text-white text-sm">{vuln.type}</span>
                          </div>
                        </td>
                        <td className="px-7 py-5">
                          <span className={`px-3 py-1.5 rounded-full text-[11px] font-bold border ${SEVERITY_STYLES[vuln.severity] ?? "bg-slate-500/10 text-slate-400 border-slate-500/20"}`}>
                            {vuln.severity}
                          </span>
                        </td>
                        <td className="px-7 py-5">
                          <span className="text-slate-400 font-mono text-xs truncate max-w-[200px] block" title={vuln.url}>
                            {vuln.url}
                          </span>
                        </td>
                        <td className="px-7 py-5">
                          <span className="text-slate-400 font-mono text-xs">{vuln.parameter}</span>
                        </td>
                        <td className="px-7 py-5">
                          {isOpen
                            ? <ChevronDown size={17} className="text-emerald-400 ml-auto" strokeWidth={2} />
                            : <ChevronRight size={17} className="text-slate-700 group-hover:text-emerald-400 transition-colors ml-auto" strokeWidth={2} />
                          }
                        </td>
                      </tr>

                      {/* Expandable detail row */}
                      {isOpen && (
                        <tr className="border-b border-white/[0.04]">
                          <td colSpan={5} className="px-7 py-5">
                            <div
                              className="rounded-xl border border-white/[0.07] overflow-hidden"
                              style={{ background: 'rgba(255,255,255,0.02)' }}
                            >
                              {/* OWASP Top 10 strip */}
                              {vuln.owaspCategory && (
                                <div className="flex items-center gap-3 px-5 py-3 border-b border-white/[0.06]" style={{ background: 'rgba(16,185,129,0.04)' }}>
                                  <span className="px-2.5 py-1 rounded-md bg-emerald-500/15 border border-emerald-500/30 text-emerald-300 text-[10px] font-bold tracking-wider">
                                    OWASP {vuln.owaspCategory}
                                  </span>
                                  <span className="text-slate-400 text-xs font-medium">{vuln.owaspName}</span>
                                </div>
                              )}

                              <div className="grid grid-cols-1 md:grid-cols-4 divide-y md:divide-y-0 md:divide-x divide-white/[0.06]">

                                {/* CVSS v3.1 */}
                                <div className="px-5 py-4 flex flex-col items-center text-center">
                                  <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">CVSS v3.1</p>
                                  {vuln.cvssScore != null ? (() => {
                                    const c = cvssBadgeColors(vuln.cvssScore!);
                                    return (
                                      <>
                                        <div
                                          className="w-16 h-16 rounded-full flex items-center justify-center font-black text-xl tabular-nums border-2"
                                          style={{
                                            background: c.bg,
                                            borderColor: c.border,
                                            color: c.text,
                                            boxShadow: `0 0 22px ${c.ring}`,
                                          }}
                                          title={`Base score ${vuln.cvssScore!.toFixed(1)}`}
                                        >
                                          {vuln.cvssScore!.toFixed(1)}
                                        </div>
                                        {vuln.cvssVector && (
                                          <code className="text-[9px] font-mono text-slate-500 break-all mt-3 leading-snug" title={vuln.cvssVector}>
                                            {vuln.cvssVector}
                                          </code>
                                        )}
                                      </>
                                    );
                                  })() : (
                                    <div className="w-16 h-16 rounded-full flex items-center justify-center font-bold text-xs border-2 border-white/[0.08] text-slate-600">
                                      N/A
                                    </div>
                                  )}
                                </div>

                                {/* Payload */}
                                <div className="px-5 py-4">
                                  <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Active Payload</p>
                                  <code className="text-amber-400 text-xs font-mono break-all leading-relaxed">
                                    {vuln.payload}
                                  </code>
                                </div>

                                {/* Parameter + URL */}
                                <div className="px-5 py-4">
                                  <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-2">Target Parameter</p>
                                  <span className="inline-block font-mono text-emerald-400 text-xs font-bold bg-emerald-500/10 px-2.5 py-1 rounded-lg border border-emerald-500/15 mb-3">
                                    {vuln.parameter}
                                  </span>
                                  <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-1.5">URL</p>
                                  <span className="text-slate-400 font-mono text-[11px] break-all">{vuln.url}</span>
                                </div>

                                {/* Fix */}
                                <div className="px-5 py-4">
                                  <div className="flex items-center gap-2 mb-2">
                                    <ShieldCheck size={13} className="text-emerald-400" strokeWidth={2} />
                                    <p className="text-[10px] font-bold text-emerald-400 uppercase tracking-widest">Remediation</p>
                                  </div>
                                  <p className="text-slate-400 text-xs leading-relaxed">{vuln.fixRecommendation}</p>
                                </div>

                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Empty state */}
      {!isLoading && resolvedId && vulnerabilities.length === 0 && !error && (
        <div className="flex flex-col items-center justify-center py-24 gap-5">
          <div className="p-7 bg-emerald-500/[0.08] rounded-2xl border border-emerald-500/15">
            <Bug size={40} className="text-emerald-400" strokeWidth={1.5} />
          </div>
          <h3 className="text-xl font-black text-white">No vulnerabilities found</h3>
          <p className="text-slate-500 text-sm">The target passed all fuzz checks.</p>
        </div>
      )}

    </div>
  );
};

export default Results;
