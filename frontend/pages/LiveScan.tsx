import React, { useEffect, useRef, useState } from "react";
import { io, Socket } from "socket.io-client";
import Terminal from "../components/Terminal";
import { ScanLog } from "../types";
import {
  Activity, Search, Sparkles, Loader2,
  AlertCircle, ShieldAlert, XCircle, CheckCircle2, Ban, WifiOff,
} from "lucide-react";
import { getScanStatus, cancelScan, ScanStatusResponse } from "../api";

const SOCKET_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:5000";

interface ProgressEvent {
  scan_id:          string;
  progress:         number;
  current_step:     string;
  status:           ScanStatusResponse["status"];
  findings_so_far:  number;
}

interface LiveScanProps {
  scanId: string;
  onScanComplete: () => void;
  onScanEnded: () => void;
  onProgressUpdate: (progress: number, findings: number) => void;
}

let logCounter = 0;

function stepToLog(step: string, status: ScanStatusResponse["status"]): ScanLog {
  logCounter += 1;
  const httpStatus =
    status === "failed"    ? 500 :
    status === "cancelled" ? 499 :
    status === "completed" ? 200 : 102;
  return { id: `log-${logCounter}`, timestamp: new Date().toISOString().slice(11, 23), url: step, payload: "", status: httpStatus, method: "STEP" };
}

const STATUS_META: Record<string, { label: string; dot: string; badge: string }> = {
  queued:    { label: "Queued",    dot: "bg-slate-400",                badge: "bg-slate-500/10 border-slate-500/20 text-slate-400"    },
  running:   { label: "Running",   dot: "bg-amber-400 animate-pulse",  badge: "bg-amber-500/10 border-amber-500/20 text-amber-400"    },
  completed: { label: "Completed", dot: "bg-emerald-400",              badge: "bg-emerald-500/10 border-emerald-500/20 text-emerald-400" },
  failed:    { label: "Failed",    dot: "bg-rose-400",                 badge: "bg-rose-500/10 border-rose-500/20 text-rose-400"       },
  cancelled: { label: "Cancelled", dot: "bg-slate-400",                badge: "bg-slate-500/10 border-slate-500/20 text-slate-400"    },
};

const glassPanel = {
  backdropFilter: 'blur(20px)',
  background: 'linear-gradient(160deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%)',
};

const LiveScan: React.FC<LiveScanProps> = ({ scanId, onScanComplete, onScanEnded, onProgressUpdate }) => {
  const [logs, setLogs]                   = useState<ScanLog[]>([]);
  const [progress, setProgress]           = useState(0);
  const [status, setStatus]               = useState<ScanStatusResponse["status"]>("queued");
  const [currentStep, setCurrentStep]     = useState("Connecting to backend…");
  const [findingsSoFar, setFindingsSoFar] = useState(0);
  const [error, setError]                 = useState<string | null>(null);
  const [cancelling, setCancelling]       = useState(false);
  const [elapsedSecs, setElapsedSecs]     = useState(0);
  const [realtimeDown, setRealtimeDown]   = useState(false);

  const timerRef       = useRef<ReturnType<typeof setInterval> | null>(null);
  const socketRef      = useRef<Socket | null>(null);
  const lastStepRef    = useRef("");
  // Anchor the elapsed timer to the scan's actual created_at (loaded from the
  // backend on mount) so navigating away and back doesn't reset the count.
  const scanStartedAtRef = useRef<number | null>(null);
  const scanEndedAtRef   = useRef<number | null>(null);
  const completedRef     = useRef(false);

  useEffect(() => {
    timerRef.current = setInterval(() => {
      const start = scanStartedAtRef.current;
      if (start == null) return;                 // waiting for first fetch
      const end = scanEndedAtRef.current ?? Date.now();
      setElapsedSecs(Math.max(0, Math.floor((end - start) / 1000)));
    }, 1000);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, []);

  // Apply a status snapshot from either the initial HTTP fetch or a WS push.
  const applySnapshot = (data: {
    progress: number; status: ScanStatusResponse["status"];
    findings_so_far: number; current_step: string;
    created_at?: string; completed_at?: string | null;
  }) => {
    setProgress(data.progress);
    setStatus(data.status);
    setFindingsSoFar(data.findings_so_far);
    onProgressUpdate(data.progress, data.findings_so_far);

    // Anchor the elapsed timer to the real scan start/end times the first
    // time we see them. Only the initial HTTP fetch carries these — the WS
    // push omits them because they don't change after creation.
    if (data.created_at && scanStartedAtRef.current == null) {
      const t = new Date(data.created_at).getTime();
      if (!Number.isNaN(t)) {
        scanStartedAtRef.current = t;
        // Immediate update so the UI doesn't flash 0 for a second.
        const end = scanEndedAtRef.current ?? Date.now();
        setElapsedSecs(Math.max(0, Math.floor((end - t) / 1000)));
      }
    }
    if (data.completed_at && scanEndedAtRef.current == null) {
      const t = new Date(data.completed_at).getTime();
      if (!Number.isNaN(t)) {
        scanEndedAtRef.current = t;
        if (scanStartedAtRef.current != null) {
          setElapsedSecs(Math.max(0, Math.floor((t - scanStartedAtRef.current) / 1000)));
        }
      }
    }

    if (data.current_step && data.current_step !== lastStepRef.current) {
      lastStepRef.current = data.current_step;
      setCurrentStep(data.current_step);
      setLogs(prev => [...prev, stepToLog(data.current_step, data.status)]);
    }
    if (["completed", "failed", "cancelled"].includes(data.status)) {
      if (timerRef.current) clearInterval(timerRef.current);
      if (!completedRef.current) {
        completedRef.current = true;
        if (data.status === "completed") {
          setTimeout(onScanComplete, 1500);
        } else {
          onScanEnded();
        }
      }
    }
  };

  // ── One-time initial HTTP fetch + WebSocket subscription ─────────────────
  useEffect(() => {
    let cancelled = false;

    // 1. Initial fetch so a page refresh mid-scan immediately shows real state,
    //    even if WS arrives slightly later (or never).
    getScanStatus(scanId)
      .then(data => { if (!cancelled) applySnapshot(data); })
      .catch(err => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Lost connection to backend.");
      });

    // 2. Open the WebSocket. Backend joins us to a room keyed by scan_id
    //    and pushes updates as the scan progresses.
    const socket = io(SOCKET_URL, {
      query: { scan_id: scanId },
      transports: ["websocket", "polling"],
      reconnectionAttempts: 3,
    });
    socketRef.current = socket;

    socket.on("scan_progress", (data: ProgressEvent) => {
      if (cancelled) return;
      setRealtimeDown(false);
      applySnapshot(data);
    });

    const fallbackToHttp = async () => {
      setRealtimeDown(true);
      try {
        const data = await getScanStatus(scanId);
        if (!cancelled) applySnapshot(data);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : "Lost connection to backend.");
      }
    };

    socket.on("connect_error", fallbackToHttp);
    socket.on("disconnect", (reason) => {
      // Benign disconnects (page navigation) don't need a fallback fetch —
      // only react to unexpected ones while the scan is still active.
      if (completedRef.current) return;
      if (reason !== "io client disconnect") fallbackToHttp();
    });

    return () => {
      cancelled = true;
      socket.disconnect();
      socketRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId]);

  const handleCancel = async () => {
    if (cancelling) return;
    setCancelling(true);
    try {
      await cancelScan(scanId);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Cancel request failed.");
      setCancelling(false);
    }
  };

  const stats = React.useMemo(() => {
    if (logs.length === 0) return { success: "0.0", missing: "0.0", errors: "0.0" };
    const total   = logs.length;
    const success = logs.filter(l => l.status < 400).length;
    const missing = logs.filter(l => l.status >= 400 && l.status < 500).length;
    const errors  = logs.filter(l => l.status >= 500).length;
    return {
      success: ((success / total) * 100).toFixed(1),
      missing: ((missing / total) * 100).toFixed(1),
      errors:  ((errors  / total) * 100).toFixed(1),
    };
  }, [logs]);

  const isActive  = status === "queued" || status === "running";
  const isAiPhase = progress > 0 && progress < 50 && logs.length < 3;
  const meta      = STATUS_META[status] ?? STATUS_META.queued;
  const fmtElapsed = `${Math.floor(elapsedSecs / 60).toString().padStart(2,"0")}:${(elapsedSecs % 60).toString().padStart(2,"0")}`;

  return (
    <div className="space-y-7 animate-in fade-in duration-700 pb-12">

      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/[0.06] pb-7">
        <div>
          <h1 className="text-4xl font-black text-white tracking-tight">
            Runtime{' '}
            <span style={{ background: 'linear-gradient(90deg, #34d399, #22d3ee)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>
              Stream
            </span>
          </h1>
          <p className="text-slate-500 mt-1.5 text-sm">
            Scan <span className="font-mono text-emerald-400">{scanId.slice(0, 8)}…</span>
            <span className="mx-2 text-slate-700">·</span>
            <span className="font-mono text-slate-400">{fmtElapsed}</span>
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className={`flex items-center gap-2 px-4 py-2 rounded-full border text-xs font-bold uppercase tracking-widest ${meta.badge}`}>
            <span className={`w-2 h-2 rounded-full ${meta.dot}`} />
            {meta.label}
          </div>
          {isActive && (
            <button
              onClick={handleCancel}
              disabled={cancelling}
              className="flex items-center gap-2 px-4 py-2 bg-rose-500/[0.08] hover:bg-rose-500/15 border border-rose-500/20 text-rose-400 rounded-xl font-bold text-sm transition-all active:scale-95 disabled:opacity-50"
            >
              {cancelling ? <Loader2 size={14} className="animate-spin" /> : <XCircle size={14} strokeWidth={2} />}
              {cancelling ? "Cancelling…" : "Cancel"}
            </button>
          )}
        </div>
      </div>

      {/* Banners */}
      {error && (
        <div className="flex items-start gap-3 bg-rose-500/[0.08] border border-rose-500/20 text-rose-400 rounded-xl px-5 py-4">
          <AlertCircle size={17} className="shrink-0 mt-0.5" strokeWidth={2} />
          <p className="text-sm">{error}</p>
        </div>
      )}
      {realtimeDown && isActive && !error && (
        <div className="flex items-start gap-3 bg-amber-500/[0.08] border border-amber-500/20 text-amber-400 rounded-xl px-5 py-4">
          <WifiOff size={17} className="shrink-0 mt-0.5" strokeWidth={2} />
          <div>
            <p className="text-sm font-bold">Real-time updates unavailable</p>
            <p className="text-xs text-amber-300/80 mt-0.5">WebSocket failed to connect. Showing the last known scan state — refresh the page for an update.</p>
          </div>
        </div>
      )}
      {status === "cancelled" && (
        <div className="flex items-center gap-3 bg-white/[0.04] border border-white/[0.08] text-slate-400 rounded-xl px-5 py-4">
          <Ban size={17} strokeWidth={2} />
          <p className="text-sm font-bold">Scan was cancelled. Start a new scan from Mission Config.</p>
        </div>
      )}
      {status === "completed" && (
        <div className="flex items-center gap-3 bg-emerald-500/[0.08] border border-emerald-500/20 text-emerald-400 rounded-xl px-5 py-4">
          <CheckCircle2 size={17} strokeWidth={2} />
          <p className="text-sm font-bold">Scan complete! Navigating to results…</p>
        </div>
      )}

      {/* Progress bar */}
      <div className="rounded-2xl px-7 py-5 border border-white/[0.08]" style={glassPanel}>
        <div className="flex items-center justify-between mb-3">
          <span className="text-[11px] font-bold uppercase tracking-widest text-slate-500">Overall Progress</span>
          <span className="font-black text-emerald-400 tabular-nums">{progress}%</span>
        </div>
        <div className="w-full h-1.5 rounded-full overflow-hidden" style={{ backgroundColor: 'rgba(255,255,255,0.06)' }}>
          <div
            className={`h-full rounded-full transition-all duration-700 ${
              status === "failed" ? "bg-rose-500" : status === "cancelled" ? "bg-slate-500" : "bg-emerald-500"
            } shadow-[0_0_8px_rgba(16,185,129,0.5)]`}
            style={{ width: `${progress}%` }}
          />
        </div>
        <p className="text-xs text-slate-500 mt-3 truncate">{currentStep}</p>
      </div>

      {/* Main grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

        {/* Terminal / AI phase */}
        <div className="lg:col-span-2">
          {isAiPhase && logs.length < 2 ? (
            <div className="rounded-2xl h-[500px] flex flex-col items-center justify-center p-10 text-center border border-white/[0.08]" style={glassPanel}>
              <div className="relative mb-8">
                <div className="w-20 h-20 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
                  <Sparkles size={36} className="text-emerald-400 animate-pulse" fill="currentColor" />
                </div>
                <div className="absolute inset-0 bg-emerald-500/10 rounded-2xl animate-ping" />
              </div>
              <h3 className="text-xl font-black text-white mb-3 tracking-tight">AI Brainstorming</h3>
              <p className="text-slate-400 text-sm max-w-xs leading-relaxed">
                Gemini is synthesizing bespoke attack vectors for your target…
              </p>
              <div className="mt-6 flex items-center gap-2.5 text-emerald-400 font-bold text-xs uppercase tracking-widest bg-emerald-500/[0.08] px-5 py-2.5 rounded-full border border-emerald-500/20">
                <Loader2 size={14} className="animate-spin" />
                Building Payload Wordlist
              </div>
            </div>
          ) : (
            <Terminal logs={logs} />
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-4">

          {/* Live findings */}
          <div className="rounded-2xl p-7 border border-white/[0.08]" style={glassPanel}>
            <div className="flex items-center gap-3 mb-5">
              <div className="p-2 rounded-xl bg-rose-500/10 border border-rose-500/15">
                <ShieldAlert size={17} className="text-rose-400" strokeWidth={2} />
              </div>
              <h3 className="font-bold text-white text-xs uppercase tracking-widest">Live Findings</h3>
            </div>
            <p className="text-6xl font-black text-white tabular-nums leading-none">{findingsSoFar}</p>
            <p className="text-slate-500 text-sm mt-2">{isActive ? "detected so far…" : "total findings"}</p>
          </div>

          {/* Scan info */}
          <div className="rounded-2xl p-7 border border-white/[0.08]" style={glassPanel}>
            <div className="flex items-center gap-3 mb-5">
              <div className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/15">
                <Activity size={17} className="text-emerald-400" strokeWidth={2} />
              </div>
              <h3 className="font-bold text-white text-xs uppercase tracking-widest">Scan Info</h3>
            </div>
            <div className="space-y-3">
              {[
                { label: "Scan ID",      value: scanId.slice(0, 8) + "…" },
                { label: "Steps Logged", value: logs.length.toString()   },
                { label: "Elapsed",      value: fmtElapsed               },
              ].map(row => (
                <div key={row.label} className="flex justify-between text-sm py-2 border-b border-white/[0.04] last:border-0">
                  <span className="text-slate-500">{row.label}</span>
                  <span className="text-white font-bold font-mono">{row.value}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Step metrics */}
          <div className="rounded-2xl p-7 border border-white/[0.08]" style={glassPanel}>
            <div className="flex items-center gap-3 mb-5">
              <div className="p-2 rounded-xl bg-emerald-500/10 border border-emerald-500/15">
                <Search size={17} className="text-emerald-400" strokeWidth={2} />
              </div>
              <h3 className="font-bold text-white text-xs uppercase tracking-widest">Step Metrics</h3>
            </div>
            <div className="space-y-4">
              {[
                { label: "OK Steps",    value: stats.success, color: "bg-emerald-500" },
                { label: "Warn Steps",  value: stats.missing, color: "bg-amber-400"   },
                { label: "Error Steps", value: stats.errors,  color: "bg-rose-500"    },
              ].map(row => (
                <div key={row.label}>
                  <div className="flex justify-between text-[11px] font-bold uppercase tracking-widest mb-1.5">
                    <span className="text-slate-500">{row.label}</span>
                    <span className="text-slate-400 font-mono">{row.value}%</span>
                  </div>
                  <div className="w-full h-1 rounded-full overflow-hidden" style={{ backgroundColor: 'rgba(255,255,255,0.06)' }}>
                    <div className={`${row.color} h-full rounded-full transition-all duration-500`} style={{ width: `${row.value}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};

export default LiveScan;
