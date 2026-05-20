import React, { useEffect, useRef } from 'react';
import { ScanLog } from '../types';

interface TerminalProps {
  logs: ScanLog[];
}

const Terminal: React.FC<TerminalProps> = ({ logs }) => {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div
      className="rounded-2xl overflow-hidden flex flex-col h-[520px] border border-white/[0.08]"
      style={{
        backdropFilter: 'blur(20px)',
        background: 'linear-gradient(160deg, rgba(255,255,255,0.05) 0%, rgba(255,255,255,0.02) 100%)',
      }}
    >
      {/* Title bar */}
      <div
        className="px-6 py-4 border-b border-white/[0.06] flex items-center justify-between shrink-0"
        style={{ backgroundColor: 'rgba(255,255,255,0.03)' }}
      >
        <div className="flex items-center gap-2">
          <div className="w-3 h-3 rounded-full bg-rose-500/80" />
          <div className="w-3 h-3 rounded-full bg-amber-500/80" />
          <div className="w-3 h-3 rounded-full bg-emerald-500/80" />
        </div>
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-[10px] font-bold text-slate-500 uppercase tracking-[0.2em]">
            SmartFuzz · Runtime Log
          </span>
        </div>
        <div className="w-16" />
      </div>

      {/* Log body */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto px-6 py-5 space-y-1 font-mono text-[12.5px]"
      >
        {logs.length === 0 ? (
          <p className="text-slate-600 italic pt-2">Awaiting first event…</p>
        ) : (
          logs.map((log) => {
            const isError = log.status >= 500;
            const isWarn  = log.status >= 400 && log.status < 500;
            return (
              <div
                key={log.id}
                className="flex items-start gap-4 px-4 py-2.5 rounded-xl hover:bg-white/[0.04] transition-colors group"
              >
                {/* Timestamp */}
                <span className="text-slate-600 shrink-0 group-hover:text-slate-500 transition-colors">
                  {log.timestamp}
                </span>

                {/* Status code badge */}
                <span
                  className={`shrink-0 font-black text-xs px-2 py-0.5 rounded-md ${
                    isError
                      ? 'bg-rose-500/15 text-rose-400'
                      : isWarn
                      ? 'bg-amber-500/15 text-amber-400'
                      : 'bg-emerald-500/10 text-emerald-400'
                  }`}
                >
                  {log.status}
                </span>

                {/* Message — full text, wraps freely */}
                <span className="text-slate-300 leading-relaxed break-words min-w-0">
                  {log.url}
                </span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};

export default Terminal;
