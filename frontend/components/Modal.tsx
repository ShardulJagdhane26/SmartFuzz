import React from 'react';
import { X, ExternalLink, ShieldCheck, AlertTriangle } from 'lucide-react';
import { Vulnerability } from '../types';

interface ModalProps {
  isOpen: boolean;
  onClose: () => void;
  vulnerability: Vulnerability | null;
}

const SEV_ICON_CLASS: Record<string, string> = {
  Critical: 'bg-rose-500/15 text-rose-400',
  High:     'bg-orange-500/15 text-orange-400',
  Medium:   'bg-amber-500/15 text-amber-400',
  Low:      'bg-emerald-500/15 text-emerald-400',
};

const SEV_BADGE_CLASS: Record<string, string> = {
  Critical: 'bg-rose-500/10 text-rose-400 border-rose-500/20',
  High:     'bg-orange-500/10 text-orange-400 border-orange-500/20',
  Medium:   'bg-amber-500/10 text-amber-400 border-amber-500/20',
  Low:      'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
};

const Modal: React.FC<ModalProps> = ({ isOpen, onClose, vulnerability }) => {
  if (!isOpen || !vulnerability) return null;

  const iconClass  = SEV_ICON_CLASS[vulnerability.severity]  ?? SEV_ICON_CLASS.Low;
  const badgeClass = SEV_BADGE_CLASS[vulnerability.severity] ?? SEV_BADGE_CLASS.Low;

  return (
    <div className="fixed inset-0 z-[60] flex items-center justify-center p-4 md:p-6" style={{ backgroundColor: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(12px)' }}>
      <div
        className="w-full max-w-2xl rounded-2xl shadow-[0_32px_80px_rgba(0,0,0,0.8),inset_0_1px_0_rgba(255,255,255,0.06)] overflow-hidden animate-in fade-in zoom-in duration-300 flex flex-col max-h-[90vh] border border-white/[0.1]"
        style={{ background: 'linear-gradient(160deg, rgba(255,255,255,0.06) 0%, rgba(255,255,255,0.02) 100%)', backdropFilter: 'blur(32px)', backgroundColor: '#0d1628' }}
      >
        {/* Header */}
        <div className="p-8 md:p-10 flex items-start justify-between relative border-b border-white/[0.06]">
          <div className="flex items-center gap-5">
            <div className={`p-3.5 rounded-xl ${iconClass}`}>
              <AlertTriangle size={36} strokeWidth={1.5} />
            </div>
            <div>
              <h2 className="text-2xl font-black text-white tracking-tight leading-none mb-2.5">
                {vulnerability.type}
              </h2>
              <div className="inline-flex items-center px-3 py-1 rounded-full bg-white/[0.05] border border-white/[0.08] text-[10px] font-bold text-slate-500 uppercase tracking-widest">
                Report ID: SEC-{vulnerability.id.toUpperCase()}
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 text-slate-600 hover:text-white transition-colors rounded-lg hover:bg-white/[0.06]"
          >
            <X size={22} strokeWidth={2} />
          </button>
        </div>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto px-8 md:px-10 pb-8 space-y-7 custom-scrollbar">

          <section className="pt-7">
            <h3 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Affected Resource</h3>
            <div className="bg-emerald-500/[0.06] p-4 rounded-xl border border-emerald-500/[0.15] flex items-center justify-between group cursor-pointer hover:bg-emerald-500/[0.1] transition-colors">
              <code className="text-emerald-400 text-sm font-bold truncate pr-4">{vulnerability.url}</code>
              <ExternalLink size={16} className="text-slate-600 group-hover:text-emerald-400 transition-colors shrink-0" />
            </div>
          </section>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
            <section>
              <h3 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Target Parameter</h3>
              <div className="bg-white/[0.04] px-4 py-2.5 rounded-lg inline-flex border border-white/[0.08]">
                <span className="text-emerald-400 font-bold mono text-sm">{vulnerability.parameter}</span>
              </div>
            </section>
            <section>
              <h3 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Threat Rating</h3>
              <div className={`px-4 py-2 rounded-lg text-[10px] font-bold uppercase tracking-widest border inline-flex ${badgeClass}`}>
                {vulnerability.severity} Risk
              </div>
            </section>
          </div>

          <section>
            <h3 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Active Payload</h3>
            <div className="bg-black/30 p-5 rounded-xl border border-white/[0.06]">
              <code className="text-amber-400 text-sm font-bold break-all">{vulnerability.payload}</code>
            </div>
          </section>

          <section>
            <h3 className="text-[10px] font-bold text-slate-500 uppercase tracking-widest mb-3">Response Excerpt</h3>
            <div className="bg-black/40 p-5 rounded-xl mono text-[12px] text-slate-400 leading-relaxed border border-white/[0.06]">
              <div className="flex items-center gap-2 mb-3 text-emerald-400 text-[10px] font-bold uppercase tracking-widest">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                Response Stream
              </div>
              <pre className="whitespace-pre-wrap break-all text-slate-400">
                {vulnerability.responseSnippet || "No response snippet captured."}
              </pre>
            </div>
          </section>

          <section className="bg-emerald-500/[0.06] border border-emerald-500/[0.15] p-7 rounded-xl">
            <div className="flex items-center gap-2.5 mb-3">
              <ShieldCheck size={17} className="text-emerald-400" strokeWidth={2} />
              <h3 className="text-[10px] font-bold text-emerald-400 uppercase tracking-widest">Remediation Guide</h3>
            </div>
            <p className="text-sm text-slate-300 leading-relaxed">
              {vulnerability.fixRecommendation}
            </p>
          </section>
        </div>

        {/* Footer */}
        <div className="px-8 md:px-10 py-5 bg-white/[0.02] border-t border-white/[0.06] flex items-center justify-end shrink-0">
          <button
            onClick={onClose}
            className="px-8 py-3 rounded-xl font-bold text-sm text-slate-300 hover:text-white border border-white/[0.1] hover:border-white/[0.2] transition-all"
            style={{ backdropFilter: 'blur(12px)', backgroundColor: 'rgba(255,255,255,0.05)' }}
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
};

export default Modal;
