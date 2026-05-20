import React, { useEffect, useState } from 'react';
import { ShieldAlert, X, ScrollText } from 'lucide-react';

interface ConsentModalProps {
  open: boolean;
  onAccept: () => void;
  onCancel: () => void;
  targetUrl: string;
}

const CHECKLIST: { id: 'ownership' | 'understanding' | 'liability'; label: string }[] = [
  { id: 'ownership',     label: "I own this target, or I have written authorization from the owner." },
  { id: 'understanding', label: "I understand this scan will send potentially malicious payloads." },
  { id: 'liability',     label: "I accept full legal responsibility for the consequences of this scan." },
];

const ConsentModal: React.FC<ConsentModalProps> = ({ open, onAccept, onCancel, targetUrl }) => {
  const [checks, setChecks] = useState({ ownership: false, understanding: false, liability: false });

  // Reset checkboxes whenever the modal re-opens so consent must be reaffirmed.
  useEffect(() => {
    if (open) setChecks({ ownership: false, understanding: false, liability: false });
  }, [open]);

  // Escape key cancels.
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onCancel(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, onCancel]);

  if (!open) return null;

  const allChecked = checks.ownership && checks.understanding && checks.liability;

  return (
    <div
      className="fixed inset-0 z-[70] flex items-center justify-center p-4 md:p-6"
      style={{ backgroundColor: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(12px)' }}
      onClick={onCancel}
      role="dialog"
      aria-modal="true"
      aria-labelledby="consent-title"
    >
      <div
        onClick={(e) => e.stopPropagation()}
        className="w-full max-w-xl rounded-2xl shadow-[0_32px_80px_rgba(0,0,0,0.8),inset_0_1px_0_rgba(255,255,255,0.06)] overflow-hidden animate-in fade-in zoom-in duration-300 flex flex-col max-h-[90vh] border border-white/[0.1]"
        style={{ background: 'linear-gradient(160deg, rgba(255,255,255,0.06) 0%, rgba(255,255,255,0.02) 100%)', backdropFilter: 'blur(32px)', backgroundColor: '#0d1628' }}
      >
        {/* Header */}
        <div className="p-7 md:p-8 flex items-start justify-between gap-4 border-b border-white/[0.06]">
          <div className="flex items-center gap-4">
            <div className="p-3 rounded-xl bg-amber-500/15 text-amber-400 border border-amber-500/20">
              <ShieldAlert size={28} strokeWidth={1.75} />
            </div>
            <div>
              <h2 id="consent-title" className="text-xl md:text-2xl font-black text-white tracking-tight leading-none mb-2">
                Authorization Required
              </h2>
              <div className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-white/[0.05] border border-white/[0.08] text-[10px] font-bold text-slate-500 uppercase tracking-widest">
                <ScrollText size={10} strokeWidth={2.5} />
                IT Act 2000 §43/66
              </div>
            </div>
          </div>
          <button
            onClick={onCancel}
            className="p-2 text-slate-600 hover:text-white transition-colors rounded-lg hover:bg-white/[0.06] shrink-0"
            aria-label="Cancel"
          >
            <X size={20} strokeWidth={2} />
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-7 md:px-8 py-6 space-y-5 custom-scrollbar">
          <p className="text-sm text-slate-300 leading-relaxed">
            You are about to launch an active security scan against{' '}
            <code className="text-emerald-400 font-bold mono break-all">{targetUrl || '—'}</code>.
          </p>

          <p className="text-sm text-slate-400 leading-relaxed">
            Active vulnerability scanning of systems you don't own or aren't authorized to test
            is a criminal offense under the IT Act 2000 §43/66 in India and similar laws worldwide.
          </p>

          <p className="text-xs font-bold text-slate-500 uppercase tracking-widest pt-2">
            By proceeding, you confirm:
          </p>

          <div className="space-y-2.5">
            {CHECKLIST.map((item) => {
              const checked = checks[item.id];
              return (
                <label
                  key={item.id}
                  className={`flex items-start gap-3.5 p-4 rounded-xl border cursor-pointer transition-all ${
                    checked
                      ? 'border-emerald-500/30 bg-emerald-500/[0.07]'
                      : 'border-white/[0.08] bg-white/[0.02] hover:border-white/[0.14] hover:bg-white/[0.04]'
                  }`}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={(e) => setChecks((prev) => ({ ...prev, [item.id]: e.target.checked }))}
                    className="w-4 h-4 accent-emerald-500 rounded mt-0.5 shrink-0"
                  />
                  <span className={`text-sm leading-snug ${checked ? 'text-white' : 'text-slate-400'}`}>
                    {item.label}
                  </span>
                </label>
              );
            })}
          </div>
        </div>

        {/* Footer */}
        <div className="px-7 md:px-8 py-5 bg-white/[0.02] border-t border-white/[0.06] flex items-center justify-end gap-3 shrink-0">
          <button
            onClick={onCancel}
            className="px-6 py-2.5 rounded-xl font-bold text-sm text-slate-300 hover:text-white border border-white/[0.1] hover:border-white/[0.2] transition-all"
            style={{ backdropFilter: 'blur(12px)', backgroundColor: 'rgba(255,255,255,0.05)' }}
          >
            Cancel
          </button>
          <button
            onClick={() => { if (allChecked) onAccept(); }}
            disabled={!allChecked}
            className="px-6 py-2.5 rounded-xl font-bold text-sm text-white transition-all shadow-[0_0_25px_rgba(16,185,129,0.35)] disabled:opacity-40 disabled:cursor-not-allowed disabled:shadow-none active:scale-95"
            style={{ background: 'linear-gradient(135deg, #10b981, #059669)' }}
          >
            I Confirm — Launch Scan
          </button>
        </div>
      </div>
    </div>
  );
};

export default ConsentModal;
