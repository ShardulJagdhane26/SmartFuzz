import React from 'react';

interface StatCardProps {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  trend?: string;
  trendType?: 'up' | 'down';
}

const StatCard: React.FC<StatCardProps> = ({ label, value, icon }) => {
  return (
    <div className="relative rounded-2xl p-8 flex flex-col items-center text-center gap-4 overflow-hidden border border-emerald-500/20 shadow-[0_0_30px_rgba(16,185,129,0.08),inset_0_1px_0_rgba(255,255,255,0.06)]" style={{ background: 'linear-gradient(135deg, rgba(16,185,129,0.1) 0%, rgba(16,185,129,0.03) 100%)', backdropFilter: 'blur(20px)' }}>
      <div className="absolute top-0 right-0 w-32 h-32 bg-emerald-500/[0.06] rounded-full blur-2xl -translate-y-1/2 translate-x-1/2" />
      <div className="relative text-emerald-400">
        {React.isValidElement(icon)
          ? React.cloneElement(icon as React.ReactElement<any>, { size: 28, strokeWidth: 1.5 })
          : icon}
      </div>
      <div className="relative">
        <p className="text-3xl font-black text-white leading-none mb-2 tabular-nums">{value}</p>
        <p className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">{label}</p>
      </div>
    </div>
  );
};

export default StatCard;
