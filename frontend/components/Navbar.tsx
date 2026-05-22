import React, { useState } from 'react';
import { Shield, Sparkles, Menu, X } from 'lucide-react';
import { NAV_ITEMS } from '../constants';
import { NavItem } from '../types';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isScanning?: boolean;
}

const Navbar: React.FC<NavbarProps> = ({ activeTab, setActiveTab, isScanning }) => {
  const [menuOpen, setMenuOpen] = useState(false);

  const go = (id: string) => {
    setActiveTab(id);
    setMenuOpen(false);
  };

  return (
    <header
      className="sticky top-0 z-50 w-full"
      style={{
        backgroundColor: 'rgba(8,13,26,0.85)',
        backdropFilter: 'blur(28px)',
        borderBottom: '1px solid rgba(255,255,255,0.06)',
      }}
    >
      {/* Top accent line */}
      <div
        className="absolute top-0 left-0 right-0 h-px"
        style={{ background: 'linear-gradient(90deg, transparent 0%, rgba(16,185,129,0.6) 35%, rgba(34,211,238,0.5) 65%, transparent 100%)' }}
      />

      <div className="px-4 md:px-10 lg:px-16 h-20 md:h-24 flex items-center gap-6">

        {/* Logo */}
        <div
          className="flex items-center gap-3.5 cursor-pointer shrink-0 group"
          onClick={() => go('landing')}
        >
          <div className="relative">
            {/* Gradient border ring */}
            <div
              className="absolute -inset-[1.5px] rounded-[13px] opacity-70 group-hover:opacity-100 transition-all duration-300"
              style={{ background: 'linear-gradient(135deg, #10b981, #22d3ee)' }}
            />
            <div
              className="relative w-12 h-12 rounded-xl flex items-center justify-center transition-all duration-300 group-hover:scale-[1.04]"
              style={{
                background: 'linear-gradient(135deg, rgba(16,185,129,0.18) 0%, rgba(8,145,178,0.12) 100%)',
                backdropFilter: 'blur(12px)',
              }}
            >
              <Shield size={22} className="text-white" fill="currentColor" strokeWidth={0} />
              <span
                className="absolute bottom-[7px] right-[7px] w-1.5 h-1.5 rounded-full"
                style={{ background: '#22d3ee', boxShadow: '0 0 7px rgba(34,211,238,0.9)' }}
              />
            </div>
            {isScanning && (
              <div className="absolute -top-1.5 -right-1.5 bg-amber-400 p-1 rounded-full border-2 border-[#080d1a] animate-bounce z-10">
                <Sparkles size={9} className="text-white" fill="currentColor" />
              </div>
            )}
          </div>

          <span className="text-[22px] font-black tracking-tight leading-none">
            <span className="text-white">Smart</span>
            <span style={{ background: 'linear-gradient(90deg, #34d399, #22d3ee)', WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent' }}>Fuzz.</span>
          </span>
        </div>

        {/* Desktop nav pill — unchanged on md+, hidden on mobile */}
        <nav
          className="ml-auto hidden md:flex items-center p-1.5 rounded-2xl gap-0.5"
          style={{
            background: 'rgba(255,255,255,0.03)',
            border: '1px solid rgba(255,255,255,0.07)',
            backdropFilter: 'blur(12px)',
          }}
        >
          {NAV_ITEMS.map((item: NavItem) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => go(item.id)}
                className="relative flex items-center gap-2 px-5 py-2.5 rounded-xl font-bold text-[15px] transition-all duration-200 whitespace-nowrap"
                style={
                  isActive
                    ? {
                        color: '#fff',
                        background: 'linear-gradient(135deg, rgba(16,185,129,0.2) 0%, rgba(8,145,178,0.12) 100%)',
                        boxShadow: '0 0 20px rgba(16,185,129,0.15), inset 0 1px 0 rgba(255,255,255,0.1)',
                        border: '1px solid rgba(52,211,153,0.25)',
                      }
                    : {
                        color: 'rgba(148,163,184,0.8)',
                        border: '1px solid transparent',
                      }
                }
                onMouseEnter={e => {
                  if (!isActive) {
                    (e.currentTarget as HTMLButtonElement).style.color = '#e2e8f0';
                    (e.currentTarget as HTMLButtonElement).style.background = 'rgba(255,255,255,0.06)';
                  }
                }}
                onMouseLeave={e => {
                  if (!isActive) {
                    (e.currentTarget as HTMLButtonElement).style.color = 'rgba(148,163,184,0.8)';
                    (e.currentTarget as HTMLButtonElement).style.background = '';
                  }
                }}
              >
                <span style={{ color: isActive ? '#34d399' : 'inherit', display: 'flex' }}>
                  {React.isValidElement(item.icon)
                    ? React.cloneElement(item.icon as React.ReactElement<any>, { size: 15, strokeWidth: 2 })
                    : item.icon}
                </span>
                {item.label}
              </button>
            );
          })}
        </nav>

        {/* Mobile hamburger — only on small screens */}
        <button
          onClick={() => setMenuOpen(v => !v)}
          aria-label={menuOpen ? 'Close menu' : 'Open menu'}
          aria-expanded={menuOpen}
          className="md:hidden ml-auto shrink-0 w-11 h-11 rounded-xl flex items-center justify-center text-slate-300 transition-all active:scale-95"
          style={{
            background: 'rgba(255,255,255,0.04)',
            border: '1px solid rgba(255,255,255,0.08)',
          }}
        >
          {menuOpen ? <X size={22} strokeWidth={2} /> : <Menu size={22} strokeWidth={2} />}
        </button>
      </div>

      {/* Mobile dropdown menu */}
      {menuOpen && (
        <nav
          className="md:hidden border-t border-white/[0.06] px-4 py-3 flex flex-col gap-1.5"
          style={{ backgroundColor: 'rgba(8,13,26,0.97)', backdropFilter: 'blur(28px)' }}
        >
          {NAV_ITEMS.map((item: NavItem) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => go(item.id)}
                className="w-full flex items-center gap-3 px-4 py-3 rounded-xl font-bold text-[15px] transition-all"
                style={
                  isActive
                    ? {
                        color: '#fff',
                        background: 'linear-gradient(135deg, rgba(16,185,129,0.2) 0%, rgba(8,145,178,0.12) 100%)',
                        border: '1px solid rgba(52,211,153,0.25)',
                      }
                    : {
                        color: 'rgba(148,163,184,0.85)',
                        border: '1px solid transparent',
                      }
                }
              >
                <span style={{ color: isActive ? '#34d399' : 'inherit', display: 'flex' }}>
                  {React.isValidElement(item.icon)
                    ? React.cloneElement(item.icon as React.ReactElement<any>, { size: 17, strokeWidth: 2 })
                    : item.icon}
                </span>
                {item.label}
              </button>
            );
          })}
        </nav>
      )}
    </header>
  );
};

export default Navbar;
