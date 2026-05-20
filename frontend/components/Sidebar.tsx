
import React from 'react';
import { Shield, Sparkles } from 'lucide-react';
import { NAV_ITEMS } from '../constants';
import { NavItem } from '../types';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  isAiThinking?: boolean;
}

const Sidebar: React.FC<SidebarProps> = ({ activeTab, setActiveTab, isAiThinking }) => {
  return (
    <div className="w-72 bg-white border-r border-slate-200 flex flex-col h-screen sticky top-0 shadow-sm z-20">
      <div className="p-8 flex items-center gap-4">
        <div className="relative">
          <div className="bg-emerald-500 p-2.5 rounded-2xl shadow-lg shadow-emerald-100">
            <Shield className="text-white" size={24} strokeWidth={2.5} />
          </div>
          {isAiThinking && (
            <div className="absolute -top-1 -right-1 bg-amber-400 p-1 rounded-full animate-bounce shadow-sm border-2 border-white">
              <Sparkles size={10} className="text-white" fill="currentColor" />
            </div>
          )}
        </div>
        <h1 className="text-2xl font-black tracking-tight text-slate-900">
          SmartFuzz<span className="text-emerald-500">.</span>
        </h1>
      </div>

      <nav className="flex-1 py-10 px-6 space-y-2 overflow-y-auto">
        {NAV_ITEMS.map((item: NavItem) => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id)}
            className={`w-full flex items-center gap-4 px-5 py-4 rounded-[1.25rem] transition-all duration-200 group ${
              activeTab === item.id
                ? 'bg-emerald-50 text-emerald-600 border-2 border-emerald-100'
                : 'text-slate-500 hover:text-slate-900 hover:bg-slate-50 border-2 border-transparent'
            }`}
          >
            <span className={`transition-transform duration-300 ${activeTab === item.id ? 'scale-110 text-emerald-600' : 'text-slate-400 group-hover:scale-110 group-hover:text-slate-600'}`}>
              {React.isValidElement(item.icon) ? React.cloneElement(item.icon as React.ReactElement<any>, { size: 22, strokeWidth: 2.5 }) : item.icon}
            </span>
            <span className="font-bold text-sm tracking-wide">{item.label}</span>
          </button>
        ))}
      </nav>
    </div>
  );
};

export default Sidebar;
