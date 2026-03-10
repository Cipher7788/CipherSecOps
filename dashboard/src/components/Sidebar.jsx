import React from 'react';
import { NavLink } from 'react-router-dom';

const NAV_ITEMS = [
  { to: '/',         label: 'Dashboard',    icon: '🛡️' },
  { to: '/threats',  label: 'Threats',      icon: '⚠️' },
  { to: '/agents',   label: 'Agents',       icon: '🖥️' },
  { to: '/network',  label: 'Network Map',  icon: '🌐' },
  { to: '/timeline', label: 'Timeline',     icon: '📅' },
  { to: '/intel',    label: 'Threat Intel', icon: '🔍' },
];

export default function Sidebar() {
  return (
    <aside className="w-60 bg-dark-card border-r border-dark-border flex flex-col shrink-0">
      {/* Brand */}
      <div className="flex items-center gap-3 px-5 py-5 border-b border-dark-border">
        <span className="text-2xl select-none">🔐</span>
        <div>
          <p className="text-sm font-bold text-white leading-tight">CipherSecOps</p>
          <p className="text-xs text-gray-400">SOC Platform</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {NAV_ITEMS.map(({ to, label, icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors duration-150 ${
                isActive
                  ? 'bg-accent-blue/20 text-accent-blue border border-accent-blue/30'
                  : 'text-gray-400 hover:bg-dark-border/60 hover:text-gray-100'
              }`
            }
          >
            <span className="text-base leading-none">{icon}</span>
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Footer */}
      <div className="px-5 py-4 border-t border-dark-border">
        <p className="text-xs text-gray-500">v1.0.0 — CipherSecOps</p>
      </div>
    </aside>
  );
}
