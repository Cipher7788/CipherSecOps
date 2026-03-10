import React, { useEffect, useState } from 'react';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';
import { getStats, getThreats } from '../services/api';

/* ── Mock data ─────────────────────────────────────────── */
const MOCK_STATS = {
  total_threats: 1284,
  active_agents: 47,
  critical_alerts: 3,
  risk_score: 72,
};

const MOCK_TREND = [
  { time: '00:00', critical: 2, high: 5, medium: 12, low: 20 },
  { time: '02:00', critical: 1, high: 4, medium: 10, low: 18 },
  { time: '04:00', critical: 0, high: 2, medium: 7,  low: 15 },
  { time: '06:00', critical: 1, high: 3, medium: 9,  low: 17 },
  { time: '08:00', critical: 3, high: 8, medium: 20, low: 30 },
  { time: '10:00', critical: 5, high: 12, medium: 28, low: 40 },
  { time: '12:00', critical: 4, high: 10, medium: 25, low: 38 },
  { time: '14:00', critical: 6, high: 14, medium: 32, low: 45 },
  { time: '16:00', critical: 3, high: 9,  medium: 22, low: 35 },
  { time: '18:00', critical: 2, high: 7,  medium: 18, low: 28 },
  { time: '20:00', critical: 4, high: 11, medium: 24, low: 36 },
  { time: '22:00', critical: 3, high: 8,  medium: 19, low: 30 },
];

const MOCK_THREATS = [
  { id: 'T-1001', title: 'Credential Dump via LSASS', severity: 'critical', agent: 'WIN-DC01', technique: 'T1003', risk: 95, status: 'open',      time: '14:32' },
  { id: 'T-1002', title: 'Lateral Movement via WMI',  severity: 'high',     agent: 'WIN-WEB02', technique: 'T1021', risk: 82, status: 'open',      time: '14:18' },
  { id: 'T-1003', title: 'Suspicious PowerShell Exec',severity: 'high',     agent: 'WIN-APP03', technique: 'T1059', risk: 78, status: 'reviewing', time: '13:55' },
  { id: 'T-1004', title: 'Port Scan Detected',        severity: 'medium',   agent: 'LNX-NGINX', technique: 'T1046', risk: 55, status: 'open',      time: '13:40' },
  { id: 'T-1005', title: 'Brute Force SSH',           severity: 'medium',   agent: 'LNX-API01', technique: 'T1110', risk: 50, status: 'resolved',  time: '13:10' },
];

/* ── Helpers ────────────────────────────────────────────── */
const SEV_STYLES = {
  critical: 'bg-red-900/60 text-red-300 border border-red-700',
  high:     'bg-orange-900/60 text-orange-300 border border-orange-700',
  medium:   'bg-yellow-900/60 text-yellow-300 border border-yellow-700',
  low:      'bg-green-900/60 text-green-300 border border-green-700',
};

const SEV_ICON = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };

function StatCard({ label, value, icon, colorClass }) {
  return (
    <div className="bg-dark-card border border-dark-border rounded-xl p-5 flex items-center gap-4 animate-fade-in">
      <div className={`text-3xl p-3 rounded-lg ${colorClass}`}>{icon}</div>
      <div>
        <p className="text-xs text-gray-400 uppercase tracking-wider">{label}</p>
        <p className="text-2xl font-bold text-white mt-0.5">{value}</p>
      </div>
    </div>
  );
}

export default function Dashboard() {
  const [stats, setStats]   = useState(MOCK_STATS);
  const [threats, setThreats] = useState(MOCK_THREATS);
  const [trend] = useState(MOCK_TREND);

  useEffect(() => {
    getStats().then(setStats).catch(() => {/* use mock */});
    getThreats({ limit: 5 }).then((d) => setThreats(d.items ?? d)).catch(() => {/* use mock */});
  }, []);

  return (
    <div className="space-y-6">
      {/* Stat cards */}
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard label="Total Threats"   value={stats.total_threats.toLocaleString()} icon="⚠️"  colorClass="bg-red-900/30" />
        <StatCard label="Active Agents"   value={stats.active_agents}                   icon="🖥️"  colorClass="bg-blue-900/30" />
        <StatCard label="Critical Alerts" value={stats.critical_alerts}                 icon="🚨"  colorClass="bg-red-900/30" />
        <StatCard label="Risk Score"      value={`${stats.risk_score}/100`}             icon="📊"  colorClass="bg-yellow-900/30" />
      </div>

      {/* Threat trend chart */}
      <div className="bg-dark-card border border-dark-border rounded-xl p-5">
        <h2 className="text-sm font-semibold text-gray-300 mb-4">Threat Activity — Last 24h</h2>
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={trend} margin={{ top: 4, right: 16, left: -16, bottom: 0 }}>
            <defs>
              {[
                { id: 'gCritical', color: '#ef4444' },
                { id: 'gHigh',     color: '#f97316' },
                { id: 'gMedium',   color: '#f59e0b' },
                { id: 'gLow',      color: '#10b981' },
              ].map(({ id, color }) => (
                <linearGradient key={id} id={id} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor={color} stopOpacity={0.4} />
                  <stop offset="95%" stopColor={color} stopOpacity={0.02} />
                </linearGradient>
              ))}
            </defs>
            <CartesianGrid strokeDasharray="3 3" stroke="#2d3149" />
            <XAxis dataKey="time" stroke="#6b7280" tick={{ fontSize: 11 }} />
            <YAxis stroke="#6b7280" tick={{ fontSize: 11 }} />
            <Tooltip
              contentStyle={{ backgroundColor: '#1a1d2e', border: '1px solid #2d3149', borderRadius: 8 }}
              labelStyle={{ color: '#9ca3af' }}
            />
            <Area type="monotone" dataKey="critical" stroke="#ef4444" fill="url(#gCritical)" strokeWidth={2} name="Critical" />
            <Area type="monotone" dataKey="high"     stroke="#f97316" fill="url(#gHigh)"     strokeWidth={2} name="High" />
            <Area type="monotone" dataKey="medium"   stroke="#f59e0b" fill="url(#gMedium)"   strokeWidth={2} name="Medium" />
            <Area type="monotone" dataKey="low"      stroke="#10b981" fill="url(#gLow)"      strokeWidth={2} name="Low" />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Recent threats table */}
      <div className="bg-dark-card border border-dark-border rounded-xl p-5">
        <h2 className="text-sm font-semibold text-gray-300 mb-4">Recent Threats</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-gray-500 uppercase tracking-wider border-b border-dark-border">
                <th className="pb-3 text-left">ID</th>
                <th className="pb-3 text-left">Title</th>
                <th className="pb-3 text-left">Severity</th>
                <th className="pb-3 text-left">Agent</th>
                <th className="pb-3 text-left">Technique</th>
                <th className="pb-3 text-left">Risk</th>
                <th className="pb-3 text-left">Time</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-dark-border">
              {threats.map((t) => (
                <tr key={t.id} className="hover:bg-dark-border/30 transition-colors">
                  <td className="py-3 font-mono text-xs text-gray-400">{t.id}</td>
                  <td className="py-3 text-gray-100 font-medium max-w-[220px] truncate">{t.title}</td>
                  <td className="py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-semibold ${SEV_STYLES[t.severity]}`}>
                      {SEV_ICON[t.severity]} {t.severity}
                    </span>
                  </td>
                  <td className="py-3 font-mono text-xs text-gray-300">{t.agent}</td>
                  <td className="py-3 font-mono text-xs text-accent-blue">{t.technique}</td>
                  <td className="py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-16 bg-dark-border rounded-full h-1.5">
                        <div
                          className={`h-1.5 rounded-full ${t.risk >= 80 ? 'bg-accent-red' : t.risk >= 60 ? 'bg-accent-yellow' : 'bg-accent-green'}`}
                          style={{ width: `${t.risk}%` }}
                        />
                      </div>
                      <span className="text-xs text-gray-400">{t.risk}</span>
                    </div>
                  </td>
                  <td className="py-3 text-xs text-gray-400">{t.time}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
