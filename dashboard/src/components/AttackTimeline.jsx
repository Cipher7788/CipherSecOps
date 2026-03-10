import React, { useEffect, useState } from 'react';
import { getTimeline } from '../services/api';

/* ── Mock events ────────────────────────────────────────── */
const MOCK_EVENTS = [
  { id: 'e01', type: 'login_failure',      agent: 'WIN-DC01',  message: 'Failed login for administrator (5 attempts)',   severity: 'high',     time: '2024-06-10T14:45:00Z' },
  { id: 'e02', type: 'suspicious_process', agent: 'WIN-APP03', message: 'PowerShell spawned from Word.exe',               severity: 'critical', time: '2024-06-10T14:32:00Z' },
  { id: 'e03', type: 'network_anomaly',    agent: 'LNX-NGINX', message: 'Outbound traffic spike to 185.220.101.45:443',   severity: 'high',     time: '2024-06-10T14:18:00Z' },
  { id: 'e04', type: 'file_change',        agent: 'WIN-FS01',  message: 'Mass file rename with .locked extension',        severity: 'critical', time: '2024-06-10T13:55:00Z' },
  { id: 'e05', type: 'login_failure',      agent: 'LNX-API01', message: 'SSH brute force from 103.99.0.122',              severity: 'medium',   time: '2024-06-10T13:40:00Z' },
  { id: 'e06', type: 'suspicious_process', agent: 'WIN-DC01',  message: 'lsass.exe accessed by unknown process',          severity: 'critical', time: '2024-06-10T13:10:00Z' },
  { id: 'e07', type: 'network_anomaly',    agent: 'LNX-DNS01', message: 'High-frequency TXT record queries (C2 beacon)',  severity: 'high',     time: '2024-06-10T12:58:00Z' },
  { id: 'e08', type: 'file_change',        agent: 'WIN-WEB02', message: 'web.config modified outside maintenance window', severity: 'medium',   time: '2024-06-10T12:35:00Z' },
  { id: 'e09', type: 'login_failure',      agent: 'AWS-PROD',  message: 'IAM root login attempt from 91.108.4.33',        severity: 'high',     time: '2024-06-10T12:10:00Z' },
  { id: 'e10', type: 'suspicious_process', agent: 'WIN-FS01',  message: 'vssadmin.exe delete shadows /all /quiet',        severity: 'critical', time: '2024-06-10T11:48:00Z' },
  { id: 'e11', type: 'network_anomaly',    agent: 'WIN-WEB02', message: 'WMI remote execution to 10.0.1.12',              severity: 'high',     time: '2024-06-10T11:30:00Z' },
  { id: 'e12', type: 'file_change',        agent: 'LNX-NGINX', message: 'New SUID binary found: /tmp/.hidden',            severity: 'medium',   time: '2024-06-10T11:15:00Z' },
];

const TYPE_CONFIG = {
  login_failure:      { icon: '🔑', label: 'Login Failure',       color: 'border-orange-500 bg-orange-900/20' },
  suspicious_process: { icon: '⚙️',  label: 'Suspicious Process',  color: 'border-red-500 bg-red-900/20' },
  network_anomaly:    { icon: '🌐', label: 'Network Anomaly',     color: 'border-blue-500 bg-blue-900/20' },
  file_change:        { icon: '📁', label: 'File Change',         color: 'border-yellow-500 bg-yellow-900/20' },
};

const SEV_BADGE = {
  critical: 'bg-red-900/60 text-red-300 border border-red-700',
  high:     'bg-orange-900/60 text-orange-300 border border-orange-700',
  medium:   'bg-yellow-900/60 text-yellow-300 border border-yellow-700',
  low:      'bg-green-900/60 text-green-300 border border-green-700',
};

function formatTime(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export default function AttackTimeline() {
  const [events, setEvents] = useState(MOCK_EVENTS);

  useEffect(() => {
    getTimeline()
      .then((d) => setEvents(d.events ?? d))
      .catch(() => {/* keep mock */});
  }, []);

  return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-white">Attack Timeline</h2>
        {/* Legend */}
        <div className="flex gap-3 text-xs flex-wrap">
          {Object.entries(TYPE_CONFIG).map(([k, v]) => (
            <span key={k} className="flex items-center gap-1 text-gray-400">
              <span>{v.icon}</span> {v.label}
            </span>
          ))}
        </div>
      </div>

      <div className="relative pl-6">
        {/* Vertical spine */}
        <div className="absolute left-2.5 top-0 bottom-0 w-px bg-dark-border" />

        <div className="space-y-3">
          {events.map((ev, idx) => {
            const cfg = TYPE_CONFIG[ev.type] ?? { icon: '❓', label: ev.type, color: 'border-gray-500 bg-gray-900/20' };
            return (
              <div
                key={ev.id}
                className={`relative flex gap-4 items-start p-4 rounded-xl border-l-2 ${cfg.color} animate-fade-in`}
                style={{ animationDelay: `${idx * 30}ms` }}
              >
                {/* Timeline dot */}
                <span className="absolute -left-[1.35rem] text-base leading-none">{cfg.icon}</span>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className={`px-2 py-0.5 rounded text-[11px] font-semibold ${SEV_BADGE[ev.severity]}`}>
                      {ev.severity}
                    </span>
                    <span className="text-xs text-gray-400 font-semibold">{cfg.label}</span>
                    <span className="text-xs font-mono text-accent-blue">{ev.agent}</span>
                  </div>
                  <p className="text-sm text-gray-100">{ev.message}</p>
                </div>

                <time className="text-xs text-gray-500 tabular-nums whitespace-nowrap shrink-0 pt-0.5">
                  {formatTime(ev.time)}
                </time>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
