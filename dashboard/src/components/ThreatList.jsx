import React, { useEffect, useState, useCallback } from 'react';
import { getThreats, updateThreatStatus } from '../services/api';

/* ── Mock data ─────────────────────────────────────────── */
const MOCK_THREATS = [
  { id: 'T-1001', title: 'Credential Dump via LSASS',         severity: 'critical', agent: 'WIN-DC01',   technique: 'T1003.001', risk: 95, status: 'open',      time: '2024-06-10 14:32' },
  { id: 'T-1002', title: 'Lateral Movement via WMI',           severity: 'high',     agent: 'WIN-WEB02',  technique: 'T1021.006', risk: 82, status: 'open',      time: '2024-06-10 14:18' },
  { id: 'T-1003', title: 'Suspicious PowerShell Execution',    severity: 'high',     agent: 'WIN-APP03',  technique: 'T1059.001', risk: 78, status: 'reviewing', time: '2024-06-10 13:55' },
  { id: 'T-1004', title: 'Port Scan Detected',                 severity: 'medium',   agent: 'LNX-NGINX',  technique: 'T1046',     risk: 55, status: 'open',      time: '2024-06-10 13:40' },
  { id: 'T-1005', title: 'Brute Force SSH Login Attempts',     severity: 'medium',   agent: 'LNX-API01',  technique: 'T1110.001', risk: 50, status: 'resolved',  time: '2024-06-10 13:10' },
  { id: 'T-1006', title: 'Ransomware File Encryption Pattern', severity: 'critical', agent: 'WIN-FS01',   technique: 'T1486',     risk: 99, status: 'open',      time: '2024-06-10 12:58' },
  { id: 'T-1007', title: 'DNS Exfiltration Detected',          severity: 'high',     agent: 'LNX-DNS01',  technique: 'T1048.003', risk: 80, status: 'reviewing', time: '2024-06-10 12:35' },
  { id: 'T-1008', title: 'Scheduled Task Persistence',         severity: 'medium',   agent: 'WIN-WEB02',  technique: 'T1053.005', risk: 60, status: 'open',      time: '2024-06-10 12:10' },
  { id: 'T-1009', title: 'Anomalous Cloud API Calls',          severity: 'medium',   agent: 'AWS-PROD',   technique: 'T1078.004', risk: 65, status: 'reviewing', time: '2024-06-10 11:48' },
  { id: 'T-1010', title: 'Process Injection via CreateThread', severity: 'critical', agent: 'WIN-DC01',   technique: 'T1055.001', risk: 92, status: 'open',      time: '2024-06-10 11:30' },
  { id: 'T-1011', title: 'Outbound C2 Beacon Traffic',        severity: 'critical', agent: 'WIN-APP03',  technique: 'T1071.001', risk: 97, status: 'open',      time: '2024-06-10 11:15' },
  { id: 'T-1012', title: 'Registry Run Key Modification',      severity: 'low',      agent: 'WIN-WS04',   technique: 'T1547.001', risk: 35, status: 'resolved',  time: '2024-06-10 10:50' },
  { id: 'T-1013', title: 'Suspicious LSASS Memory Access',     severity: 'high',     agent: 'WIN-DC01',   technique: 'T1003.001', risk: 85, status: 'reviewing', time: '2024-06-10 10:22' },
  { id: 'T-1014', title: 'Cleartext Password in CLI Args',     severity: 'low',      agent: 'LNX-API01',  technique: 'T1552.001', risk: 30, status: 'resolved',  time: '2024-06-10 09:45' },
  { id: 'T-1015', title: 'Shadow Copy Deletion',               severity: 'critical', agent: 'WIN-FS01',   technique: 'T1490',     risk: 98, status: 'open',      time: '2024-06-10 09:30' },
];

const SEV_STYLES = {
  critical: 'bg-red-900/60 text-red-300 border border-red-700',
  high:     'bg-orange-900/60 text-orange-300 border border-orange-700',
  medium:   'bg-yellow-900/60 text-yellow-300 border border-yellow-700',
  low:      'bg-green-900/60 text-green-300 border border-green-700',
};
const SEV_ICON = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢' };

const STATUS_STYLES = {
  open:      'text-red-400',
  reviewing: 'text-yellow-400',
  resolved:  'text-green-400',
};

const SEVERITIES = ['all', 'critical', 'high', 'medium', 'low'];
const PAGE_SIZE = 8;

export default function ThreatList() {
  const [threats, setThreats]       = useState(MOCK_THREATS);
  const [filter, setFilter]         = useState('all');
  const [page, setPage]             = useState(1);

  useEffect(() => {
    getThreats()
      .then((d) => setThreats(d.items ?? d))
      .catch(() => {/* keep mock */});
  }, []);

  const handleStatusChange = useCallback(async (id, newStatus) => {
    setThreats((prev) =>
      prev.map((t) => (t.id === id ? { ...t, status: newStatus } : t))
    );
    try {
      await updateThreatStatus(id, newStatus);
    } catch {
      /* optimistic update kept */
    }
  }, []);

  const filtered = filter === 'all' ? threats : threats.filter((t) => t.severity === filter);
  const totalPages = Math.ceil(filtered.length / PAGE_SIZE);
  const paginated  = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  return (
    <div className="space-y-4 animate-fade-in">
      {/* Header / filters */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h2 className="text-lg font-semibold text-white">Threat List</h2>
        <div className="flex gap-2">
          {SEVERITIES.map((s) => (
            <button
              key={s}
              onClick={() => { setFilter(s); setPage(1); }}
              className={`px-3 py-1 rounded text-xs font-semibold capitalize transition-colors ${
                filter === s
                  ? 'bg-accent-blue text-white'
                  : 'bg-dark-card border border-dark-border text-gray-400 hover:text-white'
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="bg-dark-card border border-dark-border rounded-xl overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-gray-500 uppercase tracking-wider border-b border-dark-border">
              {['ID', 'Title', 'Severity', 'Agent', 'MITRE', 'Risk', 'Status', 'Time'].map((h) => (
                <th key={h} className="px-4 py-3 text-left whitespace-nowrap">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-dark-border">
            {paginated.map((t) => (
              <tr key={t.id} className="hover:bg-dark-border/30 transition-colors">
                <td className="px-4 py-3 font-mono text-xs text-gray-400">{t.id}</td>
                <td className="px-4 py-3 text-gray-100 font-medium max-w-[200px] truncate" title={t.title}>{t.title}</td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-0.5 rounded text-xs font-semibold ${SEV_STYLES[t.severity]}`}>
                    {SEV_ICON[t.severity]} {t.severity}
                  </span>
                </td>
                <td className="px-4 py-3 font-mono text-xs text-gray-300">{t.agent}</td>
                <td className="px-4 py-3 font-mono text-xs text-accent-blue">{t.technique}</td>
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2">
                    <div className="w-14 bg-dark-border rounded-full h-1.5">
                      <div
                        className={`h-1.5 rounded-full ${t.risk >= 80 ? 'bg-accent-red' : t.risk >= 60 ? 'bg-accent-yellow' : 'bg-accent-green'}`}
                        style={{ width: `${t.risk}%` }}
                      />
                    </div>
                    <span className="text-xs text-gray-400 tabular-nums">{t.risk}</span>
                  </div>
                </td>
                <td className="px-4 py-3">
                  <select
                    value={t.status}
                    onChange={(e) => handleStatusChange(t.id, e.target.value)}
                    className={`bg-transparent text-xs font-semibold cursor-pointer focus:outline-none ${STATUS_STYLES[t.status]}`}
                  >
                    <option value="open">Open</option>
                    <option value="reviewing">Reviewing</option>
                    <option value="resolved">Resolved</option>
                  </select>
                </td>
                <td className="px-4 py-3 text-xs text-gray-400 whitespace-nowrap">{t.time}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between text-sm text-gray-400">
        <span>Showing {(page - 1) * PAGE_SIZE + 1}–{Math.min(page * PAGE_SIZE, filtered.length)} of {filtered.length}</span>
        <div className="flex gap-2">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="px-3 py-1 bg-dark-card border border-dark-border rounded hover:bg-dark-border disabled:opacity-40 transition-colors"
          >
            ← Prev
          </button>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="px-3 py-1 bg-dark-card border border-dark-border rounded hover:bg-dark-border disabled:opacity-40 transition-colors"
          >
            Next →
          </button>
        </div>
      </div>
    </div>
  );
}
