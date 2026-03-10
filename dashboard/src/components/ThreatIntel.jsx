import React, { useEffect, useState } from 'react';
import { getThreatIntel } from '../services/api';

/* ── Mock IOC data ──────────────────────────────────────── */
const MOCK_IOCS = [
  { id: 'ioc01', indicator: '185.220.101.45',                            type: 'ip',     source: 'AbuseIPDB',  threat_type: 'C2 Server',           confidence: 98, last_seen: '2024-06-10 14:30' },
  { id: 'ioc02', indicator: '103.99.0.122',                              type: 'ip',     source: 'AlienVault', threat_type: 'Brute Force',          confidence: 85, last_seen: '2024-06-10 13:40' },
  { id: 'ioc03', indicator: 'a3f4b2c1d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0', type: 'hash',   source: 'VirusTotal', threat_type: 'Ransomware',           confidence: 99, last_seen: '2024-06-10 13:55' },
  { id: 'ioc04', indicator: 'evil-domain.ru',                            type: 'domain', source: 'AlienVault', threat_type: 'Malware Distribution', confidence: 90, last_seen: '2024-06-10 13:18' },
  { id: 'ioc05', indicator: '91.108.4.33',                               type: 'ip',     source: 'AbuseIPDB',  threat_type: 'Tor Exit Node',        confidence: 76, last_seen: '2024-06-10 12:10' },
  { id: 'ioc06', indicator: 'b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0', type: 'hash',   source: 'VirusTotal', threat_type: 'Trojan Loader',         confidence: 94, last_seen: '2024-06-10 11:48' },
  { id: 'ioc07', indicator: 'malware-cdn.cc',                            type: 'domain', source: 'VirusTotal', threat_type: 'Phishing',             confidence: 88, last_seen: '2024-06-10 11:30' },
  { id: 'ioc08', indicator: '45.142.212.100',                            type: 'ip',     source: 'AbuseIPDB',  threat_type: 'Scanning',             confidence: 70, last_seen: '2024-06-10 11:00' },
  { id: 'ioc09', indicator: 'c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2', type: 'hash',   source: 'VirusTotal', threat_type: 'Infostealer',           confidence: 97, last_seen: '2024-06-10 10:45' },
  { id: 'ioc10', indicator: 'update-checker.io',                         type: 'domain', source: 'AlienVault', threat_type: 'C2 Beacon',            confidence: 82, last_seen: '2024-06-10 10:22' },
];

const SOURCE_BADGE = {
  AlienVault: 'bg-purple-900/60 text-purple-300 border border-purple-700',
  AbuseIPDB:  'bg-blue-900/60 text-blue-300 border border-blue-700',
  VirusTotal: 'bg-indigo-900/60 text-indigo-300 border border-indigo-700',
};

const TYPE_ICON = { ip: '🌐', hash: '#️⃣', domain: '🔗' };

function ConfidenceBar({ value }) {
  const color = value >= 90 ? 'bg-accent-red' : value >= 70 ? 'bg-accent-yellow' : 'bg-accent-green';
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 bg-dark-border rounded-full h-1.5">
        <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${value}%` }} />
      </div>
      <span className="text-xs text-gray-400 tabular-nums">{value}%</span>
    </div>
  );
}

export default function ThreatIntel() {
  const [iocs, setIocs] = useState(MOCK_IOCS);

  useEffect(() => {
    getThreatIntel()
      .then((d) => setIocs(d.iocs ?? d))
      .catch(() => {/* keep mock */});
  }, []);

  const totalIOCs    = iocs.length;
  const maliciousIPs = iocs.filter((i) => i.type === 'ip').length;
  const suspHashes   = iocs.filter((i) => i.type === 'hash').length;

  return (
    <div className="space-y-5 animate-fade-in">
      <h2 className="text-lg font-semibold text-white">Threat Intelligence</h2>

      {/* Summary stats */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: 'Total IOCs',         value: totalIOCs,    icon: '🔍', color: 'bg-blue-900/30' },
          { label: 'Malicious IPs',      value: maliciousIPs, icon: '🌐', color: 'bg-red-900/30' },
          { label: 'Suspicious Hashes',  value: suspHashes,   icon: '#️⃣', color: 'bg-orange-900/30' },
        ].map(({ label, value, icon, color }) => (
          <div key={label} className="bg-dark-card border border-dark-border rounded-xl p-4 flex items-center gap-3">
            <div className={`text-2xl p-2.5 rounded-lg ${color}`}>{icon}</div>
            <div>
              <p className="text-xs text-gray-400 uppercase tracking-wide">{label}</p>
              <p className="text-xl font-bold text-white">{value}</p>
            </div>
          </div>
        ))}
      </div>

      {/* IOC Table */}
      <div className="bg-dark-card border border-dark-border rounded-xl overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-xs text-gray-500 uppercase tracking-wider border-b border-dark-border">
              {['Type', 'Indicator', 'Source', 'Threat Type', 'Confidence', 'Last Seen'].map((h) => (
                <th key={h} className="px-4 py-3 text-left whitespace-nowrap">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-dark-border">
            {iocs.map((ioc) => (
              <tr key={ioc.id} className="hover:bg-dark-border/30 transition-colors">
                <td className="px-4 py-3 text-base" title={ioc.type}>{TYPE_ICON[ioc.type]}</td>
                <td className="px-4 py-3 font-mono text-xs text-gray-200 max-w-[220px] truncate" title={ioc.indicator}>
                  {ioc.indicator}
                </td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-0.5 rounded text-xs font-semibold ${SOURCE_BADGE[ioc.source] ?? 'bg-gray-800 text-gray-300'}`}>
                    {ioc.source}
                  </span>
                </td>
                <td className="px-4 py-3 text-xs text-gray-300">{ioc.threat_type}</td>
                <td className="px-4 py-3"><ConfidenceBar value={ioc.confidence} /></td>
                <td className="px-4 py-3 text-xs text-gray-400 whitespace-nowrap">{ioc.last_seen}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
