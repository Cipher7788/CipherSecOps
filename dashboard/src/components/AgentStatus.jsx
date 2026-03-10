import React, { useEffect, useState } from 'react';
import { formatDistanceToNow } from 'date-fns';
import { getAgents } from '../services/api';

/* ── Mock data ─────────────────────────────────────────── */
const MOCK_AGENTS = [
  { id: 'a1',  hostname: 'WIN-DC01',   platform: 'windows', ip: '10.0.1.10',  status: 'online',  last_seen: new Date(Date.now() - 15000),      version: '1.4.2' },
  { id: 'a2',  hostname: 'WIN-WEB02',  platform: 'windows', ip: '10.0.1.11',  status: 'online',  last_seen: new Date(Date.now() - 42000),      version: '1.4.2' },
  { id: 'a3',  hostname: 'WIN-APP03',  platform: 'windows', ip: '10.0.1.12',  status: 'idle',    last_seen: new Date(Date.now() - 300000),     version: '1.4.1' },
  { id: 'a4',  hostname: 'WIN-FS01',   platform: 'windows', ip: '10.0.1.13',  status: 'online',  last_seen: new Date(Date.now() - 8000),       version: '1.4.2' },
  { id: 'a5',  hostname: 'LNX-NGINX',  platform: 'linux',   ip: '10.0.2.10',  status: 'online',  last_seen: new Date(Date.now() - 22000),      version: '1.4.2' },
  { id: 'a6',  hostname: 'LNX-API01',  platform: 'linux',   ip: '10.0.2.11',  status: 'online',  last_seen: new Date(Date.now() - 55000),      version: '1.4.2' },
  { id: 'a7',  hostname: 'LNX-DNS01',  platform: 'linux',   ip: '10.0.2.12',  status: 'offline', last_seen: new Date(Date.now() - 3600000),    version: '1.3.9' },
  { id: 'a8',  hostname: 'LNX-DB01',   platform: 'linux',   ip: '10.0.2.13',  status: 'online',  last_seen: new Date(Date.now() - 18000),      version: '1.4.2' },
  { id: 'a9',  hostname: 'AWS-PROD',   platform: 'cloud',   ip: '172.31.0.5', status: 'online',  last_seen: new Date(Date.now() - 30000),      version: '1.4.2' },
  { id: 'a10', hostname: 'AWS-STAGE',  platform: 'cloud',   ip: '172.31.0.6', status: 'idle',    last_seen: new Date(Date.now() - 600000),     version: '1.4.1' },
  { id: 'a11', hostname: 'WIN-WS04',   platform: 'windows', ip: '10.0.1.20',  status: 'online',  last_seen: new Date(Date.now() - 10000),      version: '1.4.2' },
  { id: 'a12', hostname: 'LNX-MON01',  platform: 'linux',   ip: '10.0.2.20',  status: 'offline', last_seen: new Date(Date.now() - 7200000),    version: '1.3.8' },
];

const PLATFORM_ICON = { windows: '🪟', linux: '🐧', cloud: '☁️' };

const STATUS_DOT = {
  online:  'bg-accent-green',
  offline: 'bg-accent-red',
  idle:    'bg-accent-yellow',
};
const STATUS_LABEL = {
  online:  'text-green-400',
  offline: 'text-red-400',
  idle:    'text-yellow-400',
};

export default function AgentStatus() {
  const [agents, setAgents] = useState(MOCK_AGENTS);

  useEffect(() => {
    getAgents()
      .then((d) => setAgents(d.agents ?? d))
      .catch(() => {/* keep mock */});
  }, []);

  const online  = agents.filter((a) => a.status === 'online').length;
  const offline = agents.filter((a) => a.status === 'offline').length;
  const idle    = agents.filter((a) => a.status === 'idle').length;

  return (
    <div className="space-y-5 animate-fade-in">
      {/* Summary */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <h2 className="text-lg font-semibold text-white">Agent Status</h2>
        <div className="flex gap-4 text-sm">
          <span className="flex items-center gap-1.5 text-green-400"><span className="w-2 h-2 rounded-full bg-accent-green inline-block" />{online} Online</span>
          <span className="flex items-center gap-1.5 text-yellow-400"><span className="w-2 h-2 rounded-full bg-accent-yellow inline-block" />{idle} Idle</span>
          <span className="flex items-center gap-1.5 text-red-400"><span className="w-2 h-2 rounded-full bg-accent-red inline-block" />{offline} Offline</span>
          <span className="text-gray-400">/ {agents.length} Total</span>
        </div>
      </div>

      {/* Agent grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
        {agents.map((agent) => (
          <div
            key={agent.id}
            className="bg-dark-card border border-dark-border rounded-xl p-4 hover:border-accent-blue/40 transition-colors"
          >
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-center gap-3">
                <span className="text-2xl">{PLATFORM_ICON[agent.platform]}</span>
                <div>
                  <p className="font-semibold text-white text-sm">{agent.hostname}</p>
                  <p className="text-xs text-gray-400 font-mono">{agent.ip}</p>
                </div>
              </div>
              {/* Status dot */}
              <div className="flex items-center gap-1.5">
                <span className={`w-2.5 h-2.5 rounded-full ${STATUS_DOT[agent.status]} ${agent.status === 'online' ? 'animate-pulse' : ''}`} />
                <span className={`text-xs font-semibold capitalize ${STATUS_LABEL[agent.status]}`}>{agent.status}</span>
              </div>
            </div>

            <div className="border-t border-dark-border pt-3 space-y-1.5">
              <div className="flex justify-between text-xs">
                <span className="text-gray-500">Platform</span>
                <span className="text-gray-300 capitalize">{agent.platform}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-gray-500">Agent Version</span>
                <span className="text-gray-300 font-mono">{agent.version}</span>
              </div>
              <div className="flex justify-between text-xs">
                <span className="text-gray-500">Last Seen</span>
                <span className="text-gray-300">
                  {formatDistanceToNow(new Date(agent.last_seen), { addSuffix: true })}
                </span>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
