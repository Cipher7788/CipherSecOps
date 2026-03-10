import React, { useEffect, useState } from 'react';
import { format } from 'date-fns';

export default function Header({ criticalCount = 3, wsConnected = true }) {
  const [now, setNow] = useState(new Date());

  useEffect(() => {
    const id = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(id);
  }, []);

  return (
    <header className="h-14 bg-dark-card border-b border-dark-border flex items-center justify-between px-6 shrink-0">
      {/* Title */}
      <h1 className="text-base font-semibold text-white tracking-wide">
        CipherSecOps SOC Dashboard
      </h1>

      <div className="flex items-center gap-5">
        {/* WebSocket status */}
        <div className="flex items-center gap-2 text-xs">
          <span
            className={`w-2 h-2 rounded-full ${wsConnected ? 'bg-accent-green animate-pulse' : 'bg-accent-red'}`}
          />
          <span className={wsConnected ? 'text-accent-green' : 'text-accent-red'}>
            {wsConnected ? 'Live' : 'Disconnected'}
          </span>
        </div>

        {/* Alert bell */}
        <button
          className="relative text-gray-400 hover:text-white transition-colors"
          title={`${criticalCount} critical alerts`}
        >
          <span className="text-lg">🔔</span>
          {criticalCount > 0 && (
            <span className="absolute -top-1 -right-1 bg-accent-red text-white text-[10px] font-bold w-4 h-4 rounded-full flex items-center justify-center animate-pulse-red">
              {criticalCount > 9 ? '9+' : criticalCount}
            </span>
          )}
        </button>

        {/* Date / time */}
        <div className="text-xs text-gray-400 tabular-nums">
          {format(now, 'yyyy-MM-dd HH:mm:ss')} UTC
        </div>
      </div>
    </header>
  );
}
