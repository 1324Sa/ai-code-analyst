import React from 'react';

export interface CoverageStats {
  lines: number;
  percentage: number;
}

interface HeaderAlertsProps {
  instantAlert?: string | null;
  coverage?: CoverageStats;
}

export const HeaderAlerts: React.FC<HeaderAlertsProps> = ({
  instantAlert,
  coverage = { lines: 0, percentage: 100 },
}) => {
  return (
    <div className="space-y-2">
      {instantAlert && (
        <div
          role="alert"
          aria-live="assertive"
          className="p-3 bg-red-900/80 border border-red-500 text-red-100 rounded-lg text-sm font-semibold animate-pulse flex items-center gap-2"
        >
          <span>{instantAlert}</span>
        </div>
      )}

      <div className="flex items-center space-x-2 text-xs text-slate-400">
        <span className="px-2 py-0.5 bg-slate-800 rounded border border-slate-700 text-slate-200 font-mono">
          Lines Scanned: {coverage.lines}
        </span>
        <span className="px-2 py-0.5 bg-green-950 border border-green-700 text-green-300 rounded font-mono">
          Coverage: {coverage.percentage}%
        </span>
      </div>
    </div>
  );
};
