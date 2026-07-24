import React from 'react';

export interface CoverageHeaderProps {
  totalLines: number;
  scannedLines: number;
}

export const CoverageHeader: React.FC<CoverageHeaderProps> = ({
  totalLines = 0,
  scannedLines = 0,
}) => {
  const safeTotal = totalLines > 0 ? totalLines : 1;
  const coveragePercent = Math.min(
    100,
    Math.round((scannedLines / safeTotal) * 100)
  );

  return (
    <div className="flex items-center gap-3 p-3 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-300">
      <div>
        <span>Lines Reviewed: </span>
        <span className="text-white font-bold">{scannedLines}</span> /{' '}
        <span>{totalLines}</span>
      </div>

      <div
        role="progressbar"
        aria-valuenow={coveragePercent}
        aria-valuemin={0}
        aria-valuemax={100}
        className="flex-1 bg-slate-800 h-2 rounded-full overflow-hidden border border-slate-700"
      >
        <div
          className="bg-green-500 h-full transition-all duration-300"
          style={{ width: `${coveragePercent}%` }}
        />
      </div>

      <span className="text-green-400 font-bold">{coveragePercent}% Covered</span>
    </div>
  );
};
