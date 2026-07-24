import React from 'react';

export interface Finding {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;
  category: string;
  description: string;
  line: number;
  snippet: string;
  cwe?: string;
  pci_dss?: string;
  nist?: string;
}

interface FindingCardProps {
  finding: Finding;
  onJumpToLine: (line: number) => void;
  onOpenDiffModal: (finding: Finding) => void;
}

export const FindingCard: React.FC<FindingCardProps> = ({
  finding,
  onJumpToLine,
  onOpenDiffModal,
}) => {
  const getSeverityStyle = (severity: string) => {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-red-600 text-white';
      case 'HIGH':
        return 'bg-orange-600 text-white';
      case 'MEDIUM':
        return 'bg-yellow-600 text-black';
      case 'LOW':
        return 'bg-blue-600 text-white';
      default:
        return 'bg-slate-700 text-white';
    }
  };

  return (
    <div className="p-4 border rounded-lg bg-slate-900 border-slate-800 space-y-3 shadow-md hover:border-slate-700 transition">
      <div className="flex justify-between items-center">
        <span
          className={`px-2 py-0.5 text-xs font-bold rounded ${getSeverityStyle(
            finding.severity
          )}`}
        >
          {finding.severity}
        </span>

        {/* Jump To Line Link */}
        <button
          onClick={() => onJumpToLine(finding.line)}
          className="text-xs text-blue-400 hover:text-blue-300 hover:underline flex items-center gap-1 font-mono transition"
        >
          Jump to line {finding.line} ↵
        </button>
      </div>

      <h4 className="text-sm font-semibold text-white">{finding.title}</h4>
      <p className="text-xs text-slate-400 leading-relaxed">{finding.description}</p>

      {/* Multi-Standard Compliance Badges */}
      <div className="flex flex-wrap gap-1.5 pt-1">
        {finding.cwe && (
          <span className="px-2 py-0.5 text-[10px] font-mono bg-slate-800 text-sky-400 border border-slate-700 rounded">
            {finding.cwe}
          </span>
        )}
        {finding.pci_dss && (
          <span className="px-2 py-0.5 text-[10px] font-mono bg-slate-800 text-purple-400 border border-slate-700 rounded">
            {finding.pci_dss}
          </span>
        )}
        {finding.nist && (
          <span className="px-2 py-0.5 text-[10px] font-mono bg-slate-800 text-emerald-400 border border-slate-700 rounded">
            {finding.nist}
          </span>
        )}
      </div>

      <div className="flex justify-end pt-2">
        <button
          onClick={() => onOpenDiffModal(finding)}
          className="px-3 py-1 bg-indigo-600 hover:bg-indigo-500 text-xs text-white rounded font-medium transition shadow"
        >
          View Patch / Diff
        </button>
      </div>
    </div>
  );
};
