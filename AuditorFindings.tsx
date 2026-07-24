import React from 'react';

export interface Finding {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  line: number;
  description: string;
  snippet: string;
  fix_suggestion: string;
}

const SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

interface AuditorFindingsProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
  onOpenDiffModal: (finding: Finding) => void;
  onJumpToLine: (line: number) => void;
}

export const AuditorFindings: React.FC<AuditorFindingsProps> = ({
  findings,
  onSelectFinding,
  onOpenDiffModal,
  onJumpToLine,
}) => {
  // Sort findings automatically by priority (Critical -> High -> Medium -> Low)
  const sortedFindings = [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
  );

  return (
    <div className="space-y-4">
      {sortedFindings.map((finding) => (
        <div
          key={finding.id}
          onClick={() => onSelectFinding(finding)}
          className="p-4 border rounded-lg hover:border-blue-500 cursor-pointer bg-slate-900 border-slate-800 transition"
        >
          <div className="flex justify-between items-center mb-2">
            <span className={`px-2 py-1 text-xs font-bold rounded ${
              finding.severity === 'CRITICAL' ? 'bg-red-600 text-white' :
              finding.severity === 'HIGH' ? 'bg-orange-500 text-white' :
              finding.severity === 'MEDIUM' ? 'bg-yellow-500 text-black' : 'bg-blue-600 text-white'
            }`}>
              {finding.severity}
            </span>

            <button
              onClick={(e) => {
                e.stopPropagation();
                onJumpToLine(finding.line);
              }}
              className="text-xs text-blue-400 hover:underline"
            >
              Jump to Line {finding.line} ↵
            </button>
          </div>

          <h4 className="text-sm font-semibold text-white">{finding.title}</h4>
          <p className="text-xs text-slate-400 mt-1">{finding.description}</p>

          <div className="mt-3 flex justify-end space-x-2">
            <button
              onClick={(e) => {
                e.stopPropagation();
                onOpenDiffModal(finding);
              }}
              className="px-3 py-1 bg-indigo-600 hover:bg-indigo-500 text-xs text-white rounded font-medium"
            >
              View Patch / Diff
            </button>
          </div>
        </div>
      ))}
    </div>
  );
};
