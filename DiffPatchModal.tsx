import React from 'react';

interface DiffPatchModalProps {
  isOpen: boolean;
  onClose: () => void;
  finding: {
    title: string;
    snippet: string;
    category: string;
  } | null;
  onApplyPatch: (newSnippet: string) => void;
}

export const DiffPatchModal: React.FC<DiffPatchModalProps> = ({
  isOpen,
  onClose,
  finding,
  onApplyPatch,
}) => {
  if (!isOpen || !finding) return null;

  // Generate automated patch based on finding category
  const generateRemediatedSnippet = () => {
    if (finding.category === 'Hardcoded Secret') {
      return `API_SECRET_KEY = os.environ.get("API_SECRET_KEY")`;
    }
    if (finding.category === 'Authentication Bypass') {
      return `import hmac\nif hmac.compare_digest(api_key, API_SECRET_KEY):`;
    }
    if (finding.category === 'Injection') {
      return `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`;
    }
    return `# Secure implementation\n${finding.snippet}`;
  };

  const patchedCode = generateRemediatedSnippet();

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full p-6 shadow-2xl space-y-4">
        <div className="flex justify-between items-center border-b border-slate-800 pb-3">
          <h3 className="text-lg font-bold text-white">View Security Patch & Diff</h3>
          <button onClick={onClose} className="text-slate-400 hover:text-white">✕</button>
        </div>

        <p className="text-sm text-slate-300 font-medium">{finding.title}</p>

        <div className="grid grid-cols-2 gap-4 text-xs font-mono">
          <div className="bg-red-950/40 border border-red-800 p-3 rounded">
            <span className="text-red-400 font-bold block mb-2">- Original Code (Vulnerable)</span>
            <pre className="text-red-200 whitespace-pre-wrap">{finding.snippet}</pre>
          </div>

          <div className="bg-green-950/40 border border-green-800 p-3 rounded">
            <span className="text-green-400 font-bold block mb-2">+ Proposed Patch (Remediated)</span>
            <pre className="text-green-200 whitespace-pre-wrap">{patchedCode}</pre>
          </div>
        </div>

        <div className="flex justify-end space-x-3 pt-3">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 text-slate-300 text-xs font-semibold rounded hover:bg-slate-700"
          >
            Cancel
          </button>
          <button
            onClick={() => {
              onApplyPatch(patchedCode);
              onClose();
            }}
            className="px-4 py-2 bg-indigo-600 text-white text-xs font-semibold rounded hover:bg-indigo-500"
          >
            Apply Patch to Editor
          </button>
        </div>
      </div>
    </div>
  );
};
