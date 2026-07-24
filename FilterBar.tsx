import React, { useState, useEffect } from 'react';

export interface FilterState {
  search: string;
  category: string;
  severity: string;
}

interface FilterBarProps {
  onFilterChange: (filters: FilterState) => void;
}

const CATEGORIES = ['All', 'Injection', 'Hardcoded Secret', 'Sanitization', 'Access Control'];
const SEVERITIES = ['All', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export const FilterBar: React.FC<FilterBarProps> = ({ onFilterChange }) => {
  const [search, setSearch] = useState<string>(
    () => localStorage.getItem('audit_search') || ''
  );
  const [category, setCategory] = useState<string>(
    () => localStorage.getItem('audit_category') || 'All'
  );
  const [severity, setSeverity] = useState<string>(
    () => localStorage.getItem('audit_severity') || 'All'
  );

  useEffect(() => {
    localStorage.setItem('audit_search', search);
    localStorage.setItem('audit_category', category);
    localStorage.setItem('audit_severity', severity);

    onFilterChange({ search, category, severity });
  }, [search, category, severity, onFilterChange]);

  const handleReset = () => {
    setSearch('');
    setCategory('All');
    setSeverity('All');
    localStorage.removeItem('audit_search');
    localStorage.removeItem('audit_category');
    localStorage.removeItem('audit_severity');
  };

  return (
    <div className="flex flex-wrap items-center gap-3 p-3 bg-slate-900 border border-slate-800 rounded-lg">
      <div className="relative flex-1 min-w-[200px]">
        <input
          type="text"
          placeholder="Search vulnerability, variable, or keyword..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full px-3 py-1.5 bg-slate-800 text-white placeholder-slate-400 text-sm rounded border border-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition"
        />
      </div>

      <div className="flex items-center gap-2">
        <label className="text-xs text-slate-400 font-medium">Category:</label>
        <select
          value={category}
          onChange={(e) => setCategory(e.target.value)}
          className="px-3 py-1.5 bg-slate-800 text-white text-sm rounded border border-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer"
        >
          {CATEGORIES.map((cat) => (
            <option key={cat} value={cat}>
              {cat}
            </option>
          ))}
        </select>
      </div>

      <div className="flex items-center gap-2">
        <label className="text-xs text-slate-400 font-medium">Severity:</label>
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="px-3 py-1.5 bg-slate-800 text-white text-sm rounded border border-slate-700 focus:outline-none focus:ring-2 focus:ring-blue-500 cursor-pointer"
        >
          {SEVERITIES.map((sev) => (
            <option key={sev} value={sev}>
              {sev}
            </option>
          ))}
        </select>
      </div>

      {(search || category !== 'All' || severity !== 'All') && (
        <button
          onClick={handleReset}
          className="px-2.5 py-1.5 text-xs text-slate-400 hover:text-white bg-slate-800 hover:bg-slate-700 rounded transition border border-slate-700"
        >
          Clear Filters ✕
        </button>
      )}
    </div>
  );
};
