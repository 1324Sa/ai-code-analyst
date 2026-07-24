import React, { useState, useMemo } from 'react';
import ReactFlow, { Node, Edge, NodeMouseHandler } from 'reactflow';
import 'reactflow/dist/style.css';

interface InteractiveTaintGraphProps {
  nodesData: Node[];
  edgesData: Edge[];
  selectedFinding?: { id: string } | null;
}

export const InteractiveTaintGraph: React.FC<InteractiveTaintGraphProps> = ({
  nodesData,
  edgesData,
  selectedFinding,
}) => {
  const [highlightedNodeIds, setHighlightedNodeIds] = useState<string[]>([]);

  // BFS tracing for interactive node click path highlighting
  const handleNodeClick: NodeMouseHandler = (event, node) => {
    const visited = new Set<string>();
    const queue: string[] = [node.id];

    while (queue.length > 0) {
      const currentId = queue.shift()!;
      if (!visited.has(currentId)) {
        visited.add(currentId);
        edgesData.forEach((edge) => {
          if (edge.source === currentId && !visited.has(edge.target)) queue.push(edge.target);
          if (edge.target === currentId && !visited.has(edge.source)) queue.push(edge.source);
        });
      }
    }
    setHighlightedNodeIds(Array.from(visited));
  };

  const styledNodes = useMemo(() => {
    return nodesData.map((node) => {
      const isFunction = node.data?.nodeType === 'FUNCTION';
      const isSecret = node.data?.nodeType === 'SECRET' || node.data?.label?.includes('SECRET');
      const isHighlighted = highlightedNodeIds.includes(node.id) || selectedFinding?.id === node.id;

      return {
        ...node,
        style: {
          background: isSecret ? '#7f1d1d' : isHighlighted ? '#1e3a8a' : '#1e293b',
          border: isFunction
            ? '2px dashed #38bdf8' // Blue Dashed border for Sensitive Functions
            : isSecret
            ? '2px solid #ef4444'  // Red Solid border for Sensitive Variables
            : '1px solid #475569',
          color: '#ffffff',
          borderRadius: '8px',
          padding: '10px',
          boxShadow: isHighlighted ? '0 0 12px rgba(59, 130, 246, 0.6)' : 'none',
        },
      };
    });
  }, [nodesData, highlightedNodeIds, selectedFinding]);

  return (
    <div className="w-full h-[400px] bg-slate-950 rounded-lg border border-slate-800 relative">
      {/* Legend Indicator */}
      <div className="absolute top-3 left-3 bg-slate-900/90 p-2 rounded border border-slate-800 text-xs text-slate-300 flex gap-4 z-10">
        <div className="flex items-center gap-1.5">
          <span className="w-3 h-3 bg-red-900 border border-red-500 inline-block rounded-sm"></span>
          <span>Sensitive Variable</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-3 h-3 bg-slate-800 border-2 border-dashed border-sky-400 inline-block rounded-sm"></span>
          <span>Sensitive Function</span>
        </div>
      </div>

      <ReactFlow
        nodes={styledNodes}
        edges={edgesData}
        onNodeClick={handleNodeClick}
        fitView
      />
    </div>
  );
};
