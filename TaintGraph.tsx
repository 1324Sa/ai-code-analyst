import React, { useState, useMemo } from 'react';
import ReactFlow, { Node, Edge, NodeMouseHandler } from 'reactflow';
import 'reactflow/dist/style.css';

export interface Finding {
  id: string;
  title: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: string;
  line: number;
}

interface TaintGraphProps {
  nodesData: Node[];
  edgesData: Edge[];
  selectedFinding?: Finding | null;
}

export const TaintGraph: React.FC<TaintGraphProps> = ({
  nodesData,
  edgesData,
  selectedFinding,
}) => {
  const [highlightedNodeIds, setHighlightedNodeIds] = useState<string[]>([]);

  // Trace full taint propagation path (BFS) across edges
  const handleNodeClick: NodeMouseHandler = (event, node) => {
    const visited = new Set<string>();
    const queue: string[] = [node.id];

    while (queue.length > 0) {
      const currentId = queue.shift()!;
      if (!visited.has(currentId)) {
        visited.add(currentId);

        // Find connected neighbors (both downstream targets and upstream sources)
        edgesData.forEach((edge) => {
          if (edge.source === currentId && !visited.has(edge.target)) {
            queue.push(edge.target);
          }
          if (edge.target === currentId && !visited.has(edge.source)) {
            queue.push(edge.source);
          }
        });
      }
    }

    setHighlightedNodeIds(Array.from(visited));
  };

  // Dynamic styling for nodes based on selection, taint highlight, and secret types
  const styledNodes = useMemo(() => {
    return nodesData.map((node) => {
      const label = String(node.data?.label || '');
      const isSecret = label.includes('JWT_SECRET') || node.data?.type === 'SECRET';
      const isHighlighted =
        highlightedNodeIds.includes(node.id) || selectedFinding?.id === node.id;

      return {
        ...node,
        style: {
          background: isSecret ? '#7f1d1d' : isHighlighted ? '#1e3a8a' : '#1e293b',
          border: isSecret
            ? '2px solid #ef4444'
            : isHighlighted
            ? '2px solid #3b82f6'
            : '1px solid #475569',
          color: '#ffffff',
          borderRadius: '8px',
          padding: '10px',
          fontWeight: isHighlighted ? 'bold' : 'normal',
          boxShadow: isHighlighted ? '0 0 12px rgba(59, 130, 246, 0.5)' : 'none',
          ...node.style,
        },
      };
    });
  }, [nodesData, highlightedNodeIds, selectedFinding]);

  // Dynamic styling for edges in the active taint path
  const styledEdges = useMemo(() => {
    return edgesData.map((edge) => {
      const isConnected =
        highlightedNodeIds.includes(edge.source) &&
        highlightedNodeIds.includes(edge.target);

      return {
        ...edge,
        animated: isConnected,
        style: {
          stroke: isConnected ? '#3b82f6' : '#475569',
          strokeWidth: isConnected ? 2.5 : 1,
        },
      };
    });
  }, [edgesData, highlightedNodeIds]);

  return (
    <div className="w-full h-[400px] bg-slate-950 rounded-lg border border-slate-800 overflow-hidden">
      <ReactFlow
        nodes={styledNodes}
        edges={styledEdges}
        onNodeClick={handleNodeClick}
        fitView
      />
    </div>
  );
};
