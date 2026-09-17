"use client";

import { useMemo } from "react";
import ReactFlow, { Background, Controls, Edge, MarkerType, Node, Position } from "reactflow";
import "reactflow/dist/style.css";

const TYPE_COLOR: Record<string, string> = {
  internet: "#ef4444",
  device: "#f25623",
  interface: "#8b5cf6",
  zone: "#0891b2",
  service: "#f59e0b",
  asset: "#22c55e",
};

export function AttackGraphView({ graph }: { graph: { nodes: Record<string, unknown>[]; edges: Record<string, unknown>[] } }) {
  const { nodes, edges } = useMemo(() => {
    const nodesById = new Map(graph.nodes.map((n) => [n.id as string, n]));
    const levels = new Map<string, number>();
    const roots = graph.nodes.filter((n) => n.type === "internet" || n.type === "device").map((n) => n.id as string);

    // Simple BFS layering for a readable left-to-right layout.
    const visited = new Set<string>();
    let frontier = roots.length ? roots : [graph.nodes[0]?.id as string].filter(Boolean);
    let depth = 0;
    while (frontier.length) {
      const next: string[] = [];
      for (const id of frontier) {
        if (visited.has(id)) continue;
        visited.add(id);
        levels.set(id, depth);
        for (const e of graph.edges) {
          if (e.source === id && !visited.has(e.target as string)) next.push(e.target as string);
        }
      }
      frontier = next;
      depth += 1;
    }

    const perLevelCount = new Map<number, number>();
    const rfNodes: Node[] = graph.nodes.map((n) => {
      const level = levels.get(n.id as string) ?? depth;
      const yIndex = perLevelCount.get(level) ?? 0;
      perLevelCount.set(level, yIndex + 1);
      const type = (n.type as string) || "device";
      return {
        id: n.id as string,
        // Depth flows left-to-right (x = level) and same-depth nodes stack
        // vertically (y = sibling index) -- a wide, generously-spaced
        // horizontal layout reads far better than a tall/narrow one once a
        // graph has more than a couple of hops.
        position: { x: level * 260, y: yIndex * 130 },
        data: { label: (n.label as string) || (n.id as string) },
        sourcePosition: Position.Right,
        targetPosition: Position.Left,
        style: {
          background: "#ffffff",
          color: "#171717",
          border: `1.5px solid ${TYPE_COLOR[type] || "#dedede"}`,
          borderRadius: 8,
          fontSize: 12,
          padding: 8,
        },
      };
    });

    const rfEdges: Edge[] = graph.edges.map((e, i) => ({
      id: `e${i}`,
      source: e.source as string,
      target: e.target as string,
      label: e.relation as string,
      animated: e.relation === "reachability",
      style: { stroke: "#4d4d4d" },
      labelStyle: { fill: "#4d4d4d", fontSize: 10 },
      markerEnd: { type: MarkerType.ArrowClosed, color: "#4d4d4d" },
    }));

    return { nodes: rfNodes, edges: rfEdges };
  }, [graph]);

  return (
    <div className="h-[600px] rounded-md border border-border overflow-hidden bg-surface">
      <ReactFlow nodes={nodes} edges={edges} fitView proOptions={{ hideAttribution: true }} minZoom={0.2}>
        <Background color="#dedede" gap={16} />
        <Controls />
      </ReactFlow>
    </div>
  );
}
