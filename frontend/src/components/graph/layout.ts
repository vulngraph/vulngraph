import type { Node as RFNode } from "@xyflow/react";
import type { GraphViewNode, GraphViewEdge, GroupBy } from "../GraphView";
import type { XY } from "./useForceLayout";
import type { AssetNodeData } from "./AssetNode";
import { shortenLabel, typeLabel } from "./labels";
import { SCORE_THRESHOLDS } from "../../lib/format";

// Pure layout math for the graph canvas — node styling, concentric/grid/force
// placement, and grouped super-nodes. No React; GraphView composes these.

export const SUPER_PREFIX = "__group__:";

// accentColor returns the left-bar accent for a node — risk colour when scored,
// type-derived hue when not, so every node has a clear category colour without
// a heavy coloured box drowning the label.
function accentColor(risk?: number, kind?: string): string {
  if (risk != null) {
    if (risk >= SCORE_THRESHOLDS.page) return "#f87171";     // red
    if (risk >= SCORE_THRESHOLDS.high) return "#fb923c";     // orange
    if (risk >= SCORE_THRESHOLDS.pipeline) return "#fbbf24"; // amber
    return "#2dd4bf";                                        // teal
  }
  if (!kind) return "#3f3f46";
  let h = 0;
  for (let i = 0; i < kind.length; i++) h = (h * 31 + kind.charCodeAt(i)) % 360;
  return `hsl(${h} 55% 60%)`;
}

// For dot-zoom and grouped nodes we still need a bg/border pair.
function riskColor(risk?: number): { border: string; bg: string } {
  if (risk == null) return { border: "#3f3f46", bg: "#18181b" };
  if (risk >= SCORE_THRESHOLDS.page) return { border: "#f87171", bg: "#2a1416" };
  if (risk >= SCORE_THRESHOLDS.high) return { border: "#fb923c", bg: "#2a1c12" };
  if (risk >= SCORE_THRESHOLDS.pipeline) return { border: "#fbbf24", bg: "#241f10" };
  return { border: "#2dd4bf", bg: "#0f1f1d" };
}
function kindColor(kind?: string): { border: string; bg: string } {
  if (!kind) return { border: "#3f3f46", bg: "#18181b" };
  let h = 0;
  for (let i = 0; i < kind.length; i++) h = (h * 31 + kind.charCodeAt(i)) % 360;
  return { border: `hsl(${h} 55% 55%)`, bg: `hsl(${h} 45% 9%)` };
}

// nodeWidth: slim cards (140–180px), slightly wider for the center/seed.
function nodeWidth(signal: number, isCenter: boolean): number {
  const w = 140 + Math.round((Math.min(Math.max(signal, 0), 100) / 100) * 40); // 140–180
  return isCenter ? Math.max(w, 165) : w;
}

function groupKeyOf(n: GraphViewNode, by: GroupBy): string {
  switch (by) {
    case "account": return n.account || "(no account)";
    case "provider": return n.provider || "(unknown)";
    case "type": return n.sub || "(untyped)";
    default: return "";
  }
}

// degreeMap counts edges per node id — drives node sizing and the peek panel.
export function degreeMap(edges: GraphViewEdge[]): Map<string, number> {
  const d = new Map<string, number>();
  for (const e of edges) {
    d.set(e.source, (d.get(e.source) ?? 0) + 1);
    d.set(e.target, (d.get(e.target) ?? 0) + 1);
  }
  return d;
}

// pathToTarget finds the shortest directed path from a node to a target
// (the internet sentinel or a node named "admin") so selecting a node highlights how it
// reaches danger. Returns the node + edge ids on the path, or null if none.
export function pathToTarget(
  startId: string,
  nodes: GraphViewNode[],
  edges: GraphViewEdge[],
): { nodeIds: Set<string>; edgeKeys: Set<string> } | null {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const isTarget = (id: string) => {
    if (id === "internet") return true;
    const n = byId.get(id);
    const s = `${n?.label ?? ""} ${n?.sub ?? ""}`.toLowerCase();
    return s.includes("admin");
  };
  if (isTarget(startId)) return null;
  // adjacency: source -> [{ target, key }]
  const adj = new Map<string, { target: string; key: string }[]>();
  edges.forEach((e, i) => {
    const key = `${e.source}->${e.target}-${i}`;
    (adj.get(e.source) ?? adj.set(e.source, []).get(e.source)!).push({ target: e.target, key });
  });
  const prev = new Map<string, { from: string; key: string }>();
  const queue = [startId];
  const seen = new Set([startId]);
  let hit: string | null = null;
  while (queue.length) {
    const cur = queue.shift()!;
    if (cur !== startId && isTarget(cur)) { hit = cur; break; }
    for (const { target, key } of adj.get(cur) ?? []) {
      if (!seen.has(target)) { seen.add(target); prev.set(target, { from: cur, key }); queue.push(target); }
    }
  }
  if (!hit) return null;
  const nodeIds = new Set<string>([hit]);
  const edgeKeys = new Set<string>();
  let cur = hit;
  while (cur !== startId) {
    const p = prev.get(cur)!;
    edgeKeys.add(p.key);
    nodeIds.add(p.from);
    cur = p.from;
  }
  return { nodeIds, edgeKeys };
}

// signalGlow returns a box-shadow that makes a node's strongest security signal
// read at a glance on the canvas — danger glows, so you find it without reading
// every label. Ordered by severity: toxic > exploitable > KEV > exposed.
function signalGlow(n: GraphViewNode): string | null {
  if (n.toxicCombo) return "0 0 14px 1px rgba(248,113,113,0.55)"; // red
  if (n.exploitable) return "0 0 12px 1px rgba(248,113,113,0.4)"; // red, softer
  if (n.hasKev) return "0 0 12px 1px rgba(251,191,36,0.45)"; // amber
  if (n.exposed) return "0 0 12px 1px rgba(251,146,60,0.4)"; // orange
  return null;
}

// styledNode builds a ReactFlow node. AssetNode owns the full look (slim card
// with left accent bar, or dot at overview zoom). The node `style` only carries
// dim-opacity set later by GraphView.
function styledNode(n: GraphViewNode, position: { x: number; y: number }, isCenter: boolean, signal: number): RFNode {
  const c = n.risk != null ? riskColor(n.risk) : kindColor(n.sub);
  return {
    id: n.id,
    type: "asset",
    position,
    data: {
      label: shortenLabel(n.label),
      typeLabel: n.sub ? typeLabel(n.sub) : undefined,
      rawType: n.sub,
      isCenter,
      exposed: n.exposed,
      hasKev: n.hasKev,
      exploitable: n.exploitable,
      toxicCombo: n.toxicCombo,
      accent: accentColor(n.risk, n.sub),
      bg: c.bg,
      border: c.border,
      width: nodeWidth(signal, isCenter),
      glow: signalGlow(n),
    } satisfies AssetNodeData,
    style: { cursor: "pointer" },
  } satisfies RFNode;
}

// ── Flat (concentric) layout ──────────────────────────────────────────────────

export function flatLayout(nodes: GraphViewNode[], centerId: string | undefined, edges: GraphViewEdge[], deg: Map<string, number>, forcePos?: Map<string, XY>): RFNode[] {
  // Force-directed positions (from the worker) take precedence when available.
  if (forcePos && forcePos.size > 0) {
    return nodes.map((n) => {
      const isCenter = centerId != null && n.id === centerId;
      const signal = Math.max(n.risk ?? 0, Math.min((deg.get(n.id) ?? 0) * 12, 100));
      return styledNode(n, forcePos.get(n.id) ?? { x: 0, y: 0 }, isCenter, signal);
    });
  }

  // No edges → a concentric ring with an arbitrary "center" reads as broken.
  // Lay the assets out as a tidy grid instead (no fake center) so the result
  // looks intentional: "here are the matching assets; double-click to expand".
  if (edges.length === 0) {
    const cols = Math.ceil(Math.sqrt(nodes.length));
    const cellW = 200;
    const cellH = 66;
    return nodes.map((n, i) => {
      const signal = Math.max(n.risk ?? 0, 0);
      return styledNode(
        n,
        { x: (i % cols) * cellW, y: Math.floor(i / cols) * cellH },
        false,
        signal,
      );
    });
  }

  // BFS depth from the center (or seed) so connected nodes cluster in rings.
  const depthMap = new Map<string, number>();
  const adj = new Map<string, string[]>();
  for (const e of edges) {
    (adj.get(e.source) ?? adj.set(e.source, []).get(e.source)!).push(e.target);
    (adj.get(e.target) ?? adj.set(e.target, []).get(e.target)!).push(e.source);
  }
  const seeds = centerId ? [centerId] : [nodes[0]?.id].filter(Boolean);
  for (const s of seeds) depthMap.set(s, 0);
  const queue = [...seeds];
  while (queue.length) {
    const cur = queue.shift()!;
    const d = depthMap.get(cur)!;
    for (const nb of (adj.get(cur) ?? [])) {
      if (!depthMap.has(nb)) { depthMap.set(nb, d + 1); queue.push(nb); }
    }
  }
  const maxDepth = Math.max(0, ...depthMap.values());
  for (const n of nodes) if (!depthMap.has(n.id)) depthMap.set(n.id, maxDepth + 1);

  const byDepth = new Map<number, string[]>();
  for (const [id, d] of depthMap) (byDepth.get(d) ?? byDepth.set(d, []).get(d)!).push(id);
  const nodePos = new Map<string, { x: number; y: number }>();
  nodePos.set(nodes[0]?.id ?? "", { x: 0, y: 0 });
  if (centerId) nodePos.set(centerId, { x: 0, y: 0 });
  const baseRadii = [0, 220, 420, 600, 780];
  for (const [depth, ids] of byDepth) {
    // Ensure the ring circumference is wide enough that 180px-wide node cards
    // don't overlap: minimum radius = (count × 190) / 2π.
    const minR = (ids.length * 190) / (2 * Math.PI);
    const r = Math.max(baseRadii[depth] ?? depth * 200, minR);
    ids.forEach((id, i) => {
      const angle = (2 * Math.PI * i) / Math.max(ids.length, 1) - Math.PI / 2;
      nodePos.set(id, { x: Math.cos(angle) * r, y: Math.sin(angle) * r });
    });
  }

  return nodes.map((n) => {
    // Only highlight a node as "center" when one was explicitly given (blast
    // radius / By-asset seed). Multi-seed views (By type, presets, Cypher) have
    // no real center, so don't glow an arbitrary node.
    const isCenter = centerId != null && n.id === centerId;
    const signal = Math.max(n.risk ?? 0, Math.min((deg.get(n.id) ?? 0) * 12, 100));
    return styledNode(n, nodePos.get(n.id) ?? { x: 0, y: 0 }, isCenter, signal);
  });
}

// ── Grouped layout (super-nodes per account/provider/type) ────────────────────

export type GroupedResult = {
  rfNodes: RFNode[];
  rep: Map<string, string>; // original node id -> currently-visible node id
  superIds: Set<string>; // ids of super-nodes (toggle targets)
};

export function groupedLayout(nodes: GraphViewNode[], by: GroupBy, expanded: Set<string>, deg: Map<string, number>): GroupedResult {
  const groups = new Map<string, GraphViewNode[]>();
  for (const n of nodes) (groups.get(groupKeyOf(n, by)) ?? groups.set(groupKeyOf(n, by), []).get(groupKeyOf(n, by))!).push(n);

  const keys = [...groups.keys()].sort();
  const rfNodes: RFNode[] = [];
  const rep = new Map<string, string>();
  const superIds = new Set<string>();
  const ringR = Math.max(320, keys.length * 90);

  keys.forEach((key, gi) => {
    const members = groups.get(key)!;
    const angle = (2 * Math.PI * gi) / Math.max(keys.length, 1) - Math.PI / 2;
    const cx = Math.cos(angle) * ringR;
    const cy = Math.sin(angle) * ringR;
    const superId = SUPER_PREFIX + key;
    const maxRisk = members.reduce((m, n) => Math.max(m, n.risk ?? 0), 0);

    if (!expanded.has(key)) {
      // Collapsed: one super-node, members route to it.
      for (const m of members) rep.set(m.id, superId);
      superIds.add(superId);
      const c = maxRisk > 0 ? riskColor(maxRisk) : kindColor(key);
      rfNodes.push({
        id: superId,
        position: { x: cx, y: cy },
        data: { label: `${key}\n${members.length} asset${members.length !== 1 ? "s" : ""}` },
        style: {
          background: c.bg,
          border: `2px solid ${c.border}`,
          borderRadius: 12,
          color: "#e4e4e7",
          fontSize: 11,
          fontWeight: 700,
          padding: "10px 14px",
          width: nodeWidth(Math.max(maxRisk, Math.min(members.length * 6, 100)), true),
          minHeight: 44,
          whiteSpace: "pre-line",
          textAlign: "center",
          cursor: "pointer",
        },
      } satisfies RFNode);
    } else {
      // Expanded: a small header super-node + members in a ring around it.
      superIds.add(superId);
      rfNodes.push({
        id: superId,
        position: { x: cx, y: cy },
        data: { label: `${key} ▾` },
        style: {
          background: "#0f1f1d",
          border: "1px dashed #2dd4bf",
          borderRadius: 10,
          color: "#2dd4bf",
          fontSize: 10,
          fontWeight: 700,
          padding: "4px 8px",
          width: 140,
          textAlign: "center",
          cursor: "pointer",
        },
      } satisfies RFNode);
      const mr = Math.max(120, members.length * 22);
      members.forEach((m, i) => {
        rep.set(m.id, m.id);
        const a = (2 * Math.PI * i) / Math.max(members.length, 1) - Math.PI / 2;
        const signal = Math.max(m.risk ?? 0, Math.min((deg.get(m.id) ?? 0) * 12, 100));
        rfNodes.push(styledNode(m, { x: cx + Math.cos(a) * mr, y: cy + Math.sin(a) * mr }, false, signal));
      });
    }
  });

  return { rfNodes, rep, superIds };
}
