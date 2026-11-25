import type { GraphViewNode, GraphViewEdge } from "../GraphView";
import { SCORE_THRESHOLDS } from "../../lib/format";

// Attack-path storytelling, computed client-side from the rendered subgraph.
// We have no dedicated attack-paths endpoint, so we enumerate candidate chains
// here: shortest directed path from each internet-exposed entry to the nearest
// target (a high-risk or toxic-combination node, or one named "admin"),
// following the directed relationship edges. Pure — no React, no DOM — so it's unit-testable.

export type AttackHop = {
  id: string;
  label: string;
  sub?: string;
  via?: string; // edge type that leads INTO this hop (undefined for the entry)
};

export type AttackPath = {
  id: string;
  hops: AttackHop[]; // ordered: entry → … → target
  edgeKeys: Set<string>; // edge keys on the path, matching GraphView's `${src}->${dst}-${i}`
  severity: "critical" | "high" | "medium";
  targetRisk: number;
};

// Edge types an attacker can traverse to move toward higher privilege / blast
// radius. Other edges (protected_by, applies_to…) don't advance an attack.
const TRAVERSABLE = new Set([
  "exposed_to_internet",
  "dns_points_to",
  "runs_in",
  "deploys_to",
  "executes_as",
  "can_assume",
  "can_escalate",
  "can_escalate_to",
  "sg_allows_from",
]);

function isTarget(n: GraphViewNode | undefined): boolean {
  if (!n) return false;
  if (n.toxicCombo) return true;
  if ((n.risk ?? 0) >= SCORE_THRESHOLDS.page) return true;
  const s = `${n.label} ${n.sub ?? ""}`.toLowerCase();
  return s.includes("admin");
}

function isEntry(n: GraphViewNode, exposedSources: Set<string>): boolean {
  return n.id === "internet" || !!n.exposed || exposedSources.has(n.id);
}

function severityFor(risk: number): AttackPath["severity"] {
  if (risk >= SCORE_THRESHOLDS.page) return "critical";
  if (risk >= SCORE_THRESHOLDS.high) return "high";
  return "medium";
}

// computeAttackPaths enumerates the shortest entry→target chain for each
// entry node, dedupes identical hop sequences, and returns them ordered by
// severity then brevity (shortest, scariest first). `hidden` nodes are excluded
// from traversal (break-the-chain) — but the original edge index is preserved
// in each edge key so highlight matching against the rendered edges still works.
export function computeAttackPaths(nodes: GraphViewNode[], edges: GraphViewEdge[], hidden?: Set<string>): AttackPath[] {
  if (nodes.length === 0 || edges.length === 0) return [];
  const isHidden = (id: string) => hidden != null && hidden.has(id);
  const byId = new Map(nodes.map((n) => [n.id, n]));

  // Nodes that are the source of an exposed_to_internet edge are entry points
  // even if their `exposed` flag isn't projected.
  const exposedSources = new Set<string>();
  for (const e of edges) if (e.label === "exposed_to_internet") exposedSources.add(e.source);

  // Directed adjacency over traversable edges, carrying the edge key + type.
  const adj = new Map<string, { target: string; key: string; via: string }[]>();
  edges.forEach((e, i) => {
    if (!TRAVERSABLE.has(e.label ?? "")) return;
    if (!byId.has(e.source) || !byId.has(e.target)) return;
    if (isHidden(e.source) || isHidden(e.target)) return;
    const list = adj.get(e.source) ?? adj.set(e.source, []).get(e.source)!;
    list.push({ target: e.target, key: `${e.source}->${e.target}-${i}`, via: e.label ?? "" });
  });

  const entries = nodes.filter((n) => !isHidden(n.id) && isEntry(n, exposedSources));
  const seenSeq = new Set<string>();
  const paths: AttackPath[] = [];

  for (const entry of entries) {
    // BFS to the nearest target (a different node).
    const prev = new Map<string, { from: string; key: string; via: string }>();
    const queue = [entry.id];
    const seen = new Set([entry.id]);
    let hit: string | null = null;
    while (queue.length) {
      const cur = queue.shift()!;
      if (cur !== entry.id && isTarget(byId.get(cur))) {
        hit = cur;
        break;
      }
      for (const { target, key, via } of adj.get(cur) ?? []) {
        if (!seen.has(target)) {
          seen.add(target);
          prev.set(target, { from: cur, key, via });
          queue.push(target);
        }
      }
    }
    if (!hit) continue;

    // Rebuild the chain entry → hit.
    const chain: { id: string; via?: string }[] = [{ id: hit }];
    const edgeKeys = new Set<string>();
    let cur = hit;
    while (cur !== entry.id) {
      const p = prev.get(cur)!;
      edgeKeys.add(p.key);
      chain[chain.length - 1].via = p.via;
      chain.push({ id: p.from });
      cur = p.from;
    }
    chain.reverse();

    const seqKey = chain.map((c) => c.id).join(">");
    if (seenSeq.has(seqKey)) continue;
    seenSeq.add(seqKey);

    const hops: AttackHop[] = chain.map((c) => {
      const n = byId.get(c.id);
      return { id: c.id, label: n?.label ?? c.id, sub: n?.sub, via: c.via };
    });
    const targetRisk = byId.get(hit)?.risk ?? 80;
    paths.push({ id: seqKey, hops, edgeKeys, severity: severityFor(targetRisk), targetRisk });
  }

  const rank = { critical: 0, high: 1, medium: 2 };
  paths.sort((a, b) => rank[a.severity] - rank[b.severity] || a.hops.length - b.hops.length);
  return paths.slice(0, 25);
}
