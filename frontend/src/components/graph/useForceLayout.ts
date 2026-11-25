import { useEffect, useMemo, useRef, useState } from "react";
import type { ForceInput, ForceOutput } from "./forceLayout.worker";

export type XY = { x: number; y: number };

type ForceNode = { id: string; risk?: number; provider?: string };
type ForceEdge = { source: string; target: string };

// useForceLayout runs the d3-force simulation in a Web Worker and returns the
// computed positions keyed by node id. It re-simulates only when the graph's
// structure (node ids + edge pairs) changes — not on every render — so dragging
// or selection never restarts the layout. `enabled` lets callers fall back to
// other layouts (grid/concentric) without paying for the worker.
export function useForceLayout(nodes: ForceNode[], edges: ForceEdge[], enabled: boolean): Map<string, XY> {
  const [positions, setPositions] = useState<Map<string, XY>>(new Map());
  const reqRef = useRef(0);

  // Structural key — re-sim only when topology changes.
  const key = useMemo(() => {
    if (!enabled) return "";
    const ids = nodes.map((n) => n.id).join(",");
    const links = edges.map((e) => `${e.source}>${e.target}`).join(",");
    return `${ids}|${links}`;
  }, [nodes, edges, enabled]);

  useEffect(() => {
    if (!enabled || nodes.length === 0 || typeof Worker === "undefined") {
      setPositions(new Map());
      return;
    }
    let worker: Worker;
    try {
      worker = new Worker(new URL("./forceLayout.worker.ts", import.meta.url), { type: "module" });
    } catch {
      // No Worker support (e.g. jsdom in tests) — callers fall back to the
      // concentric layout when positions stay empty.
      setPositions(new Map());
      return;
    }
    const requestId = ++reqRef.current;

    const present = new Set(nodes.map((n) => n.id));
    const providers = [...new Set(nodes.map((n) => n.provider).filter((p): p is string => !!p))];
    const providerAngles: Record<string, number> = {};
    providers.forEach((p, i) => {
      providerAngles[p] = (2 * Math.PI * i) / providers.length;
    });

    worker.onmessage = (e: MessageEvent<ForceOutput>) => {
      if (e.data.requestId !== reqRef.current) return;
      setPositions(new Map(e.data.positions));
    };

    const input: ForceInput = {
      requestId,
      nodes: nodes.map((n) => ({ id: n.id, risk: n.risk ?? 0, provider: n.provider ?? "" })),
      links: edges.filter((e) => present.has(e.source) && present.has(e.target)).map((e) => ({ source: e.source, target: e.target })),
      providerAngles,
      multiProvider: providers.length > 1,
      // More ticks for larger graphs so they settle; capped for responsiveness.
      tickCount: Math.min(400, 150 + nodes.length * 2),
    };
    worker.postMessage(input);

    return () => worker.terminate();
  }, [key]);

  return positions;
}
