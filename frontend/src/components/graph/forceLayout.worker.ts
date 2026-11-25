// Force-directed layout, off the main thread. Receives plain node/link data,
// runs a d3-force simulation to completion, posts back final positions. Pure
// math — no DOM. A trimmed force-directed layout:
// link + charge + center + collide, with optional provider clustering so a
// multi-cloud graph separates into readable lobes.
import {
  forceCenter,
  forceCollide,
  forceLink,
  forceManyBody,
  forceSimulation,
  forceX,
  forceY,
  type SimulationLinkDatum,
  type SimulationNodeDatum,
} from "d3-force";

interface SimNode extends SimulationNodeDatum {
  id: string;
  risk: number;
  provider: string;
}

type SimLink = SimulationLinkDatum<SimNode>;

export interface ForceInput {
  requestId: number;
  nodes: { id: string; risk: number; provider: string }[];
  links: { source: string; target: string }[];
  providerAngles: Record<string, number>;
  multiProvider: boolean;
  tickCount: number;
}

export interface ForceOutput {
  requestId: number;
  positions: Array<[string, { x: number; y: number }]>;
}

self.onmessage = (e: MessageEvent<ForceInput>) => {
  const { requestId, nodes, links, providerAngles, multiProvider, tickCount } = e.data;

  const linkForce = forceLink<SimNode, SimLink>(
    links.map((l) => ({ source: l.source, target: l.target })) as SimLink[],
  )
    .id((d) => (d as SimNode).id)
    .distance(150)
    .strength(0.35);

  // d3 mutates these in place, adding x/y; type them as SimNode up front.
  const simNodes: SimNode[] = nodes.map((n) => ({ id: n.id, risk: n.risk, provider: n.provider }));

  const clusterR = 520;
  const sim = forceSimulation<SimNode>(simNodes)
    .force("link", linkForce)
    .force("charge", forceManyBody<SimNode>().strength(-480).distanceMax(700))
    .force("center", forceCenter(0, 0).strength(0.05))
    .force(
      "collide",
      forceCollide<SimNode>()
        .radius((d) => 105 * (d.risk >= 70 ? 1.25 : 1))
        .strength(0.85)
        .iterations(2),
    )
    .force(
      "x",
      forceX<SimNode>((d) => (multiProvider ? Math.cos(providerAngles[d.provider] ?? 0) * clusterR : 0)).strength(
        multiProvider ? 0.12 : 0.03,
      ),
    )
    .force(
      "y",
      forceY<SimNode>((d) => (multiProvider ? Math.sin(providerAngles[d.provider] ?? 0) * clusterR : 0)).strength(
        multiProvider ? 0.12 : 0.03,
      ),
    )
    .alphaDecay(0.02)
    .velocityDecay(0.3);

  sim.alpha(1).stop();
  sim.tick(tickCount);

  const positions: ForceOutput["positions"] = simNodes.map((n) => [
    n.id,
    { x: Number.isFinite(n.x) ? (n.x ?? 0) : 0, y: Number.isFinite(n.y) ? (n.y ?? 0) : 0 },
  ]);
  (self as unknown as Worker).postMessage({ requestId, positions } satisfies ForceOutput);
};
