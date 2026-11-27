import { describe, expect, it } from "vitest";
import { computeAttackPaths, pathSummary } from "./attackPaths";
import type { GraphViewNode, GraphViewEdge } from "../GraphView";

const n = (id: string, extra: Partial<GraphViewNode> = {}): GraphViewNode => ({ id, label: id, ...extra });

describe("computeAttackPaths", () => {
  it("returns nothing without edges", () => {
    expect(computeAttackPaths([n("a")], [])).toEqual([]);
  });

  it("finds an internet → admin chain through traversable edges", () => {
    const nodes = [
      n("lb", { exposed: true, sub: "load_balancer" }),
      n("pod", { sub: "k8s_pod" }),
      n("admin-role", { sub: "iam_role", risk: 90 }),
    ];
    const edges: GraphViewEdge[] = [
      { source: "lb", target: "pod", label: "dns_points_to" },
      { source: "pod", target: "admin-role", label: "executes_as" },
    ];
    const paths = computeAttackPaths(nodes, edges);
    expect(paths).toHaveLength(1);
    expect(paths[0].hops.map((h) => h.id)).toEqual(["lb", "pod", "admin-role"]);
    expect(paths[0].severity).toBe("critical");
    // Edge keys match GraphView's `${src}->${dst}-${i}` so they highlight.
    expect([...paths[0].edgeKeys]).toContain("lb->pod-0");
    expect([...paths[0].edgeKeys]).toContain("pod->admin-role-1");
    // The hop's `via` is the edge type leading into it.
    expect(paths[0].hops[2].via).toBe("executes_as");
  });

  it("ignores non-traversable edges (protected_by)", () => {
    const nodes = [n("lb", { exposed: true }), n("admin", { risk: 95 })];
    const edges: GraphViewEdge[] = [{ source: "lb", target: "admin", label: "protected_by" }];
    expect(computeAttackPaths(nodes, edges)).toEqual([]);
  });

  it("treats the internet sentinel and exposed-edge sources as entries", () => {
    const nodes = [n("internet"), n("vm"), n("admin", { sub: "iam_role admin" })];
    const edges: GraphViewEdge[] = [
      { source: "internet", target: "vm", label: "exposed_to_internet" },
      { source: "vm", target: "admin", label: "can_assume" },
    ];
    const paths = computeAttackPaths(nodes, edges);
    expect(paths.length).toBeGreaterThanOrEqual(1);
    expect(paths[0].hops[paths[0].hops.length - 1].id).toBe("admin");
  });

  it("break-the-chain: a hidden choke point eliminates the path", () => {
    const nodes = [
      n("lb", { exposed: true }),
      n("pod", { sub: "k8s_pod" }),
      n("admin", { risk: 90 }),
    ];
    const edges: GraphViewEdge[] = [
      { source: "lb", target: "pod", label: "dns_points_to" },
      { source: "pod", target: "admin", label: "executes_as" },
    ];
    expect(computeAttackPaths(nodes, edges)).toHaveLength(1);
    // Hiding the intermediate pod severs the only route to admin.
    expect(computeAttackPaths(nodes, edges, new Set(["pod"]))).toHaveLength(0);
  });

  it("orders critical paths before lower-severity ones", () => {
    const nodes = [
      n("e1", { exposed: true }),
      n("med", { risk: 65 }),
      n("e2", { exposed: true }),
      n("crit", { toxicCombo: true, risk: 88 }),
    ];
    const edges: GraphViewEdge[] = [
      { source: "e1", target: "med", label: "can_assume" },
      { source: "e2", target: "crit", label: "can_assume" },
    ];
    const paths = computeAttackPaths(nodes, edges);
    expect(paths[0].severity).toBe("critical");
  });

  it("starts the chain at the internet node the entry is exposed to", () => {
    const nodes = [n("internet", { label: "Internet", sub: "external" }), n("vm"), n("admin", { sub: "iam_role admin" })];
    const edges: GraphViewEdge[] = [
      { source: "vm", target: "internet", label: "exposed_to_internet" },
      { source: "vm", target: "admin", label: "can_escalate_to" },
    ];
    const [path] = computeAttackPaths(nodes, edges);
    expect(path.hops.map((h) => h.id)).toEqual(["internet", "vm", "admin"]);
    expect(path.hops[1].via).toBe("exposed_to_internet");
    expect(path.hops[2].via).toBe("can_escalate_to");
    expect([...path.edgeKeys].sort()).toEqual(["vm->admin-1", "vm->internet-0"]);
  });

  it("summarises a path as start, first hop and end", () => {
    const nodes = [n("internet", { label: "Internet" }), n("vm", { label: "web-1" }), n("role", { label: "web" }), n("admin", { label: "ec2-admin", risk: 90 })];
    const edges: GraphViewEdge[] = [
      { source: "vm", target: "internet", label: "exposed_to_internet" },
      { source: "vm", target: "role", label: "executes_as" },
      { source: "role", target: "admin", label: "can_escalate_to" },
    ];
    const [path] = computeAttackPaths(nodes, edges);
    expect(pathSummary(path)).toEqual(["Internet", "web-1", "ec2-admin"]);
  });

  it("follows an instance profile (has_role) from a workload to its role", () => {
    const nodes = [n("vm", { exposed: true }), n("role", { sub: "iam_role" }), n("admin", { label: "ec2-admin" })];
    const edges: GraphViewEdge[] = [
      { source: "vm", target: "role", label: "has_role" },
      { source: "role", target: "admin", label: "can_escalate_to" },
    ];
    expect(computeAttackPaths(nodes, edges)[0].hops.map((h) => h.id)).toEqual(["vm", "role", "admin"]);
  });
});
