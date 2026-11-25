import { describe, expect, it } from "vitest";
import type { GraphStatus } from "./api";
import { graphMultiHopNotice, graphNotReadyNotice, graphStateLabel } from "./graphStatus";

describe("graph status copy", () => {
  it.each<[GraphStatus | undefined, boolean, string]>([
    [{ ready: true, state: "ready" }, false, "graph ready"],
    [{ ready: false, state: "not_ready", node_count: 0 }, true, "graph not ready"],
    [{ ready: false, state: "not_configured" }, true, "graph engine not configured"],
    [{ ready: false, state: "unknown" }, true, "graph status unknown"],
    [undefined, false, "graph status unknown"],
  ])("%o → banner %s, label %s", (status, banner, label) => {
    expect(graphNotReadyNotice(status) !== null).toBe(banner);
    expect(graphStateLabel(status)).toBe(label);
  });

  it("words each not-ready state for what it is", () => {
    expect(graphNotReadyNotice({ ready: false, state: "not_ready" })).toMatch(/restores its saved snapshot/);
    expect(graphNotReadyNotice({ ready: false, state: "not_configured" })).toMatch(/No graph engine configured/);
    expect(graphNotReadyNotice({ ready: false, state: "unknown" })).toMatch(/state unknown/);
  });

  it("warns about multi-hop results only when a node table was measured above one node group", () => {
    expect(graphMultiHopNotice(undefined)).toBeNull();
    expect(graphMultiHopNotice({ ready: true, state: "ready" })).toBeNull();
    expect(graphMultiHopNotice({ ready: true, state: "ready", multi_hop_may_be_incomplete: false })).toBeNull();
    const notice = graphMultiHopNotice({
      ready: true,
      state: "ready",
      multi_hop_may_be_incomplete: true,
      oversized_node_tables: [{ label: "Package", rows: 200000 }],
    });
    expect(notice).toMatch(/Multi-hop results may be incomplete/);
    expect(notice).toMatch(/Package \(200,000 rows\)/);
    expect(notice).toMatch(/Single-hop results and risk scores are not affected/);
  });
});
