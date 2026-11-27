import { describe, expect, it } from "vitest";
import { edgeType } from "./labels";

describe("edgeType", () => {
  it.each([
    ["ExecutesAs", "executes_as"],
    ["CanEscalateTo", "can_escalate_to"],
    ["ExposedToInternet", "exposed_to_internet"],
    ["ConnectedViaSG", "connected_via_sg"],
    ["AllowsFrom", "sg_allows_from"],
  ])("maps rel table %s to %s", (rel, type) => {
    expect(edgeType(rel)).toBe(type);
  });

  it.each([
    ["ExposedToInternetK8sWorkload", "exposed_to_internet"],
    ["ExecutesAsK8sWorkload", "executes_as"],
    ["ExecutesAsK8sServiceAccount", "executes_as"],
    ["FederatedAccessAsset", "federated_access"],
    ["DeploysToService", "deploys_to"],
    ["DefinedInK8sWorkload", "defined_in"],
  ])("maps the endpoint-split rel %s to %s", (rel, type) => {
    expect(edgeType(rel)).toBe(type);
  });

  it("leaves edge types and unknown labels unchanged", () => {
    expect(edgeType("can_assume")).toBe("can_assume");
    expect(edgeType("SomethingNew")).toBe("SomethingNew");
  });

  it("leaves a rel shared by several edge types unchanged", () => {
    expect(edgeType("Accesses")).toBe("Accesses");
    expect(edgeType("AccessesK8sWorkload")).toBe("AccessesK8sWorkload");
  });
});
