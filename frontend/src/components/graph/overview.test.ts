import { describe, expect, it } from "vitest";
import { DOT_ZOOM, dotDiameter, edgeWidth } from "./overview";

describe("dotDiameter", () => {
  it("keeps the card-based size at normal zoom", () => {
    expect(dotDiameter(140, 1)).toBe(8);
    expect(dotDiameter(200, 1)).toBe(18);
  });

  it("raises small dots so they stay visible when zoomed far out", () => {
    expect(dotDiameter(140, 0.2)).toBe(30);
    expect(dotDiameter(140, 0.5)).toBe(12);
  });

  it("caps the compensation", () => {
    expect(dotDiameter(140, 0.01)).toBe(30);
  });
});

describe("edgeWidth", () => {
  it("is unchanged at and above the dot zoom", () => {
    expect(edgeWidth(1, DOT_ZOOM)).toBe(1);
    expect(edgeWidth(2.5, 1)).toBe(2.5);
  });

  it("is raised below the dot zoom and capped", () => {
    expect(edgeWidth(1, 0.2)).toBeCloseTo(4);
    expect(edgeWidth(1, 0.01)).toBe(8);
  });

  it("never lowers a thicker edge", () => {
    expect(edgeWidth(7, 0.3)).toBe(7);
  });
});
