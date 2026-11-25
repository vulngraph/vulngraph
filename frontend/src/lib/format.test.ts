import { describe, expect, test } from "vitest";
import scoreBands from "../generated/score-bands.json";
import { SCORE_THRESHOLDS, bandAtLeast, bandLabel, bandTone, scoreToBand } from "./format";

describe("score bands", () => {
  test("every server band has a label and a tone, and nothing else does", () => {
    const server = scoreBands.bands.map((b) => b.band).sort();
    expect(server).toEqual(["high", "monitor", "page", "pipeline"]);
    for (const band of server) {
      expect(bandLabel(band)).not.toBe("");
    }
    expect(bandLabel("auto")).toBe("");
    expect(bandTone("high")).toBe("text-orange");
  });

  test("scoreToBand agrees with the server at every boundary", () => {
    for (const { band, min_score } of scoreBands.bands) {
      expect(scoreToBand(min_score)).toBe(band);
      if (min_score > 0) expect(scoreToBand(min_score - 1)).not.toBe(band);
    }
  });

  test("the thresholds are the server's, not a local copy", () => {
    const min = Object.fromEntries(scoreBands.bands.map((b) => [b.band, b.min_score]));
    expect(SCORE_THRESHOLDS).toEqual({ page: min.page, high: min.high, pipeline: min.pipeline });
    // A suppressed finding is capped one below the pipeline threshold; it must
    // read as low, not medium.
    expect(scoreToBand(SCORE_THRESHOLDS.pipeline - 1)).toBe("monitor");
  });

  test("bandAtLeast ranks bands and puts an unenriched band below all", () => {
    expect(bandAtLeast("page", "high")).toBe(true);
    expect(bandAtLeast("high", "high")).toBe(true);
    expect(bandAtLeast("pipeline", "high")).toBe(false);
    expect(bandAtLeast("", "pipeline")).toBe(false);
    expect(bandAtLeast(undefined, "pipeline")).toBe(false);
    expect(bandAtLeast("monitor", "pipeline")).toBe(false);
  });
});
