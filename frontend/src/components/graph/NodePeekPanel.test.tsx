import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { NodePeekPanel } from "./NodePeekPanel";
import { SCORE_THRESHOLDS } from "../../lib/format";

function riskLine(risk: number) {
  render(
    <NodePeekPanel
      node={{ id: "n1", label: "web-1", risk }}
      degree={0}
      pathHighlighted={false}
      expanding={false}
      onClose={() => {}}
    />,
  );
  return screen.getByText(`Risk score: ${risk}`);
}

// The peek panel colours a node's risk at the same band boundaries the canvas
// uses for the same node (layout.ts), so one node never reads as two bands.
test.each([
  [SCORE_THRESHOLDS.page, "text-red"],
  [SCORE_THRESHOLDS.page - 1, "text-orange"],
  [SCORE_THRESHOLDS.high, "text-orange"],
  [SCORE_THRESHOLDS.high - 1, "text-amber"],
  [SCORE_THRESHOLDS.pipeline, "text-amber"],
  [SCORE_THRESHOLDS.pipeline - 1, "text-text-3"],
])("risk %i is coloured %s", (risk, tone) => {
  expect(riskLine(risk)).toHaveClass(tone);
});
