import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import type { FindingContext } from "../lib/api";
import { SafeToFixSection } from "./FindingDetailPanel";

const withImpact = (impact: FindingContext["impact"]) =>
  ({ reasoning: { safety_band: "caution" }, impact }) as unknown as FindingContext;

test("a failed dependents lookup reads as unknown, never as 0 dependents", () => {
  render(<SafeToFixSection finding={withImpact({ dependents: 0, dependents_known: false, unused: true })} />);
  expect(screen.getByText("dependents unknown")).toBeInTheDocument();
  expect(screen.queryByText(/^0$/)).not.toBeInTheDocument();
});

test("a measured zero still shows the count", () => {
  render(<SafeToFixSection finding={withImpact({ dependents: 0, dependents_known: true, unused: false })} />);
  expect(screen.getByText("0")).toBeInTheDocument();
  expect(screen.queryByText("dependents unknown")).not.toBeInTheDocument();
});
