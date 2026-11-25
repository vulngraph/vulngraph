import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import { MustFixBadge } from "./MustFixBadge";

test("an enriched finding with no class reads as unknown, never as not urgent", () => {
  render(<MustFixBadge cls="" state="enriched" />);
  expect(screen.getByText(/Urgency \?/)).toBeInTheDocument();
  expect(screen.queryByText(/Not urgent/)).toBeNull();
});

test("routine is the stated not-urgent verdict", () => {
  render(<MustFixBadge cls="routine" state="enriched" />);
  expect(screen.getByText(/Not urgent/)).toBeInTheDocument();
});

test("an unenriched finding renders nothing", () => {
  const { container } = render(<MustFixBadge cls="" state="never_enriched" />);
  expect(container).toBeEmptyDOMElement();
});
