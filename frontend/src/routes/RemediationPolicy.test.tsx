import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderWithClient } from "../test/render";
import { PolicySection } from "./RemediationPolicy";

const basePolicy = {
  id: "p1",
  suggest_threshold: 60,
  action_rules: {},
  updated_at: "2026-08-20T00:00:00Z",
  updated_by: "admin@example.com",
};

test("only the real backend action classes render, not the retired fake ones", async () => {
  server.use(meHandler("admin"), http.get("/api/policy", () => HttpResponse.json(basePolicy)));

  renderWithClient(<PolicySection />);

  expect(await screen.findByText("Observe")).toBeInTheDocument();
  expect(screen.getByText("Remediate")).toBeInTheDocument();
  expect(screen.getByText("Modify")).toBeInTheDocument();
  expect(screen.getByText("Isolate")).toBeInTheDocument();
  expect(screen.getByText("Destroy")).toBeInTheDocument();

  // These classes are not in respond/domain.go's ActionClass enum — a rule set
  // on them could never match anything the backend emits.
  expect(screen.queryByText("Notify owner")).not.toBeInTheDocument();
  expect(screen.queryByText("Patch instance")).not.toBeInTheDocument();
  expect(screen.queryByText("Rotate credentials")).not.toBeInTheDocument();
});

test("no control offers to run a remediation on its own", async () => {
  server.use(meHandler("admin"), http.get("/api/policy", () => HttpResponse.json(basePolicy)));

  renderWithClient(<PolicySection />);

  expect(await screen.findByText(/never runs a remediation on its own/i)).toBeInTheDocument();
  expect(screen.queryByLabelText(/Auto threshold/i)).not.toBeInTheDocument();
  for (const select of screen.getAllByRole("combobox")) {
    const options = within(select).getAllByRole("option").map((o) => o.textContent);
    expect(options).toEqual(["Requires approval", "Guidance only"]);
  }
  expect(screen.queryByRole("combobox", { name: /Mode for Observe/ })).not.toBeInTheDocument();
});

test("a class with no rule reads as requiring approval, and a change saves the explicit mode", async () => {
  let putBody: unknown = null;
  server.use(
    meHandler("admin"),
    http.get("/api/policy", () => HttpResponse.json(basePolicy)),
    http.put("/api/policy", async ({ request }) => {
      putBody = await request.json();
      return new HttpResponse(null, { status: 204 });
    }),
  );

  renderWithClient(<PolicySection />);

  const destroy = await screen.findByRole("combobox", { name: "Mode for Destroy" });
  expect(destroy).toHaveValue("jit");
  fireEvent.change(destroy, { target: { value: "disabled" } });
  fireEvent.click(screen.getByRole("button", { name: "Save policy" }));

  await waitFor(() => expect(putBody).toEqual({ suggest_threshold: 60, action_rules: { destroy: "disabled" } }));
});

test("a save does not visibly revert the slider before the refetch lands", async () => {
  let putBody: unknown = null;
  const resolvePutRef: { current: (() => void) | null } = { current: null };

  server.use(
    meHandler("admin"),
    http.get("/api/policy", () => HttpResponse.json(basePolicy)),
    http.put("/api/policy", async ({ request }) => {
      putBody = await request.json();
      // Hold the response open until the test lets it through, so we can
      // observe state right after onSuccess fires but before the refetched
      // GET has resolved.
      await new Promise<void>((resolve) => { resolvePutRef.current = resolve; });
      return new HttpResponse(null, { status: 204 });
    }),
  );

  renderWithClient(<PolicySection />);

  const suggestSlider = await screen.findByLabelText(/Suggest threshold/);
  fireEvent.change(suggestSlider, { target: { value: "70" } });
  expect(await screen.findByText(/Suggest threshold — 70%/)).toBeInTheDocument();

  fireEvent.click(screen.getByRole("button", { name: "Save policy" }));

  await waitFor(() => expect(putBody).not.toBeNull());
  expect(screen.getByText(/Suggest threshold — 70%/)).toBeInTheDocument();

  resolvePutRef.current?.();

  await waitFor(() => expect(screen.getByText(/Saved\./)).toBeInTheDocument());
  expect(screen.getByText(/Suggest threshold — 70%/)).toBeInTheDocument();
});

test("a non-admin sees a read-only slider that stays in the tab order", async () => {
  server.use(meHandler("analyst"), http.get("/api/policy", () => HttpResponse.json(basePolicy)));

  renderWithClient(<PolicySection />);

  const suggestSlider = await screen.findByLabelText(/Suggest threshold/);
  expect(suggestSlider).toHaveAttribute("readonly");
  expect(suggestSlider).toHaveAttribute("aria-disabled", "true");
  expect(suggestSlider).not.toHaveAttribute("disabled");
});
