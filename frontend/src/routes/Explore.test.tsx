import { http, HttpResponse } from "msw";
import { fireEvent, screen, waitFor } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";

// The Graph page is now a single Cypher workbench — no tabs.

test("cypher console runs a query and renders grouped results", async () => {
  let ran = "";
  server.use(
    meHandler("viewer"),
    http.post("/api/graph/cypher", async ({ request }) => {
      const body = (await request.json()) as { query: string };
      ran = body.query;
      return HttpResponse.json({
        nodes: [{ id: "i-1", type: "ec2_instance", name: "web", provider: "aws", account_id: "111122223333" }],
        edges: [],
        truncated: false,
      });
    }),
  );

  renderApp("/investigate/graph");

  // Page loads directly as the workbench — no tab click needed.
  expect(await screen.findByText(/read-only/)).toBeInTheDocument();

  // Load a query from the library — chip click auto-runs it. The same example
  // can also surface as a post-result "Try:" suggestion chip, so there may be
  // more than one matching button; the quick-start row's is always first.
  fireEvent.click(screen.getAllByRole("button", { name: /High-risk exposed/ })[0]);
  await waitFor(() => expect(ran).toContain("MATCH"));

  // Results render with the group-by control.
  expect(await screen.findByText("group by")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Account" })).toBeInTheDocument();
});

test("ask-in-English generates Cypher, runs it, and shows the query", async () => {
  const generated = "MATCH (n:Asset) WHERE n.exposed RETURN n LIMIT 50";
  server.use(
    meHandler("viewer"),
    http.post("/api/graph/nl", () =>
      HttpResponse.json({
        nodes: [{ id: "i-1", type: "ec2_instance", name: "web", provider: "aws", exposed: true }],
        edges: [],
        truncated: false,
        generated_cypher: generated,
      }),
    ),
  );

  renderApp("/investigate/graph");

  const input = await screen.findByPlaceholderText(/internet-exposed assets/);
  fireEvent.change(input, { target: { value: "exposed ec2 instances" } });
  fireEvent.click(screen.getByRole("button", { name: /Generate/ }));

  // NLQBar previews the generated Cypher first — nothing touches the editor
  // until the analyst confirms.
  fireEvent.click(await screen.findByRole("button", { name: /Run in graph/ }));

  // Generated Cypher lands in the editor; results rendered.
  expect(await screen.findByDisplayValue(generated)).toBeInTheDocument();
  expect(await screen.findByText("group by")).toBeInTheDocument();
});

test("aggregate query renders a scalar value, not an empty graph", async () => {
  server.use(
    meHandler("viewer"),
    http.post("/api/graph/cypher", () =>
      HttpResponse.json({
        nodes: [],
        edges: [],
        truncated: false,
        columns: ["repo_count"],
        rows: [{ repo_count: 42 }],
      }),
    ),
  );

  renderApp("/investigate/graph");

  fireEvent.click(await screen.findByRole("button", { name: /High-risk exposed/ }));

  // The scalar value and its column label render — the "No results" empty state must NOT show.
  expect(await screen.findByText("42")).toBeInTheDocument();
  expect(screen.getByText("repo_count")).toBeInTheDocument();
  expect(screen.queryByText(/No results/)).not.toBeInTheDocument();
});

test("a result the engine flags as possibly incomplete says so", async () => {
  server.use(
    meHandler("viewer"),
    http.post("/api/graph/cypher", () =>
      HttpResponse.json({
        nodes: [{ id: "i-1", type: "ec2_instance", name: "web", provider: "aws" }],
        edges: [],
        truncated: false,
        multi_hop_may_be_incomplete: true,
      }),
    ),
  );

  renderApp("/investigate/graph");
  fireEvent.click((await screen.findAllByRole("button", { name: /High-risk exposed/ }))[0]);

  expect(await screen.findByText(/An empty or short result here is not proof that no path exists/)).toBeInTheDocument();
});

test("cypher console explains when the graph engine is unavailable", async () => {
  server.use(
    meHandler("viewer"),
    http.post("/api/graph/cypher", () =>
      HttpResponse.json({ type: "/errors/internal", title: "Internal", status: 503, detail: "graph engine not available" }, { status: 503 }),
    ),
  );

  renderApp("/investigate/graph");

  fireEvent.click(await screen.findByRole("button", { name: /High-risk exposed/ }));

  expect(await screen.findByText(/graph engine not available|unavailable/i)).toBeInTheDocument();
});

// The banner keys on the measured build state: `ready` used to mean only that a
// Cypher runner was wired, so the banner never showed during a rebuild.
test("shows the not-ready banner while the graph is rebuilding", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/graph/status", () => HttpResponse.json({ ready: false, state: "not_ready", node_count: 0 })),
  );
  renderApp("/investigate/graph");
  expect(await screen.findByText(/Graph engine not ready/)).toBeInTheDocument();
});

test("names a missing graph engine as not configured", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/graph/status", () => HttpResponse.json({ ready: false, state: "not_configured" })),
  );
  renderApp("/investigate/graph");
  expect(await screen.findByText(/No graph engine configured/)).toBeInTheDocument();
});

test("warns that multi-hop results may be incomplete when a node table is oversized", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/graph/status", () =>
      HttpResponse.json({
        ready: true,
        state: "ready",
        multi_hop_may_be_incomplete: true,
        oversized_node_tables: [{ label: "Package", rows: 140000 }],
      })),
  );
  renderApp("/investigate/graph");
  expect(await screen.findByText(/Multi-hop results may be incomplete: Package \(140,000 rows\)/)).toBeInTheDocument();
});

test("shows no banner when a built graph is serving", async () => {
  server.use(meHandler("viewer"));
  renderApp("/investigate/graph");
  expect(await screen.findByText(/read-only/)).toBeInTheDocument();
  expect(screen.queryByText(/Graph engine not ready|No graph engine configured|state unknown|may be incomplete/)).not.toBeInTheDocument();
});
