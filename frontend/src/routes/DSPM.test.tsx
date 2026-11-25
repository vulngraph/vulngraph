import { http, HttpResponse } from "msw";
import { screen, waitFor } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";

// The summary tiles and the worklist consume /api/dspm/summary and
// /api/dspm/stores and build no Cypher (the Graph tab, its NL bar and the asset
// drawer's classification lookup still do, and this file does not cover them): the tile counts and the worklist predicate are
// computed and tested server-side (internal/app/explore/dspm.go), and this file
// only pins that the UI renders what the API says rather than recomputing it.

function summaryHandler(overrides: Record<string, unknown> = {}) {
  return http.get("/api/dspm/summary", () =>
    HttpResponse.json({
      stores: { total: 9000, sensitive: 130, secret_vault: 5000, internal: 4000 },
      confidence: { asserted: 10, inferred: 120, unknown: 0 },
      exposure: {
        public_confirmed: 1,
        public_possible: 20,
        public_unobserved: 22,
        network_exposed: 1,
        public_or_exposed: 21,
      },
      encryption: {
        unencrypted: 7,
        encrypted: 20,
        unknown: 102,
        observed_types: ["rds_instance", "s3_bucket"],
        coverage_pct: 20,
      },
      classes: [
        { class: "credentials", stores: 5000, asserted: 5000, inferred: 0, sensitive: true },
        { class: "financial", stores: 60, asserted: 0, inferred: 60, sensitive: true },
      ],
      method: "resource names and operator tags — no file contents are read",
      caveat:
        "Classifications are inferred from resource names and operator tags. Nothing here reads object contents, so an inferred class is a lead to verify, not a scan result.",
      ...overrides,
    }),
  );
}

function storesHandler() {
  return http.get("/api/dspm/stores", () =>
    HttpResponse.json({
      nodes: [
        { id: "bkt-c", name: "world-readable", type: "s3_bucket", provider: "aws", public: true, public_tier: 2, encryption: "unencrypted", max_score: 40 },
        { id: "bkt-p", name: "unblocked-only", type: "s3_bucket", provider: "aws", public: true, public_tier: 1, encryption: "encrypted" },
        { id: "bkt-u", name: "access-denied-bucket", type: "s3_bucket", provider: "aws", public: false, public_tier: 3, encryption: "unknown" },
        { id: "dataclass:pii", name: "PII", type: "data_class", provider: "" },
      ],
      // edge_type carries the PascalCase rel label — what execCypher actually
      // returns (repo_cypher.go reads typed.Label), not the ClickHouse value.
      edges: [
        // confidence rides on the ContainsData edge: "high" is asserted
        // (operator tag / resource type), "medium" is a guess from the
        // resource name.
        { src_id: "bkt-c", dst_id: "dataclass:pii", edge_type: "ContainsData", confidence: "high" },
        { src_id: "bkt-p", dst_id: "dataclass:pii", edge_type: "ContainsData", confidence: "medium" },
        { src_id: "bkt-u", dst_id: "dataclass:pii", edge_type: "ContainsData" },
      ],
      truncated: false,
      columns: [],
      rows: [],
    }),
  );
}

test("DSPM renders the server-computed tiles, not browser arithmetic", async () => {
  server.use(meHandler("viewer"), summaryHandler(), storesHandler());

  renderApp("/investigate/dspm");

  expect(await screen.findByText("world-readable")).toBeInTheDocument();
  expect(screen.getAllByText(/^PII\??$/).length).toBeGreaterThan(0);

  await waitFor(() => {
    // Confirmed and possible exposure are separate tiles because they are
    // separate facts. The old page showed one count as both "exposed" and "public" — the same
    // fact twice, because exposed was defined as (exposed OR public).
    expect(screen.getByText("Public — confirmed")).toBeInTheDocument();
    expect(screen.getByText("Public — possible")).toBeInTheDocument();
    expect(screen.getByText("Internet-reachable")).toBeInTheDocument();
    // The encryption tile names its own coverage instead of implying a total.
    expect(screen.getByText("Unencrypted (S3 / RDS)")).toBeInTheDocument();
    expect(screen.getByText(/20% of stores measured/)).toBeInTheDocument();
    // Coverage gaps stay on screen rather than being folded into a risk count.
    expect(screen.getByText("Exposure unobserved")).toBeInTheDocument();
    expect(screen.getByText("Encryption unobserved")).toBeInTheDocument();
    // Credential vaults are counted as what they are, not as classified content.
    expect(screen.getByText("Secret / vault entries")).toBeInTheDocument();
  });

  // No tile is labelled with the old duplicated wording.
  expect(screen.queryByText("Exposed sensitive")).not.toBeInTheDocument();
  expect(screen.queryByText("Public sensitive")).not.toBeInTheDocument();
});

test("DSPM shows the heuristic caveat and the confidence split", async () => {
  server.use(meHandler("viewer"), summaryHandler(), storesHandler());

  renderApp("/investigate/dspm");

  expect(await screen.findByText(/not a scan result/)).toBeInTheDocument();
  expect(
    await screen.findByText(
      /10 asserted \(operator tag or resource type\) · 120 inferred from the resource name/,
    ),
  ).toBeInTheDocument();
});

test("DSPM distinguishes confirmed, possible and unobserved exposure per store", async () => {
  server.use(meHandler("viewer"), summaryHandler(), storesHandler());

  renderApp("/investigate/dspm");

  expect(await screen.findByText("world-readable")).toBeInTheDocument();
  expect(screen.getByText("unblocked-only")).toBeInTheDocument();
  expect(screen.getByText("access-denied-bucket")).toBeInTheDocument();

  // Confirmed tier keeps the red "public" badge; possible tier gets "public?".
  expect(screen.getByText("public")).toBeInTheDocument();
  expect(screen.getByText("public?")).toBeInTheDocument();
  // A bucket whose exposure config could not be read is neither — it used to be
  // badged PUBLIC? on the strength of an AccessDenied.
  expect(screen.getByTitle(/Exposure unknown/)).toBeInTheDocument();
  // Only the observed-unencrypted store carries the unencrypted badge; the two
  // stores reporting encrypted/unknown do not.
  expect(screen.getAllByText("unencrypted")).toHaveLength(1);
  // The unknown store is marked unknown instead of rendering like the encrypted one.
  expect(screen.getAllByTitle(/Encryption unknown/)).toHaveLength(1);
});

test("DSPM marks a name-guessed classification as a guess", async () => {
  server.use(meHandler("viewer"), summaryHandler(), storesHandler());

  renderApp("/investigate/dspm");

  // The asserted (operator-tagged / type-derived) class renders plain…
  expect(await screen.findByTitle(/Asserted: an operator tag/)).toBeInTheDocument();
  // Two badges render plain "PII": the asserted one and the one with no recorded
  // confidence. Only a medium-confidence guess is marked.
  expect(screen.getAllByText("PII")).toHaveLength(2);
  // …and the name-inferred one is visibly marked as an inference.
  expect(screen.getByTitle(/Inferred from the resource NAME only/)).toBeInTheDocument();
  expect(screen.getByText("PII?")).toBeInTheDocument();
  // An edge with no recorded confidence says so rather than implying either.
  expect(screen.getByTitle(/Provenance not recorded/)).toBeInTheDocument();
});
