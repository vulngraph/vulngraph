import { http, HttpResponse } from "msw";
import { screen, within } from "@testing-library/react";
import { expect, test } from "vitest";
import { server } from "../test/setup";
import { meHandler } from "../test/handlers";
import { renderApp } from "../test/render";

const context = {
  id: "f1",
  source: "aws_guardduty",
  type: "threat",
  severity: "high",
  title: "SSH brute force against i-123",
  description: "An EC2 instance is being brute-forced over SSH.",
  resource_id: "i-123",
  check_id: "UnauthorizedAccess:EC2/SSHBruteForce",
  score: 82,
  score_band: "page",
  known_exploited: false,
  detected_at: "2026-06-14T00:00:00Z",
  exposure: { internet_facing: true, privileged: false },
  blast: { count: 4, by_type: { ec2_instance: 3 }, can_assume: [], truncated: false },
  provenance: { connector: "aws", owner: "payments-team", environment: "prod", age_bucket: "established" },
  reasoning: {
    action_class: "isolate",
    summary: "contain the host",
    rationale: "owned prod, internet-facing",
    outcome: "escalated",
    confidence_band: "low",
    confidence_score: 0.41,
    effective_n: 2.5,
    sample_count: 3,
    blast_radius: 4,
    cove_concerns: ["isolate would sever prod traffic"],
    decided_at: "2026-06-14T01:00:00Z",
  },
  factors: [{ source: "kev", points: 30, detail: "CISA KEV" }],
  peers: [{ type: "exposure", check_id: "aws-ec2-public-ip", score_band: "high" }],
};

const belief = {
  finding_id: "f1",
  resource_id: "i-123",
  claim: "Raw score 82 is not justified: the host is contained behind SSO+MFA and unreachable.",
  severity: "low",
  confidence: "high",
  status: "confirmed",
  provenance: "adjudicator",
  evidence: [
    { clause: "reachable only via SSO", source: "trust_entry", fact: "contained" },
    { clause: "no internet path", source: "reachability", fact: "unreachable" },
  ],
};

test("renders a finding's full context", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/findings/f1", () => HttpResponse.json(context)),
    http.get("/api/beliefs/f1", () => HttpResponse.json(belief)),
    http.get("/api/assets/i-123/blast-radius", () =>
      HttpResponse.json({ seed_id: "i-123", max_depth: 2, truncated: false, assets: [], edges: [] }),
    ),
    http.post("/api/graph/cypher", () =>
      HttpResponse.json({ nodes: [], edges: [], truncated: false }),
    ),
  );

  renderApp("/investigate/findings/f1");

  expect(await screen.findByText("SSH brute force against i-123")).toBeInTheDocument();
  // reasoning, factors, provenance, peers, blast all surface
  expect(screen.getByText("contain the host")).toBeInTheDocument();
  expect(screen.getByText("payments-team")).toBeInTheDocument();
  expect(screen.getByText(/CISA KEV/)).toBeInTheDocument();
  expect(screen.getByText("4 reachable")).toBeInTheDocument();
  expect(screen.getByText("aws-ec2-public-ip")).toBeInTheDocument();
  // a peer's band chip reads the severity word, not the wire value
  const peerRow = screen.getByText("aws-ec2-public-ip").parentElement!;
  expect(within(peerRow).getByText("high")).toHaveClass("text-orange");
  // the 7-step AHC trace renders confidence evidence + the CoVe concern
  expect(screen.getByText(/41% decayed success rate/)).toBeInTheDocument();
  expect(screen.getByText(/isolate would sever prod traffic/)).toBeInTheDocument();
  // the true-severity belief panel: verdict, adjudicated provenance, cited evidence
  expect(await screen.findByText("True severity")).toBeInTheDocument();
  expect(screen.getByText("adjudicated")).toBeInTheDocument();
  expect(screen.getByText(/is not justified/)).toBeInTheDocument();
  expect(screen.getByText(/trust_entry: contained/)).toBeInTheDocument();
});

test("belief panel is absent when a finding has no belief (404)", async () => {
  server.use(
    meHandler("viewer"),
    http.get("/api/findings/f1", () => HttpResponse.json(context)),
    http.get("/api/beliefs/f1", () => new HttpResponse(null, { status: 404 })),
    http.get("/api/assets/i-123/blast-radius", () =>
      HttpResponse.json({ seed_id: "i-123", max_depth: 2, truncated: false, assets: [], edges: [] }),
    ),
    http.post("/api/graph/cypher", () =>
      HttpResponse.json({ nodes: [], edges: [], truncated: false }),
    ),
  );

  renderApp("/investigate/findings/f1");

  expect(await screen.findByText("SSH brute force against i-123")).toBeInTheDocument();
  expect(screen.queryByText("True severity")).not.toBeInTheDocument();
});
