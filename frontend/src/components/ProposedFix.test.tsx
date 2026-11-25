import { render, screen } from "@testing-library/react";
import { expect, test } from "vitest";
import type { Decision } from "../lib/api";
import { ProposedFix } from "./ProposedFix";

const base: Decision = {
  id: "d1",
  ts: "2026-06-14T00:00:00Z",
  actor: "agent",
  action: "decision",
  target_type: "finding",
  target_id: "f1",
  target_resource: "arn:aws:s3:::data-lake",
  target_must_fix_reason: "internet-reachable · blast 4",
  target_remediation: "Enable S3 Block Public Access.",
};

test("a proposed fix shows what changes, why, its reach, how to undo it and how to run it by hand", () => {
  render(
    <ProposedFix
      decision={{
        ...base,
        remediation: {
          action: "s3_block_public",
          change: "block all public access on S3 bucket data-lake (us-east-1)",
          destructive: false,
          reversible: true,
          rollback: "Remove the block: aws s3api delete-public-access-block --bucket data-lake",
          cli: "aws s3api put-public-access-block --bucket data-lake",
        },
      }}
      detail={{ action_class: "remediate", blast_radius: 4, blast_radius_known: true, safety_band: "safe" }}
    />,
  );

  expect(screen.getByText("block all public access on S3 bucket data-lake (us-east-1)")).toBeInTheDocument();
  expect(screen.getByText("internet-reachable · blast 4")).toBeInTheDocument();
  expect(screen.getByText(/Source advice: Enable S3 Block Public Access/)).toBeInTheDocument();
  expect(screen.getByText(/4 other assets reachable/)).toBeInTheDocument();
  expect(screen.getByText("Reversible")).toBeInTheDocument();
  expect(screen.getByText(/delete-public-access-block/)).toBeInTheDocument();
  expect(screen.getByText("aws s3api put-public-access-block --bucket data-lake")).toBeInTheDocument();
  expect(screen.getByRole("button", { name: "Copy command" })).toBeInTheDocument();
  expect(screen.getByText("Safe to fix")).toBeInTheDocument();
});

test("an unmeasured blast radius never reads as a small one", () => {
  render(<ProposedFix decision={base} detail={{ action_class: "remediate", blast_radius: 0, blast_radius_known: false }} />);
  expect(screen.getByText(/unmeasured — size it before approving/)).toBeInTheDocument();
  expect(screen.queryByText(/0 other assets/)).not.toBeInTheDocument();
});

test("an irreversible, destructive fix says so, and an IaC-owned resource points at the repo", () => {
  render(
    <ProposedFix
      decision={{
        ...base,
        remediation: {
          action: "gcp_firewall_remove",
          change: "DELETE GCP firewall rule allow-ssh in project prod-1",
          destructive: true,
          reversible: false,
          rollback: "Not reversible from the request — save the rule first",
          cli: "gcloud compute firewall-rules delete allow-ssh --project prod-1",
        },
      }}
      detail={{
        action_class: "remediate",
        blast_radius: 2,
        fix_location: { kind: "source_repo", repo: "org/infra" },
      }}
    />,
  );
  expect(screen.getByText("Not reversible")).toBeInTheDocument();
  expect(screen.getByText(/needs a second admin's approval grant/)).toBeInTheDocument();
  expect(screen.getByText(/deployed from org\/infra/)).toBeInTheDocument();
});

test("with no fitting executor action the plan summary is the change, applied by hand", () => {
  render(<ProposedFix decision={base} detail={{ action_class: "modify", summary: "rotate the database password" }} />);
  expect(screen.getByText("rotate the database password")).toBeInTheDocument();
  expect(screen.getByText(/No executor action fits this plan/)).toBeInTheDocument();
  expect(screen.queryByRole("button", { name: "Copy command" })).not.toBeInTheDocument();
});
