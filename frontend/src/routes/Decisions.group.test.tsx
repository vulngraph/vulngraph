import { describe, expect, it } from "vitest";
import type { QueueItem } from "../lib/api";
import { groupQueue, tierQueue } from "../components/queue";

function item(over: Partial<QueueItem>): QueueItem {
  return {
    cluster_key: "ck",
    title: "t",
    action_class: "remediate",
    outcome: "escalated",
    worst_score: 50,
    blast_radius: 0,
    count: 1,
    resources: 1,
    finding_ids: ["f"],
    decided_at: "2026-07-09T00:00:00Z",
    ...over,
  } as QueueItem;
}

describe("groupQueue", () => {
  it("groups same check_id + action_class, keeps singletons apart", () => {
    const items = [
      item({ cluster_key: "a", check_id: "wildcard-cname", action_class: "remediate" }),
      item({ cluster_key: "b", check_id: "wildcard-cname", action_class: "remediate" }),
      item({ cluster_key: "c", check_id: "wildcard-cname", action_class: "observe" }), // same check, different action
      item({ cluster_key: "d", check_id: "open-bucket", action_class: "remediate" }),
    ];
    const { grouped, singles } = groupQueue(items);
    expect(grouped).toHaveLength(1);
    expect(grouped[0].map((q: QueueItem) => q.cluster_key)).toEqual(["a", "b"]);
    expect(singles.map((q: QueueItem) => q.cluster_key).sort()).toEqual(["c", "d"]);
  });

  it("falls back to title when check_id is missing and preserves server order across groups", () => {
    const items = [
      item({ cluster_key: "a", title: "X" }),
      item({ cluster_key: "b", title: "X" }),
      item({ cluster_key: "c", title: "Y" }),
      item({ cluster_key: "d", title: "Y" }),
      item({ cluster_key: "e", title: "Y" }),
    ];
    const { grouped, singles } = groupQueue(items);
    expect(singles).toHaveLength(0);
    // "X" (size 2) appears before "Y" (size 3) in `items` — the server's
    // order wins, not group size.
    expect(grouped.map((g: QueueItem[]) => g.length)).toEqual([2, 3]);
    expect(grouped[0].map((q: QueueItem) => q.cluster_key)).toEqual(["a", "b"]);
    expect(grouped[1].map((q: QueueItem) => q.cluster_key)).toEqual(["c", "d", "e"]);
  });

  it("keeps groups and singletons in the server's original relative order, not re-sorted by score", () => {
    const items = [
      item({ cluster_key: "s1", check_id: "solo-1", worst_score: 10 }),
      item({ cluster_key: "g1a", check_id: "dup", worst_score: 5 }),
      item({ cluster_key: "s2", check_id: "solo-2", worst_score: 99 }),
      item({ cluster_key: "g1b", check_id: "dup", worst_score: 5 }),
    ];
    const { grouped, singles } = groupQueue(items);
    // The "dup" group's earliest member (g1a) sits before s2 in the server
    // order, and s1 (worst_score 10) sits before s2 (worst_score 99) — a
    // score-based sort would have flipped both.
    expect(grouped).toHaveLength(1);
    expect(grouped[0].map((q: QueueItem) => q.cluster_key)).toEqual(["g1a", "g1b"]);
    expect(singles.map((q: QueueItem) => q.cluster_key)).toEqual(["s1", "s2"]);
  });

  it("groups distinct checks of one title family (≥3) with the same action", () => {
    const items = [
      item({ cluster_key: "a", check_id: "privesc-1", title: "IAM privilege escalation: iam:PutRolePolicy", action_class: "modify" }),
      item({ cluster_key: "b", check_id: "privesc-2", title: "IAM privilege escalation: sts:AssumeRole", action_class: "modify" }),
      item({ cluster_key: "c", check_id: "privesc-3", title: "IAM privilege escalation: iam:CreateAccessKey", action_class: "modify" }),
      item({ cluster_key: "d", check_id: "privesc-4", title: "IAM privilege escalation: ssm:SendCommand", action_class: "remediate" }), // different action
      item({ cluster_key: "e", check_id: "bucket-1", title: "S3 bucket public", action_class: "modify" }),
    ];
    const { grouped, singles } = groupQueue(items);
    expect(grouped).toHaveLength(1);
    expect(grouped[0].map((q: QueueItem) => q.cluster_key).sort()).toEqual(["a", "b", "c"]);
    expect(singles.map((q: QueueItem) => q.cluster_key).sort()).toEqual(["d", "e"]);
  });

  it("tiers by safety band (safe first) and never mixes tiers inside a group", () => {
    const t = (k: string, band: string | undefined, title: string) =>
      item({ cluster_key: k, safety_band: band, title, action_class: "modify" } as Partial<QueueItem>);
    const items = [
      t("r1", "risky", "IAM privilege escalation: a"),
      t("r2", "risky", "IAM privilege escalation: b"),
      t("r3", "risky", "IAM privilege escalation: c"),
      t("s1", "safe", "IAM privilege escalation: d"),
      t("s2", "safe", "IAM privilege escalation: e"),
      t("s3", "safe", "IAM privilege escalation: f"),
      t("u1", undefined, "Orphan check"),
    ];
    const tiers = tierQueue(items);
    expect(tiers.map((x) => x.tier)).toEqual(["safe", "risky", "unknown"]);
    // Same family, but the safe and risky members form separate groups.
    expect(tiers[0].grouped[0].map((q: QueueItem) => q.cluster_key).sort()).toEqual(["s1", "s2", "s3"]);
    expect(tiers[1].grouped[0].map((q: QueueItem) => q.cluster_key).sort()).toEqual(["r1", "r2", "r3"]);
    expect(tiers[2].singles.map((q: QueueItem) => q.cluster_key)).toEqual(["u1"]);
  });
});
