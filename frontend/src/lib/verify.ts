// Live verification of a finding: open the chat agent with an instruction to
// confirm or refute the finding against the *current* cloud state, not the last
// sync. The agent uses only the chat service's read-only live tools
// (live_aws_describe, get_cloudtrail_events) — the backend injects the connector
// credential, so the model never sees a key, never mutates, and only probes the
// one resource the finding is about. The verdict is advisory: a human still
// governs the fix.

import type { Finding } from "./api";

// verifyContext binds the chat session to the finding (rides on every turn).
export function verifyContext(f: Finding): string {
  const parts = [`Finding: ${f.title}`];
  if (f.resource_id) parts.push(`resource: ${f.resource_id} (${f.resource_type ?? "?"})`);
  if (f.region) parts.push(`region: ${f.region}`);
  if (f.source) parts.push(`source: ${f.source}`);
  if (f.check_id) parts.push(`check: ${f.check_id}`);
  return parts.join("; ");
}

// verifyMessage is the first turn: a scoped, read-only verification instruction.
export function verifyMessage(f: Finding): string {
  const target = f.resource_id
    ? `resource ${f.resource_id}${f.region ? ` in ${f.region}` : ""}`
    : "this finding's resource";
  return [
    `Verify whether this finding is still true against the LIVE cloud state, not the last sync.`,
    `Use only read-only live checks (live_aws_describe, get_cloudtrail_events) against ${target}.`,
    `Do not attempt any mutation.`,
    ``,
    `Return a verdict as the first line — one of: VERIFIED (still true, safe to act on), `,
    `REFUTED (false positive or already remediated), or INCONCLUSIVE (couldn't confirm live). `,
    `Then give the specific evidence you saw (the actual API responses / CloudTrail activity) `,
    `and, if VERIFIED, whether the resource looks actively used or dormant.`,
  ].join("\n");
}

// openVerify fires the chat-open event the ChatPanel listens for.
export function openVerify(f: Finding): void {
  window.dispatchEvent(
    new CustomEvent("graph:chat-open", {
      detail: { message: verifyMessage(f), context: verifyContext(f) },
    }),
  );
}
