import { useState } from "react";
import type { Connector, OrgAccount, OrgTestReport } from "../lib/api";
import { useOrgAccounts, useTestConnector } from "../lib/queries";
import { Button, ErrorNote, Loading, StatusDot } from "../components/ui";
import { timeAgo } from "../lib/format";

// generateExternalId returns a random sts:ExternalId (32 hex chars). It is
// generated in the browser so the operator can paste it into the StackSet
// parameters before the connector exists; the server only ever receives it as
// config and never echoes it back.
export function generateExternalId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return "graph-" + Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

const templates = [
  { name: "graph-hub-role.yaml", what: "the hub role graph runs as (graph's own account)" },
  { name: "graph-org-stackset.yaml", what: "the StackSet + management-account role + discovery role (management account)" },
  { name: "graph-readonly-role.yaml", what: "the member role the StackSet deploys (upload to S3)" },
  { name: "graph-execution-role.yaml", what: "optional: Approve & run execution role" },
];

const stackSetsConsole = "https://console.aws.amazon.com/cloudformation/home#/stacksets";

// AwsOrgSetupGuide is the step list shown while creating an aws_org connector.
export function AwsOrgSetupGuide({ externalId, onRegenerate }: { externalId: string; onRegenerate: () => void }) {
  return (
    <div className="space-y-2 rounded border border-border-subtle bg-surface-2 p-3 text-[11px] text-text-2">
      <p className="font-medium text-text">Onboard a whole AWS Organization</p>
      <ol className="list-decimal space-y-1 pl-4">
        <li>
          Deploy <code>graph-hub-role.yaml</code> in the account graph runs in, and run graph as that role. With{" "}
          <code>TrustType=principal</code> (an instance role, or a stored IAM user key) graph assumes the hub role
          itself: paste the stack&apos;s <code>HubRoleArn</code> output as <code>hub_role_arn</code>.
        </li>
        <li>
          In the management account, upload <code>graph-readonly-role.yaml</code> to S3 and deploy{" "}
          <code>graph-org-stackset.yaml</code> with the hub role ARN and this ExternalId. New accounts in the target
          OUs get the role automatically (<a className="text-teal underline" href={stackSetsConsole} target="_blank" rel="noreferrer">StackSets console</a>).
        </li>
        <li>
          Paste the stack&apos;s <code>ManagementRoleArn</code> output below as <code>management_role_arn</code>, create
          the connector, then use &quot;Test connection&quot;.
        </li>
      </ol>
      <div className="flex flex-wrap items-center gap-2">
        <span>ExternalId:</span>
        <code className="rounded bg-bg px-1.5 py-0.5 text-text" data-testid="external-id">
          {externalId}
        </code>
        <Button type="button" onClick={onRegenerate}>
          Regenerate
        </Button>
      </div>
      <ul className="space-y-0.5">
        {templates.map((t) => (
          <li key={t.name}>
            <a className="text-teal underline" href={`/api/aws-org/templates/${t.name}`} download={t.name}>
              {t.name}
            </a>{" "}
            — {t.what}
          </li>
        ))}
      </ul>
      <p className="text-text-3">
        No access key is copied to any account: graph assumes each member role from its own identity, presenting the
        ExternalId. See docs/onboarding-aws-org.md.
      </p>
    </div>
  );
}

const statusTone: Record<string, "ok" | "warning" | "error"> = {
  active: "ok",
  pending: "warning",
  excluded: "warning",
  unknown: "warning",
  suspended: "error",
  closed: "error",
  removed: "error",
  conflict: "error",
  error: "error",
};

// AwsOrgPanel is the org connector card's extra section: connection test and
// the discovered accounts with their child connectors' health.
export function AwsOrgPanel({ connector, isAdmin }: { connector: Connector; isAdmin: boolean }) {
  const [showAccounts, setShowAccounts] = useState(false);
  const accounts = useOrgAccounts(connector.id, showAccounts);
  const test = useTestConnector();

  return (
    <div className="mt-3 space-y-2">
      <div className="flex flex-wrap gap-1.5">
        <Button onClick={() => setShowAccounts(!showAccounts)}>{showAccounts ? "Hide accounts" : "Accounts"}</Button>
        {isAdmin && (
          <Button onClick={() => test.mutate(connector.id)} disabled={test.isPending}>
            {test.isPending ? "Testing…" : "Test connection"}
          </Button>
        )}
      </div>
      {test.isError && <ErrorNote message={(test.error as Error).message} />}
      {test.data && <TestReport report={test.data} />}
      {showAccounts && accounts.isLoading && <Loading />}
      {showAccounts && accounts.isError && <ErrorNote message={(accounts.error as Error).message} />}
      {showAccounts && accounts.data && <AccountList accounts={accounts.data} />}
    </div>
  );
}

function TestReport({ report: r }: { report: OrgTestReport }) {
  return (
    <div className="space-y-1 rounded border border-border-subtle p-2 text-[11px]" data-testid="org-test-report">
      <Step ok={r.hub_ok} label={r.hub_ok ? `Hub identity: ${r.hub_identity ?? ""}` : "Hub identity"} error={r.hub_error} />
      {r.list_ran && (
        <Step ok={r.list_ok} label={r.list_ok ? `Listed ${r.account_count} accounts` : "List accounts"} error={r.list_error} />
      )}
      {r.members.map((m) => (
        <Step key={m.account_id} ok={m.ok} label={`Assume member role in ${m.account_id}${m.ok ? "" : ` — ${m.cause}`}`} error={m.detail} />
      ))}
    </div>
  );
}

function Step({ ok, label, error }: { ok: boolean; label: string; error?: string }) {
  return (
    <div>
      <StatusDot tone={ok ? "ok" : "error"} label={label} />
      {!ok && error && <p className="ml-4 break-words text-text-3">{error}</p>}
    </div>
  );
}

function AccountList({ accounts }: { accounts: OrgAccount[] }) {
  if (accounts.length === 0) {
    return <p className="text-[11px] text-text-3">No accounts discovered yet — discovery runs hourly, or click &quot;Sync now&quot;.</p>;
  }
  return (
    <div className="max-h-64 overflow-y-auto rounded border border-border-subtle">
      <table className="w-full text-left text-[11px]">
        <thead className="text-text-3">
          <tr>
            <th className="px-2 py-1">Account</th>
            <th className="px-2 py-1">Status</th>
            <th className="px-2 py-1">Connector</th>
          </tr>
        </thead>
        <tbody>
          {accounts.map((a) => (
            <tr key={a.account_id} className="border-t border-border-subtle align-top">
              <td className="px-2 py-1">
                <div className="text-text">{a.name || a.account_id}</div>
                <div className="text-text-3">{a.account_id}</div>
              </td>
              <td className="px-2 py-1" title={a.status_detail}>
                <StatusDot tone={statusTone[a.status] ?? "warning"} label={a.status} />
                {a.status !== "active" && a.status_detail && <div className="text-text-3">{a.status_detail}</div>}
              </td>
              <td className="px-2 py-1">
                {a.child ? (
                  <>
                    <StatusDot
                      tone={!a.child.enabled ? "warning" : a.child.sync_status === "error" || a.child.stale ? "error" : "ok"}
                      label={!a.child.enabled ? "disabled" : a.child.stale ? "stale" : a.child.sync_status}
                    />
                    <div className="text-text-3">
                      {a.child.last_success_at ? `synced ${timeAgo(a.child.last_success_at)}` : "never synced"}
                    </div>
                  </>
                ) : (
                  <span className="text-text-3">none</span>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
