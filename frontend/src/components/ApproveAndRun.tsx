import { useState, type ReactNode } from "react";
import { AlertTriangle, CheckCircle2, Clock, Loader2, Play, Users, XCircle } from "lucide-react";
import { errorMessage, type DecisionAuditRow, type DecisionDryRun, type DecisionExecutionPlan } from "../lib/api";
import {
  liveRequest,
  useDecisionDryRun,
  useDecisionExecution,
  useRequestDecisionRun,
  useRunDecision,
  type RunBody,
} from "../lib/decisionExecution";

// ApproveAndRun walks an admin from "yes" to a fix that actually ran, through
// the executor's own checks: which connector, a dry run of the exact change, a
// typed confirmation for anything destructive or irreversible, and — where the
// fix needs two people — a second admin's confirmation. Nothing here runs
// anything on its own; every step is a click, and the server re-checks each.
export function ApproveAndRun({ decisionId }: { decisionId: string }) {
  const plan = useDecisionExecution(decisionId, true);

  return (
    <section aria-label="Run this fix">
      <div className="mb-1.5 text-[11px] uppercase tracking-wide text-text-3">Run this fix</div>
      <div className="space-y-2.5 rounded border border-border-subtle bg-surface-2 px-3 py-2.5 text-[12px]">
        {plan.isPending ? (
          <p className="text-text-3">Checking whether this fix can run from Vulngraph…</p>
        ) : plan.isError ? (
          <p role="alert" className="text-red">Couldn't load the run plan: {errorMessage(plan.error)}</p>
        ) : (
          <>
            <RunState decisionId={decisionId} plan={plan.data} />
            <AuditTrail plan={plan.data} />
          </>
        )}
      </div>
    </section>
  );
}

function RunState({ decisionId, plan }: { decisionId: string; plan: DecisionExecutionPlan }) {
  const run = plan.run;
  if (run?.status === "succeeded") {
    return (
      <Status icon={<CheckCircle2 className="h-3.5 w-3.5 text-emerald" />} title="Fix ran">
        <span className="block text-text">{run.detail}</span>
        <span className="block text-[11px] text-text-3">
          Run by {run.executed_by}
          {run.requested_by !== run.executed_by && <> · approved by {run.requested_by}</>}
        </span>
      </Status>
    );
  }
  if (run?.status === "running") {
    return (
      <Status icon={<Loader2 className="h-3.5 w-3.5 animate-spin text-teal" />} title="Running">
        <span className="text-text-2">{run.plan}</span>
      </Status>
    );
  }
  if (run?.status === "outcome_unknown") {
    return (
      <Status icon={<AlertTriangle className="h-3.5 w-3.5 text-amber" />} title="Result unknown">
        <span className="block text-text-2">{run.plan}</span>
        <span className="block text-[11px] text-text-3">
          The cloud call was cut off after it may have been sent. Check the resource in the cloud console before
          anything is retried; an admin releases the run once the state is known.
        </span>
      </Status>
    );
  }
  if (liveRequest(run)) {
    return run!.requested_by_you ? (
      <Status icon={<Clock className="h-3.5 w-3.5 text-amber" />} title="Waiting for a second admin">
        <span className="block text-text-2">You approved: {run!.plan}</span>
        <span className="block text-[11px] text-text-3">
          A different admin must confirm it in this panel by {clock(run!.grant_expires_at)}. After that the request
          lapses and has to be made again.
        </span>
      </Status>
    ) : (
      <SecondAdminConfirm decisionId={decisionId} plan={plan} />
    );
  }
  if (plan.state === "guidance_only") {
    return (
      <Status icon={<XCircle className="h-3.5 w-3.5 text-text-3" />} title="Guidance only">
        <span className="block text-text-2">{plan.reason}</span>
        <span className="block text-[11px] text-text-3">Run it by hand with the command above, or in IaC.</span>
      </Status>
    );
  }
  return <RunFlow decisionId={decisionId} plan={plan} />;
}

// RunFlow is the first admin's path: fill what the finding lacks, dry-run,
// confirm, then run (or request the second admin).
function RunFlow({ decisionId, plan }: { decisionId: string; plan: DecisionExecutionPlan }) {
  const dryRun = useDecisionDryRun(decisionId);
  const request = useRequestDecisionRun(decisionId);
  const run = useRunDecision(decisionId);
  const [inputs, setInputs] = useState<Record<string, string>>({});
  const [confirm, setConfirm] = useState("");
  const [preview, setPreview] = useState<DecisionDryRun | null>(null);
  const busy = dryRun.isPending || request.isPending || run.isPending;
  const body = (): RunBody => ({ inputs: filled(inputs), confirm });
  const confirmed = !preview?.confirm_text || confirm.trim() === preview.confirm_text;
  const lastRun = plan.run;

  return (
    <div className="space-y-2">
      {lastRun?.status === "failed" && (
        <p className="text-red">The last attempt failed: {lastRun.error}</p>
      )}
      {lastRun?.status === "awaiting_second_admin" && (
        <p className="text-amber">The last request for a second admin lapsed before anyone confirmed it.</p>
      )}
      <p className="text-text-2">
        Runs <span className="font-mono">{plan.action}</span> through connector{" "}
        <span className="text-text">{plan.connector_name}</span>
        {plan.requires_second_admin && " — a second admin must confirm it"}.
      </p>

      {plan.inputs.length > 0 && (
        <fieldset className="space-y-1.5">
          <legend className="text-[11px] text-text-3">
            {plan.state === "needs_input"
              ? "The finding doesn't carry these — fill them in from the evidence:"
              : "Optional — leave blank to use the connector's default:"}
          </legend>
          {plan.inputs.map((key) => (
            <label key={key} className="flex items-center gap-2">
              <span className="w-24 shrink-0 font-mono text-[11px] text-text-3">{key}</span>
              <input
                value={inputs[key] ?? ""}
                onChange={(e) => {
                  setInputs((cur) => ({ ...cur, [key]: e.target.value }));
                  setPreview(null);
                }}
                disabled={busy}
                className="min-w-0 flex-1 rounded border border-border-subtle bg-surface-3 px-2 py-1 font-mono text-[12px] text-text focus:border-teal/40 focus:outline-none"
              />
            </label>
          ))}
        </fieldset>
      )}

      {!preview ? (
        <button
          onClick={() => dryRun.mutate(body(), { onSuccess: (p) => { setPreview(p); setConfirm(""); } })}
          disabled={busy}
          className="flex items-center gap-1.5 rounded border border-teal/30 bg-teal/10 px-3 py-1.5 text-[12px] font-medium text-teal transition-colors hover:bg-teal/20 disabled:opacity-40"
        >
          <Play className="h-3.5 w-3.5" />
          {plan.requires_second_admin ? "Approve & request a second admin…" : "Approve & run…"}
        </button>
      ) : (
        <div className="space-y-2">
          <div className="text-[11px] uppercase tracking-wide text-text-3">Dry run — what will change</div>
          <pre className="whitespace-pre-wrap rounded border border-border-subtle bg-surface-3 px-2 py-1.5 font-mono text-[11px] text-text">
            {preview.detail}
          </pre>
          {preview.confirm_text && (
            <ConfirmInput want={preview.confirm_text} value={confirm} onChange={setConfirm} disabled={busy} />
          )}
          <div className="flex flex-wrap gap-2">
            {preview.destructive ? (
              <button
                onClick={() => request.mutate(body())}
                disabled={busy || !confirmed}
                className="flex items-center gap-1.5 rounded border border-amber/30 bg-amber/10 px-3 py-1.5 text-[12px] font-medium text-amber transition-colors hover:bg-amber/20 disabled:opacity-40"
              >
                <Users className="h-3.5 w-3.5" /> Approve & request second admin
              </button>
            ) : (
              <button
                onClick={() => run.mutate(body())}
                disabled={busy || !confirmed}
                className="flex items-center gap-1.5 rounded border border-teal/30 bg-teal/10 px-3 py-1.5 text-[12px] font-medium text-teal transition-colors hover:bg-teal/20 disabled:opacity-40"
              >
                {run.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
                {run.isPending ? "Running…" : "Run now"}
              </button>
            )}
            <button
              onClick={() => setPreview(null)}
              disabled={busy}
              className="rounded border border-border-subtle bg-surface-3 px-3 py-1.5 text-[12px] text-text-3 transition-colors hover:text-text-2 disabled:opacity-40"
            >
              Cancel
            </button>
          </div>
        </div>
      )}
      {[dryRun, request, run].map((m, i) =>
        m.isError ? (
          <p key={i} role="alert" className="text-[11px] text-red">
            {errorMessage(m.error)}
          </p>
        ) : null,
      )}
    </div>
  );
}

// SecondAdminConfirm is the second admin's path: read the exact plan the first
// admin approved, type the confirmation, run it.
function SecondAdminConfirm({ decisionId, plan }: { decisionId: string; plan: DecisionExecutionPlan }) {
  const run = useRunDecision(decisionId);
  const [confirm, setConfirm] = useState("");
  const r = plan.run!;
  const want = r.confirm_text ?? "";
  return (
    <Status icon={<Users className="h-3.5 w-3.5 text-amber" />} title="Needs a second admin">
      <span className="block text-text-2">
        {r.requested_by} approved: <span className="text-text">{r.plan}</span>
      </span>
      <span className="mb-2 block text-[11px] text-text-3">
        Confirming runs it now, as you, by {clock(r.grant_expires_at)}.
      </span>
      {want && <ConfirmInput want={want} value={confirm} onChange={setConfirm} disabled={run.isPending} />}
      <button
        onClick={() => run.mutate({ confirm })}
        disabled={run.isPending || (!!want && confirm.trim() !== want)}
        className="mt-2 flex items-center gap-1.5 rounded border border-amber/30 bg-amber/10 px-3 py-1.5 text-[12px] font-medium text-amber transition-colors hover:bg-amber/20 disabled:opacity-40"
      >
        {run.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
        {run.isPending ? "Running…" : "Confirm & run"}
      </button>
      {run.isError && (
        <p role="alert" className="mt-1 text-[11px] text-red">
          {errorMessage(run.error)}
        </p>
      )}
    </Status>
  );
}

function ConfirmInput({ want, value, onChange, disabled }: {
  want: string;
  value: string;
  onChange: (v: string) => void;
  disabled: boolean;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-[11px] text-text-3">
        This fix is destructive or can't be undone. Type <span className="font-mono text-text">{want}</span> to confirm.
      </span>
      <input
        aria-label="Typed confirmation"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        className="w-full rounded border border-border-subtle bg-surface-3 px-2 py-1 font-mono text-[12px] text-text focus:border-amber/40 focus:outline-none"
      />
    </label>
  );
}

const AUDIT_LABELS: Record<string, string> = {
  "executor.dry_run": "Dry run",
  "executor.approve": "Approved — grant minted",
  "executor.execute_intent": "About to run",
  "executor.execute": "Ran",
  "executor.execute_failed": "Refused or failed",
};

// AuditTrail shows the executor's own audit rows for this decision's run —
// the record of who asked, who approved and what happened.
function AuditTrail({ plan }: { plan: DecisionExecutionPlan }) {
  if (!plan.run) return null;
  if (!plan.audit_known) {
    return <p className="text-[11px] text-amber">The audit rows for this run couldn't be loaded.</p>;
  }
  if (plan.audit.length === 0) return null;
  return (
    <div>
      <div className="mb-1 text-[11px] uppercase tracking-wide text-text-3">Audit trail</div>
      <ol className="space-y-0.5">
        {plan.audit.map((row: DecisionAuditRow, i) => (
          <li key={i} className="flex gap-2 text-[11px]" title={row.details}>
            <span className="shrink-0 text-text-3">{clock(row.ts)}</span>
            <span className="text-text-2">{AUDIT_LABELS[row.action] ?? row.action}</span>
            <span className="truncate text-text-3">{row.actor}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}

function Status({ icon, title, children }: { icon: ReactNode; title: string; children: ReactNode }) {
  return (
    <div className="flex items-start gap-2">
      <span className="mt-0.5 shrink-0">{icon}</span>
      <div className="min-w-0 flex-1">
        <div className="font-medium text-text">{title}</div>
        {children}
      </div>
    </div>
  );
}

function filled(inputs: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(inputs).filter(([, v]) => v.trim() !== ""));
}

function clock(iso?: string): string {
  return iso ? new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "—";
}
