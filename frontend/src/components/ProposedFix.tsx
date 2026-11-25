import { useState, type ReactNode } from "react";
import { Copy, Check, Undo2, AlertTriangle } from "lucide-react";
import type { Decision } from "../lib/api";
import { copyText } from "../lib/clipboard";
import { SafetyBadge, FixLocationLine, type FixLocation } from "./SafetyBadge";

// The fields of the decision's audit details this panel reads (respond's
// auditFor).
export type FixDetail = {
  action_class?: string;
  summary?: string;
  blast_radius?: number;
  blast_radius_known?: boolean;
  cove_concerns?: string[];
  safety_band?: string;
  fix_location?: FixLocation;
};

// ProposedFix lays out, for one proposed state-changing fix, everything a person
// needs before saying yes: what will change, why, how far it reaches, whether it
// can be undone, whether it is safe to run, and how to run it by hand. Vulngraph
// never runs it on its own (ADR 087) — nothing here executes anything.
export function ProposedFix({ decision, detail }: { decision: Decision; detail: FixDetail }) {
  const rem = decision.remediation;
  const concerns = detail.cove_concerns ?? [];
  const iacOwned = detail.fix_location?.kind === "source_repo" && !!detail.fix_location.repo;

  return (
    <section aria-label="Proposed fix">
      <div className="mb-1.5 text-[11px] uppercase tracking-wide text-text-3">Proposed fix</div>
      <dl className="space-y-2.5 rounded border border-border-subtle bg-surface-2 px-3 py-2.5 text-[12px]">
        <Row label="What will change">
          <span className="text-text">{rem?.change ?? detail.summary ?? "—"}</span>
          {!rem && (
            <span className="mt-0.5 block text-[11px] text-text-3">
              No executor action fits this plan — apply it by hand or in IaC.
            </span>
          )}
          {decision.target_resource && (
            <span className="mt-0.5 block truncate font-mono text-[11px] text-text-3" title={decision.target_resource}>
              {decision.target_resource}
            </span>
          )}
        </Row>

        {(decision.target_must_fix_reason || decision.target_remediation) && (
          <Row label="Why">
            {decision.target_must_fix_reason && <span className="text-text-2">{decision.target_must_fix_reason}</span>}
            {decision.target_remediation && (
              <span className="mt-0.5 block text-[11px] text-text-3">Source advice: {decision.target_remediation}</span>
            )}
          </Row>
        )}

        <Row label="Blast radius">
          {detail.blast_radius_known === false ? (
            <span className="text-amber" title="The blast-radius walk failed at decision time — this is not evidence the change's reach is small.">
              unmeasured — size it before approving
            </span>
          ) : detail.blast_radius === undefined ? (
            <span className="text-text-3">not recorded</span>
          ) : (
            <span className="text-text-2">
              {detail.blast_radius} other {detail.blast_radius === 1 ? "asset" : "assets"} reachable from this resource
            </span>
          )}
        </Row>

        {rem && (
          <Row label="Undo">
            <span className={`inline-flex items-center gap-1 ${rem.reversible ? "text-teal" : "text-red"}`}>
              {rem.reversible ? <Undo2 className="h-3 w-3" /> : <AlertTriangle className="h-3 w-3" />}
              {rem.reversible ? "Reversible" : "Not reversible"}
            </span>
            <span className="mt-0.5 block text-[11px] text-text-3">{rem.rollback}</span>
          </Row>
        )}

        <Row label="Safe to run?">
          <div className="flex flex-wrap items-center gap-2">
            <SafetyBadge band={detail.safety_band} />
            {concerns.length > 0 && (
              <span className="text-[11px] text-amber">
                {concerns.length} verification {concerns.length === 1 ? "concern" : "concerns"} — read them above
              </span>
            )}
            {rem?.destructive && (
              <span className="text-[11px] text-red">needs a second admin's approval grant</span>
            )}
            {!detail.safety_band && concerns.length === 0 && !rem?.destructive && (
              <span className="text-[11px] text-text-3">no assessment recorded — check the finding before acting</span>
            )}
          </div>
        </Row>

        {(rem || detail.fix_location?.kind) && (
          <Row label="Run it by hand">
            <FixLocationLine fix={detail.fix_location} className="block" />
            {rem && <CopyCommand command={rem.cli} />}
            {rem && iacOwned && (
              <span className="mt-1 block text-[11px] text-amber">
                This resource is deployed from {detail.fix_location?.repo}; change it there, or the next apply reverts
                a CLI change.
              </span>
            )}
            {rem?.cli.includes("<") && (
              <span className="mt-1 block text-[11px] text-text-3">
                Fill the &lt;placeholders&gt; from the finding detail before running.
              </span>
            )}
          </Row>
        )}
      </dl>
    </section>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-[11px] text-text-3">{label}</dt>
      <dd className="mt-0.5">{children}</dd>
    </div>
  );
}

function CopyCommand({ command }: { command: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div className="mt-1 flex items-start gap-2 rounded border border-border-subtle bg-surface-3 px-2 py-1.5">
      <code className="min-w-0 flex-1 break-all font-mono text-[11px] text-text-2">{command}</code>
      <button
        type="button"
        onClick={async () => setCopied(await copyText(command))}
        className="shrink-0 rounded p-0.5 text-text-3 hover:bg-surface-2 hover:text-text"
        aria-label="Copy command"
      >
        {copied ? <Check className="h-3.5 w-3.5 text-teal" /> : <Copy className="h-3.5 w-3.5" />}
      </button>
    </div>
  );
}
