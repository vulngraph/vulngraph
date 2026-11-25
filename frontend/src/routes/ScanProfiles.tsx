import { useState } from "react";
import { useNavigate } from "@tanstack/react-router";
import {
  useIsAdmin,
  useScanProfiles,
  useDeleteScanProfile,
  useTriggerProfileScan,
} from "../lib/queries";
import type { ScanProfile } from "../lib/api";
import { Button, ErrorNote, Loading, PageHeader } from "../components/ui";
import { timeAgo } from "../lib/assetMeta";
import { WorkflowBuilder } from "../components/WorkflowBuilder";

// ── Schedule label helper ─────────────────────────────────────────────────────

function scheduleLabel(cron: string): string {
  if (!cron) return "Manual";
  const t = cron.trim();
  if (t === "0 * * * *") return "Hourly";
  if (t === "0 0 * * *" || t === "@daily") return "Daily";
  if (t === "0 0 * * 0" || t === "0 2 * * 0" || t === "@weekly") return "Weekly";
  if (t === "0 0 1 * *" || t === "@monthly") return "Monthly";
  return t;
}

// ── Target label helper ───────────────────────────────────────────────────────

// Human-readable asset-type names for the labels below. Anything not listed
// falls back to the raw graph type with underscores turned into spaces.
const TYPE_NAMES: Record<string, string> = {
  ec2_instance:    "EC2",
  gce_instance:    "GCE",
  azure_vm:        "Azure VM",
  k8s_service:     "K8s services",
  rds_instance:    "RDS",
  lambda_function: "Lambda",
  load_balancer:   "Load balancers",
  s3_bucket:       "S3 buckets",
  gcs_bucket:      "GCS buckets",
};

const PROVIDER_NAMES: Record<string, string> = { aws: "AWS", gcp: "GCP", azure: "Azure" };

function prettyType(t: string): string {
  return TYPE_NAMES[t] ?? t.replace(/_/g, " ");
}

// Pull every single-quoted string out of a Cypher fragment, e.g.
// "a.type IN ['ec2_instance', 'rds_instance']" → ["ec2_instance", "rds_instance"].
function quoted(fragment: string): string[] {
  return Array.from(fragment.matchAll(/'([^']+)'/g)).map((m) => m[1]);
}

// targetLabel renders a profile's target_query as a short human phrase.
//
// The builders (WorkflowBuilder.buildCypher + the target presets) all emit the
// same shape — MATCH (a:Asset)-[:ExposedToInternet]->(:Asset {id:'internet'})
// with an optional WHERE of a.provider / a.type / a.score / a.has_kev /
// a.exploitable predicates — so parse exactly that and only fall back to
// "Custom query" for genuinely hand-written Cypher.
function targetLabel(query: string): string {
  if (!query || !query.trim()) return "All exposed";
  const q = query.trim();

  const exposed = /ExposedToInternet/i.test(q);
  const whereMatch = q.match(/\bWHERE\b([\s\S]*?)(?:\bRETURN\b|$)/i);
  const where = whereMatch ? whereMatch[1] : "";

  // Unknown MATCH shape, or a WHERE with predicates we don't model → give up.
  if (!exposed) return "Custom query";

  const parts: string[] = [];
  let recognisedAll = true;

  for (const raw of where.split(/\bAND\b/i)) {
    const clause = raw.trim();
    if (!clause) continue;
    if (/^a\.provider\b/i.test(clause)) {
      const vals = quoted(clause).map((v) => PROVIDER_NAMES[v] ?? v.toUpperCase());
      if (vals.length === 0) { recognisedAll = false; continue; }
      parts.push(vals.join("/"));
      continue;
    }
    if (/^a\.type\b/i.test(clause)) {
      const vals = quoted(clause).map(prettyType);
      if (vals.length === 0) { recognisedAll = false; continue; }
      parts.push(vals.join(", "));
      continue;
    }
    const score = clause.match(/^a\.score\s*>=?\s*(\d+)/i);
    if (score) { parts.push(`score ≥ ${score[1]}`); continue; }
    if (/^a\.has_kev\s*=\s*1/i.test(clause)) { parts.push("KEV"); continue; }
    if (/^a\.exploitable\s*=\s*1/i.test(clause)) { parts.push("exploitable"); continue; }
    recognisedAll = false;
  }

  if (!recognisedAll) return "Custom query";
  if (parts.length === 0) return "All exposed";
  return `Exposed · ${parts.join(" · ")}`;
}

// ── Sub-components ────────────────────────────────────────────────────────────

function ScannerBadge({ scannerType }: { scannerType: string }) {
  return (
    <span className="rounded border border-border-subtle bg-surface-2 px-1.5 py-0.5 font-mono text-[11px] text-text-3">
      {scannerType}
    </span>
  );
}

function EnabledPip({ enabled }: { enabled: boolean }) {
  return (
    <span
      className={`inline-flex items-center gap-1 text-[11px] ${enabled ? "text-emerald" : "text-text-3"}`}
    >
      <span
        className={`h-1.5 w-1.5 rounded-full ${enabled ? "bg-emerald" : "bg-surface-3"}`}
      />
      {enabled ? "enabled" : "disabled"}
    </span>
  );
}

// ── Delete confirmation modal ─────────────────────────────────────────────────

function DeleteConfirm({
  profile,
  onCancel,
}: {
  profile: ScanProfile;
  onCancel: () => void;
}) {
  const del = useDeleteScanProfile();
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-bg/80 backdrop-blur-sm">
      <div className="glass w-full max-w-sm rounded-xl p-6">
        <h2 className="mb-2 font-display text-base text-text">Delete workflow?</h2>
        <p className="mb-5 text-[11px] text-text-3">
          <strong className="text-text">{profile.name}</strong> will be permanently removed. Scan
          runs already completed are not affected.
        </p>
        {del.isError && <ErrorNote message={(del.error as Error).message} />}
        <div className="flex gap-2">
          <Button
            variant="danger"
            disabled={del.isPending}
            onClick={() => del.mutate(profile.id, { onSuccess: onCancel })}
          >
            {del.isPending ? "Deleting…" : "Delete"}
          </Button>
          <Button onClick={onCancel}>Cancel</Button>
        </div>
      </div>
    </div>
  );
}

// ── Profile card ──────────────────────────────────────────────────────────────

function ProfileCard({
  profile,
  isAdmin,
  onDelete,
  onEdit,
}: {
  profile: ScanProfile;
  isAdmin: boolean;
  onDelete: (p: ScanProfile) => void;
  onEdit: (p: ScanProfile) => void;
}) {
  const trigger = useTriggerProfileScan();
  const navigate = useNavigate();

  function handleTrigger() {
    trigger.mutate(profile.id, {
      onSuccess: () => navigate({ to: "/scans" }),
    });
  }

  const schedStr = scheduleLabel(profile.schedule ?? "");
  const isManual = !profile.schedule || !profile.schedule.trim();
  const whoLabel = targetLabel(profile.target_query ?? "");

  return (
    <div className="glass flex flex-col gap-4 rounded-xl p-5">
      {/* Header row */}
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="mb-1 flex flex-wrap items-center gap-2">
            <span className="truncate font-display text-sm text-text">{profile.name}</span>
            <ScannerBadge scannerType={profile.scanner_type} />
            <EnabledPip enabled={profile.enabled} />
            {/* Schedule badge */}
            {!isManual && (
              <span className="flex items-center gap-1 rounded border border-border-subtle px-1.5 py-0.5 text-[11px] text-text-3">
                ⏰ {schedStr}
              </span>
            )}
            {/* Drift badge */}
            {profile.drift_enabled && (
              <span className="flex items-center gap-1 rounded border border-teal/30 bg-teal/8 px-1.5 py-0.5 text-[11px] text-teal">
                ⚡ Drift
              </span>
            )}
          </div>
          {/* WHO summary */}
          <p className="text-[11px] text-text-3">
            {whoLabel}
            {profile.description ? ` · ${profile.description}` : ""}
          </p>
          {profile.schedule_error && (
            <p className="mt-0.5 text-[11px] text-red" title={profile.schedule_error}>
              Schedule is invalid and never runs: {profile.schedule_error}
            </p>
          )}
        </div>

        {/* Actions */}
        {isAdmin && (
          <div className="flex shrink-0 items-center gap-1.5">
            <button
              onClick={handleTrigger}
              disabled={trigger.isPending}
              title="Run now"
              aria-label={`Run ${profile.name} now`}
              className="flex h-7 w-7 items-center justify-center rounded border border-border-subtle text-text-3 transition-colors hover:border-teal hover:text-teal disabled:cursor-not-allowed disabled:opacity-50"
            >
              {trigger.isPending ? (
                <span className="text-[11px]">…</span>
              ) : (
                <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor">
                  <path d="M3 2.5l7 3.5-7 3.5V2.5z" />
                </svg>
              )}
            </button>
            <button
              onClick={() => onEdit(profile)}
              title="Edit workflow"
              aria-label={`Edit ${profile.name}`}
              className="flex h-7 w-7 items-center justify-center rounded border border-border-subtle text-text-3 transition-colors hover:border-teal/50 hover:text-text-2"
            >
              ✏
            </button>
            <button
              onClick={() => onDelete(profile)}
              title="Delete"
              aria-label={`Delete ${profile.name}`}
              className="flex h-7 w-7 items-center justify-center rounded border border-border-subtle text-text-3 transition-colors hover:border-red/50 hover:text-red"
            >
              <svg width="12" height="12" viewBox="0 0 12 12" fill="currentColor">
                <path d="M4.5 1h3l.5.5H10V3H2V1.5h2L4.5 1zm-2 3h7l-.7 6.5H4.2L3.5 4z" />
              </svg>
            </button>
          </div>
        )}
      </div>

      {/* Detail grid */}
      <dl className="grid grid-cols-2 gap-x-4 gap-y-3 sm:grid-cols-4">
        {/* Target */}
        <div>
          <dt className="mb-0.5 text-[11px] uppercase tracking-wide text-text-3">Target</dt>
          <dd className="text-[11px] text-text-2">{targetLabel(profile.target_query ?? "")}</dd>
        </div>

        {/* Templates */}
        <div>
          <dt className="mb-0.5 text-[11px] uppercase tracking-wide text-text-3">Templates</dt>
          <dd>
            {profile.template_strategy === "ai_contextual" ? (
              <span
                className="inline-flex items-center gap-1 rounded border border-red/30 bg-red/10 px-1.5 py-0.5 text-[11px] text-red"
                title="AI contextual selection is not available, so every run of this profile fails. Edit it to use default or tag selection."
              >
                AI contextual (unavailable)
              </span>
            ) : profile.template_strategy === "tags" ? (
              <div className="flex flex-wrap gap-1">
                {(profile.template_tags ?? []).slice(0, 3).map((t) => (
                  <span
                    key={t}
                    className="rounded border border-border-subtle bg-surface-2 px-1.5 py-0.5 text-[11px] text-text-3"
                  >
                    {t}
                  </span>
                ))}
                {(profile.template_tags ?? []).length > 3 && (
                  <span className="text-[11px] text-text-3">
                    +{(profile.template_tags ?? []).length - 3}
                  </span>
                )}
                {(profile.template_tags ?? []).length === 0 && (
                  <span className="text-[11px] text-text-3">by tags</span>
                )}
              </div>
            ) : (
              <span className="text-[11px] text-text-2">Default (by asset type)</span>
            )}
          </dd>
        </div>

        {/* Schedule */}
        <div>
          <dt className="mb-0.5 text-[11px] uppercase tracking-wide text-text-3">Schedule</dt>
          <dd>
            {isManual ? (
              <span className="text-[11px] text-text-3">Manual</span>
            ) : (
              <code className="font-mono text-[11px] text-text-2">{schedStr}</code>
            )}
          </dd>
        </div>

        {/* Updated — this is the profile row's updated_at, NOT the last run time
            (the profile API doesn't expose a last-run timestamp). */}
        <div>
          <dt className="mb-0.5 text-[11px] uppercase tracking-wide text-text-3">Updated</dt>
          <dd>
            <span className="text-[11px] text-text-3">
              {profile.updated_at ? (
                <span title={new Date(profile.updated_at).toISOString()}>
                  {timeAgo(profile.updated_at)}
                </span>
              ) : (
                "Never"
              )}
            </span>
          </dd>
        </div>
      </dl>

      {/* Trigger error */}
      {trigger.isError && (
        <p className="text-[11px] text-red">{(trigger.error as Error).message}</p>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function ScanProfiles() {
  const { data, isLoading, isError, error } = useScanProfiles();
  const isAdmin = useIsAdmin();

  const [deleteTarget, setDeleteTarget] = useState<ScanProfile | null>(null);
  const [builderOpen, setBuilderOpen] = useState(false);
  const [editTarget, setEditTarget] = useState<ScanProfile | undefined>(undefined);

  function openNew() { setEditTarget(undefined); setBuilderOpen(true); }
  function openEdit(p: ScanProfile) { setEditTarget(p); setBuilderOpen(true); }
  function closeBuilder() { setBuilderOpen(false); setEditTarget(undefined); }

  const profiles = Array.isArray(data) ? data : [];

  return (
    <div>
      {/* Page header */}
      <div className="flex items-start justify-between">
        <PageHeader
          title="Workflows"
          subtitle="Cypher-driven scan workflows — define when to scan, who to scan, and what to run."
        />
        {isAdmin && (
          <button
            onClick={openNew}
            className="rounded border border-teal/40 bg-teal/10 px-3 py-1.5 text-[11px] font-medium text-teal transition-colors hover:bg-teal/20"
          >
            + New workflow
          </button>
        )}
      </div>

      {isLoading && <Loading />}
      {isError && <ErrorNote message={(error as Error).message} />}

      {/* Profile cards */}
      {profiles.length > 0 && (
        <div className="grid gap-4 sm:grid-cols-1 lg:grid-cols-2">
          {profiles.map((p) => (
            <ProfileCard
              key={p.id}
              profile={p}
              isAdmin={isAdmin}
              onDelete={setDeleteTarget}
              onEdit={openEdit}
            />
          ))}
        </div>
      )}

      {/* Empty state */}
      {profiles.length === 0 && !isLoading && (
        <div className="rounded-lg border border-border-subtle bg-surface p-10 text-center">
          <p className="mb-1 text-sm text-text">No workflows yet.</p>
          {isAdmin ? (
            <button
              onClick={openNew}
              className="mt-3 rounded border border-teal/40 bg-teal/10 px-3 py-1.5 text-[11px] text-teal transition-colors hover:bg-teal/20"
            >
              Create your first workflow
            </button>
          ) : (
            <p className="text-[11px] text-text-3">Ask an admin to create a scan workflow.</p>
          )}
        </div>
      )}

      {/* Delete confirmation */}
      {deleteTarget && (
        <DeleteConfirm profile={deleteTarget} onCancel={() => setDeleteTarget(null)} />
      )}

      {/* Workflow builder modal */}
      {builderOpen && (
        <WorkflowBuilder
          profile={editTarget}
          onClose={closeBuilder}
        />
      )}
    </div>
  );
}
