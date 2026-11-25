import { useEffect, useState } from "react";
import type { LucideIcon } from "lucide-react";
import { Clock, Play, Target as TargetIcon, X, Zap } from "lucide-react";
import {
  useCreateScanProfile,
  useUpdateScanProfile,
  useTriggerProfileScan,
  useWorkflowPresets,
  type TriggerPreset,
  type TargetPreset,
} from "../lib/queries";
import type { ScanProfile } from "../lib/api";
import { SCORE_THRESHOLDS } from "../lib/format";
import { ErrorNote } from "./ui";

// ── Types ─────────────────────────────────────────────────────────────────────

type FormState = {
  name: string;
  description: string;
  // WHEN
  triggerId: string;     // preset id or "custom"
  schedule: string;
  driftEnabled: boolean;
  // WHO
  targetId: string;      // preset id or "custom"
  targetQuery: string;
  // chip state
  providers: string[];   // "aws" | "gcp" | "azure"
  types: string[];       // "ec2" | "k8s" | "rds"
  minScore: number | null;
  signals: string[];     // "kev" | "exploitable"
  // DO
  scannerType: string;
  templateStrategy: string;
  templateTags: string[];
  tagInput: string;
  enabled: boolean;
};

// MAX_TARGETS mirrors scan.MaxTargets (internal/app/scan/service.go): the cap on
// how many assets a single scan run can cover.
//
// Every target query this file composes MUST end in `LIMIT MAX_TARGETS`. An
// unbounded query does not scan more — target resolution refuses a result that
// hit the graph node budget, because a truncated target LIST is unusable input
// to a scan's scope decision, so the profile fails every run instead. The server
// rejects an unbounded query at save time (scan.ValidateTargetQuery), which is
// the real enforcement; this constant is what keeps the builder from composing
// one in the first place and pushing the user into that error.
const MAX_TARGETS = 500;

// DEFAULT_QUERY must stay byte-identical to the API's `all_exposed` preset
// (internal/app/scan/presets.go). It doubles as a sentinel: onSubmit sends
// target_query: "" when the query still equals this, which selects the
// non-Cypher ListExternal path server-side. If the two drift apart, picking
// "all exposed" in the UI silently switches the profile onto the Cypher
// resolver instead — a different code path with a different failure mode.
const DEFAULT_QUERY = `MATCH (a:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
RETURN a
ORDER BY a.score DESC
LIMIT ${MAX_TARGETS}`;

export type WorkflowBuilderMode = "workflow" | "runOnce";

// The target_query sent to the API: the default query and a blank one both
// mean "no WHO filter" and are sent as "", so the server's drift selection
// (target_query = '') sees the same profile the form shows as unscoped.
export function submittedTargetQuery(query: string): string {
  return query.trim() === "" || query === DEFAULT_QUERY ? "" : query;
}

// A one-off run still has to be persisted as a profile: the worker re-loads the
// profile row by id when the River job executes, so deleting it right after
// triggering would fail the run with "load profile: not found". Instead the
// profile is created disabled (never scheduled again) and named so it is
// obvious in the Workflows list what it is.
export function oneOffName(now: Date = new Date()): string {
  return `One-off scan ${now.toISOString().slice(0, 16).replace("T", " ")}Z`;
}

function initialState(profile?: ScanProfile, mode: WorkflowBuilderMode = "workflow"): FormState {
  if (profile) {
    return {
      name: profile.name,
      description: profile.description ?? "",
      triggerId: inferTriggerId(profile.schedule ?? "", profile.drift_enabled ?? false),
      schedule: profile.schedule ?? "",
      driftEnabled: profile.drift_enabled ?? false,
      targetId: "custom",
      targetQuery: profile.target_query || DEFAULT_QUERY,
      providers: [],
      types: [],
      minScore: null,
      signals: [],
      scannerType: profile.scanner_type || "nuclei",
      templateStrategy: profile.template_strategy || "all",
      templateTags: profile.template_tags ?? [],
      tagInput: "",
      enabled: profile.enabled,
    };
  }
  return {
    name: mode === "runOnce" ? oneOffName() : "",
    description: "",
    triggerId: mode === "runOnce" ? "run_once" : "manual",
    schedule: "",
    driftEnabled: false,
    targetId: "all_exposed",
    targetQuery: DEFAULT_QUERY,
    providers: [],
    types: [],
    minScore: null,
    signals: [],
    scannerType: "nuclei",
    templateStrategy: "all",
    templateTags: [],
    tagInput: "",
    // A one-off run must not stay live as a schedulable profile.
    enabled: mode !== "runOnce",
  };
}

function inferTriggerId(schedule: string, drift: boolean): string {
  if (!schedule && !drift) return "manual";
  if (schedule === "0 2 * * 1" && drift) return "drift_weekly";
  if (schedule === "0 2 * * *" && !drift) return "daily";
  if (schedule === "0 2 * * 1" && !drift) return "weekly";
  if (schedule === "0 2 1 * *" && !drift) return "monthly";
  if (!schedule && drift) return "drift";
  return "custom";
}

// ── Cypher composer: chips → query ────────────────────────────────────────────

function buildCypher(
  providers: string[],
  types: string[],
  minScore: number | null,
  signals: string[]
): string {
  const filters: string[] = [];
  if (providers.length === 1) filters.push(`a.provider = '${providers[0]}'`);
  else if (providers.length > 1) filters.push(`a.provider IN [${providers.map((p) => `'${p}'`).join(", ")}]`);
  if (types.length === 1) filters.push(`a.type = '${TYPE_VALUES[types[0]]}'`);
  else if (types.length > 1) filters.push(`a.type IN [${types.map((t) => `'${TYPE_VALUES[t]}'`).join(", ")}]`);
  if (minScore !== null) filters.push(`a.score >= ${minScore}`);
  if (signals.includes("kev")) filters.push("a.has_kev = 1");
  if (signals.includes("exploitable")) filters.push("a.exploitable = 1");
  const where = filters.length > 0 ? `\nWHERE ${filters.join("\n  AND ")}` : "";
  return `MATCH (a:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})${where}\nRETURN a\nORDER BY a.score DESC\nLIMIT ${MAX_TARGETS}`;
}

const TYPE_VALUES: Record<string, string> = {
  ec2: "ec2_instance",
  k8s: "k8s_service",
  rds: "rds_instance",
  lambda: "lambda_function",
  lb: "load_balancer",
};

// ── WorkflowBuilder ───────────────────────────────────────────────────────────

export function WorkflowBuilder({
  profile,
  onClose,
  onSaved,
  mode = "workflow",
}: {
  profile?: ScanProfile;
  onClose: () => void;
  onSaved?: (p: ScanProfile) => void;
  /**
   * "workflow" (default) creates/edits a saved scan workflow.
   * "runOnce" creates a disabled profile and triggers it immediately — the
   * single-shot "Create scan" path on the Scans page.
   */
  mode?: WorkflowBuilderMode;
}) {
  const isRunOnce = mode === "runOnce";
  const [form, setForm] = useState<FormState>(() => initialState(profile, mode));
  const { data: presets } = useWorkflowPresets();
  const create = useCreateScanProfile();
  const update = useUpdateScanProfile();
  const trigger = useTriggerProfileScan();
  const isEdit = !!profile;
  const isPending = create.isPending || update.isPending || trigger.isPending;
  const error = create.error || update.error || trigger.error;

  // The server starts drift scans only for profiles with no target query
  // (scan.listDriftProfilesQ); a scoped profile is never drift-triggered.
  const isScoped = submittedTargetQuery(form.targetQuery) !== "";

  const set = <K extends keyof FormState>(key: K, value: FormState[K]) =>
    setForm((f) => ({ ...f, [key]: value }));

  // ── WHEN selection ──────────────────────────────────────────────────────────

  function pickTrigger(preset: TriggerPreset) {
    setForm((f) => ({
      ...f,
      triggerId: preset.id,
      schedule: preset.schedule,
      driftEnabled: preset.drift_enabled,
    }));
  }

  // ── WHO: chips → Cypher (only when not using a preset directly) ─────────────

  function toggleProvider(p: string) {
    setForm((f) => {
      const next = f.providers.includes(p)
        ? f.providers.filter((x) => x !== p)
        : [...f.providers, p];
      return {
        ...f,
        providers: next,
        targetId: "custom",
        targetQuery: buildCypher(next, f.types, f.minScore, f.signals),
      };
    });
  }

  function toggleType(t: string) {
    setForm((f) => {
      const next = f.types.includes(t) ? f.types.filter((x) => x !== t) : [...f.types, t];
      return {
        ...f,
        types: next,
        targetId: "custom",
        targetQuery: buildCypher(f.providers, next, f.minScore, f.signals),
      };
    });
  }

  function setMinScore(score: number | null) {
    setForm((f) => ({
      ...f,
      minScore: score,
      targetId: "custom",
      targetQuery: buildCypher(f.providers, f.types, score, f.signals),
    }));
  }

  function toggleSignal(s: string) {
    setForm((f) => {
      const next = f.signals.includes(s) ? f.signals.filter((x) => x !== s) : [...f.signals, s];
      return {
        ...f,
        signals: next,
        targetId: "custom",
        targetQuery: buildCypher(f.providers, f.types, f.minScore, next),
      };
    });
  }

  function pickTargetPreset(p: TargetPreset) {
    setForm((f) => ({
      ...f,
      targetId: p.id,
      targetQuery: p.query || DEFAULT_QUERY,
      // clear chips — user picked a preset, chips are decorative now
      providers: [],
      types: [],
      minScore: null,
      signals: [],
    }));
  }

  // ── DO: template tags ───────────────────────────────────────────────────────

  function addTag() {
    const t = form.tagInput.trim().toLowerCase();
    if (t && !form.templateTags.includes(t)) {
      setForm((f) => ({ ...f, templateTags: [...f.templateTags, t], tagInput: "" }));
    }
  }

  function removeTag(t: string) {
    set("templateTags", form.templateTags.filter((x) => x !== t));
  }

  // ── Submit ──────────────────────────────────────────────────────────────────

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const payload = {
      name: form.name.trim(),
      description: form.description.trim(),
      scanner_type: form.scannerType,
      template_strategy: form.templateStrategy as "all" | "tags" | "ai_contextual",
      template_tags: form.templateTags,
      schedule: form.schedule,
      drift_enabled: form.driftEnabled,
      target_query: submittedTargetQuery(form.targetQuery),
      enabled: form.enabled,
    };
    if (isRunOnce) {
      // Create disabled (no schedule, no drift) then fire it straight away.
      create.mutate(
        { ...payload, schedule: "", drift_enabled: false, enabled: false },
        {
          onSuccess: (p) =>
            trigger.mutate(p.id, {
              onSuccess: () => { onSaved?.(p); onClose(); },
            }),
        },
      );
      return;
    }
    if (isEdit && profile) {
      update.mutate({ id: profile.id, ...payload }, { onSuccess: (p) => { onSaved?.(p); onClose(); } });
    } else {
      create.mutate(payload, { onSuccess: (p) => { onSaved?.(p); onClose(); } });
    }
  }

  // ── Keyboard close ──────────────────────────────────────────────────────────
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  const triggers = presets?.triggers ?? DEFAULT_TRIGGERS;
  const targets = presets?.targets ?? DEFAULT_TARGETS;

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-bg/80 px-4 py-10 backdrop-blur-sm">
      <div className="w-full max-w-2xl rounded-xl border border-border-subtle bg-bg shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-border-subtle px-6 py-4">
          <div>
            <h2 className="font-display text-base text-text">
              {isRunOnce ? "Run a scan" : isEdit ? "Edit workflow" : "New workflow"}
            </h2>
            <p className="mt-0.5 text-[11px] text-text-3">
              {isRunOnce
                ? "Pick who to scan and what to run — this starts immediately and is not scheduled."
                : "Define when to scan, who to scan, and what to run."}
            </p>
          </div>
          <button
            onClick={onClose}
            className="flex h-7 w-7 items-center justify-center rounded text-text-3 hover:text-text"
            aria-label="Close"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="divide-y divide-border-subtle">
          {/* Name */}
          <div className="px-6 py-5">
            <input
              value={form.name}
              onChange={(e) => set("name", e.target.value)}
              placeholder={isRunOnce ? "Scan name…" : "Workflow name…"}
              required
              className="w-full rounded border border-border-subtle bg-surface px-3 py-2 font-display text-sm text-text outline-none placeholder:text-text-3 focus:border-teal"
            />
            <input
              value={form.description}
              onChange={(e) => set("description", e.target.value)}
              placeholder="Description (optional)"
              className="mt-2 w-full rounded border border-border-subtle bg-surface px-3 py-2 text-xs text-text-2 outline-none placeholder:text-text-3 focus:border-teal"
            />
          </div>

          {/* WHEN */}
          <section className="px-6 py-5">
            <SectionLabel icon={Clock} label="WHEN" sub="Trigger" />
            {isRunOnce ? (
              <div className="mt-3">
                <span className="inline-flex items-center gap-1.5 rounded border border-teal/50 bg-teal/15 px-3 py-1.5 text-[11px] text-teal">
                  <Play className="h-3 w-3" />
                  Run once
                </span>
                <p className="mt-2 text-[11px] text-text-3">
                  Starts as soon as you submit. Kept in Workflows as a disabled
                  one-off so the run stays traceable, but never scheduled again.
                </p>
              </div>
            ) : (
              <div className="mt-3 flex flex-wrap gap-2">
                {triggers.map((t) => (
                  <TriggerChip
                    key={t.id}
                    preset={t}
                    active={form.triggerId === t.id}
                    onClick={() => pickTrigger(t)}
                  />
                ))}
              </div>
            )}
            {!isRunOnce && form.triggerId === "custom" && (
              <div className="mt-3 flex items-center gap-3">
                <input
                  value={form.schedule}
                  onChange={(e) => set("schedule", e.target.value)}
                  placeholder="Cron expression, e.g. 0 2 * * 1"
                  className="flex-1 rounded border border-border-subtle bg-surface px-3 py-1.5 font-mono text-[11px] text-text-2 outline-none focus:border-teal"
                />
                <label className="flex cursor-pointer items-center gap-1.5 text-[11px] text-text-3">
                  <input
                    type="checkbox"
                    checked={form.driftEnabled}
                    onChange={(e) => set("driftEnabled", e.target.checked)}
                    className="rounded"
                  />
                  On drift
                </label>
              </div>
            )}
            {form.driftEnabled && !isScoped && (
              <p className="mt-2 flex items-center gap-1.5 text-[11px] text-teal">
                <Zap className="h-3 w-3 shrink-0" />
                Scan runs automatically when a connector sync reports a change to an internet-exposed asset.
              </p>
            )}
            {form.driftEnabled && isScoped && (
              <p role="alert" className="mt-2 flex items-center gap-1.5 text-[11px] text-amber">
                <Zap className="h-3 w-3 shrink-0" />
                Drift triggers only profiles that target all internet-exposed assets. This profile has a WHO filter, so asset changes will not start it.
              </p>
            )}
          </section>

          {/* WHO */}
          <section className="px-6 py-5">
            <SectionLabel icon={TargetIcon} label="WHO" sub="Targets" />

            {/* Preset picker */}
            <div className="mt-3 flex items-center gap-2">
              <span className="text-[11px] uppercase tracking-wide text-text-3">Preset</span>
              <select
                value={form.targetId}
                onChange={(e) => {
                  const p = targets.find((t) => t.id === e.target.value);
                  if (p) pickTargetPreset(p);
                }}
                className="rounded border border-border-subtle bg-surface px-2 py-1 text-[11px] text-text-2 outline-none focus:border-teal"
              >
                {targets.map((t) => (
                  <option key={t.id} value={t.id}>{t.label}</option>
                ))}
              </select>
            </div>

            {/* Chips */}
            <div className="mt-3 space-y-2">
              <ChipRow label="Provider">
                {["aws", "gcp", "azure"].map((p) => (
                  <Chip key={p} active={form.providers.includes(p)} onClick={() => toggleProvider(p)}>
                    {p.toUpperCase()}
                  </Chip>
                ))}
              </ChipRow>
              <ChipRow label="Type">
                {Object.keys(TYPE_VALUES).map((t) => (
                  <Chip key={t} active={form.types.includes(t)} onClick={() => toggleType(t)}>
                    {TYPE_LABELS[t]}
                  </Chip>
                ))}
              </ChipRow>
              <ChipRow label="Risk">
                {[SCORE_THRESHOLDS.pipeline, SCORE_THRESHOLDS.high, SCORE_THRESHOLDS.page].map((s) => (
                  <Chip key={s} active={form.minScore === s} onClick={() => setMinScore(form.minScore === s ? null : s)}>
                    ≥{s}
                  </Chip>
                ))}
              </ChipRow>
              <ChipRow label="Signal">
                <Chip active={form.signals.includes("kev")} onClick={() => toggleSignal("kev")}>KEV</Chip>
                <Chip active={form.signals.includes("exploitable")} onClick={() => toggleSignal("exploitable")}>Exploitable</Chip>
              </ChipRow>
            </div>

            {/* Live Cypher preview */}
            <div className="mt-3">
              <div className="mb-1 flex items-center justify-between">
                <span className="text-[11px] uppercase tracking-wide text-text-3">Cypher query</span>
                <span className="text-[11px] text-text-3">Edit directly to customise</span>
              </div>
              <textarea
                value={form.targetQuery}
                onChange={(e) => {
                  set("targetQuery", e.target.value);
                  set("targetId", "custom");
                }}
                rows={5}
                spellCheck={false}
                className="w-full resize-none rounded border border-border-subtle bg-surface-2 px-3 py-2.5 font-mono text-[11px] leading-relaxed text-text-2 outline-none focus:border-teal"
              />
            </div>
          </section>

          {/* DO */}
          <section className="px-6 py-5">
            <SectionLabel icon={Zap} label="DO" sub="Action" />
            <div className="mt-3 space-y-3">
              {/* Scanner — nuclei only for now */}
              <div className="flex items-center gap-3">
                <span className="text-[11px] uppercase tracking-wide text-text-3">Scanner</span>
                <span className="rounded border border-teal/30 bg-teal/10 px-2 py-0.5 font-mono text-[11px] text-teal">
                  nuclei
                </span>
              </div>

              {/* Template strategy */}
              <div className="flex flex-wrap items-center gap-4">
                <span className="text-[11px] uppercase tracking-wide text-text-3">Templates</span>
                {(["all", "tags"] as const).map((s) => (
                  <label key={s} className="flex cursor-pointer items-center gap-1.5 text-[11px] text-text-3 hover:text-text-2">
                    <input
                      type="radio"
                      name="templateStrategy"
                      value={s}
                      checked={form.templateStrategy === s}
                      onChange={() => set("templateStrategy", s)}
                      className="accent-teal"
                    />
                    {s === "all" ? "Default (by asset type)" : "By tags"}
                  </label>
                ))}
              </div>

              {/* Tag editor */}
              {form.templateStrategy === "tags" && (
                <div className="flex flex-wrap gap-1.5">
                  {form.templateTags.map((t) => (
                    <span key={t} className="flex items-center gap-1 rounded border border-border-subtle bg-surface-2 px-2 py-0.5 text-[11px] text-text-2">
                      {t}
                      <button
                        type="button"
                        onClick={() => removeTag(t)}
                        aria-label={`Remove ${t}`}
                        className="text-text-3 hover:text-text"
                      >
                        <X className="h-2.5 w-2.5" />
                      </button>
                    </span>
                  ))}
                  <input
                    value={form.tagInput}
                    onChange={(e) => set("tagInput", e.target.value)}
                    onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addTag(); } }}
                    placeholder="+ add tag"
                    className="rounded border border-dashed border-border-subtle bg-transparent px-2 py-0.5 text-[11px] text-text-3 outline-none focus:border-teal focus:text-text-2"
                  />
                </div>
              )}
            </div>
          </section>

          {/* Footer — the error box renders on its own row above the actions so a
              long message can never squash the buttons out of the flex row. */}
          <div className="px-6 py-4">
            {error && (
              <div className="mb-3">
                <ErrorNote message={(error as Error).message} />
              </div>
            )}
            <div className="flex items-center justify-between gap-4">
              {isRunOnce ? (
                <span className="text-[11px] text-text-3">Runs once, right now.</span>
              ) : (
                <label className="flex cursor-pointer items-center gap-2 text-[11px] text-text-3">
                  <input
                    type="checkbox"
                    checked={form.enabled}
                    onChange={(e) => set("enabled", e.target.checked)}
                    className="accent-teal"
                  />
                  Enabled
                </label>
              )}
              <div className="flex shrink-0 gap-2">
                <button
                  type="button"
                  onClick={onClose}
                  className="rounded border border-border-subtle px-3 py-1.5 text-[11px] text-text-3 transition-colors hover:text-text"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isPending || !form.name.trim()}
                  title={!form.name.trim() ? "Enter a name to continue" : undefined}
                  className="flex items-center gap-1.5 rounded border border-teal/40 bg-teal/10 px-4 py-1.5 text-[11px] text-teal transition-colors hover:bg-teal/20 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  {isRunOnce && !isPending && <Play className="h-3 w-3" />}
                  {isPending
                    ? isRunOnce
                      ? "Starting…"
                      : "Saving…"
                    : isRunOnce
                    ? "Run scan"
                    : isEdit
                    ? "Save changes"
                    : "Create workflow"}
                </button>
              </div>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function SectionLabel({ icon: Icon, label, sub }: { icon: LucideIcon; label: string; sub: string }) {
  return (
    <div className="flex items-center gap-2">
      <Icon className="h-3.5 w-3.5 shrink-0 text-teal" />
      <span className="font-display text-sm text-text">{label}</span>
      <span className="text-[11px] uppercase tracking-wide text-text-3">{sub}</span>
    </div>
  );
}

function TriggerChip({
  preset,
  active,
  onClick,
}: {
  preset: TriggerPreset;
  active: boolean;
  onClick: () => void;
}) {
  const hasDrift = preset.drift_enabled;
  const hasSched = !!preset.schedule;
  return (
    <button
      type="button"
      onClick={onClick}
      title={preset.description}
      className={`flex items-center gap-1.5 rounded border px-3 py-1.5 text-[11px] transition-colors ${
        active
          ? "border-teal/50 bg-teal/15 text-teal"
          : "border-border-subtle text-text-3 hover:border-teal/30 hover:text-text-2"
      }`}
    >
      {hasSched && <Clock className="h-3 w-3 shrink-0" aria-label="Scheduled" />}
      {hasDrift && <Zap className="h-3 w-3 shrink-0" aria-label="Drift" />}
      {preset.label}
    </button>
  );
}

function ChipRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="w-14 shrink-0 text-[11px] uppercase tracking-wide text-text-3">{label}</span>
      {children}
    </div>
  );
}

function Chip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`rounded border px-2.5 py-1 text-[11px] transition-colors ${
        active
          ? "border-teal/40 bg-teal/15 text-teal"
          : "border-border-subtle text-text-3 hover:border-teal/20 hover:text-text-2"
      }`}
    >
      {children}
    </button>
  );
}

const TYPE_LABELS: Record<string, string> = {
  ec2: "EC2",
  k8s: "K8s",
  rds: "RDS",
  lambda: "Lambda",
  lb: "Load balancer",
};

// Fallback presets if API hasn't loaded yet
const DEFAULT_TRIGGERS: TriggerPreset[] = [
  { id: "manual", label: "Manual", description: "Run explicitly only.", schedule: "", drift_enabled: false },
  { id: "weekly", label: "Weekly", description: "Every Monday at 02:00 UTC.", schedule: "0 2 * * 1", drift_enabled: false },
  { id: "daily", label: "Daily", description: "Every day at 02:00 UTC.", schedule: "0 2 * * *", drift_enabled: false },
  { id: "drift", label: "On drift", description: "When an asset changes.", schedule: "", drift_enabled: true },
  { id: "drift_weekly", label: "Drift + Weekly", description: "On change and weekly.", schedule: "0 2 * * 1", drift_enabled: true },
  { id: "custom", label: "Custom…", description: "Custom cron.", schedule: "", drift_enabled: false },
];

// exposedQuery composes a fallback preset's Cypher with the same trailing
// LIMIT every other target query carries. These fallbacks are used while
// /api/workflows/presets is loading or unavailable — an unbounded one here
// would fill the form with a query the server then rejects at save time
// (scan.ValidateTargetQuery), turning a transient API blip into a confusing
// validation error on a preset the user never edited.
function exposedQuery(where?: string): string {
  const filter = where ? `\nWHERE ${where}` : "";
  return `MATCH (a:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})${filter}\nRETURN a\nORDER BY a.score DESC\nLIMIT ${MAX_TARGETS}`;
}

const DEFAULT_TARGETS: TargetPreset[] = [
  { id: "all_exposed", label: "Top internet-exposed assets by risk", description: `The ${MAX_TARGETS} highest-risk assets reachable from the internet.`, query: DEFAULT_QUERY },
  { id: "high_risk", label: `High risk (score \u2265 ${SCORE_THRESHOLDS.high})`, description: "", query: exposedQuery(`a.score >= ${SCORE_THRESHOLDS.high}`) },
  { id: "kev_exposed", label: "Exposed + KEV packages", description: "", query: exposedQuery("a.has_kev = 1") },
  { id: "aws_exposed", label: "AWS exposed", description: "", query: exposedQuery("a.provider = 'aws'") },
  { id: "gcp_exposed", label: "GCP exposed", description: "", query: exposedQuery("a.provider = 'gcp'") },
];
