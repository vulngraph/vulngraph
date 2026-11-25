import { useEffect, useRef, useState } from "react";
import { ShieldCheck } from "lucide-react";
import type { ActionMode, UpdatePolicyPayload } from "../lib/api";
import { useRemediationPolicy, useUpdatePolicy, useIsAdmin } from "../lib/queries";
import { ErrorNote, Loading } from "../components/ui";
import { FormActions } from "../components/form";
import { timeAgo } from "../lib/format";

// State-changing action classes the agent may propose
// (internal/app/respond/domain.go ActionClass). Keep this list exactly in sync
// — a class the backend can never emit makes its mode switch a silent no-op.
// Observe is read-only and listed separately: it needs no approval and has
// nothing to configure.
const ACTION_CLASSES: { id: string; label: string; description: string }[] = [
  { id: "remediate", label: "Remediate", description: "Apply a fix (e.g. tighten IAM)" },
  { id: "modify",    label: "Modify",    description: "Edit config or policy" },
  { id: "isolate",   label: "Isolate",   description: "Network-quarantine an asset" },
  { id: "destroy",   label: "Destroy",   description: "Delete a resource permanently" },
];

const MODES: ActionMode[] = ["jit", "disabled"];

const MODE_LABELS: Record<ActionMode, string> = {
  jit:      "Requires approval",
  disabled: "Guidance only",
};

const MODE_STYLES: Record<ActionMode, string> = {
  jit:      "text-amber border-amber/30 bg-amber/10",
  disabled: "text-text-3 border-border-subtle bg-surface",
};

function sameRules(a: Record<string, ActionMode> | undefined, b: Record<string, ActionMode> | undefined) {
  const aa = a ?? {};
  const bb = b ?? {};
  const keys = new Set([...Object.keys(aa), ...Object.keys(bb)]);
  for (const k of keys) {
    if (aa[k] !== bb[k]) return false;
  }
  return true;
}

export function PolicySection() {
  const isAdmin = useIsAdmin();
  const { data: policy, isLoading, isError } = useRemediationPolicy();
  const update = useUpdatePolicy();

  const [localRules, setLocalRules] = useState<Record<string, ActionMode> | null>(null);
  const [localSuggest, setLocalSuggest] = useState<number | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  // Set after a successful save; cleared once the refetched policy matches
  // what was submitted, so the slider never visibly snaps back to a stale
  // value while the "Saved." message is showing.
  const pendingSaveRef = useRef<UpdatePolicyPayload | null>(null);
  const savedTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    return () => {
      if (savedTimeoutRef.current) clearTimeout(savedTimeoutRef.current);
    };
  }, []);

  useEffect(() => {
    const pending = pendingSaveRef.current;
    if (!pending || !policy) return;
    const matches =
      policy.suggest_threshold === pending.suggest_threshold &&
      sameRules(policy.action_rules, pending.action_rules);
    if (matches) {
      pendingSaveRef.current = null;
      setLocalRules(null);
      setLocalSuggest(null);
    }
  }, [policy]);

  const suggestThreshold = localSuggest ?? policy?.suggest_threshold ?? 60;
  const rules: Record<string, ActionMode> = localRules ?? policy?.action_rules ?? {};

  // No rule means the class is proposed and waits for approval — the same
  // human gate as an explicit "jit" rule.
  function getMode(actionClass: string): ActionMode {
    return rules[actionClass] ?? "jit";
  }

  function setMode(actionClass: string, mode: ActionMode) {
    setLocalRules({ ...rules, [actionClass]: mode });
    setSaved(false);
  }

  function handleRevert() {
    setLocalRules(null);
    setLocalSuggest(null);
    setSaveError(null);
    setSaved(false);
  }

  function handleSave() {
    if (!policy) return;
    const payload: UpdatePolicyPayload = {
      suggest_threshold: suggestThreshold,
      action_rules:      localRules ?? policy.action_rules ?? {},
    };
    setSaveError(null);
    update.mutate(payload, {
      onSuccess: () => {
        setSaved(true);
        pendingSaveRef.current = payload;
        if (savedTimeoutRef.current) clearTimeout(savedTimeoutRef.current);
        savedTimeoutRef.current = setTimeout(() => setSaved(false), 2500);
      },
      onError: (e) => setSaveError((e as Error).message),
    });
  }

  if (isLoading) return <Loading />;

  // A failed fetch must not fall through to the "?? 60" default and render a
  // slider indistinguishable from a real, live policy. Fail closed: show the
  // error, never a fabricated threshold (a zero value is not a measurement).
  if (isError || !policy) {
    return <ErrorNote message="Could not load the remediation policy — the service may be temporarily busy. Refresh to retry." />;
  }

  const dirty = localRules !== null || localSuggest !== null;

  return (
    <div className="space-y-4">
      <div className="glass flex items-start gap-3 rounded-xl p-4">
        <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0 text-teal" aria-hidden />
        <p className="text-[11px] leading-relaxed text-text-2">
          Vulngraph never runs a remediation on its own. Every proposed change waits for an explicit
          approval, and the executor still needs a second admin for destructive actions. This
          policy only changes the approval queue: whether a class is listed there, and whether
          a card is labelled waiting or escalated. It does not block a fix from being run.
        </p>
      </div>

      {/* Threshold slider */}
      <div className="glass rounded-xl p-5">
        <div className="mb-4 text-[11px] leading-relaxed text-text-2">
          Confidence comes from past approvals and denials of similar proposals. It decides how
          urgently a proposal is raised, never whether a person is asked.
        </div>
        <label className="block">
          <span className="mb-1 block text-[11px] uppercase tracking-wide text-text-3">
            Suggest threshold — {suggestThreshold}%
          </span>
          <input
            type="range" min={0} max={100} step={1}
            value={suggestThreshold}
            readOnly={!isAdmin}
            aria-disabled={!isAdmin}
            onChange={(e) => {
              if (!isAdmin) return;
              setLocalSuggest(Number(e.target.value));
              setSaved(false);
            }}
            className="w-full accent-teal aria-disabled:opacity-50"
          />
          <div className="mt-1 flex justify-between text-[11px] text-text-3">
            <span>Below this → escalated</span>
            <span>At or above → waits for approval</span>
          </div>
        </label>
      </div>

      {/* Per-action-class rules */}
      <div className="glass overflow-hidden rounded-xl">
        <div className="border-b border-border-subtle px-4 py-3">
          <div className="text-xs font-medium text-text">Per-action-class rules</div>
          <div className="mt-0.5 text-[11px] text-text-2">
            <span className="font-mono text-amber">Requires approval</span> offers the fix in the
            approval queue; it runs only after someone approves it.
            <span className="ml-1 font-mono text-text-3">Guidance only</span> leaves the class out of
            the approval queue unless the finding is urgent.
          </div>
        </div>
        <div className="divide-y divide-border-subtle/40">
          <div className="flex items-center gap-3 px-4 py-2.5">
            <div className="min-w-0 flex-1">
              <div className="text-[11px] font-medium text-text">Observe</div>
              <div className="text-[11px] text-text-3">Read-only data collection</div>
            </div>
            <span className="rounded border border-teal/30 bg-teal/10 px-2 py-0.5 text-[11px] text-teal">
              Read-only · no approval needed
            </span>
          </div>
          {ACTION_CLASSES.map(({ id, label, description }) => {
            const mode = getMode(id);
            return (
              <div key={id} className="flex items-center gap-3 px-4 py-2.5">
                <div className="min-w-0 flex-1">
                  <div className="text-[11px] font-medium text-text">{label}</div>
                  <div className="text-[11px] text-text-3">{description}</div>
                </div>
                {isAdmin ? (
                  <select
                    value={mode}
                    aria-label={`Mode for ${label}`}
                    onChange={(e) => setMode(id, e.target.value as ActionMode)}
                    className={[
                      "rounded border px-2 py-1 text-[11px] focus:outline-none focus:border-teal",
                      MODE_STYLES[mode],
                    ].join(" ")}
                  >
                    {MODES.map((m) => (
                      <option key={m} value={m}>{MODE_LABELS[m]}</option>
                    ))}
                  </select>
                ) : (
                  <span className={[
                    "rounded border px-2 py-0.5 text-[11px]",
                    MODE_STYLES[mode],
                  ].join(" ")}>
                    {MODE_LABELS[mode]}
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </div>

      {/* Save bar */}
      {isAdmin && (
        <div className="flex flex-wrap items-center gap-3">
          <FormActions
            submitLabel="Save policy"
            cancelLabel="Revert"
            onCancel={dirty ? handleRevert : undefined}
            isPending={update.isPending}
            disabled={!dirty}
            onSubmit={handleSave}
            type="button"
          />
          <div role="status" aria-live="polite">
            {saved && <span className="text-[11px] text-teal">Saved.</span>}
            {saveError && <span className="text-[11px] text-red">{saveError}</span>}
          </div>
          {!dirty && !saved && (
            <span className="text-[11px] text-text-3">
              {policy?.updated_by
                ? `Last saved by ${policy.updated_by}${policy.updated_at ? ` · ${timeAgo(policy.updated_at)}` : ""}`
                : "No changes"}
            </span>
          )}
        </div>
      )}
      {!isAdmin && (
        <p className="text-[11px] text-text-3">Read-only — admin access required to change the remediation policy.</p>
      )}
    </div>
  );
}
