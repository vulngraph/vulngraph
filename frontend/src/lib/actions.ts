// Shared presentation helpers for agent actions — used by the queue cards in
// components/queue.tsx (which re-exports these) and the audit-trail cards in
// routes/Decisions.tsx.
//
// action_class has exactly 5 real values — respond.ActionClass in
// internal/app/respond/domain.go — ordered least- to most-invasive.
// This is the single place that orders/labels/describes/tones them; everything
// downstream (legend, badges, icons) derives from ACTION_CLASSES so a 6th value
// never needs updating in five different files.
export type KnownActionClass = "observe" | "remediate" | "modify" | "isolate" | "destroy";

export const ACTION_CLASSES: {
  value: KnownActionClass;
  label: string;
  tone: ActionTone;
  description: string;
}[] = [
  {
    value: "observe",
    label: "Observe",
    tone: "muted",
    description: "No action needed. The agent watched and recorded why — nothing changes, nothing is gated.",
  },
  {
    value: "remediate",
    label: "Remediate",
    tone: "teal",
    description: "A standard fix that resolves the finding without cutting off access or availability.",
  },
  {
    value: "modify",
    label: "Modify",
    tone: "amber",
    description: "Changes a configuration or permission (e.g. tighten a policy) — reversible, but alters behavior.",
  },
  {
    value: "isolate",
    label: "Isolate",
    tone: "red",
    description: "Cuts off access to the resource (quarantine, revoke) to stop an active risk. Destructive-tier.",
  },
  {
    value: "destroy",
    label: "Destroy",
    tone: "red",
    description: "Deletes or terminates the resource outright — the most invasive action, used only as a last resort.",
  },
];

const ACTION_CLASS_BY_VALUE = new Map(ACTION_CLASSES.map((a) => [a.value, a]));

// Human-readable labels for the action_class enum. Kept as a flat map for
// ACTION_LABELS[x]-style callers; ACTION_CLASSES above is the source of truth.
export const ACTION_LABELS: Record<string, string> = Object.fromEntries(
  ACTION_CLASSES.map((a) => [a.value, a.label]),
);

export function labelAction(action_class?: string, fallback?: string): string {
  if (action_class) return ACTION_CLASS_BY_VALUE.get(action_class as KnownActionClass)?.label ?? action_class;
  if (fallback) return fallback;
  return "Unknown action";
}

export function describeAction(action_class?: string): string | undefined {
  return action_class ? ACTION_CLASS_BY_VALUE.get(action_class as KnownActionClass)?.description : undefined;
}

// Action class accent colours — teal for a constructive fix, amber for a
// reversible config/permission change, red for destructive (isolate/destroy),
// muted for observe (no action taken).
export type ActionTone = "teal" | "amber" | "red" | "muted";

export function actionTone(action_class?: string): ActionTone {
  if (!action_class) return "muted";
  return ACTION_CLASS_BY_VALUE.get(action_class as KnownActionClass)?.tone ?? "muted";
}

export const TONE_CLASSES: Record<ActionTone, { border: string; bg: string; text: string; accent: string }> = {
  teal:  { border: "border-teal/25",  bg: "bg-teal/5",   text: "text-teal",   accent: "bg-teal/15 text-teal border-teal/30" },
  amber: { border: "border-amber/25", bg: "bg-amber/5",  text: "text-amber",  accent: "bg-amber/15 text-amber border-amber/30" },
  red:   { border: "border-red/25",   bg: "bg-red/5",    text: "text-red",    accent: "bg-red/15 text-red border-red/30" },
  muted: { border: "border-border-subtle", bg: "bg-surface-2", text: "text-text-2", accent: "bg-surface-3 text-text-2 border-border-subtle" },
};

export const BORDER_COLORS: Record<ActionTone, string> = {
  teal: "#0d9488",
  amber: "#f59e0b",
  red: "#ef4444",
  muted: "rgba(255,255,255,0.07)",
};

// respond.Decision.outcome values. One place for label + tone + tooltip so
// Decisions.tsx's OutcomeBadge, DecisionDetailPanel.tsx, ReasoningTrace.tsx,
// and queue.tsx all explain the same word the same way. Vulngraph never runs a
// remediation on its own (ADR 087): every state-changing outcome waits for a
// person.
export const OUTCOME_META: Record<string, { label: string; tone: string; title: string }> = {
  observed: {
    label: "Observed",
    tone: "text-teal border-teal/30 bg-teal/10",
    title: "Read-only — nothing to change, so nothing to approve",
  },
  parked_for_approval: {
    label: "Needs approval",
    tone: "text-amber border-amber/30 bg-amber/10",
    title: "Waiting for your approval — nothing runs until someone says yes",
  },
  escalated: {
    label: "Escalated",
    tone: "text-red border-red/30 bg-red/10",
    title: "Sent to you for manual review — low confidence or a verification concern",
  },
  // The agent stopped re-asking because a human already ruled on
  // this pattern. Never reaches the queue (suppressed decisions are excluded
  // from ListPendingReasoning), so this is only for the decisions trail/detail.
  suppressed_by_verdict: {
    label: "Already ruled",
    tone: "text-text-3 border-border-subtle bg-surface-2",
    title: "A human already ruled on this pattern — the agent stopped re-asking",
  },
};

// Explains the decaying-memory confidence-band word — matches
// confidenceLabel() in DecisionDetailPanel.tsx, which adds the sample count
// on top of this same wording.
export const CONFIDENCE_BAND_TITLE: Record<string, string> = {
  high: "People have consistently approved this kind of fix here — it still needs your approval",
  medium: "Some evidence, not yet strong enough to fully trust",
  low: "Thin evidence — few or inconsistent past verdicts",
  insufficient: "Not enough past verdicts yet to have a confidence read",
};
