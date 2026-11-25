import { Siren, ArrowUpRight, ShieldCheck, Lock, HelpCircle } from "lucide-react";

// Evidence-backed urgency tier (internal/app/enrich/mustfix.go) — computed
// at enrich time from real reachability + exploitability + blast radius +
// compensating controls (or, for a leaked secret, from whether it is a test-mode
// key, GitHub's validity check, and who can read the repo), NOT from the score. It answers a different question to the
// score band: "which of these do I fix RIGHT NOW".
export type MustFixClass = "must_fix" | "elevated" | "contained" | "controlled" | "routine";

// EnrichmentState mirrors finding.EnrichmentState. It is what makes an empty
// must_fix_class readable: blank + enriched is a real verdict, blank +
// never_enriched is silence. Without it the UI cannot tell them apart.
export type EnrichmentState = "never_enriched" | "stale" | "enriched";

const MUST_FIX_META: Record<MustFixClass, { label: string; cls: string; icon: typeof Siren; title: string }> = {
  must_fix: {
    label: "Must fix",
    cls: "border-red/40 bg-red/15 text-red",
    icon: Siren,
    title:
      "Either internet-reachable, exploitable (known-exploited, active threat or privilege escalation), with a blast radius of 5+ assets, on a resource that still exists, and not gated by a compensating control (one never demotes a known-exploited or active-threat finding) — all confirmed from the graph — or a non-test-mode credential leaked in a public repository that GitHub's validity check reports active or has not checked",
  },
  elevated: {
    label: "Elevated",
    cls: "border-amber/30 bg-amber/10 text-amber",
    icon: ArrowUpRight,
    title:
      "High signal, not the full must-fix picture: exploitable and either internet-reachable or with a blast radius of 5+ assets; known-exploited or an active threat but short of must-fix; a confirmed malicious package, a known-exploited package, or vulnerable code or packages deployed to an internet-exposed workload; a non-test-mode credential (validity active or unknown) leaked in a private or internal repository; or a Kubernetes role granted to an identity outside the cluster or to 5+ subjects",
  },
  contained: {
    label: "Contained",
    cls: "border-border-subtle bg-surface-2 text-text-2",
    icon: ShieldCheck,
    title:
      "No internet-reachable attack path, so internal/lateral risk only (including a package or code deployed to no internet-exposed workload, and a Kubernetes role granted only to fewer than 5 in-cluster subjects); a Kubernetes role bound to no subject; or a leaked credential known not to work (a test-mode key, or one GitHub's validity check reports inactive). Never applied to a known-exploited or active-threat finding",
  },
  controlled: {
    label: "Controlled",
    cls: "border-border-subtle bg-surface-2 text-text-3",
    icon: Lock,
    title:
      "A privilege-escalation path gated by an observed compensating control: a role whose assumption requires MFA or enters through a non-admin SSO permission set, or an inactive or MFA-gated user with no access key. Never applied to a known-exploited or active-threat finding",
  },
  // The majority verdict, served as an explicit class so the badge renders it from a
  // stated value instead of inferring it from an absence.
  routine: {
    label: "Not urgent",
    cls: "border-border-subtle bg-surface text-text-3",
    icon: HelpCircle,
    title:
      "Assessed for urgency, with no positive exploitability evidence found (no known-exploited CVE, no active threat and no privilege-escalation path); or a privilege-escalation path that is neither internet-reachable nor has a measured blast radius of 5+ assets; or a package that runs only on inventoried VMs, whose urgency is carried by its per-fleet VM finding. The score still carries this finding's risk.",
  },
};

function isMustFixClass(v?: string): v is MustFixClass {
  return (
    v === "must_fix" || v === "elevated" || v === "contained" || v === "controlled" || v === "routine"
  );
}

// MustFixBadge renders the urgency tier. "Weighed, no urgency evidence" is its own
// class (routine) rather than an empty string, so this reads a stated verdict instead of
// inferring one from an absence.
//
// An enriched finding with an empty or unknown class has no verdict: the classifier
// failed open on missing evidence. It renders "Urgency ?", never "Not urgent", so
// unknown is not shown as clean.
//
// While the finding is unenriched there is genuinely no verdict yet, and callers
// should show their pending state instead — pass state and this renders nothing.
export function MustFixBadge({
  cls,
  state,
  className = "",
}: {
  cls?: string;
  state?: string;
  className?: string;
}) {
  if (state === "never_enriched") return null;

  if (!isMustFixClass(cls)) {
    return (
      <span
        className={`inline-flex items-center gap-1 rounded border border-border-subtle bg-surface px-1.5 py-0.5 text-[11px] font-medium uppercase text-text-3 ${className}`}
        title="Urgency unknown: the classifier lacked the evidence to decide (for example unknown repository visibility, a truncated supply-chain walk, or no RBAC subject evidence). Not a verdict; the score still carries this finding's risk."
      >
        <HelpCircle className="h-3 w-3" /> Urgency ?
      </span>
    );
  }

  const m = MUST_FIX_META[cls];
  const Icon = m.icon;
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase ${m.cls} ${className}`}
      title={m.title}
    >
      <Icon className="h-3 w-3" /> {m.label}
    </span>
  );
}

// MUST_FIX_ORDER lists the tiers most- to least-urgent — the legend below
// reads top to bottom in the same order a triager should work the queue.
const MUST_FIX_ORDER: MustFixClass[] = ["must_fix", "elevated", "contained", "controlled", "routine"];

// MustFixLegend spells out what the urgency tiers mean, the same way
// queue.tsx's ActionClassLegend does for action classes — the badge label +
// hover title alone are easy to miss.
// Callers show/hide it behind a "what do these mean?" toggle, matching Decisions.
export function MustFixLegend() {
  return (
    <div className="grid gap-2 rounded-lg border border-border-subtle bg-surface-2 p-3 sm:grid-cols-2 lg:grid-cols-5">
      {MUST_FIX_ORDER.map((cls) => {
        const m = MUST_FIX_META[cls];
        const Icon = m.icon;
        return (
          <div key={cls} className="flex items-start gap-2">
            <span className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded border ${m.cls}`}>
              <Icon className="h-3.5 w-3.5" />
            </span>
            <div className="min-w-0">
              <div className="text-[11px] font-semibold text-text-2">{m.label}</div>
              <p className="text-[11px] leading-snug text-text-3">{m.title}</p>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// StalenessNote flags that a finding's enrichment outputs predate the current graph
// (and possibly the current scoring logic), so its verdicts above may be out of
// date. A meaningful fraction of open privesc findings can sit in this state after
// a classifier change or a graph rebuild, and nothing else in the UI shows
// enrichment age.
export function StalenessNote({ state, className = "" }: { state?: string; className?: string }) {
  if (state !== "stale") return null;
  return (
    <span
      className={`inline-flex items-center gap-1 text-[11px] text-amber ${className}`}
      title="Enrichment last ran more than 48h ago, so these verdicts may reflect an older graph or an older scoring version"
    >
      stale assessment
    </span>
  );
}
