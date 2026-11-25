import { GitBranch, Cloud, ShieldCheck, ShieldAlert, ShieldQuestion } from "lucide-react";

// Safety band = how likely applying the fix is to break something (respond/impact.go).
// The inverse of attack blast radius: "what depends on this that a fix could disrupt".
export type SafetyBand = "safe" | "caution" | "risky";

export type FixLocation = {
  kind?: string; // source_repo | cloud_console
  repo?: string;
  confidence?: string;
  account?: string;
  region?: string;
  hint?: string;
};

const SAFETY_META: Record<SafetyBand, { label: string; cls: string; icon: typeof ShieldCheck }> = {
  safe:    { label: "Safe to fix",  cls: "border-teal/30 bg-teal/10 text-teal",   icon: ShieldCheck },
  caution: { label: "Verify first", cls: "border-amber/30 bg-amber/10 text-amber", icon: ShieldQuestion },
  risky:   { label: "Risky",        cls: "border-red/30 bg-red/10 text-red",       icon: ShieldAlert },
};

function isBand(v?: string): v is SafetyBand {
  return v === "safe" || v === "caution" || v === "risky";
}

// SafetyBadge renders the safe-to-fix band as a colored pill. Renders nothing for
// an unknown/empty band so callers can drop it in unconditionally.
export function SafetyBadge({ band, className = "" }: { band?: string; className?: string }) {
  if (!isBand(band)) return null;
  const m = SAFETY_META[band];
  const Icon = m.icon;
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase ${m.cls} ${className}`}
      title="How risky applying the fix is — based on what depends on this resource and whether it looks used"
    >
      <Icon className="h-3 w-3" /> {m.label}
    </span>
  );
}

// FixLocationLine renders "where to apply the fix" — the deploying repo (change +
// redeploy) or the cloud console when there is no IaC owner. Renders nothing when
// there is no location to point at.
export function FixLocationLine({ fix, className = "" }: { fix?: FixLocation | null; className?: string }) {
  if (!fix || !fix.kind) return null;
  if (fix.kind === "source_repo" && fix.repo) {
    return (
      <span className={`inline-flex items-center gap-1 text-[11px] text-text-3 ${className}`} title={fix.hint}>
        <GitBranch className="h-3 w-3 text-teal" />
        Fix in <span className="font-mono text-text-2">{fix.repo}</span> → redeploy
        {fix.confidence === "medium" && <span className="text-amber">(verify repo)</span>}
      </span>
    );
  }
  if (fix.kind === "cloud_console") {
    const where = [fix.account, fix.region].filter(Boolean).join(" · ");
    return (
      <span className={`inline-flex items-center gap-1 text-[11px] text-text-3 ${className}`} title={fix.hint}>
        <Cloud className="h-3 w-3 text-text-3" />
        Apply in console{where ? <span className="font-mono text-text-2">{where}</span> : null}
        <span className="text-text-3">— no IaC owner</span>
      </span>
    );
  }
  return null;
}
