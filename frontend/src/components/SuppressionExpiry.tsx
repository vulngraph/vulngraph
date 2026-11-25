import { expiryBounds, expiryStatus } from "../lib/expiry";

// ExpiryPicker is the "suppress until" date input shared by every suppress and
// renew control. Bounded to tomorrow…a year out, matching the server's limits;
// callers seed it with expiryBounds().initial (90 days).
export function ExpiryPicker({ value, onChange, label = "until" }: {
  value: string;
  onChange: (date: string) => void;
  label?: string;
}) {
  const { min, max } = expiryBounds();
  return (
    <label className="flex items-center gap-1 text-[11px] text-text-3">
      {label}
      <input
        type="date"
        aria-label="suppression expiry"
        required
        value={value}
        min={min}
        max={max}
        onChange={(e) => onChange(e.target.value)}
        onClick={(e) => e.stopPropagation()}
        className="rounded border border-border-subtle bg-surface px-1.5 py-1 text-[11px] text-text focus:border-amber/40 focus:outline-none"
      />
    </label>
  );
}

// ExceptionExpiredBadge marks a finding whose suppression lapsed: it is back in
// the pipeline, and someone once decided it was acceptable.
export function ExceptionExpiredBadge() {
  return (
    <span
      title="This finding was suppressed and the suppression expired — review it again or renew the exception"
      className="rounded border border-amber/30 bg-amber/10 px-1 py-0.5 text-[11px] font-medium uppercase text-amber"
    >
      exception expired
    </span>
  );
}

const EXPIRY_TONE = {
  expired: "text-red",
  soon: "text-amber",
  ok: "text-text-3",
} as const;

// ExpiryLabel renders "expires in 12d" / "expired 3d ago", coloured by urgency.
export function ExpiryLabel({ expiresAt }: { expiresAt: string }) {
  const { state, label } = expiryStatus(expiresAt);
  return (
    <span className={EXPIRY_TONE[state]} title={new Date(expiresAt).toLocaleString()}>
      {label}
    </span>
  );
}
