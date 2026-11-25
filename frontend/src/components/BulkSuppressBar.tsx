import { useState } from "react";
import { expiryBounds, expiryToISO } from "../lib/expiry";
import { ExpiryPicker } from "./SuppressionExpiry";

// BulkSuppressBar is the sticky selection toolbar shown once rows are selected:
// the count, a required-reason input, the suppress button, and clear. It is
// shared by the must-fix worklist, the start-here worklist and the flat
// instance list, so the required-reason rule lives in one place and the accent
// colour is a prop.
export type BulkAccent = "red" | "teal" | "amber";

// Tailwind needs literal class strings, so each accent is a full lookup rather
// than an interpolated `border-${accent}/30`.
const ACCENT: Record<BulkAccent, { wrap: string; input: string; button: string }> = {
  red:   { wrap: "border-red/30 bg-surface-2",  input: "focus:border-amber/40", button: "border-border-subtle text-text-2 hover:text-text" },
  teal:  { wrap: "border-teal/30 bg-surface-2", input: "focus:border-teal/40",  button: "border-teal/40 bg-teal/10 text-teal hover:bg-teal/20" },
  amber: { wrap: "border-amber/30 bg-amber/5",  input: "focus:border-amber/40", button: "border-amber/30 bg-amber/10 text-amber hover:bg-amber/20" },
};

export interface BulkSuppressBarProps {
  accent: BulkAccent;
  count: number;
  reason: string;
  onReasonChange: (reason: string) => void;
  // Called with the chosen expiry (RFC 3339). The bar owns the date so every
  // caller gets the same 90-day default and bounds.
  onSuppress: (expiresAt: string) => void;
  onClear: () => void;
  isPending?: boolean;
  errorMessage?: string;
}

export function BulkSuppressBar({
  accent, count, reason, onReasonChange, onSuppress, onClear, isPending, errorMessage,
}: BulkSuppressBarProps) {
  const a = ACCENT[accent];
  const [expiry, setExpiry] = useState(() => expiryBounds().initial);
  const canSuppress = reason.trim().length > 0 && expiry !== "";
  const suppress = () => onSuppress(expiryToISO(expiry));
  return (
    <div className={`sticky top-0 z-10 mb-2 flex flex-wrap items-center gap-2 rounded border px-3 py-2 text-[11px] ${a.wrap}`}>
      <span className="font-medium text-text">{count} selected</span>
      <button onClick={onClear} className="text-text-3 hover:text-text-2">clear</button>
      <div className="ml-auto flex items-center gap-1.5">
        <input
          value={reason}
          onChange={(e) => onReasonChange(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter" && canSuppress) suppress(); }}
          placeholder="Suppression reason (required)…"
          className={`w-56 rounded border border-border-subtle bg-bg px-2 py-1 text-[11px] text-text placeholder:text-text-3 focus:outline-none ${a.input}`}
        />
        <ExpiryPicker value={expiry} onChange={setExpiry} />
        <button
          onClick={suppress}
          disabled={!canSuppress || isPending}
          className={`rounded border px-2 py-1 font-medium disabled:opacity-40 ${a.button}`}
        >
          {isPending ? "Suppressing…" : `Suppress ${count}`}
        </button>
      </div>
      {errorMessage && <span className="w-full text-red">{errorMessage}</span>}
    </div>
  );
}
