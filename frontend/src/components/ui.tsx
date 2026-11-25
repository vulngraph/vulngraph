import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode } from "react";
import { useCanGoBack, useRouter } from "@tanstack/react-router";
import { bandLabel } from "../lib/format";

// Small design-system primitives. Surfaces use tonal opacity (never shadows).

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <div className={`glass rounded-xl p-4 ${className}`}>{children}</div>;
}

export function PageHeader({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div className="mb-6">
      <h1 className="font-display text-xl font-semibold tracking-tight text-text">{title}</h1>
      {subtitle && <p className="mt-1.5 text-[13px] leading-relaxed text-text-3">{subtitle}</p>}
    </div>
  );
}

// BackLink goes back in history when the previous entry is in-app (preserving
// the parent list's filters), and falls back to a plain navigation otherwise.
export function BackLink({ to, label }: { to: string; label: string }) {
  const router = useRouter();
  const canGoBack = useCanGoBack();
  return (
    <button
      type="button"
      onClick={() => {
        if (canGoBack) router.history.back();
        else router.navigate({ to });
      }}
      className="mb-3 inline-block text-[12px] text-text-3 hover:text-text-2"
    >
      ← {label}
    </button>
  );
}

const severityColor: Record<string, string> = {
  critical: "text-red border-red/30 bg-red/10",
  high: "text-orange border-orange/30 bg-orange/10",
  medium: "text-amber border-amber/30 bg-amber/10",
  low: "text-sky border-sky/30 bg-sky/10",
  info: "text-text-3 border-border-subtle bg-surface",
};

export function SeverityBadge({ severity }: { severity: string }) {
  const cls = severityColor[severity] ?? severityColor.info;
  return (
    <span className={`inline-flex rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase ${cls}`}>
      {severity}
    </span>
  );
}

// ScoreBadge shows the enriched contextual risk score (0–100), coloured by its
// band. This is the value findings lead on; raw severity is secondary.
export function ScoreBadge({ score, band }: { score: number; band?: string }) {
  // Pill shape — no border, rounded-full, score leads
  const bg: Record<string, string> = {
    page:     "bg-red/15 text-red",
    high:     "bg-orange/15 text-orange",
    pipeline: "bg-amber/15 text-amber",
    monitor:  "bg-surface-2 text-text-3",
  };
  const cls = bg[band ?? ""] ?? bg.monitor;
  // The circle carries no text of its own beyond the number — give it a title
  // so hovering explains what the number/colour mean, since most call sites
  // don't add their own label next to it (Assets.tsx is the exception).
  const label = bandLabel(band);
  const title = score > 0
    ? `Risk score ${score}${label ? ` — ${label}` : ""}`
    : "No risk score";
  return (
    <span title={title} className={`inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-[12px] font-bold tabular-nums ${cls}`}>
      {score > 0 ? score : "—"}
    </span>
  );
}

export type StatusTone = "ok" | "warning" | "error";

const statusDotColor: Record<StatusTone, string> = {
  ok: "bg-emerald",
  warning: "bg-amber",
  error: "bg-red",
};

export function StatusDot({ tone, label }: { tone: StatusTone; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] text-text-2">
      <span className={`h-1.5 w-1.5 rounded-full ${statusDotColor[tone]}`} />
      {label}
    </span>
  );
}

export function Empty({ message }: { message: string }) {
  return (
    <div className="rounded-xl border border-border-subtle bg-surface p-10 text-center">
      <div className="mx-auto mb-3 h-8 w-8 rounded-full border border-border-subtle bg-surface-2 flex items-center justify-center">
        <span className="text-text-3 text-sm">—</span>
      </div>
      <p className="text-xs text-text-3">{message}</p>
    </div>
  );
}

export function Loading() {
  return (
    <div className="p-10 text-center">
      <div className="inline-flex items-center gap-2 text-xs text-text-3">
        <span className="h-1.5 w-1.5 rounded-full bg-teal animate-pulse" />
        Loading…
      </div>
    </div>
  );
}

export function ErrorNote({ message }: { message: string }) {
  return <div className="rounded-lg border border-red/30 bg-red/10 p-4 text-xs text-red">{message}</div>;
}

// KevBadge is the one canonical rendering of "this is a CISA Known Exploited
// Vulnerability" — a link to the catalog plus an explanatory title, so the
// meaning survives even if the reader has never heard "KEV" before. Every
// KEV marker renders through this, so none is a bare or title-only pill.
export function KevBadge({ className = "" }: { className?: string }) {
  return (
    <a
      href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
      target="_blank"
      rel="noopener noreferrer"
      onClick={(e) => e.stopPropagation()}
      title="CISA Known Exploited Vulnerability — view catalog"
      className={`rounded border border-red/30 bg-red/10 px-1.5 py-0.5 text-[11px] font-medium uppercase text-red hover:border-red/60 ${className}`}
    >
      KEV
    </a>
  );
}

type ButtonVariant = "primary" | "ghost" | "danger";

const buttonVariant: Record<ButtonVariant, string> = {
  primary: "btn-teal border-transparent",
  ghost: "border-border-subtle text-text-2 hover:bg-surface",
  danger: "border-red/30 bg-red/10 text-red hover:bg-red/20",
};

export function Button({
  variant = "ghost",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  return (
    <button
      {...props}
      className={`rounded border px-2.5 py-1 text-[13px] font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${buttonVariant[variant]} ${className}`}
    />
  );
}

// Field is a labelled input for the small admin forms. textarea renders a
// multi-line control (used for pasted keys/JSON).
export function Field({
  label,
  textarea,
  ...props
}: InputHTMLAttributes<HTMLInputElement> & { label: string; textarea?: boolean }) {
  return (
    <label className="block">
      <span className="mb-1 block text-[12px] uppercase text-text-3">{label}</span>
      {textarea ? (
        <textarea
          {...(props as InputHTMLAttributes<HTMLTextAreaElement>)}
          className="min-h-[4rem] w-full rounded border border-border-subtle bg-surface px-2 py-1 font-mono text-[12px] text-text focus:border-teal focus:outline-none"
        />
      ) : (
        <input
          {...props}
          className="w-full rounded border border-border-subtle bg-surface px-2 py-1 text-[13px] text-text focus:border-teal focus:outline-none"
        />
      )}
    </label>
  );
}
