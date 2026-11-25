// Suppression expiry. The API requires an explicit expires_at on every
// suppression (capped at 365 days); the UI pre-fills 90 days so the common case is
// one click, and the operator can pick any date in between.
export const DEFAULT_SUPPRESSION_DAYS = 90;
export const MAX_SUPPRESSION_DAYS = 365;

const DAY_MS = 24 * 60 * 60 * 1000;

// localDate formats a Date as the YYYY-MM-DD a native date input uses, in the
// browser's own timezone.
function localDate(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function addDays(now: Date, days: number): Date {
  const d = new Date(now);
  d.setDate(d.getDate() + days);
  return d;
}

// expiryBounds are the picker's default, min (tomorrow) and max (a year out).
export function expiryBounds(now: Date = new Date()) {
  return {
    initial: localDate(addDays(now, DEFAULT_SUPPRESSION_DAYS)),
    min: localDate(addDays(now, 1)),
    max: localDate(addDays(now, MAX_SUPPRESSION_DAYS)),
  };
}

// expiryToISO turns a picked date into the end of that day in the browser's
// timezone, so "expires on the 3rd" means it still holds all of the 3rd. The
// server allows a day of slack past 365 days for exactly this.
export function expiryToISO(date: string): string {
  const [y, m, d] = date.split("-").map(Number);
  return new Date(y, m - 1, d, 23, 59, 59).toISOString();
}

// expiryStatus describes a suppression's expiry for display: expired, expiring
// soon (inside the 14-day notice window), or fine.
export function expiryStatus(expiresAt: string, now: Date = new Date()): {
  state: "expired" | "soon" | "ok";
  label: string;
} {
  const diff = new Date(expiresAt).getTime() - now.getTime();
  const days = Math.round(Math.abs(diff) / DAY_MS);
  if (diff <= 0) {
    return { state: "expired", label: days === 0 ? "expired today" : `expired ${days}d ago` };
  }
  const label = days === 0 ? "expires today" : `expires in ${days}d`;
  return { state: days <= 14 ? "soon" : "ok", label };
}
