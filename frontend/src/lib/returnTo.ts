// Return-to-path across an OAuth round trip. Password login renders in place
// (the URL never changes), but Google/Okta sign-in leaves the SPA and the
// backend callback always lands on "/". Remember where the user was so the
// shell can send them back once the session is up.
const KEY = "graph-return-to";

// Only same-origin absolute paths — never "//host" or "https://…" — so a
// tampered value can't become an open redirect.
export function isSafeReturnPath(p: unknown): p is string {
  return typeof p === "string" && p.startsWith("/") && !p.startsWith("//") && !p.startsWith("/\\") && !p.startsWith("/api/");
}

export function rememberReturnPath(path: string) {
  if (!isSafeReturnPath(path) || path === "/" || path === "/home") return;
  try {
    sessionStorage.setItem(KEY, path);
  } catch {
    /* storage unavailable — fall back to landing on home */
  }
}

// browser wraps full-page navigation so tests can observe it (jsdom's
// window.location can't be spied on).
export const browser = {
  assign(url: string) {
    window.location.assign(url);
  },
};

// takeReturnPath reads and clears the remembered path (one-shot).
export function takeReturnPath(): string | null {
  try {
    const p = sessionStorage.getItem(KEY);
    sessionStorage.removeItem(KEY);
    return isSafeReturnPath(p) ? p : null;
  } catch {
    return null;
  }
}
