import { useEffect, useState, type FormEvent } from "react";
import { Share2 } from "lucide-react";
import { useQueryClient } from "@tanstack/react-query";
import { useRouterState } from "@tanstack/react-router";
import { useAuthProviders, useLogin, useSessionExpired } from "../lib/queries";
import { APIError } from "../lib/api";
import { browser, rememberReturnPath } from "../lib/returnTo";
import { Loading } from "../components/ui";

// Guard against an SSO redirect loop: if the IdP round trip succeeded but the
// app still says 401 (e.g. the account is disabled or not permitted), landing
// here again must not bounce straight back to the IdP.
const AUTO_SSO_KEY = "graph-sso-auto-redirect-at";
const AUTO_SSO_COOLDOWN_MS = 2 * 60_000;

function recentlyAutoRedirected(): boolean {
  try {
    const at = Number(sessionStorage.getItem(AUTO_SSO_KEY) ?? 0);
    return Date.now() - at < AUTO_SSO_COOLDOWN_MS;
  } catch {
    return true; // can't remember → never auto-redirect
  }
}

function markAutoRedirect() {
  try {
    sessionStorage.setItem(AUTO_SSO_KEY, String(Date.now()));
  } catch {
    /* ignore */
  }
}

// loginErrorMessage never says which factor failed — only that sign-in
// didn't succeed — so the form can't be used to probe passwords or 2FA.
export function loginErrorMessage(err: unknown): string {
  if (err instanceof APIError) {
    if (err.status === 429) return "Too many sign-in attempts. Wait a minute, then try again.";
    // Behind an authenticating proxy without break-glass the route isn't served.
    if (err.status === 404) return "Password sign-in isn't available on this server. Use your organization's single sign-on.";
    if (err.status === 400 || err.status === 401 || err.status === 403) {
      return "Sign-in failed. Check your email, password and authenticator code (if you use one).";
    }
  }
  return "Sign-in is unavailable right now — try again in a moment.";
}

export function Login() {
  const login = useLogin();
  const providers = useAuthProviders();
  const qc = useQueryClient();
  const expired = useSessionExpired();
  const href = useRouterState({ select: (s) => s.location.href });
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");

  const list = providers.data;
  const ids = new Set((list ?? []).map((p) => p.id));
  const hasGoogle = ids.has("google");
  const hasOkta = ids.has("okta");
  // If discovery failed (transient error), offer the form anyway rather than
  // a dead end; a 404 from login then explains when it isn't served.
  const hasPassword = providers.isError || ids.has("password");
  const proxyOnly = list != null && list.length === 0;
  const googleOnly = list != null && list.length === 1 && hasGoogle;
  const [autoSSO] = useState(() => !recentlyAutoRedirected());

  // Google as the only method: go straight to it — once. Never for an empty
  // list (that's an authenticating proxy, which has already run).
  useEffect(() => {
    if (googleOnly && autoSSO) {
      markAutoRedirect();
      rememberReturnPath(href);
      browser.assign("/api/auth/google");
    }
  }, [googleOnly, autoSSO, href]);

  function submit(e: FormEvent) {
    e.preventDefault();
    login.mutate({ email, password, totp_code: totp.trim() || undefined });
  }

  function retry() {
    void providers.refetch();
    void qc.invalidateQueries({ queryKey: ["me"] });
  }

  const rememberHere = () => rememberReturnPath(href);

  return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="glass w-80 rounded-xl p-7">
        <div className="mb-1 flex items-center gap-2">
          <span className="flex h-7 w-7 items-center justify-center rounded-md bg-teal/15">
            <Share2 className="h-4 w-4 text-teal" />
          </span>
          <h1 className="font-display text-lg font-semibold text-text">Vulngraph</h1>
        </div>
        <p className="mb-6 text-xs text-text-3">Vulngraph proposes fixes; a person approves every change. Sign in to review.</p>

        {expired && (
          <p role="status" className="mb-4 rounded border border-amber/30 bg-amber/10 px-2.5 py-2 text-[11px] text-amber">
            Your session has ended — sign in again to continue where you left off.
          </p>
        )}

        {providers.isLoading && <Loading />}

        {proxyOnly && (
          <div className="space-y-3">
            <p className="text-xs text-text-2">
              Sign-in is handled by your access proxy. If you see this, your account may not be permitted to use graph —
              contact your administrator.
            </p>
            <button
              type="button"
              onClick={retry}
              className="w-full rounded border border-border-subtle bg-surface px-3 py-2 text-sm text-text transition-colors hover:bg-surface-3"
            >
              Retry
            </button>
          </div>
        )}

        {googleOnly && autoSSO && <Loading />}

        {(hasGoogle || hasOkta) && !(googleOnly && autoSSO) && (
          <div className="mb-4 space-y-2">
            {googleOnly && (
              <p className="text-[11px] text-text-3">
                Sign-in didn't complete. If this keeps happening your account may not be permitted.
              </p>
            )}
            {hasGoogle && (
              <a
                href="/api/auth/google"
                onClick={rememberHere}
                className="flex w-full items-center justify-center gap-2 rounded border border-border-subtle bg-surface px-3 py-2 text-sm text-text transition-colors hover:bg-surface-3"
              >
                <svg className="h-4 w-4" viewBox="0 0 24 24" aria-hidden>
                  <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                  <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                  <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z"/>
                  <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                </svg>
                Sign in with Google
              </a>
            )}
            {hasOkta && (
              <a
                href="/api/auth/okta"
                onClick={rememberHere}
                className="flex w-full items-center justify-center gap-2 rounded border border-border-subtle bg-surface px-3 py-2 text-sm text-text transition-colors hover:bg-surface-3"
              >
                <span aria-hidden className="inline-block h-3.5 w-3.5 rounded-full border-[3px] border-[#007dc1]" />
                Sign in with Okta
              </a>
            )}
            {hasPassword && (
              <div className="relative flex items-center gap-2 pt-2">
                <div className="flex-1 border-t border-border-subtle" />
                <span className="text-[11px] text-text-3">or</span>
                <div className="flex-1 border-t border-border-subtle" />
              </div>
            )}
          </div>
        )}

        {hasPassword && (
          <form onSubmit={submit}>
            <label className="mb-3 block">
              <span className="mb-1 block text-[11px] text-text-2">Email</span>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                autoComplete="username"
                required
                className="w-full rounded border border-border-subtle bg-bg px-2 py-1.5 text-sm text-text outline-none focus:border-teal"
              />
            </label>
            <label className="mb-3 block">
              <span className="mb-1 block text-[11px] text-text-2">Password</span>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
                className="w-full rounded border border-border-subtle bg-bg px-2 py-1.5 text-sm text-text outline-none focus:border-teal"
              />
            </label>
            {/* Always visible: the backend checks password and code together and
                answers with one generic error, so the UI can't wait to be told
                a code is needed. Leave blank if 2FA isn't enabled. */}
            <label className="mb-3 block">
              <span className="mb-1 block text-[11px] text-text-2">
                Authenticator code <span className="text-text-3">(if 2FA is enabled)</span>
              </span>
              <input
                value={totp}
                onChange={(e) => setTotp(e.target.value)}
                inputMode="numeric"
                autoComplete="one-time-code"
                pattern="[0-9 ]*"
                className="w-full rounded border border-border-subtle bg-bg px-2 py-1.5 text-sm text-text outline-none focus:border-teal"
              />
            </label>

            {login.isError && (
              <p role="alert" className="mb-3 text-[11px] text-red">
                {loginErrorMessage(login.error)}
              </p>
            )}

            <button
              type="submit"
              disabled={login.isPending}
              className="btn-teal w-full rounded py-2 text-sm font-medium disabled:opacity-50"
            >
              {login.isPending ? "Signing in…" : "Sign in"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
