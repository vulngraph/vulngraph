import { lazy, Suspense, useEffect, useState, type ReactNode } from "react";
import { Link, useNavigate, useRouter, useRouterState } from "@tanstack/react-router";
import { useQueryClient } from "@tanstack/react-query";
import type { LucideIcon } from "lucide-react";
import {
  Activity,
  Telescope,
  Settings as SettingsIcon,
  ShieldCheck,
  Crosshair,
  Radar,
  LogOut,
  Sun,
  Moon,
  Users as UsersIcon,
} from "./icons";
import { VLogomark } from "./VLogomark";
import { useLogout, useMe } from "../lib/queries";
import { onUnauthorized } from "../lib/api";
import { handleUnauthorized } from "../lib/queryClient";
import { takeReturnPath } from "../lib/returnTo";
import { Login } from "../routes/Login";
import { Loading } from "./ui";

const ChatPanel = lazy(() =>
  import("./ChatPanel").then((m) => ({ default: m.ChatPanel }))
);

const tabs: { to: string; label: string; icon: LucideIcon; shortcut: string }[] = [
  { to: "/home",        label: "Home",        icon: Crosshair,  shortcut: "h" },
  { to: "/decisions",   label: "Decisions",   icon: Activity,   shortcut: "d" },
  { to: "/investigate", label: "Investigate", icon: Telescope,  shortcut: "i" },
  { to: "/scans",       label: "Scans",       icon: Radar,      shortcut: "s" },
  { to: "/compliance",  label: "Compliance",  icon: ShieldCheck, shortcut: "c" },
];

// Active-tab style for the top tab bar.
const ACTIVE_STYLE: React.CSSProperties = {
  background: "rgba(13,148,136,0.12)",
  borderBottom: "2px solid #0d9488",
};
const NAV_PILL_STYLE: React.CSSProperties = {
  background: "var(--graph-surface-2, rgba(255,255,255,0.04))",
  border: "1px solid var(--graph-border, rgba(255,255,255,0.08))",
};
const HEADER_STYLE: React.CSSProperties = {
  background: "var(--graph-panel-bg)",
  borderBottom: "1px solid var(--graph-panel-border)",
};

export function AppShell({ children }: { children: ReactNode }) {
  const me = useMe();
  const logout = useLogout();
  const navigate = useNavigate();
  const router = useRouter();
  const qc = useQueryClient();
  const { location } = useRouterState();
  const signedIn = !!me.data;
  const isAdmin = me.data?.role === "admin";

  // Raw (non-Query) fetches report 401s through notifyUnauthorized; route
  // them through the same session-expiry path as queries and mutations.
  useEffect(() => onUnauthorized(() => handleUnauthorized(qc)), [qc]);

  // After an OAuth round trip the backend lands us on "/" — go back to the
  // page the user was on when they were asked to sign in.
  useEffect(() => {
    if (!signedIn) return;
    const back = takeReturnPath();
    if (back) router.history.push(back);
  }, [signedIn, router]);

  const [theme, setTheme] = useState<"dark" | "light">(() => {
    if (typeof window === "undefined") return "dark";
    const stored = localStorage.getItem("graph-theme") as "dark" | "light" | null;
    if (stored) return stored;
    // matchMedia is absent in jsdom — fall back to dark there.
    return typeof window.matchMedia === "function" &&
      window.matchMedia("(prefers-color-scheme: light)").matches
      ? "light"
      : "dark";
  });

  useEffect(() => {
    const root = document.documentElement;
    if (theme === "light") {
      root.classList.remove("dark");
      root.classList.add("light");
    } else {
      root.classList.remove("light");
      root.classList.add("dark");
    }
    localStorage.setItem("graph-theme", theme);
  }, [theme]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const target = e.target as HTMLElement;
      if (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable) return;
      const tab = tabs.find((t) => t.shortcut === e.key);
      if (tab) void navigate({ to: tab.to });
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [navigate]);

  if (me.isLoading) return <Loading />;
  if (me.isError || !me.data) return <Login />;

  return (
    <div className="min-h-full">
      <header className="sticky top-0 z-10 shrink-0" style={HEADER_STYLE}>
        <div className="flex items-center justify-between px-3 py-2">
          {/* Logo + pill nav */}
          <div className="flex items-center gap-3">
            <span className="flex items-center gap-1.5 font-display text-sm font-semibold text-teal mr-1">
              <VLogomark size={14} />
              graph
            </span>
            <nav
              role="tablist"
              className="flex items-center gap-0.5 rounded-xl p-1"
              style={NAV_PILL_STYLE}
            >
              {tabs.map((t) => {
                const active = t.to === "/home"
                  ? location.pathname === "/home" || location.pathname === "/"
                  : location.pathname.startsWith(t.to);
                const Icon = t.icon;
                return (
                  <Link
                    key={t.to}
                    to={t.to}
                    role="tab"
                    aria-selected={active}
                    className={`flex items-center gap-1.5 rounded-none px-3 py-1.5 text-sm font-medium transition-all ${
                      active ? "text-text" : "text-text-3 hover:bg-surface hover:text-text"
                    }`}
                    style={active ? ACTIVE_STYLE : undefined}
                  >
                    <Icon className={`h-4 w-4 ${active ? "text-teal" : ""}`} />
                    <span className="hidden md:inline">{t.label}</span>
                    <kbd className="ml-0.5 hidden rounded px-0.5 font-mono text-[11px] text-text-3 opacity-60 lg:block">
                      {t.shortcut}
                    </kbd>
                  </Link>
                );
              })}
            </nav>
          </div>

          {/* Right actions */}
          <div className="flex items-center gap-1.5">
            <span className="hidden text-[11px] text-text-3 sm:block">{me.data.email}</span>
            {isAdmin && (
              <Link
                to="/settings"
                search={{ sub: "users" } as Record<string, string>}
                aria-label="Users"
                title="User management"
                className="rounded-lg border border-border-subtle bg-surface p-1.5 text-text-3 transition-colors hover:bg-surface-3 hover:text-text"
              >
                <UsersIcon className="h-3.5 w-3.5" />
              </Link>
            )}
            <Link
              to="/settings"
              aria-label="Settings"
              className={`rounded-lg border p-1.5 transition-colors ${
                location.pathname.startsWith("/settings")
                  ? "border-teal/30 bg-teal/10 text-text"
                  : "border-border-subtle bg-surface text-text-3 hover:bg-surface-3 hover:text-text"
              }`}
            >
              <SettingsIcon className="h-3.5 w-3.5" />
            </Link>
            <button
              onClick={() => setTheme(t => t === "dark" ? "light" : "dark")}
              className="flex h-8 w-8 items-center justify-center rounded-lg text-text-3 hover:bg-surface hover:text-text-2 transition-colors"
              title={theme === "dark" ? "Switch to light mode" : "Switch to dark mode"}
              aria-label="Toggle theme"
            >
              {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            </button>
            <button
              onClick={() => logout.mutate()}
              aria-label="Sign out"
              className="rounded-lg border border-border-subtle bg-surface p-1.5 text-text-3 transition-colors hover:bg-surface-3 hover:text-text"
            >
              <LogOut className="h-3.5 w-3.5" />
            </button>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-[1600px] px-5 py-6">{children}</main>
      <Suspense fallback={null}>
        <ChatPanel key={me.data.id} userId={me.data.id} />
      </Suspense>
    </div>
  );
}
