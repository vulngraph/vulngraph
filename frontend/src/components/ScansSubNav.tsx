import { Link, Outlet, useRouterState } from "@tanstack/react-router";

const tabs = [
  { to: "/scans", label: "Runs" },
  { to: "/scans/templates", label: "Templates & AI Generator" },
  { to: "/scans/profiles", label: "Workflows" },
] as const;

// Shared sub-navigation for the Scans section (Runs / Templates / Workflows).
export function ScansSubNav() {
  const { location } = useRouterState();
  return (
    <div className="mb-5 flex items-center gap-0 border-b border-border-subtle">
      {tabs.map((t) => {
        const active =
          t.to === "/scans"
            ? location.pathname === "/scans" || /^\/scans\/(?!templates|profiles)/.test(location.pathname)
            : location.pathname.startsWith(t.to);
        return (
          <Link
            key={t.to}
            to={t.to}
            className={`border-b-2 px-4 py-2.5 text-xs transition-colors ${
              active ? "border-teal text-text" : "border-transparent text-text-3 hover:text-text-2"
            }`}
          >
            {t.label}
          </Link>
        );
      })}
    </div>
  );
}

// Layout for the whole /scans section: the sub-nav is rendered exactly once here
// and every child route (Runs, Templates, Workflows, run detail) renders below it.
export function ScansLayout() {
  return (
    <div>
      <ScansSubNav />
      <Outlet />
    </div>
  );
}
