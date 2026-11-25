import { Link, Outlet, useRouterState } from "@tanstack/react-router";
import type { LucideIcon } from "lucide-react";
import { Database, DollarSign, GitCompare, Globe, Users } from "lucide-react";
import { Layers, Network, ShieldAlert } from "../components/icons";

const subTabs: { to: string; label: string; icon: LucideIcon }[] = [
  { to: "/investigate/graph",    label: "Graph",    icon: Network    },
  { to: "/investigate/findings", label: "Findings", icon: ShieldAlert },
  { to: "/investigate/drift",    label: "Drift",    icon: GitCompare  },
  { to: "/investigate/assets",   label: "Assets",   icon: Layers     },
  { to: "/investigate/identity", label: "Identity", icon: Users      },
  { to: "/investigate/dspm",     label: "Data",     icon: Database   },
  { to: "/investigate/domains",  label: "Domains",  icon: Globe      },
  { to: "/investigate/cost",     label: "Cost",     icon: DollarSign },
];

const pillNav: React.CSSProperties = {
  background: "var(--graph-surface-2, rgba(255,255,255,0.04))",
  border: "1px solid var(--graph-border, rgba(255,255,255,0.08))",
};
const activeTab: React.CSSProperties = {
  background: "rgba(13,148,136,0.15)",
  borderRadius: "6px",
  border: "1px solid rgba(13,148,136,0.3)",
};

export function Investigate() {
  const { location } = useRouterState();

  return (
    <div>
      <div className="-mx-5 -mt-6 mb-6 border-b border-border-subtle px-5 py-1.5">
        <nav
          className="flex items-center gap-0.5 rounded-xl p-1"
          style={pillNav}
        >
          {subTabs.map((t) => {
            const active = location.pathname.startsWith(t.to);
            const Icon = t.icon;
            return (
              <Link
                key={t.to}
                to={t.to}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium transition-all ${
                  active ? "text-text" : "text-text-3 hover:text-text-2"
                }`}
                style={active ? activeTab : undefined}
              >
                <Icon className={`h-3 w-3 ${active ? "text-teal" : ""}`} />
                {t.label}
              </Link>
            );
          })}
        </nav>
      </div>
      <Outlet />
    </div>
  );
}
