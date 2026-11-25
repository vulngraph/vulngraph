import { Link, useRouterState } from "@tanstack/react-router";
import type { ComponentType } from "react";
import { Bell, Bot, Coins, EyeOff, Key, Plug2, Terminal, Users } from "lucide-react";
import { PageHeader } from "../components/ui";
import { ConnectorsSection } from "./Connectors";
import { AlertsSection } from "./AlertChannels";
import { PolicySection } from "./RemediationPolicy";
import { APIKeysSection } from "./ApiKeys";
import { SuppressionsSection } from "./Suppressions";
import { UsersSection } from "./Users";
import { MCPSection } from "./Mcp";
import { LLMUsageSection } from "./LLMUsage";
import { useIsAdmin } from "../lib/queries";

// ── Section registry ────────────────────────────────────────────────────────
// Single source of truth: each entry both drives the sidebar link and the
// rendered pane, so a typo/rename can't desync the two.

const SECTIONS = {
  connectors:   { label: "Connectors",        icon: Plug2,    group: "Integrations", Component: ConnectorsSection },
  alerts:       { label: "Alerts",            icon: Bell,     group: "Integrations", Component: AlertsSection },
  policy:       { label: "Remediation Policy", icon: Bot,      group: "Agent",        Component: PolicySection },
  llmusage:     { label: "LLM Usage",         icon: Coins,    group: "Agent",        Component: LLMUsageSection, adminOnly: true },
  apikeys:      { label: "API Keys",          icon: Key,      group: "Access",       Component: APIKeysSection },
  suppressions: { label: "Suppressions",      icon: EyeOff,   group: "Access",       Component: SuppressionsSection },
  users:        { label: "Users",             icon: Users,    group: "Access",       Component: UsersSection, adminOnly: true },
  mcp:          { label: "MCP",               icon: Terminal, group: "Access",       Component: MCPSection },
} satisfies Record<string, { label: string; icon: ComponentType<{ className?: string }>; group: string; Component: ComponentType; adminOnly?: boolean }>;

type SectionId = keyof typeof SECTIONS;

const SECTION_IDS = Object.keys(SECTIONS) as SectionId[];

const GROUP_ORDER = ["Integrations", "Agent", "Access"] as const;

const GROUPS = GROUP_ORDER.map((group) => ({
  label: group,
  items: SECTION_IDS.filter((id) => SECTIONS[id].group === group),
}));

function isSectionId(value: string): value is SectionId {
  return (SECTION_IDS as string[]).includes(value);
}

// ── Page ──────────────────────────────────────────────────────────────────────

export function Settings() {
  const { location } = useRouterState();
  const search = location.search as Record<string, unknown>;
  const requested = typeof search.sub === "string" ? search.sub : "connectors";
  // Unknown ?sub= values (old bookmarks, typos) fall back to the first section
  // instead of rendering an empty page.
  const sub = isSectionId(requested) ? requested : "connectors";
  const Active = SECTIONS[sub].Component;
  const isAdmin = useIsAdmin();
  // Admin-only sections (user management) are hidden from the sidebar for
  // everyone else; the section itself still guards a direct ?sub= link.
  const visible = (id: SectionId) => isAdmin || !("adminOnly" in SECTIONS[id] && SECTIONS[id].adminOnly);

  return (
    <div className="flex">
      {/* Sidebar */}
      <aside className="sticky top-14 max-h-[calc(100vh-3.5rem)] w-52 shrink-0 self-start overflow-y-auto border-r border-border-subtle pt-6 pr-2">
        <nav aria-label="Settings sections">
          {GROUPS.map((group) => (
            <div key={group.label} className="mb-5">
              <div className="mb-1 px-3 text-[11px] font-semibold uppercase tracking-widest text-text-3">
                {group.label}
              </div>
              <ul>
                {group.items.filter(visible).map((id) => {
                  const item = SECTIONS[id];
                  const Icon = item.icon;
                  const active = sub === id;
                  return (
                    <li key={id}>
                      <Link
                        to="/settings"
                        search={{ sub: id } as Record<string, string>}
                        aria-current={active ? "page" : undefined}
                        className={[
                          "flex items-center gap-2.5 rounded-l px-3 py-2 text-[13px] transition-colors",
                          active
                            ? "border-r-2 border-teal bg-teal/10 font-medium text-teal"
                            : "text-text-3 hover:bg-surface/50 hover:text-text-2",
                        ].join(" ")}
                      >
                        <Icon className="h-4 w-4 shrink-0" />
                        {item.label}
                      </Link>
                    </li>
                  );
                })}
              </ul>
            </div>
          ))}
        </nav>
      </aside>

      {/* Content */}
      <div className="flex-1">
        <div className="max-w-3xl mx-auto">
          <PageHeader title="Settings" subtitle="Connectors, alerting, remediation policy, and access controls." />
          <Active />
        </div>
      </div>
    </div>
  );
}
