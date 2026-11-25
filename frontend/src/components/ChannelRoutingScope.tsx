// Owner/environment routing scope for an alert channel (ADR 089), alongside the
// event-type and severity rules. An empty scope routes everything, like the
// other rules; a scoped channel only receives notifications that carry the
// dimension it is scoped on, so an owner-scoped channel never gets ownerless
// events such as phishing.
import { useState } from "react";
import type { RoutingEnvironment as Env } from "../lib/api";

const ENVIRONMENTS = ["prod", "staging", "dev", "unknown"] as const satisfies readonly Env[];

export interface RoutingScope {
  owner_teams: string[];
  environments: string[];
  route_unowned: boolean;
}

function parseTeams(raw: string): string[] {
  return raw
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);
}

export function ChannelRoutingFields({
  value,
  onChange,
}: {
  value: RoutingScope;
  onChange: (next: RoutingScope) => void;
}) {
  // The raw text is kept locally so typing "a, " is not normalised away mid-word.
  const [teamsText, setTeamsText] = useState(value.owner_teams.join(", "));
  const toggleEnv = (e: string) =>
    onChange({
      ...value,
      environments: value.environments.includes(e)
        ? value.environments.filter((x) => x !== e)
        : [...value.environments, e],
    });

  return (
    <div className="space-y-3">
      <label className="block">
        <span className="mb-1.5 block text-[11px] font-medium text-text-2">
          Owner teams <span className="text-text-3">(comma-separated; none = all owners)</span>
        </span>
        <input
          aria-label="Owner teams"
          value={teamsText}
          placeholder="payments, @acme/identity"
          onChange={(e) => {
            setTeamsText(e.target.value);
            onChange({ ...value, owner_teams: parseTeams(e.target.value) });
          }}
          className="w-full rounded border border-border-subtle bg-bg px-2.5 py-1.5 text-[12px] text-text outline-none focus:border-teal"
        />
        <span className="mt-1 block text-[11px] text-text-3">
          Matches the owner resolved for each finding — an owner/team tag, else the CODEOWNERS team of the repo that
          declares the resource.
        </span>
      </label>

      <div>
        <span className="mb-1.5 block text-[11px] font-medium text-text-2">
          Environments <span className="text-text-3">(none = all)</span>
        </span>
        <div className="flex flex-wrap gap-1.5">
          {ENVIRONMENTS.map((e) => {
            const on = value.environments.includes(e);
            return (
              <button
                key={e}
                type="button"
                aria-pressed={on}
                onClick={() => toggleEnv(e)}
                className={`rounded border px-2 py-1 text-[11px] transition-colors ${
                  on ? "border-teal/40 bg-teal/10 text-teal" : "border-border-subtle text-text-3 hover:bg-surface"
                }`}
              >
                {e}
              </button>
            );
          })}
        </div>
      </div>

      <label className="flex items-center gap-2">
        <input
          type="checkbox"
          checked={value.route_unowned}
          onChange={(e) => onChange({ ...value, route_unowned: e.target.checked })}
          className="h-4 w-4 accent-teal"
        />
        <span className="text-[12px] text-text-2">
          Default channel for unowned findings
          <span className="ml-1 text-text-3">— findings no tag, IaC repo or CODEOWNERS rule claims</span>
        </span>
      </label>
    </div>
  );
}

// RoutingScopeSummary is the one-line scope shown on a channel row.
export function RoutingScopeSummary({ scope }: { scope: RoutingScope }) {
  const parts: string[] = [];
  if (scope.owner_teams.length > 0) parts.push(scope.owner_teams.map((t) => `@${t}`).join(", "));
  if (scope.route_unowned) parts.push("unowned findings");
  if (scope.environments.length > 0) parts.push(scope.environments.join("/"));
  if (parts.length === 0) return null;
  return <span className="text-[11px] text-text-3">· scoped to {parts.join(" · ")}</span>;
}
