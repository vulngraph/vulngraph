// Ownership + environment presentation for findings (ADR 089): the owner and
// environment badges, the facet-backed filters for the findings list, and the
// CSV export that carries both. The API keeps three owner states apart and so
// does this file: an owner team, "unowned" (owner_source "none" — resolved to
// nobody, a visible state), and "" (enrichment has not resolved it yet).
import type { Finding } from "../lib/api";
import { downloadCSV, toCSV } from "../lib/csv";
import { useFindingSummary } from "../lib/queries";

export const UNOWNED = "unowned";

const ENVIRONMENTS = ["prod", "staging", "dev", "unknown"] as const;

type Routed = Pick<Finding, "owner_team" | "owner_source" | "owner_confidence" | "environment">;

// ownerLabel is the owner as a human reads it: the team, "unowned", or "" when
// nothing has been resolved yet.
export function ownerLabel(f: Routed): string {
  if (f.owner_source === "none") return UNOWNED;
  return f.owner_team ?? "";
}

const SOURCE_TITLES: Record<string, string> = {
  tag: "from an owner/team tag on the resource",
  codeowners: "from CODEOWNERS of the repo that declares the resource",
  iac: "the repo that declares the resource (no CODEOWNERS rule matched)",
};

export function OwnerBadge({ finding: f }: { finding: Routed }) {
  if (f.owner_source === "none") {
    return (
      <span
        className="rounded border border-amber/30 bg-amber/10 px-1 py-0.5 text-[11px] font-medium text-amber"
        title="No tag, IaC declaration or CODEOWNERS rule names an owner — alerts go to the unowned default channel"
      >
        unowned
      </span>
    );
  }
  if (!f.owner_team) return null; // not resolved yet: say nothing rather than guess
  const how = SOURCE_TITLES[f.owner_source ?? ""] ?? "";
  return (
    <span
      className="rounded border border-border-subtle bg-surface px-1 py-0.5 text-[11px] text-text-2"
      title={`Owner ${f.owner_team}${how ? ` — ${how}` : ""}${f.owner_confidence ? ` (${f.owner_confidence} confidence)` : ""}`}
    >
      @{f.owner_team}
    </span>
  );
}

export function EnvironmentBadge({ env }: { env?: string }) {
  if (!env) return null;
  const tone =
    env === "prod"
      ? "border-red/30 bg-red/10 text-red"
      : env === "unknown"
        ? "border-border-subtle bg-surface text-text-3"
        : "border-teal/30 bg-teal/5 text-teal";
  return (
    <span className={`rounded border px-1 py-0.5 text-[11px] font-medium ${tone}`} title={`Environment: ${env}`}>
      {env}
    </span>
  );
}

// facetOptions turns a facet map into select options, largest first. The
// not-yet-resolved bucket ("") is counted in the label of "All" rather than
// offered as a choice: the API has no filter for it, by design.
function facetOptions(counts: Record<string, number> | undefined, pinned: readonly string[]) {
  const entries = Object.entries(counts ?? {}).filter(([k]) => k !== "");
  const seen = new Set(entries.map(([k]) => k));
  for (const p of pinned) if (!seen.has(p)) entries.push([p, 0]);
  return entries.sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

const selectClass = (active: boolean) =>
  `rounded border px-2 py-1 text-[11px] outline-none focus:border-teal transition-colors ${
    active ? "border-teal/60 bg-teal/5 text-teal" : "border-border-subtle bg-bg text-text-2"
  }`;

// OwnerEnvFilters are the owner and environment selects, labelled with the open
// finding counts from the summary facets.
export function OwnerEnvFilters({
  owner,
  environment,
  onChange,
}: {
  owner: string;
  environment: string;
  onChange: (key: "owner" | "environment", value: string) => void;
}) {
  const { data } = useFindingSummary();
  const pendingOwners = data?.by_owner?.[""] ?? 0;
  return (
    <>
      <select
        value={owner}
        onChange={(e) => onChange("owner", e.target.value)}
        aria-label="Owner filter"
        className={selectClass(!!owner)}
      >
        <option value="">All owners{pendingOwners ? ` (${pendingOwners} unresolved)` : ""}</option>
        {facetOptions(data?.by_owner, [UNOWNED]).map(([k, n]) => (
          <option key={k} value={k}>
            {k === UNOWNED ? "Unowned" : `@${k}`} ({n})
          </option>
        ))}
      </select>
      <select
        value={environment}
        onChange={(e) => onChange("environment", e.target.value)}
        aria-label="Environment filter"
        className={selectClass(!!environment)}
      >
        <option value="">All environments</option>
        {facetOptions(data?.by_environment, ENVIRONMENTS).map(([k, n]) => (
          <option key={k} value={k}>
            {k} ({n})
          </option>
        ))}
      </select>
    </>
  );
}

const CSV_COLUMNS: { header: string; value: (f: Finding) => string | number | undefined }[] = [
  { header: "id", value: (f) => f.id },
  { header: "title", value: (f) => f.title },
  { header: "severity", value: (f) => f.severity },
  { header: "score", value: (f) => f.score },
  { header: "source", value: (f) => f.source },
  { header: "check_id", value: (f) => f.check_id },
  { header: "resource_id", value: (f) => f.resource_id },
  { header: "owner", value: (f) => ownerLabel(f) },
  { header: "owner_source", value: (f) => f.owner_source },
  { header: "environment", value: (f) => f.environment },
  { header: "must_fix_class", value: (f) => f.must_fix_class },
  { header: "detected_at", value: (f) => f.detected_at },
];

export function findingsToCSV(items: Finding[]): string {
  return toCSV(
    CSV_COLUMNS.map((c) => c.header),
    items.map((f) => CSV_COLUMNS.map((c) => c.value(f))),
  );
}

// ExportFindingsButton downloads what is loaded. Labelled as such when more
// pages exist, so a partial export never passes for the whole population.
export function ExportFindingsButton({ items, partial }: { items: Finding[]; partial: boolean }) {
  function exportCSV() {
    downloadCSV("findings.csv", findingsToCSV(items));
  }
  return (
    <button
      onClick={exportCSV}
      disabled={items.length === 0}
      title="Export the listed findings, with owner and environment, as CSV"
      className="text-[11px] text-text-3 underline decoration-dotted hover:text-teal disabled:opacity-40"
    >
      {partial ? `Export loaded (${items.length})` : "Export CSV"}
    </button>
  );
}
