import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import { ChevronRight, Sparkles } from "lucide-react";
import { useCompliance, useFindingClusters } from "../lib/queries";
import type { ComplianceCoverage, FindingCluster } from "../lib/api";
import { Empty, ErrorNote, KevBadge, Loading, PageHeader, ScoreBadge, SeverityBadge } from "../components/ui";
import { openAssistant } from "../lib/assistant";
import { ConnectSourceNotice, useNoConnectors } from "../components/ConnectSourceNotice";
import { ComplianceRequirements } from "./ComplianceRequirements";

type ControlStatus = ComplianceCoverage["controls"][number];

function frameworkOf(id: string): string {
  const parts = id.split("-");
  return parts.length >= 2 ? `${parts[0]}-${parts[1]}` : (parts[0] ?? "Other");
}

// FRAMEWORK_GLOSSARY explains what the four framework chips actually are —
// the frameworks aggregate coverage is reported against (data.frameworks,
// real multi-framework membership from control.frameworks), not the
// dash-prefix families the accordion below groups by. These are the same
// four names shown in the summary banner chips and the "Framework" filter
// (both read control.frameworks, never frameworkOf()'s ID-prefix guess).
const FRAMEWORK_GLOSSARY: Record<string, string> = {
  CIS: "Center for Internet Security cloud benchmarks — vendor-neutral hardening baselines for AWS, GCP, Azure, Kubernetes, and GitHub.",
  SOC2: "AICPA Trust Services Criteria — the security controls a SOC 2 audit evaluates (access control, monitoring, change management).",
  "PCI-DSS": "Payment Card Industry Data Security Standard — required wherever cardholder data is stored, processed, or transmitted.",
  HIPAA: "Health Insurance Portability and Accountability Act — U.S. safeguards for protected health information.",
};

// PROVIDER_TAGS gives each control row a short, cosmetic provider label
// derived from its ID (e.g. "CIS-AWS-4.1" → AWS). Purely a reading aid —
// unlike frameworkOf() it is never used for grouping, filtering, or counting,
// so it can't drift from the accordion's real pass/fail math.
const PROVIDER_TAGS: [RegExp, string][] = [
  [/-AWS-|-AWS$/i, "AWS"],
  [/-GCP-/i, "GCP"],
  [/-AZ-/i, "Azure"],
  [/-K8S-/i, "K8s"],
  [/-GH-/i, "GitHub"],
  [/-DNS-/i, "DNS"],
];
function providerOf(id: string): string | null {
  for (const [re, label] of PROVIDER_TAGS) {
    if (re.test(id)) return label;
  }
  return null;
}

// ComplianceLegend explains the methodology (how a control passes/fails —
// a bare-minimum coverage model, not a certified audit) and the
// framework glossary. Same toggle-panel pattern as Findings' MustFixLegend.
function ComplianceLegend() {
  return (
    <div className="space-y-3 rounded-lg border border-border-subtle bg-surface-2 p-3">
      <p className="text-[11px] leading-snug text-text-3">
        A control passes when none of the checks mapped to it have an open finding. This is
        baseline coverage computed from the current CSPM and scan checks — a snapshot, not a
        certified audit or a substitute for one.
      </p>
      <div className="grid gap-2 sm:grid-cols-2">
        {Object.entries(FRAMEWORK_GLOSSARY).map(([fw, desc]) => (
          <div key={fw} className="flex items-start gap-2">
            <span className="mt-0.5 shrink-0 rounded border border-border-subtle bg-surface px-1.5 py-0.5 text-[11px] font-medium text-text">
              {fw}
            </span>
            <p className="text-[11px] leading-snug text-text-3">{desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

function worstCluster(clusters: FindingCluster[]): FindingCluster | undefined {
  if (clusters.length === 0) return undefined;
  return clusters.reduce((best, cl) =>
    cl.max_score > best.max_score ? cl : best
  );
}

function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, n) + "…" : s;
}

// pctTone/pctBarTone are the single ≥80/≥50/else threshold used everywhere a
// pass-percentage gets colored (banner bar, framework chips, group headers), so
// no site re-derives its own thresholds and disagrees with the others.
function pctTone(pct: number): string {
  if (pct >= 80) return "text-emerald";
  if (pct >= 50) return "text-amber";
  return "text-red";
}
function pctBarTone(pct: number): string {
  if (pct >= 80) return "bg-emerald";
  if (pct >= 50) return "bg-amber";
  return "bg-red";
}

// A Findings link with no `view` lands on the "Must fix" worklist, which
// ignores `q` entirely — every jump-to-findings link here needs `view: "all"`
// or the search silently matches nothing.
function findingsSearch(q: string): Record<string, string> {
  return { view: "all", q };
}

type Filters = { framework: string; failingOnly: boolean; q: string };

// parseFilters reads every filter off the URL — the single source of truth,
// so a triage view (framework + failing-only + search) is shareable and
// survives reload instead of resetting every time the route remounts.
function parseFilters(sp: Record<string, unknown>): Filters {
  const str = (k: string) => (sp[k] == null ? "" : String(sp[k]));
  return {
    framework: str("framework"),
    failingOnly: str("failing") !== "false", // default true
    q: str("q"),
  };
}

export function Compliance() {
  const [showLegend, setShowLegend] = useState(false);
  const { data, isLoading, isError, error } = useCompliance();
  const noConnectors = useNoConnectors();
  const clusters = useFindingClusters();
  const clustersByCheck = new Map<string, FindingCluster>();
  for (const c of clusters.data?.items ?? []) {
    clustersByCheck.set(c.check_id, c);
  }

  const { location } = useRouterState();
  const navigate = useNavigate();
  const { framework: frameworkFilter, failingOnly, q } = useMemo(
    () => parseFilters(location.search as Record<string, unknown>),
    [location.search]
  );

  const searchRef = useRef(location.search as Record<string, unknown>);
  searchRef.current = location.search as Record<string, unknown>;

  function setParams(updates: Record<string, string | boolean>) {
    const next: Record<string, unknown> = { ...searchRef.current };
    for (const [key, value] of Object.entries(updates)) {
      const isDefault = (key === "failing" && value === true) || value === "";
      if (isDefault) delete next[key];
      else next[key] = value;
    }
    void navigate({ to: "/compliance", search: next as Record<string, string> });
  }

  // Search input: local state for keystroke responsiveness, debounced into
  // the URL (the real source of truth) so search survives a refresh or a share.
  const [qInput, setQInput] = useState(q);
  const committedQ = useRef(q);
  useEffect(() => {
    if (q !== committedQ.current) {
      committedQ.current = q;
      setQInput(q);
    }
  }, [q]);
  useEffect(() => {
    if (qInput === committedQ.current) return;
    const t = setTimeout(() => {
      committedQ.current = qInput;
      setParams({ q: qInput });
    }, 300);
    return () => clearTimeout(t);
  }, [qInput]);

  // The "Framework" filter uses the same real membership (control.frameworks)
  // as the banner chips and data.frameworks — CIS / SOC2 / PCI-DSS / HIPAA —
  // NOT frameworkOf()'s dash-prefix families ("CIS-AWS", "SOC2-CC6.3", ...)
  // the accordion below groups by. Those are two genuinely different things
  // (one real standard vs. one check family); filtering on the second would make
  // picking "SOC2" show nothing resembling the "SOC2 3/27" banner chip above it.
  const realFrameworks = useMemo(
    () => (data?.frameworks ?? []).map((f) => f.framework).sort(),
    [data]
  );

  const searchLower = q.trim().toLowerCase();
  const visibleControls = (data?.controls ?? []).filter((c) => {
    if (frameworkFilter && !c.control.frameworks.includes(frameworkFilter)) return false;
    if (failingOnly && c.state !== "failing") return false;
    if (searchLower) {
      const haystack = `${c.control.title} ${c.control.id} ${c.control.check_ids.join(" ")}`.toLowerCase();
      if (!haystack.includes(searchLower)) return false;
    }
    return true;
  });

  const groups = new Map<string, ControlStatus[]>();
  for (const c of visibleControls) {
    const fw = frameworkOf(c.control.id);
    const list = groups.get(fw) ?? [];
    list.push(c);
    groups.set(fw, list);
  }

  // Summary stats — always computed from the full unfiltered control set so
  // the banner stays stable regardless of toolbar filters below.
  const allGroups = new Map<string, ControlStatus[]>();
  for (const c of data?.controls ?? []) {
    const fw = frameworkOf(c.control.id);
    const list = allGroups.get(fw) ?? [];
    list.push(c);
    allGroups.set(fw, list);
  }
  const overallPct = data && data.total > 0
    ? Math.round((data.passing / data.total) * 100)
    : null;
  // Real per-framework coverage from the server, not the fake dash-prefix
  // taxonomy `allGroups` groups controls by.
  const fullyCoveredFrameworks = (data?.frameworks ?? []).filter(
    (fw) => fw.total > 0 && fw.passing === fw.total
  ).length;

  // Worst failing cluster across all controls for the summary callout
  const allFailingClusters: FindingCluster[] = [];
  for (const c of data?.controls ?? []) {
    if (c.state === "failing") {
      for (const id of c.control.check_ids) {
        const cl = clustersByCheck.get(id);
        if (cl) allFailingClusters.push(cl);
      }
    }
  }
  const worst = worstCluster(allFailingClusters);

  const clustersFailed = clusters.isError;
  const ready = !isLoading && !isError && !clusters.isLoading && !clustersFailed;

  return (
    <div>
      <div className="flex items-start justify-between gap-4">
        <PageHeader
          title="Posture"
          subtitle="Benchmark control coverage — click a control to see the findings driving it and what to do."
        />
        <button
          onClick={() => setShowLegend((v) => !v)}
          className="mt-1 shrink-0 text-[11px] text-text-3 underline decoration-dotted hover:text-teal"
        >
          {showLegend ? "hide" : "what does this measure?"}
        </button>
      </div>
      {showLegend && (
        <div className="mb-4">
          <ComplianceLegend />
        </div>
      )}
      {noConnectors && <ConnectSourceNotice variant="banner" />}
      {(isLoading || clusters.isLoading) && <Loading />}
      {isError && <ErrorNote message={(error as Error).message} />}
      {!isLoading && !isError && clustersFailed && (
        <ErrorNote message={`Could not load the finding data behind these controls: ${(clusters.error as Error)?.message ?? "unknown error"}. Failing-control detail is unavailable until this succeeds.`} />
      )}
      {ready && data && data.controls.length === 0 && <Empty message="No controls evaluated yet." />}
      {ready && data && data.controls.length > 0 && (
        <>
          {/* Summary banner */}
          <div className="mb-6 rounded-lg border border-border-subtle bg-surface px-4 py-3">
            <div className="flex flex-wrap items-center gap-4">
              <div className="flex items-baseline gap-2">
                <span className="font-display text-3xl tabular-nums text-text">
                  {overallPct}%
                </span>
                <span className="text-xs text-text-3">controls passing overall</span>
              </div>
              <div className="h-4 w-px bg-border-subtle" />
              <div className="flex items-baseline gap-2">
                <span className="font-display text-xl tabular-nums text-text">
                  {data.passing}/{data.total}
                </span>
                <span className="text-xs text-text-3">controls passing</span>
              </div>
              <div className="h-4 w-px bg-border-subtle" />
              <div className="flex items-baseline gap-2">
                <span className="font-display text-xl tabular-nums text-text">
                  {fullyCoveredFrameworks}
                </span>
                <span className="text-xs text-text-3">
                  framework{fullyCoveredFrameworks !== 1 ? "s" : ""} fully covered
                </span>
              </div>
              {data.failing > 0 && (
                <span className="rounded border border-red/30 bg-red/10 px-2 py-0.5 text-[11px] font-medium text-red">
                  {data.failing} failing
                </span>
              )}
              {data.partial > 0 && (
                <span className="rounded border border-amber/30 bg-amber/10 px-2 py-0.5 text-[11px] font-medium text-amber">
                  {data.partial} partially assessed
                </span>
              )}
              {data.not_assessed > 0 && (
                <span className="rounded border border-border-subtle px-2 py-0.5 text-[11px] font-medium text-text-3">
                  {data.not_assessed} not assessed
                </span>
              )}
              {worst && (
                <>
                  <div className="h-4 w-px bg-border-subtle" />
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] text-text-3">worst:</span>
                    <ScoreBadge score={worst.max_score} band={worst.worst_band} />
                    <Link
                      to="/investigate/findings"
                      search={findingsSearch(worst.check_id)}
                      className="text-[11px] text-text hover:text-teal"
                    >
                      {truncate(worst.title, 50)}
                    </Link>
                  </div>
                </>
              )}
            </div>
            {/* Overall progress bar */}
            {overallPct !== null && (
              <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-border-subtle">
                <div
                  className={`h-full rounded-full transition-all ${pctBarTone(overallPct)}`}
                  style={{ width: `${overallPct}%` }}
                />
              </div>
            )}
            {/* Per-framework coverage — the same checks rolled up under each
                real framework (CIS / SOC2 / PCI-DSS / HIPAA). Clickable: sets
                the Framework filter below to show exactly the controls this
                number is counted from. */}
            {data.frameworks && data.frameworks.length > 0 && (
              <div className="mt-3 flex flex-wrap gap-2">
                {data.frameworks.map((fw) => {
                  const pct = fw.total > 0 ? Math.round((fw.passing / fw.total) * 100) : 0;
                  const active = frameworkFilter === fw.framework;
                  return (
                    <button
                      key={fw.framework}
                      type="button"
                      title={`${FRAMEWORK_GLOSSARY[fw.framework]} Click to show these ${fw.total} controls below.`}
                      onClick={() => setParams({ framework: active ? "" : fw.framework })}
                      aria-pressed={active}
                      className={`flex items-center gap-2 rounded border px-2.5 py-1 transition-colors ${
                        active
                          ? "border-teal/40 bg-teal/10"
                          : "border-border-subtle bg-surface hover:border-teal/30"
                      }`}
                    >
                      <span className="text-[11px] font-medium text-text">{fw.framework}</span>
                      <span className={`text-[11px] tabular-nums ${pctTone(pct)}`}>
                        {fw.passing}/{fw.total}
                      </span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {/* Triage toolbar */}
          <div className="mb-4 flex flex-wrap items-center gap-2">
            <select
              value={frameworkFilter}
              onChange={(e) => setParams({ framework: e.target.value })}
              className="h-8 rounded border border-border-subtle bg-surface px-2 text-[12px] text-text"
              aria-label="Filter by framework"
              title="Filters to the controls that count toward the chosen standard's coverage — same membership as the chips above."
            >
              <option value="">Framework: All</option>
              {realFrameworks.map((fw) => (
                <option key={fw} value={fw}>
                  {fw}
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={() => setParams({ failing: !failingOnly })}
              aria-pressed={failingOnly}
              className={`h-8 rounded border px-2.5 text-[12px] font-medium transition-colors ${
                failingOnly
                  ? "border-red/30 bg-red/10 text-red"
                  : "border-border-subtle bg-surface text-text-3"
              }`}
            >
              Failing only
            </button>
            <input
              type="text"
              value={qInput}
              onChange={(e) => setQInput(e.target.value)}
              placeholder="Filter by control name or ID…"
              className="h-8 min-w-[220px] flex-1 rounded border border-border-subtle bg-surface px-2.5 text-[12px] text-text placeholder:text-text-3"
              aria-label="Filter controls by name or ID"
            />
          </div>

          <p className="mb-2 text-[11px] text-text-3">
            {frameworkFilter ? (
              <>
                Showing the {visibleControls.length} control{visibleControls.length !== 1 ? "s" : ""} counted
                toward <span className="text-text-2">{frameworkFilter}</span> coverage above, grouped below
                by check family.{" "}
                <button type="button" onClick={() => setParams({ framework: "" })} className="text-teal hover:underline">
                  Clear
                </button>
              </>
            ) : (
              "Grouped below by check family (e.g. CIS-AWS, SOC2-CC6.3) — click a framework chip above to see just its controls."
            )}
          </p>
          <div className="space-y-4">
            {[...groups.entries()].map(([fw, controls]) => (
              <FrameworkGroup
                key={fw}
                framework={fw}
                displayControls={controls}
                allControls={allGroups.get(fw) ?? controls}
                clustersByCheck={clustersByCheck}
                failingOnly={failingOnly}
              />
            ))}
            {groups.size === 0 && (
              <Empty message="No controls match the current filters." />
            )}
          </div>
        </>
      )}
      <ComplianceRequirements />
    </div>
  );
}

function FrameworkGroup({
  framework,
  displayControls,
  allControls,
  clustersByCheck,
  failingOnly,
}: {
  framework: string;
  displayControls: ControlStatus[];
  allControls: ControlStatus[];
  clustersByCheck: Map<string, FindingCluster>;
  failingOnly: boolean;
}) {
  // Header stats always come from the framework's full control set — stable
  // regardless of the "failing only" toggle, same philosophy as the summary
  // banner above. displayControls (already filtered by the caller) is only
  // ever what actually renders below.
  const pass = allControls.filter((c) => c.passing).length;
  const fail = allControls.filter((c) => c.state === "failing").length;
  const notAssessed = allControls.filter((c) => c.state === "not_assessed").length;
  const partial = allControls.filter((c) => c.state === "partial").length;
  const pct = allControls.length > 0 ? Math.round((pass / allControls.length) * 100) : 0;

  // Default-open only frameworks with failing controls while triaging
  // ("failing only" on, so every rendered group has at least one failing
  // control by construction); otherwise start collapsed so the page isn't a
  // wall of open accordions.
  const [open, setOpen] = useState(failingOnly);

  return (
    <div>
      {/* Framework header — clickable expand toggle */}
      <button
        type="button"
        className="mb-2 flex w-full items-center gap-2 text-left"
        onClick={() => setOpen((v) => !v)}
      >
        <ChevronRight className={`h-3 w-3 text-text-3 transition-transform ${open ? "rotate-90" : ""}`} />
        <span className="font-display text-sm text-text">{framework}</span>
        <span className="text-[11px] tabular-nums text-text-3">{pass}/{allControls.length} passing</span>
        {fail > 0 ? (
          <span className="text-[11px] text-red">{fail} failing</span>
        ) : notAssessed === 0 && partial === 0 ? (
          <span className="text-[11px] text-emerald">all passing</span>
        ) : null}
        {partial > 0 && <span className="text-[11px] text-amber">{partial} partially assessed</span>}
        {notAssessed > 0 && <span className="text-[11px] text-text-3">{notAssessed} not assessed</span>}
        {/* Framework coverage bar */}
        <div className="ml-auto flex items-center gap-2">
          <div className="h-1.5 w-24 overflow-hidden rounded-full bg-border-subtle">
            <div className={`h-full rounded-full ${pctBarTone(pct)}`} style={{ width: `${pct}%` }} />
          </div>
          <span className={`text-[11px] tabular-nums ${pctTone(pct)}`}>{pct}%</span>
        </div>
      </button>

      {open && (
        <div className="glass overflow-hidden rounded-lg">
          {[...displayControls]
            .sort((a, b) => {
              // Failing controls first, then by worst cluster score descending
              if ((a.state === "failing") !== (b.state === "failing")) return a.state === "failing" ? -1 : 1;
              const aScore = Math.max(0, ...a.control.check_ids.map((id) => clustersByCheck.get(id)?.max_score ?? 0));
              const bScore = Math.max(0, ...b.control.check_ids.map((id) => clustersByCheck.get(id)?.max_score ?? 0));
              return bScore - aScore;
            })
            .map((c) => (
            <ControlRow
              key={c.control.id}
              status={c}
              clustersByCheck={clustersByCheck}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function ControlRow({
  status: c,
  clustersByCheck,
}: {
  status: ControlStatus;
  clustersByCheck: Map<string, FindingCluster>;
}) {
  const [open, setOpen] = useState(false);

  const failingClusters = c.control.check_ids
    .map((id) => clustersByCheck.get(id))
    .filter(Boolean) as FindingCluster[];

  // Passing controls can expand too, to show the check IDs that evidence the
  // pass — without this, "passing" was a bare assertion with nothing behind
  // it, unlike every failing control which shows its driving findings.
  const failing = c.state === "failing";
  const notAssessed = c.state === "not_assessed";
  const partial = c.state === "partial";
  const canExpand = !failing || failingClusters.length > 0;
  const totalInstances = failingClusters.reduce((n, cl) => n + cl.instances, 0);
  const worst = worstCluster(failingClusters);
  const provider = providerOf(c.control.id);

  return (
    <>
      <div
        role={canExpand ? "button" : undefined}
        tabIndex={canExpand ? 0 : undefined}
        onKeyDown={(e) => {
          if (canExpand && (e.key === "Enter" || e.key === " ")) {
            e.preventDefault();
            setOpen((v) => !v);
          }
        }}
        className={`flex items-start justify-between border-b border-border-subtle/40 px-4 py-3 last:border-0 ${
          canExpand ? "cursor-pointer hover:bg-surface/50" : ""
        }`}
        onClick={() => canExpand && setOpen((v) => !v)}
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            {canExpand && (
              <ChevronRight className={`shrink-0 h-3 w-3 text-text-3 transition-transform ${open ? "rotate-90" : ""}`} />
            )}
            <span className={`text-sm ${failing ? "text-text" : "text-text-2"}`}>
              {c.control.title}
            </span>
          </div>
          <div className="mt-0.5 flex items-center gap-1.5 font-mono text-[11px] text-text-3">
            {c.control.id}
            {provider && (
              <span className="rounded border border-border-subtle bg-surface-2 px-1 py-px font-sans text-[10px] text-text-3">
                {provider}
              </span>
            )}
          </div>

          {/* Inline worst finding preview — visible without expanding */}
          {failing && worst && (
            <div className="mt-1.5 flex flex-wrap items-center gap-2">
              <ScoreBadge score={worst.max_score} band={worst.worst_band} />
              <Link
                to="/investigate/findings"
                search={findingsSearch(worst.check_id)}
                className="text-[11px] text-text-2 hover:text-teal transition-colors"
                onClick={e => e.stopPropagation()}
              >{truncate(worst.title, 55)}</Link>
              {worst.known_exploited && <KevBadge />}
              <SeverityBadge severity={worst.severity} />
              {totalInstances > 0 && (
                <Link
                  to="/investigate/findings"
                  search={findingsSearch(worst.check_id)}
                  className="text-[11px] tabular-nums text-text-3 hover:text-teal"
                  onClick={(e) => e.stopPropagation()}
                >
                  {totalInstances} instance{totalInstances !== 1 ? "s" : ""} →
                </Link>
              )}
            </div>
          )}
        </div>

        <div className="ml-4 mt-0.5 flex shrink-0 items-center gap-2">
          <span className={`h-1.5 w-1.5 rounded-full ${failing ? "bg-red" : partial ? "bg-amber" : notAssessed ? "bg-text-3" : "bg-emerald"}`} />
          <span className={`text-[11px] ${failing ? "text-red" : partial ? "text-amber" : notAssessed ? "text-text-3" : "text-emerald"}`}>
            {failing ? "failing" : partial ? "partially assessed" : notAssessed ? "not assessed" : "passing"}
          </span>
        </div>
      </div>

      {open && c.passing && (
        <div className="border-b border-border-subtle/40 bg-bg/40 px-4 py-3 last:border-0">
          <div className="mb-1 text-[11px] uppercase tracking-wide text-text-3">
            Why this passes
          </div>
          <p className="text-[11px] leading-snug text-text-2">
            No open finding on any of the {c.control.check_ids.length} check
            {c.control.check_ids.length !== 1 ? "s" : ""} this control is evidenced by:{" "}
            <span className="font-mono text-text-3">{c.control.check_ids.join(", ")}</span>.
          </p>
        </div>
      )}

      {open && notAssessed && (
        <div className="border-b border-border-subtle/40 bg-bg/40 px-4 py-3 last:border-0">
          <div className="mb-1 text-[11px] uppercase tracking-wide text-text-3">
            Why this is not assessed
          </div>
          <p className="text-[11px] leading-snug text-text-2">
            No open finding, but none of its checks could evaluate a live asset — no connector or no
            resources of the type they grade, or the evidence they read was never collected:{" "}
            <span className="font-mono text-text-3">{c.control.check_ids.join(", ")}</span>.
          </p>
        </div>
      )}

      {open && partial && (
        <div className="border-b border-border-subtle/40 bg-bg/40 px-4 py-3 last:border-0">
          <div className="mb-1 text-[11px] uppercase tracking-wide text-text-3">
            Why this is only partially assessed
          </div>
          <p className="text-[11px] leading-snug text-text-2">
            No open finding, but only some of its checks could evaluate a live asset; the rest graded
            nothing, so they are not evidence the control passes:{" "}
            <span className="font-mono text-text-3">{c.control.check_ids.join(", ")}</span>.
          </p>
        </div>
      )}

      {open && failing && (
        <div className="border-b border-border-subtle/40 bg-bg/40 px-4 py-3 last:border-0">
          <div className="mb-2 text-[11px] uppercase tracking-wide text-text-3">
            Findings causing this control to fail
          </div>
          <div className="space-y-2">
            {failingClusters.map((cl) => (
              <ClusterCard key={cl.check_id} cluster={cl} />
            ))}
          </div>
        </div>
      )}
    </>
  );
}

function ClusterCard({ cluster: cl }: { cluster: FindingCluster }) {
  const [remExpanded, setRemExpanded] = useState(false);
  const remFull = cl.remediation ?? "";
  const remShort = truncate(remFull, 80);
  const remNeedsExpand = remFull.length > 80;

  return (
    <div className="rounded-lg border border-border-subtle bg-surface px-3 py-2.5">
      <div className="flex items-start gap-3">
        <ScoreBadge score={cl.max_score} band={cl.worst_band} />
        <div className="min-w-0 flex-1">
          {/* Title + badges */}
          <div className="flex flex-wrap items-center gap-2">
            <Link to="/investigate/findings" search={findingsSearch(cl.check_id)} className="text-xs text-text hover:text-teal transition-colors" onClick={e => e.stopPropagation()}>{cl.title}</Link>
            {cl.known_exploited && <KevBadge />}
            <SeverityBadge severity={cl.severity} />
            <span className="font-mono text-[11px] text-text-3">{cl.check_id}</span>
          </div>

          {/* Factor strip — score context */}
          {(cl.known_exploited || cl.instances > 10 || cl.severity === "critical") && (
            <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
              {cl.known_exploited && (
                <span className="rounded bg-red/10 px-1.5 py-0.5 text-[11px] font-medium text-red">
                  Known exploited in the wild
                </span>
              )}
              {cl.instances > 10 && (
                <span className="rounded bg-amber/10 px-1.5 py-0.5 text-[11px] text-amber">
                  Wide blast radius ({cl.instances} instances)
                </span>
              )}
              {cl.severity === "critical" && !cl.known_exploited && (
                <span className="rounded bg-red/10 px-1.5 py-0.5 text-[11px] font-medium text-red">
                  Critical severity
                </span>
              )}
            </div>
          )}

          {/* Instance / resource summary */}
          <div className="mt-1 text-[11px] text-text-3">
            {cl.instances} instance{cl.instances !== 1 ? "s" : ""}{" "}
            across {cl.resources} resource{cl.resources !== 1 ? "s" : ""}
            {cl.last_detected && (
              <span className="ml-2 text-text-3">
                · last {new Date(cl.last_detected).toLocaleDateString()}
              </span>
            )}
          </div>

          {/* Remediation — own line, visually distinct */}
          {remFull && (
            <div className="mt-1.5 flex items-start gap-1 text-[11px]">
              <span className="shrink-0 text-text-3">Remediation:</span>
              <span className="text-text-2">
                {remNeedsExpand && !remExpanded ? remShort : remFull}
                {remNeedsExpand && (
                  <button
                    type="button"
                    className="ml-1 text-teal hover:underline"
                    onClick={(e) => { e.stopPropagation(); setRemExpanded((v) => !v); }}
                  >
                    {remExpanded ? "less" : "more"}
                  </button>
                )}
              </span>
            </div>
          )}
        </div>

        <div className="flex items-center gap-2 shrink-0">
          <Link
            to="/investigate/findings"
            search={findingsSearch(cl.check_id)}
            className="rounded border border-teal/30 bg-teal/10 px-2 py-1 text-[11px] text-teal hover:bg-teal/20"
            onClick={(e) => e.stopPropagation()}
          >
            View →
          </Link>
          <button
            className="inline-flex items-center gap-1.5 rounded-lg border border-teal/30 bg-teal/10 px-2.5 py-1.5 text-[11px] font-medium text-teal transition-colors hover:bg-teal/20"
            onClick={(e) => {
              e.stopPropagation();
              const facts = [`Check: ${cl.check_id}`, `${cl.instances} instance${cl.instances !== 1 ? "s" : ""}`, `Score: ${cl.max_score}`];
              if (cl.known_exploited) facts.push("KEV: yes");
              if (cl.remediation) facts.push(`Fix hint: ${cl.remediation.split(/\.\s/)[0]}`);
              openAssistant({ subject: `Compliance control: ${cl.title}`, facts, question: "What is the risk and recommended remediation path?" });
            }}
          >
            <Sparkles className="h-3 w-3" />
            Ask AI →
          </button>
        </div>
      </div>
    </div>
  );
}
