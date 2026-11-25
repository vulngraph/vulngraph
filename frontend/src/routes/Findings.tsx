import { useState, useEffect, useMemo, useRef } from "react";
import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import { ChevronRight, ChevronDown, ExternalLink } from "lucide-react";
import type { Finding, FindingCluster } from "../lib/api";
import {
  useFindingClusters,
  useFinding,
  useFindings,
  useIsAdmin,
  useSuppressFinding,
  useUnsuppressFinding,
  useBulkSuppress,
  type FindingFilter,
} from "../lib/queries";
import { Button, Empty, ErrorNote, Field, KevBadge, Loading, PageHeader, ScoreBadge } from "../components/ui";
import { openAssistant } from "../lib/assistant";
import { StartHereView } from "../components/StartHereView";
import { MustFixView } from "../components/MustFixView";
import { FindingDetailPanel } from "../components/FindingDetailPanel";
import { BulkSuppressBar } from "../components/BulkSuppressBar";
import { ExceptionExpiredBadge, ExpiryPicker } from "../components/SuppressionExpiry";
import { expiryBounds, expiryToISO } from "../lib/expiry";
import { useInfiniteSentinel } from "../lib/useInfiniteSentinel";
import { MustFixBadge, MustFixLegend, StalenessNote } from "../components/MustFixBadge";
import { SCORE_THRESHOLDS, bandAtLeast, bandLabel, bandTone, shortenId } from "../lib/format";
import { EnvironmentBadge, ExportFindingsButton, OwnerBadge, OwnerEnvFilters } from "../components/Ownership";

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}

// Labels/colors come from lib/format.ts's bandLabel/bandTone rather than a
// second hardcoded copy — "All" is the one filter-only value with no
// wire-level band.
const BANDS = [
  { value: "", label: "All", color: undefined as string | undefined },
  { value: "page", label: capitalize(bandLabel("page")), color: bandTone("page") },
  { value: "high", label: capitalize(bandLabel("high")), color: bandTone("high") },
  { value: "pipeline", label: capitalize(bandLabel("pipeline")), color: bandTone("pipeline") },
];

// A band filter keeps findings at or above the chosen band, in both views.
type FilterBand = "page" | "high" | "pipeline";
function isFilterBand(band: string): band is FilterBand {
  return band === "page" || band === "high" || band === "pipeline";
}

const SOURCES = [
  { value: "", label: "All sources" },
  { value: "cspm", label: "CSPM" },
  { value: "supply_chain", label: "Supply chain" },
  { value: "nuclei", label: "Nuclei" },
];

const PROVIDERS = [
  { value: "", label: "All providers" },
  { value: "aws", label: "AWS" },
  { value: "gcp", label: "GCP" },
  { value: "github", label: "GitHub" },
  { value: "kubernetes", label: "K8s" },
];

// Finding categories by check_id pattern — lets users filter out dominant
// categories (e.g. RBAC/privesc that flood the list) to surface other types.
const CATEGORIES = [
  { value: "", label: "All types" },
  { value: "privesc", label: "Privilege escalation", test: (id: string) => id.includes("privesc") || (id.includes("cluster-admin") && !id.includes("k8s-")) },
  { value: "k8s", label: "Kubernetes", test: (id: string) => id.startsWith("k8s-") },
  { value: "exposure", label: "Internet exposure", test: (id: string) => id.includes("public") || id.includes("internet") || id.includes("exposed") || id.includes("world-open") || id.includes("facing") || id.includes("eip") },
  { value: "dns", label: "DNS & takeover", test: (id: string) => id.includes("dns") || id.includes("cname") || id.includes("takeover") },
  { value: "cert", label: "Certificates", test: (id: string) => id.includes("cert") || id.includes("ssl-cert") },
  { value: "vulnerability", label: "Vulnerabilities", test: (id: string) => /^cve-/i.test(id) || /^ghsa-/i.test(id) || id.includes("osv") },
  { value: "network", label: "Network access", test: (id: string) => id.includes("security-group") || id.includes("firewall") || id.includes("node-port") || id.includes("sg-") },
  { value: "audit", label: "Audit & logging", test: (id: string) => id.includes("cloudtrail") || id.includes("logging") || id.includes("audit") },
];

// sourceLabel returns a short display label for a source value.
function sourceLabel(source?: string): string {
  if (!source) return "";
  if (source === "cspm") return "CSPM";
  if (source === "supply_chain") return "Supply chain";
  if (source === "nuclei") return "Nuclei";
  return source;
}

// isCVE returns true if the check_id looks like a CVE identifier.
function isCVE(checkID: string): boolean {
  return /^CVE-\d{4}-\d+$/i.test(checkID);
}

// checkImpactLine returns a short "why this matters" line for common check
// categories — visible on the collapsed card so users don't need to expand.
// Returns the differentiating insight only — NOT a restatement of the title.
// The card title already names the category (e.g. "IAM privilege escalation:
// iam:PutRolePolicy"), so this line must add something new, or it's noise.
function checkImpactLine(checkID: string): string {
  if (checkID.startsWith("aws-privesc-")) return "reaches admin in one step if this principal is compromised";
  if (checkID.startsWith("gcp-privesc-")) return "reaches project owner via this service-account grant";
  if (checkID.includes("cname-takeover")) return "subdomain takeover — external party can serve from this domain";
  if (checkID.includes("cluster-admin")) return "unrestricted cluster-admin access — all K8s resources";
  if (checkID.includes("wildcard-verbs")) return "ClusterRole with wildcard verbs — overly permissive RBAC";
  if (checkID.includes("public-ip") || checkID.includes("gce-public")) return "internet-facing compute instance";
  if (checkID.includes("node-port")) return "NodePort exposes service on every cluster node's IP";
  if (checkID.includes("no-ssl") || checkID.includes("no-tls")) return "unencrypted connections allowed";
  if (checkID.includes("public-bucket") || checkID.includes("s3-public")) return "publicly readable storage bucket";
  if (checkID.includes("world-open")) return "security group open to internet (0.0.0.0/0)";
  if (checkID.includes("cert-expir")) return "TLS certificate expiring — outage risk";
  if (checkID.includes("federated")) return "GitHub Actions can assume cloud IAM role via OIDC";
  return "";
}

type FindingView = "mustFix" | "startHere" | "all";

const FINDING_VIEWS: { id: FindingView; label: string }[] = [
  { id: "mustFix",   label: "Must fix" },
  { id: "startHere", label: "Start here" },
  { id: "all",       label: "All" },
];

// ?view= aliases. signals/hygiene/timeline are the All view with a filter or a
// sort applied, so they map onto All plus the filter they name. (Drift is its
// own route; ?view=drift lands on All.)
const VIEW_ALIASES: Record<string, { view: FindingView; band?: string; sort?: FindingSort }> = {
  signals:  { view: "all", band: "high" },   // High and above
  hygiene:  { view: "all", sort: "detected" },
  timeline: { view: "all", sort: "detected" },
  drift:    { view: "all" },
};

type FindingSort = "score" | "detected";

const SORTS: { value: FindingSort; label: string }[] = [
  { value: "score",    label: "Score" },
  { value: "detected", label: "Newest" },
];

// Filters derived from the URL. The URL is the single source of truth — there is
// no mirrored component state to drift out of sync with it.
type Filters = {
  view: FindingView;
  band: string;
  source: string;
  provider: string;
  category: string;
  owner: string;
  environment: string;
  q: string;
  sort: FindingSort;
  grouped: boolean;
};

// parseFilters reads every filter off the router's parsed search object (NOT the
// raw query string: the router JSON-encodes values, so a literal "0" round-trips
// as %220%22), applying the ?view= alias mapping so an alias lands somewhere
// equivalent.
function parseFilters(sp: Record<string, unknown>): Filters {
  const str = (k: string) => (sp[k] == null ? "" : String(sp[k]));
  const raw = str("view");
  const alias = VIEW_ALIASES[raw];
  const view: FindingView =
    alias?.view ??
    (raw === "startHere" || raw === "all" || raw === "mustFix" ? (raw as FindingView) : "mustFix");
  const sortParam = str("sort");
  return {
    view,
    band: str("band") || alias?.band || "",
    source: str("source"),
    provider: str("provider"),
    category: str("category"),
    owner: str("owner"),
    environment: str("environment"),
    q: str("q"),
    sort: sortParam === "detected" ? "detected" : sortParam === "score" ? "score" : alias?.sort ?? "score",
    grouped: str("grouped") !== "false",
  };
}

export function Findings() {
  const { location } = useRouterState();
  const navigate = useNavigate();
  // Every filter is read straight off the URL, so a findings view is fully
  // shareable/bookmarkable and survives reload. No filter may also live in
  // useState mirrored from the URL: that is two sources of truth for one value.
  const f = useMemo(() => parseFilters(location.search as Record<string, unknown>), [location.search]);
  const { view, band, source, provider, category, owner, environment, q, sort, grouped } = f;
  // Owner/environment filter server-side on the instance list; the grouped view
  // is built from per-check clusters that carry no owner, so either filter
  // lists instances rather than silently ignoring it.
  const routed = !!(owner || environment);

  // Latest parsed search, so a setParam called from a debounced callback doesn't
  // write from a closure that captured an older location.
  const searchRef = useRef(location.search as Record<string, unknown>);
  searchRef.current = location.search as Record<string, unknown>;

  // setParams updates one or more filters in the URL ("" clears) and navigates.
  function setParams(updates: Record<string, string | boolean>) {
    const next: Record<string, unknown> = { ...searchRef.current };
    for (const [key, value] of Object.entries(updates)) {
      if (value === "") delete next[key]; else next[key] = value;
    }
    void navigate({ to: "/investigate/findings", search: next as Record<string, string> });
  }
  function setParam(key: string, value: string | boolean) {
    setParams({ [key]: value });
  }

  // Must fix / Start here are pre-filtered worklists that do not take the shared
  // filters, so changing one from those tabs moves to All with it applied rather
  // than leaving an inert control behind.
  function setFilter(key: string, value: string) {
    if (view === "all") setParam(key, value);
    else setParams({ [key]: value, view: "all" });
  }

  function switchView(v: FindingView) {
    setParam("view", v === "mustFix" ? "" : v);
  }

  // Search input: local state for keystroke responsiveness, debounced into the
  // URL (the real source of truth) so search survives a refresh or a share.
  const [qInput, setQInput] = useState(q);
  const committedQ = useRef(q);
  // Collapsed by default, same pattern as Decisions' action-class legend — the
  // must-fix tier badges carry a hover title, but that's easy to miss.
  const [showMustFixLegend, setShowMustFixLegend] = useState(false);
  useEffect(() => {
    // URL changed from outside the box (deep link, cluster title link, clear).
    if (q !== committedQ.current) {
      committedQ.current = q;
      setQInput(q);
    }
  }, [q]);
  useEffect(() => {
    if (qInput === committedQ.current) return;
    const t = setTimeout(() => {
      committedQ.current = qInput;
      if (view === "all") setParam("q", qInput);
      else setParams({ q: qInput, view: "all" });
    }, 300);
    return () => clearTimeout(t);
  }, [qInput]);

  function clearAll() {
    committedQ.current = "";
    setQInput("");
    void navigate({ to: "/investigate/findings", search: view === "mustFix" ? {} : { view } });
  }

  return (
    <div>
      <PageHeader
        title="Findings"
        subtitle="Risk-scored across CSPM, scanning, and supply chain."
      />

      {/* View switcher */}
      <div role="tablist" aria-label="Finding views" className="mb-4 flex gap-0.5 border-b border-border-subtle -mx-5 px-5">
        {FINDING_VIEWS.map((v) => (
          <button
            key={v.id}
            role="tab"
            aria-selected={view === v.id}
            onClick={() => switchView(v.id)}
            className={`border-b-2 px-3 py-2 text-xs transition-colors ${
              view === v.id
                ? "border-teal text-text"
                : "border-transparent text-text-3 hover:text-text-2"
            }`}
          >
            {v.label}
          </button>
        ))}
      </div>

      {/* Filters — shown on every view so they're discoverable. The band pills and
          the grouping/sort controls only apply to All; Must fix and Start here
          pre-filter by their own definition, so those controls are hidden there. */}
      <div className="mb-4 flex flex-wrap items-center gap-3">
        {/* Band filter */}
        {view === "all" && (
          <>
            <div className="flex gap-0.5">
              {BANDS.map((b) => (
                <button
                  key={b.value || "all"}
                  onClick={() => setParam("band", b.value)}
                  className={`rounded px-2.5 py-1 text-[11px] transition-colors ${
                    band === b.value
                      ? "bg-surface-3 text-text"
                      : `text-text-3 hover:text-text-2 ${b.color ?? ""}`
                  }`}
                >
                  {b.label}
                </button>
              ))}
            </div>
            <div className="h-3 w-px bg-border-subtle" />
          </>
        )}

        {/* Source filter — teal highlight when active so filter state is visible at a glance */}
        <select
          value={source}
          onChange={(e) => setFilter("source", e.target.value)}
          aria-label="Source filter"
          className={`rounded border px-2 py-1 text-[11px] outline-none focus:border-teal transition-colors ${
            source ? "border-teal/60 bg-teal/5 text-teal" : "border-border-subtle bg-bg text-text-2"
          }`}
        >
          {SOURCES.map((s) => <option key={s.value} value={s.value}>{s.label}</option>)}
        </select>

        {/* Provider filter — teal highlight when active */}
        <select
          value={provider}
          onChange={(e) => setFilter("provider", e.target.value)}
          aria-label="Provider filter"
          className={`rounded border px-2 py-1 text-[11px] outline-none focus:border-teal transition-colors ${
            provider ? "border-teal/60 bg-teal/5 text-teal" : "border-border-subtle bg-bg text-text-2"
          }`}
        >
          {PROVIDERS.map((p) => <option key={p.value} value={p.value}>{p.label}</option>)}
        </select>

        {/* Category / type filter — lets users filter out dominant types (e.g. privesc) */}
        <select
          value={category}
          onChange={(e) => setFilter("category", e.target.value)}
          aria-label="Type filter"
          className={`rounded border px-2 py-1 text-[11px] outline-none focus:border-teal transition-colors ${
            category ? "border-teal/60 bg-teal/5 text-teal" : "border-border-subtle bg-bg text-text-2"
          }`}
        >
          {CATEGORIES.map((c) => <option key={c.value} value={c.value}>{c.label}</option>)}
        </select>

        <OwnerEnvFilters owner={owner} environment={environment} onChange={setFilter} />

        <div className="relative flex-1 max-w-xs">
          <input
            value={qInput}
            onChange={(e) => setQInput(e.target.value)}
            placeholder="search findings…"
            className="w-full rounded border border-border-subtle bg-bg px-2.5 py-1 pr-7 text-[11px] text-text outline-none focus:border-teal"
          />
          {qInput && (
            <button onClick={() => { committedQ.current = ""; setQInput(""); setParam("q", ""); }} className="absolute right-2 top-1/2 -translate-y-1/2 text-text-3 hover:text-text-2">✕</button>
          )}
        </div>

        <div className="ml-auto flex items-center gap-2">
          {/* Clear all — visible when any non-default filter is active */}
          {(band || source || provider || category || owner || environment || qInput) && (
            <button
              onClick={clearAll}
              className="text-[11px] text-text-3 hover:text-red transition-colors"
              title="Clear all filters"
            >
              ✕ clear
            </button>
          )}
          {view === "all" && (
            <>
              {/* Sort — the flat view can sort by detection date. Grouped stays
                  score-ordered. */}
              {(!grouped || routed) && (
                <select
                  value={sort}
                  onChange={(e) => setParam("sort", e.target.value === "score" ? "" : e.target.value)}
                  aria-label="Sort"
                  className="rounded border border-border-subtle bg-bg px-2 py-1 text-[11px] text-text-2 outline-none focus:border-teal"
                >
                  {SORTS.map((s) => <option key={s.value} value={s.value}>Sort: {s.label}</option>)}
                </select>
              )}
              {routed ? (
                <span className="text-[11px] text-text-3" title="Grouped checks carry no owner or environment">
                  owner/environment filters list instances
                </span>
              ) : (
                <>
                  <ToggleBtn label="Grouped" active={grouped} onClick={() => setParam("grouped", "")} />
                  <ToggleBtn label="All instances" active={!grouped} onClick={() => setParam("grouped", false)} />
                </>
              )}
            </>
          )}
          <button
            onClick={() => setShowMustFixLegend((v) => !v)}
            className="text-[11px] text-text-3 underline decoration-dotted hover:text-teal"
          >
            {showMustFixLegend ? "hide" : "what do the urgency tiers mean?"}
          </button>
        </div>
      </div>

      {showMustFixLegend && (
        <div className="mb-4">
          <MustFixLegend />
        </div>
      )}

      {/* Main content — gated per view */}
      {view === "mustFix" && <MustFixView search={q} />}
      {view === "startHere" && <StartHereView search={q} />}
      {view === "all" && (
        grouped && !routed
          ? <ClusterView band={band} source={source} provider={provider} category={category} search={q} />
          : <InstanceView band={band} source={source} provider={provider} category={category} owner={owner} environment={environment} search={q} sort={sort} />
      )}
    </div>
  );
}

// ── Grouped (clustered) view ──────────────────────────────────────────────────

// matchesProvider filters a finding by provider using its check_id prefix (the
// /api/findings and clusters endpoints have no provider field). An empty or
// unrecognised provider matches everything. Shared by ClusterView and InstanceView.
function matchesProvider(provider: string, checkId: string, source: string): boolean {
  switch (provider) {
    case "aws": return checkId.startsWith("aws-") || checkId.startsWith("CVE");
    case "gcp": return checkId.startsWith("gcp-") || checkId.startsWith("gcp_");
    case "github": return checkId.startsWith("github-") || source.includes("supply");
    case "kubernetes": return checkId.startsWith("k8s-");
    default: return true;
  }
}

function ClusterView({ band, source, provider, category, search }: { band: string; source: string; provider: string; category: string; search: string }) {
  const isAdmin = useIsAdmin();
  const [showExpected, setShowExpected] = useState(false);
  const { data, isLoading, isError } = useFindingClusters();
  const all = data?.items ?? [];

  // Apply client-side filters
  const sq = search.trim().toLowerCase();
  const filtered = all.filter((c) => {
    if (isFilterBand(band) && !bandAtLeast(c.worst_band, band)) return false;
    if (source && (c.source ?? "") !== source) return false;
    if (!matchesProvider(provider, c.check_id, c.source ?? "")) return false;
    if (sq && !c.title.toLowerCase().includes(sq) && !c.check_id.toLowerCase().includes(sq)) return false;
    if (category) {
      const cat = CATEGORIES.find((ct) => ct.value === category);
      if (cat?.test && !cat.test(c.check_id.toLowerCase())) return false;
    }
    return true;
  });

  const expectedCount = filtered.filter((c) => c.worst_band === "monitor").length;
  const clusters = showExpected ? filtered : filtered.filter((c) => c.worst_band !== "monitor");

  return (
    <>
      {/* Actionable count + monitor-band toggle */}
      {!isLoading && !isError && (
        <div className="mb-3 flex items-center justify-between text-[11px]">
          <span className="text-text-2">
            <span className="font-medium text-text">{clusters.length}</span>{" "}
            {clusters.length === 1 ? "issue" : "issues"}{" "}
            {sq ? (
              <>
                matching{" "}
                <span className="rounded bg-surface-3 px-1.5 py-0.5 font-mono text-[11px] text-text-2">"{search}"</span>
              </>
            ) : (
              "need attention"
            )}
            {data?.truncated && (
              <span className="text-text-3">
                {" "}· showing the top {all.length} of {data.total_checks} checks by score
              </span>
            )}
          </span>
          {expectedCount > 0 && (
            <button onClick={() => setShowExpected((v) => !v)} className="text-text-3 hover:text-teal">
              {showExpected ? "▾ hide" : "▸ show"} {expectedCount} scored under {SCORE_THRESHOLDS.pipeline}
            </button>
          )}
        </div>
      )}
      {isLoading && <Loading />}
      {isError && (
        <ErrorNote message="Could not load findings — the service may be temporarily busy. Refresh to retry." />
      )}
      {!isLoading && !isError && clusters.length === 0 && all.length === 0 && (
        <Empty message="No findings. Connect a source and run a sync." />
      )}
      {!isLoading && !isError && clusters.length === 0 && all.length > 0 && (
        <div className="rounded-lg border border-border-subtle bg-surface p-4 text-[11px] text-text-2">
          {/* Use filtered count not total — "All 500" is misleading when search narrows to 89 */}
          {sq || band || source || provider || category ? (
            <>
              <span className="font-medium text-text">{filtered.length}</span> matching finding{filtered.length !== 1 ? "s" : ""} {filtered.length === 0 ? "found." : `scored under ${SCORE_THRESHOLDS.pipeline} (monitor band), below the pipeline threshold.`}{" "}
              {filtered.length > 0 && (
                <button onClick={() => setShowExpected(true)} className="text-teal hover:underline">Show them.</button>
              )}
              {filtered.length === 0 && sq && (
                <span className="ml-1 text-text-3">These findings may have score=0 (enrichment pending after recent sync) — check back in a few minutes.</span>
              )}
            </>
          ) : (
            <>
              All {clusters.length === 0 && filtered.length > 0 ? filtered.length : all.length} finding{all.length !== 1 ? "s" : ""} scored under {SCORE_THRESHOLDS.pipeline} (monitor band), below the pipeline threshold.{" "}
              <button onClick={() => setShowExpected(true)} className="text-teal hover:underline">Show them.</button>
            </>
          )}
        </div>
      )}
      <div className="space-y-2">
        {clusters.map((c) => (
          <ClusterCard key={c.check_id} cluster={c} isAdmin={isAdmin} />
        ))}
      </div>
    </>
  );
}

// ClusterCard shows a finding cluster for exploration — score, fix, agent recommendation.
// Governance actions (approve/deny) live in Decisions only.
function ClusterCard({ cluster: c, isAdmin }: { cluster: FindingCluster; isAdmin: boolean }) {
  const [open, setOpen] = useState(false);
  const isEnriching = (!c.max_score || c.max_score === 0) && c.instances > 0;

  const bandAccent = c.worst_band === 'page' ? '#ef4444' : c.worst_band === 'high' ? '#f97316' : c.worst_band === 'pipeline' ? '#f59e0b' : 'rgba(255,255,255,0.07)';

  return (
    <div className="glass rounded-xl overflow-hidden activity-shimmer-hover"
         style={{borderLeft: `3px solid ${bandAccent}`}}>
      {/* div+role instead of <button> — <Link> (→<a>) inside <button> is invalid HTML
          and causes browser-specific expand/collapse inconsistencies. */}
      <div
        className="card-hover flex w-full items-start gap-3 rounded-lg p-3 text-left cursor-pointer select-none"
        onClick={() => setOpen((v) => !v)}
        role="button"
        tabIndex={0}
        onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); setOpen((v) => !v); } }}
      >
        {/* Score badge with band label below */}
        <div className="flex flex-col items-center gap-0.5 shrink-0">
          {isEnriching ? (
            <div className="flex h-9 w-9 items-center justify-center rounded border border-border-subtle bg-surface-2">
              <span className="animate-pulse text-[11px] text-text-3">···</span>
            </div>
          ) : (
            <ScoreBadge score={c.max_score} band={c.worst_band} />
          )}
        </div>

        <div className="min-w-0 flex-1">
          {/* Top row: chevron + resource count + title + badges */}
          <div className="flex flex-wrap items-center gap-2">
            <span className="inline-flex items-center gap-1 text-text-3 text-[11px] shrink-0">
              {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
              <span className="rounded bg-teal/10 px-1.5 py-0.5 text-[11px] font-medium text-teal tabular-nums">
                {c.resources}
              </span>
            </span>
            {/* Title deep-links to filtered view — stopPropagation so the
                parent div toggle doesn't also fire and filter out all other clusters. */}
            <Link
              to="/investigate/findings"
              search={{ q: c.check_id } as Record<string, string>}
              onClick={(e) => e.stopPropagation()}
              className="font-medium text-text hover:text-teal transition-colors"
              title={`Filter to ${c.check_id}`}
            >
              {c.title}
            </Link>
            {c.known_exploited && <KevBadge />}
            {/* Source label */}
            {c.source && (
              <span className="rounded bg-surface-3 px-1.5 py-0.5 text-[11px] text-text-3">{sourceLabel(c.source)}</span>
            )}
            {/* check_id: CVE links to NVD, others show copy-on-right-click */}
            {isCVE(c.check_id) ? (
              <a
                href={`https://nvd.nist.gov/vuln/detail/${c.check_id}`}
                target="_blank"
                rel="noopener noreferrer"
                onClick={e => e.stopPropagation()}
                className="font-mono text-[11px] text-teal hover:underline"
                title="View on NVD"
              >
                {c.check_id}
              </a>
            ) : (
              <Link
                to="/investigate/findings"
                search={{ q: c.check_id } as Record<string, string>}
                onClick={(e) => e.stopPropagation()}
                className="font-mono text-[11px] text-text-3 hover:text-teal transition-colors"
              >
                {c.check_id}
              </Link>
            )}
          </div>

          {/* Score drivers — explain why the score is high without expanding */}
          {!isEnriching && (c.known_exploited || checkImpactLine(c.check_id)) && (
            <p className="mt-0.5 text-[11px] text-text-3">
              {c.known_exploited ? "known exploited vulnerability (CISA KEV)" : checkImpactLine(c.check_id)}
            </p>
          )}

          {/* Remediation hint — visible without expanding */}
          {c.remediation && (
            <p className="mt-0.5 max-w-prose truncate text-[11px] text-text-3" title={c.remediation}>
              <span className="text-teal">Fix: </span>{c.remediation}
            </p>
          )}

        </div>
      </div>

      {open && (
        <div className="border-t border-border-subtle/50 px-3 py-3">
          {c.remediation && (
            <p className="mb-3 rounded border border-teal/20 bg-teal/5 px-2.5 py-2 text-[11px] leading-relaxed text-text-2">
              <span className="font-medium text-teal">Fix: </span>{c.remediation}
            </p>
          )}
          <div className="mb-3">
            <button
              onClick={(e) => {
                e.stopPropagation();
                const facts = [`check: ${c.check_id}`, `${c.resources} affected resource${c.resources !== 1 ? "s" : ""}`];
                if ((c.max_score ?? 0) > 0) facts.push(`score: ${c.max_score}`);
                if (c.known_exploited) facts.push("CISA KEV — known exploited");
                if (c.remediation) facts.push(`suggested fix: ${c.remediation}`);
                openAssistant({
                  subject: `Investigate finding: ${c.title}`,
                  facts,
                  question: "What is the risk and how should I prioritise remediation?",
                });
              }}
              className="rounded-lg border border-teal/30 bg-teal/10 px-3 py-1.5 text-[11px] font-medium text-teal transition-colors hover:bg-teal/20"
            >
              Ask AI →
            </button>
          </div>
          <ClusterInstances checkID={c.check_id} isAdmin={isAdmin} />
        </div>
      )}
    </div>
  );
}

// ClusterInstances lazily fetches the instances for one check when expanded.
// Groups by resource type so it's immediately clear what categories of thing
// are affected (packages, EC2 instances, IAM roles, etc.) rather than just
// an opaque account number that only works for AWS ARNs.
function ClusterInstances({ checkID, isAdmin }: { checkID: string; isAdmin: boolean }) {
  const { data, isLoading } = useFindings({ check_id: checkID, sort: "score" });
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const items = data?.pages.flatMap((p) => p.items) ?? [];
  if (isLoading) return <Loading />;
  if (items.length === 0) return <Empty message="No instances." />;

  // Group by type, falling back to source when type is absent.
  const groups = new Map<string, Finding[]>();
  for (const f of items) {
    const key = f.resource_type || f.source || "unknown";
    (groups.get(key) ?? groups.set(key, []).get(key)!).push(f);
  }

  // Sort groups: higher-scored groups first.
  const sortedGroups = [...groups.entries()].sort(
    (a, b) => Math.max(...b[1].map((f) => f.score)) - Math.max(...a[1].map((f) => f.score)),
  );

  return (
    <div className="space-y-4">
      {sortedGroups.map(([type, fs]) => (
        <div key={type}>
          <div className="mb-1.5 flex items-center gap-2 text-[11px] uppercase tracking-wide text-text-3">
            <span className="text-text-2">{typeGroupLabel(type)}</span>
            <span>· {fs.length} affected</span>
            {accountOf(fs[0]?.resource_id) && (
              <span className="rounded bg-surface-3 px-1.5 py-0.5 font-mono text-[11px] normal-case text-text-3">
                {accountOf(fs[0].resource_id)}
              </span>
            )}
          </div>
          <table className="w-full border-collapse text-sm">
            <tbody>
              {fs.map((f) => (
                <FindingRow key={f.id} finding={f} isAdmin={isAdmin} compact onOpenPanel={setSelectedFindingId} />
              ))}
            </tbody>
          </table>
        </div>
      ))}
      <FindingDetailPanel findingId={selectedFindingId} onClose={() => setSelectedFindingId(null)} />
    </div>
  );
}

// typeGroupLabel makes resource_type values human-readable as section headers.
function typeGroupLabel(type: string): string {
  const map: Record<string, string> = {
    package: "Packages", ec2_instance: "EC2 Instances", iam_role: "IAM Roles",
    iam_user: "IAM Users", gcp_service_account: "Service Accounts",
    s3_bucket: "S3 Buckets", gcs_bucket: "GCS Buckets", k8s_pod: "Pods",
    k8s_deployment: "Deployments", k8s_service: "Services",
    security_group: "Security Groups", github_repo: "Repos",
    gce_instance: "GCE Instances", subnet: "Subnets", dns_record: "DNS Records",
  };
  return map[type] ?? type.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}

// accountOf pulls the AWS account id out of an ARN resource id, or null.
function accountOf(resourceID?: string): string | null {
  const m = resourceID?.match(/arn:aws:[^:]*:[^:]*:(\d{12}):/);
  return m ? m[1] : null;
}

// repoShort trims an org prefix so "example-org/infra" → "infra".
function repoShort(repo: string): string {
  const slash = repo.lastIndexOf("/");
  return slash >= 0 ? repo.slice(slash + 1) : repo;
}

// ── Flat (all instances) view ─────────────────────────────────────────────────

function InstanceView({ band, source, provider, category, owner, environment, search, sort }: { band: string; source: string; provider: string; category: string; owner?: string; environment?: string; search: string; sort?: "score" | "detected" }) {
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkReason, setBulkReason] = useState("");
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const isAdmin = useIsAdmin();
  const bulk = useBulkSuppress();
  const sentinelRef = useRef<HTMLDivElement>(null);

  const filter: FindingFilter = {};
  if (source) filter.source = source;
  if (sort) filter.sort = sort;
  if (owner) filter.owner = owner;
  if (environment) filter.environment = environment;
  // Band → minScore mapping. The band pills and search live in the parent
  // toolbar; this view must not carry its own, which would shadow the parent
  // search and apply a second, different score threshold.
  if (isFilterBand(band)) filter.min_score = SCORE_THRESHOLDS[band];
  const query = useFindings(filter);
  const { data, isLoading, isError, error, hasNextPage, isFetchingNextPage } = query;

  // Auto-load next page when the sentinel scrolls into view.
  useInfiniteSentinel(sentinelRef, query);

  // Client-side search over the fetched page (same pattern as grouped ClusterView)
  const sq = search.trim().toLowerCase();
  const cat = category ? CATEGORIES.find((c) => c.value === category) : null;
  const items = (data?.pages.flatMap((p) => p.items) ?? [])
    .filter((f) => !sq || f.title.toLowerCase().includes(sq) || (f.check_id ?? "").toLowerCase().includes(sq) || (f.resource_id ?? "").toLowerCase().includes(sq))
    .filter((f) => !cat?.test || cat.test((f.check_id ?? "").toLowerCase()))
    // Client-side provider filter (same check_id-prefix heuristic as ClusterView);
    // the /api/findings endpoint has no provider param.
    .filter((f) => matchesProvider(provider, f.check_id ?? "", f.source ?? ""));

  // Multi-select bulk suppress (admin) — the team-triage path. Selection is
  // scoped to the rows currently loaded; select-all covers the fetched page.
  const selectable = isAdmin;
  const selectableItems = items.filter((f) => !f.is_suppressed);
  const allSelected = selectableItems.length > 0 && selectableItems.every((f) => selected.has(f.id));
  function toggle(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }
  function toggleAll() {
    setSelected(allSelected ? new Set() : new Set(selectableItems.map((f) => f.id)));
  }
  // mutate (not mutateAsync): a failed bulk call surfaces via bulk.error in
  // the bar instead of an unhandled promise rejection, and keeps the selection.
  function bulkSuppress(expiresAt: string) {
    const reason = bulkReason.trim();
    if (!reason || selected.size === 0 || bulk.isPending) return;
    bulk.mutate(
      { ids: [...selected], reason, expiresAt },
      { onSuccess: () => { setSelected(new Set()); setBulkReason(""); } },
    );
  }

  return (
    <>
      {/* Bulk action bar — appears when rows are selected (admin) */}
      {selectable && selected.size > 0 && (
        <BulkSuppressBar
          accent="amber"
          count={selected.size}
          reason={bulkReason}
          onReasonChange={setBulkReason}
          onSuppress={bulkSuppress}
          onClear={() => setSelected(new Set())}
          isPending={bulk.isPending}
          errorMessage={bulk.isError ? (bulk.error as Error).message : undefined}
        />
      )}

      {isLoading && <Loading />}
      {isError && <ErrorNote message={(error as Error).message} />}
      {!isLoading && items.length === 0 && <Empty message="No findings match these filters." />}
      {items.length > 0 && (
        <>
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-border-subtle text-left text-[11px] uppercase text-text-3">
                {selectable && (
                  <th className="w-6 py-2">
                    <input type="checkbox" checked={allSelected} onChange={toggleAll} aria-label="select all findings" />
                  </th>
                )}
                <th className="py-2 font-medium">Score</th>
                <th className="py-2 font-medium">Title</th>
                <th className="py-2 font-medium">Severity</th>
                <th className="py-2 font-medium">Resource</th>
                <th className="py-2 font-medium">Source</th>
                {isAdmin && <th className="py-2 font-medium">Actions</th>}
              </tr>
            </thead>
            <tbody>
              {items.map((f) => (
                <FindingRow
                  key={f.id}
                  finding={f}
                  isAdmin={isAdmin}
                  selectable={selectable}
                  selected={selected.has(f.id)}
                  onToggleSelect={() => toggle(f.id)}
                  onOpenPanel={setSelectedFindingId}
                />
              ))}
            </tbody>
          </table>
          {/* Sentinel — auto-triggers next page fetch when scrolled into view */}
          <div ref={sentinelRef} className="h-px" />
          {isFetchingNextPage && (
            <div className="mt-3 text-center text-[11px] text-text-3">Loading…</div>
          )}
          {!hasNextPage && items.length > 0 && (
            <div className="mt-3 text-center text-[11px] text-text-3">{items.length} issues total</div>
          )}
          <div className="mt-2 text-right">
            <ExportFindingsButton items={items} partial={!!hasNextPage} />
          </div>
        </>
      )}

      <FindingDetailPanel findingId={selectedFindingId} onClose={() => setSelectedFindingId(null)} />
    </>
  );
}

function ToggleBtn({ label, active, onClick }: { label: string; active: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className={`rounded px-2.5 py-1 text-[11px] ${active ? "bg-surface-3 text-text" : "text-text-3 hover:text-text-2"}`}
    >
      {label}
    </button>
  );
}

function FindingRow({ finding: f, isAdmin, compact, selectable, selected, onToggleSelect, onOpenPanel }: { finding: Finding; isAdmin: boolean; compact?: boolean; selectable?: boolean; selected?: boolean; onToggleSelect?: () => void; onOpenPanel?: (id: string) => void }) {
  const suppress = useSuppressFinding();
  const unsuppress = useUnsuppressFinding();
  const [open, setOpen] = useState(false);
  const [suppressOpen, setSuppressOpen] = useState(false);
  const [reason, setReason] = useState("");
  const [expiry, setExpiry] = useState(() => expiryBounds().initial);
  // +1 column when the selection checkbox is shown.
  const colSpan = (isAdmin ? (compact ? 5 : 6) : (compact ? 4 : 5)) + (selectable ? 1 : 0);

  // The API states this outright. It must not be guessed from score === 0 &&
  // !score_band, which is indistinguishable from a genuinely zero-scored finding
  // — real, fully-enriched low-risk findings would render as "still working on
  // it" forever, and a pipeline that had never run would look like one that had.
  const isEnriching = f.enrichment_state === "never_enriched";

  // Compact rows eagerly fetch context so the mini-preview populates without
  // a click. Normal rows stay lazy (only fetch when the row is expanded).
  const detail = useFinding(compact ? f.id : (open ? f.id : ""));

  const ctx = detail.data;

  return (
    <>
      <tr
        // Primary click opens the slide-over — the house convention for a
        // single-entity row. The chevron in the title cell still toggles the
        // inline detail, which the suppress form and the mini-preview hang off.
        onClick={() => (onOpenPanel ? onOpenPanel(f.id) : setOpen(v => !v))}
        className={`group border-b border-border-subtle/50 hover:bg-surface cursor-pointer ${f.is_suppressed ? "opacity-50" : ""} ${open ? "bg-surface" : ""}`}
      >
        {/* Selection checkbox — suppressed rows aren't selectable */}
        {selectable && (
          <td className="py-2 pr-1 align-top" onClick={(e) => e.stopPropagation()}>
            <input
              type="checkbox"
              checked={!!selected}
              disabled={f.is_suppressed}
              onChange={onToggleSelect}
              aria-label={`select ${f.title}`}
            />
          </td>
        )}
        {/* Score column with band label */}
        <td className="py-2 pr-3 align-top">
          <div className="flex flex-col items-start gap-0.5">
            {isEnriching ? (
              <div className="flex h-8 w-8 items-center justify-center rounded border border-border-subtle bg-surface-2">
                <span className="animate-pulse text-[11px] text-text-3">···</span>
              </div>
            ) : (
              <ScoreBadge score={f.score} band={f.score_band} />
            )}
          </div>
        </td>

        {/* Title column */}
        <td className="py-2 pr-3">
          <div className="flex items-center gap-1.5 text-text group-hover:text-teal transition-colors flex-wrap">
            <button
              type="button"
              aria-expanded={open}
              aria-label={open ? `collapse details for ${f.title}` : `expand details for ${f.title}`}
              onClick={(e) => { e.stopPropagation(); setOpen(v => !v); }}
              className="shrink-0 text-text-3 hover:text-teal"
            >
              {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
            </button>
            <span className="font-medium">{compact ? shortenId(f.resource_id) || f.title : f.title}</span>
            {f.known_exploited && <KevBadge />}
            {f.is_suppressed && (
              <span className="rounded border border-border-subtle bg-surface px-1 py-0.5 text-[11px] font-medium uppercase text-text-3">suppressed</span>
            )}
            {f.exception_expired && <ExceptionExpiredBadge />}
            <OwnerBadge finding={f} />
            <EnvironmentBadge env={f.environment} />
            {/* Evidence-backed urgency (the must-fix tier). */}
            <MustFixBadge cls={f.must_fix_class} state={f.enrichment_state} />
            <StalenessNote state={f.enrichment_state} />
            {/* check_id in flat view — helps identify the specific rule without expanding */}
            {!compact && f.check_id && (
              isCVE(f.check_id) ? (
                <a
                  href={`https://nvd.nist.gov/vuln/detail/${f.check_id}`}
                  target="_blank" rel="noopener noreferrer"
                  onClick={e => e.stopPropagation()}
                  className="font-mono text-[11px] text-teal hover:underline"
                >{f.check_id}</a>
              ) : (
                <span className="font-mono text-[11px] text-text-3">{f.check_id}</span>
              )
            )}
          </div>
          {/* Compact mode: mini-preview (provenance, blast radius, remediation) */}
          {compact && (
            <div className="mt-0.5 space-y-0.5">
              {/* Mini-preview: provenance, blast radius, remediation hint */}
              <div className="flex flex-wrap items-center gap-x-2.5 gap-y-0.5 text-[11px]">
                {ctx?.provenance?.source_repo && (
                  <span className="text-text-3">from{" "}
                    {ctx.provenance.source_repo.includes('/') ? (
                      <a
                        href={`https://github.com/${ctx.provenance.source_repo.replace(/^github\.com\//, '')}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        onClick={e => e.stopPropagation()}
                        className="text-teal hover:underline"
                      >
                        {repoShort(ctx.provenance.source_repo)}
                      </a>
                    ) : (
                      <span className="text-text-2">{repoShort(ctx.provenance.source_repo)}</span>
                    )}
                  </span>
                )}
                {(ctx?.blast?.count ?? 0) > 0 && (
                  ctx?.resource_id && !ctx.resource_id.startsWith("pkg:") ? (
                    <Link
                      to="/investigate/assets/$id"
                      params={{ id: ctx.resource_id }}
                      hash="blast-radius"
                      onClick={e => e.stopPropagation()}
                      className="text-teal hover:underline"
                    >
                      {ctx.blast!.count} reachable →
                    </Link>
                  ) : (
                    <span className="text-text-3">{ctx!.blast!.count} {ctx?.resource_id?.startsWith("pkg:") ? (ctx!.blast!.count === 1 ? "service" : "services") : "reachable"}</span>
                  )
                )}
                {ctx?.reasoning?.confidence_band === "low" && (
                  <span className="rounded bg-amber/10 px-1.5 py-0.5 text-[11px] font-medium text-amber">low confidence</span>
                )}
                {ctx?.remediation && !ctx?.provenance?.source_repo && (
                  <span className="max-w-xs truncate text-text-3 italic" title={ctx.remediation}>
                    {ctx.remediation.length > 55 ? ctx.remediation.slice(0, 55) + "…" : ctx.remediation}
                  </span>
                )}
                {!ctx && detail.isLoading && (
                  <span className="text-text-3 animate-pulse">···</span>
                )}
              </div>
            </div>
          )}
          {/* Flat (non-compact) mode: mini-preview when expanded */}
          {!compact && open && (
            <div className="mt-0.5 flex flex-wrap items-center gap-x-2.5 gap-y-0.5 text-[11px]">
              {ctx?.reasoning?.confidence_band === "low" && (
                <span className="rounded bg-amber/10 px-1.5 py-0.5 text-[11px] font-medium text-amber">low confidence</span>
              )}
            </div>
          )}
        </td>

        {/* Severity: always muted — score badge is the primary risk signal.
            Severity text is kept for reference but never colored. */}
        <td className="py-2 pr-3">
          <span
            className="text-[11px] text-text-3 capitalize"
            title={`Detection severity: ${f.severity}`}
          >
            {f.severity}
          </span>
        </td>

        {/* Resource column: link to /assets/$id in flat view */}
        {!compact && (
          <td className="py-2 pr-3">
            {f.resource_id ? (
              <Link
                to="/investigate/assets/$id"
                params={{ id: f.resource_id }}
                onClick={e => e.stopPropagation()}
                className="font-mono text-[11px] text-text-2 hover:text-teal transition-colors truncate max-w-[200px] block"
                title={f.resource_id}
              >
                {shortenId(f.resource_id)}
              </Link>
            ) : (
              <span className="font-mono text-[11px] text-text-2">—</span>
            )}
          </td>
        )}

        {/* Source / region column */}
        <td className="py-2 text-[11px] text-text-3">
          {compact ? (
            <span>{f.region}</span>
          ) : (
            <span className="rounded bg-surface-3 px-1.5 py-0.5 text-[11px] text-text-3">{sourceLabel(f.source)}</span>
          )}
        </td>

        {/* Actions column */}
        {isAdmin && (
          <td className="py-2" onClick={e => e.stopPropagation()}>
            {f.is_suppressed ? (
              <Button onClick={() => unsuppress.mutate(f.id)} disabled={unsuppress.isPending}>Unsuppress</Button>
            ) : (
              // The suppress form lives in the inline detail row, so arming it
              // must also expand that row — otherwise the click looks inert.
              <Button onClick={() => { setSuppressOpen((v) => !v); setOpen(true); }}>Suppress</Button>
            )}
          </td>
        )}
      </tr>

      {/* Inline detail — no navigation required */}
      {open && (
        <tr className="border-b border-border-subtle/50 bg-surface/60">
          <td colSpan={colSpan} className="px-3 py-3">
            {/* Suppress form — inline when Suppress button is clicked */}
            {isAdmin && suppressOpen && !f.is_suppressed && (
              <form
                className="mb-3 flex items-end gap-2 rounded border border-amber/20 bg-amber/5 px-3 py-2.5"
                onClick={e => e.stopPropagation()}
                onSubmit={(e) => {
                  e.preventDefault();
                  suppress.mutate(
                    { id: f.id, reason, expiresAt: expiryToISO(expiry) },
                    { onSuccess: () => { setSuppressOpen(false); setReason(""); } },
                  );
                }}
              >
                <div className="flex-1">
                  <Field label="Reason for suppression" value={reason} onChange={(e) => setReason(e.target.value)}
                    placeholder="why this finding is being suppressed" required />
                </div>
                <ExpiryPicker value={expiry} onChange={setExpiry} />
                <Button variant="primary" type="submit" disabled={suppress.isPending || !reason || !expiry}>
                  {suppress.isPending ? "Suppressing…" : "Confirm"}
                </Button>
                <Button type="button" onClick={() => setSuppressOpen(false)}>Cancel</Button>
              </form>
            )}
            {suppress.isError && <p className="mb-2 text-[11px] text-red">{(suppress.error as Error).message}</p>}
            {detail.isLoading ? (
              <div className="text-[11px] text-text-3">Loading detail…</div>
            ) : ctx ? (
              <div className="space-y-2.5">
                {/* Remediation — most important, up top */}
                {ctx.remediation && (
                  <div className="rounded border border-teal/20 bg-teal/5 px-3 py-2 text-[11px]">
                    <span className="font-semibold text-teal">Fix: </span>
                    <span className="text-text-2">{ctx.remediation}</span>
                  </div>
                )}

                {/* Score factors — immediately after remediation so score justification is prominent */}
                {ctx.factors && ctx.factors.length > 0 && (
                  <div className="rounded border border-border-subtle/40 bg-surface-2/50 px-3 py-2">
                    <div className="mb-1.5 text-[11px] uppercase tracking-wide text-text-3">Why score {ctx.score}</div>
                    <div className="flex flex-wrap gap-x-4 gap-y-0.5">
                      {ctx.factors.map((fac, i) => (
                        <span key={i} className="text-[11px] text-text-3">
                          <span className="capitalize text-text-2">{(fac.source ?? "").replace(/_/g, " ")}</span>
                          {fac.detail && <span className="ml-1">{fac.detail}</span>}
                          {fac.points != null && <span className="ml-1 text-text tabular-nums">{fac.points >= 0 ? `+${fac.points}` : fac.points}</span>}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Exposure pills — promoted to be visible near the top */}
                {(ctx.exposure?.internet_facing || ctx.exposure?.privileged) && (
                  <div className="flex items-center gap-1.5">
                    {ctx.exposure.internet_facing && <span className="rounded border border-orange/30 bg-orange/10 px-1.5 py-0.5 text-[11px] text-orange">internet-facing</span>}
                    {ctx.exposure.privileged && <span className="rounded border border-amber/30 bg-amber/10 px-1.5 py-0.5 text-[11px] text-amber">privileged</span>}
                  </div>
                )}

                <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 text-[11px] md:grid-cols-4">
                  {/* Resource */}
                  {ctx.resource_id && (
                    <div>
                      <div className="text-[11px] uppercase tracking-wide text-text-3">Resource</div>
                      <div className="mt-0.5">
                        <Link
                          to="/investigate/assets/$id"
                          params={{ id: ctx.resource_id }}
                          onClick={e => e.stopPropagation()}
                          className="font-mono text-[11px] text-teal hover:underline break-all"
                        >
                          {ctx.resource_name || shortenId(ctx.resource_id)}
                        </Link>
                      </div>
                    </div>
                  )}

                  {/* Owner / account */}
                  {(ctx.provenance?.account_id || ctx.provenance?.owner) && (
                    <div>
                      <div className="text-[11px] uppercase tracking-wide text-text-3">Owner</div>
                      <div className="mt-0.5 text-text-2">
                        {ctx.provenance.owner && ctx.provenance.owner !== "unknown" && <span>{ctx.provenance.owner}</span>}
                        {ctx.provenance.account_id && (
                          <span className={`font-mono text-[11px] text-text-3 ${ctx.provenance.owner && ctx.provenance.owner !== "unknown" ? " block" : ""}`}>
                            {ctx.provenance.account_id}
                          </span>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Blast radius — what this asset can reach.
                      Package PURLs (pkg:…) represent supply-chain; show
                      "used by N services" rather than a navigable asset link. */}
                  {(ctx.blast?.count ?? 0) > 0 && (
                    <div>
                      <div className="text-[11px] uppercase tracking-wide text-text-3">
                        {ctx.resource_id?.startsWith("pkg:") ? "Used by" : "Blast radius"}
                      </div>
                      <div className="mt-0.5">
                        {ctx.resource_id && !ctx.resource_id.startsWith("pkg:") ? (
                          /* Navigate to asset detail; #blast-radius scrolls to the graph */
                          <Link to="/investigate/assets/$id" params={{ id: ctx.resource_id }}
                            hash="blast-radius"
                            onClick={e => e.stopPropagation()}
                            className="text-[11px] text-teal hover:underline">
                            {ctx.blast!.count} reachable — view connections →
                          </Link>
                        ) : (
                          <span className="text-[11px] text-text-2">
                            {ctx.blast!.count} {ctx.resource_id?.startsWith("pkg:") ? "service" : "asset"}{ctx.blast!.count !== 1 ? "s" : ""}
                          </span>
                        )}
                        {ctx.blast?.by_type && Object.entries(ctx.blast.by_type).length > 0 && (
                          <div className="mt-0.5 flex flex-wrap gap-x-2 text-[11px] text-text-3">
                            {Object.entries(ctx.blast.by_type).map(([t, n]) => (
                              <span key={t}>{typeGroupLabel(t)}: {n}</span>
                            ))}
                          </div>
                        )}
                        {ctx.blast?.can_assume && ctx.blast.can_assume.length > 0 && (
                          <div className="mt-0.5 text-[11px] text-amber">Can assume {ctx.blast.can_assume.length} IAM role{ctx.blast.can_assume.length !== 1 ? "s" : ""}</div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Source repo */}
                  {ctx.provenance?.source_repo && (
                    <div>
                      <div className="text-[11px] uppercase tracking-wide text-text-3">Deployed from</div>
                      <div className="mt-0.5 truncate">
                        {ctx.provenance.source_repo.includes('/') ? (
                          <a
                            href={`https://github.com/${ctx.provenance.source_repo.replace(/^github\.com\//, '')}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            onClick={e => e.stopPropagation()}
                            className="flex items-center gap-1 font-mono text-[11px] text-teal hover:underline"
                          >
                            <ExternalLink className="h-2.5 w-2.5 shrink-0" />
                            {ctx.provenance.source_repo.replace(/^github\.com\//, '')}
                          </a>
                        ) : (
                          <span className="font-mono text-[11px] text-text-2">{ctx.provenance.source_repo}</span>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Detected */}
                  <div>
                    <div className="text-[11px] uppercase tracking-wide text-text-3">Detected</div>
                    <div className="mt-0.5 text-text-3">{new Date(ctx.detected_at).toLocaleDateString()}</div>
                  </div>
                </div>

                {/* AHC reasoning — why the agent escalated or deprioritised this */}
                {ctx.reasoning?.summary && (
                  <div className="rounded border border-border-subtle bg-surface-2 px-3 py-2 text-[11px]">
                    <div className="mb-1 flex items-center gap-1.5 text-[11px] uppercase tracking-wide text-text-3">
                      <span>Agent analysis</span>
                      {ctx.reasoning.confidence_band && (
                        <span className={`rounded px-1.5 py-0.5 font-medium ${
                          ctx.reasoning.confidence_band === "high" ? "bg-teal/10 text-teal" :
                          ctx.reasoning.confidence_band === "low" ? "bg-amber/10 text-amber" : "bg-surface-3 text-text-3"
                        }`}>{ctx.reasoning.confidence_band} confidence</span>
                      )}
                      {ctx.reasoning.outcome && (
                        <span className={`rounded px-1.5 py-0.5 font-medium ${
                          ctx.reasoning.outcome === "escalated" ? "bg-orange/10 text-orange" :
                          ctx.reasoning.outcome === "parked_for_approval" ? "bg-amber/10 text-amber" : "bg-surface-3 text-text-3"
                        }`}>{ctx.reasoning.outcome.replace(/_/g, " ")}</span>
                      )}
                    </div>
                    <p className="text-text-2 leading-relaxed">{ctx.reasoning.summary}</p>
                    {ctx.reasoning.rationale && ctx.reasoning.rationale !== ctx.reasoning.summary && (
                      <p className="mt-1 text-text-3">{ctx.reasoning.rationale}</p>
                    )}
                    {ctx.reasoning.cove_concerns && ctx.reasoning.cove_concerns.length > 0 && (
                      <ul className="mt-1.5 space-y-0.5">
                        {ctx.reasoning.cove_concerns.map((concern, i) => (
                          <li key={i} className="flex items-start gap-1.5 text-[11px] text-amber">
                            <span className="shrink-0 mt-0.5">⚠</span>{concern}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                )}

                {/* Actions */}
                <div className="flex items-center gap-2 border-t border-border-subtle/40 pt-2">
                  <Link to="/investigate/findings/$id" params={{ id: f.id }}
                    onClick={e => e.stopPropagation()}
                    className="text-[11px] text-teal hover:underline">
                    Full detail →
                  </Link>
                  {ctx.resource_id && (
                    <Link to="/investigate/assets/$id" params={{ id: ctx.resource_id }}
                      onClick={e => e.stopPropagation()}
                      className="text-[11px] text-text-3 hover:text-teal">
                      View asset →
                    </Link>
                  )}
                </div>
              </div>
            ) : null}
          </td>
        </tr>
      )}
    </>
  );
}
