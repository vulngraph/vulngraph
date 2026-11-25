import { useState } from "react";
import { Link, useNavigate, useRouterState } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { useAssets, useAssetSummary, useFinding, type AssetFilter } from "../lib/queries";
import { api, type Asset, type Finding } from "../lib/api";
import { Button, Empty, ErrorNote, KevBadge, Loading, PageHeader, ScoreBadge, SeverityBadge } from "../components/ui";
import { GlobeIcon, providerClass, typeMetaFor } from "../lib/assetMeta";
import { timeAgo as timeAgoBase, bandTone, bandLabel, stripVersionSuffix } from "../lib/format";
import { ChevronDown, ChevronRight, Download } from "lucide-react";
import { DropdownMenu, type MenuItem } from "../components/DropdownMenu";
import { AssetDetailPanel } from "../components/AssetDetailPanel";
import { openAssistant } from "../lib/assistant";
import { downloadCSV, toCSV } from "../lib/csv";

const timeAgo = (iso?: string) => timeAgoBase(iso, "compact");

export function Assets() {
  const { location } = useRouterState();
  const navigate = useNavigate();
  const [provider, setProvider] = useState("");
  const [type, setType] = useState("");
  const [exposed, setExposed] = useState(false);
  const [minScore, setMinScore] = useState(0);
  const [search, setSearch] = useState("");
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<"" | "risk">(
    () => new URLSearchParams(location.search).get("sort") === "risk" ? "risk" : ""
  );

  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);
  const summary = useAssetSummary();

  const filter: AssetFilter = {};
  if (sort === "risk") {
    filter.sort = "risk";
  } else {
    if (provider) filter.provider = provider;
    if (type) filter.type = type;
    if (q) filter.q = q;
    if (exposed) filter.exposed = true;
    if (minScore > 0) filter.minScore = minScore;
  }
  const { data, isLoading, isError, error, fetchNextPage, hasNextPage, isFetchingNextPage } = useAssets(filter);
  const items = data?.pages.flatMap((p) => p.items) ?? [];

  // Providers ranked by asset count. The head stays as pills (they fit on one
  // line); the unbounded tail collapses into a dropdown so a long provider list
  // can't wrap into three rows of chips.
  const providers = summary.data ? Object.entries(summary.data.by_provider).sort((a, b) => b[1] - a[1]) : [];
  const PROVIDER_PILLS = 4;
  const headProviders = providers.slice(0, PROVIDER_PILLS);
  const tailProviders = providers.slice(PROVIDER_PILLS);
  const tailActive = tailProviders.some(([p]) => p === provider);

  // Types are searchable in a single dropdown — ranked by count, since with a
  // filter box the alphabetical ordering buys nothing.
  const typeEntries = summary.data
    ? Object.entries(summary.data.by_type).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    : [];
  const typeLabel = (t: string) => typeMetaFor(t).label || t.replace(/_/g, " ");
  const typeItems: MenuItem[] = [
    { id: "", label: "All types", meta: String(summary.data?.total ?? 0), checked: !type },
    ...typeEntries.map(([t, n]) => ({
      id: t,
      label: typeLabel(t),
      meta: String(n),
      checked: type === t,
      keywords: t,
    })),
  ];

  function exportCSV() {
    const header = ["id", "name", "type", "provider", "region", "risk_score"];
    const rows = items.map((a) => [a.id, a.name, a.type, a.provider, a.region ?? "", a.max_score ?? 0]);
    downloadCSV("assets.csv", toCSV(header, rows));
  }

  // Infinite query only loads pages the user has fetched — an export while more
  // pages remain is partial, so the label discloses that rather than reading
  // "Export CSV" for what is really "export what happened to be loaded".
  const exportLabel = hasNextPage ? `Export loaded (${items.length})` : "Export CSV";

  return (
    <div>
      <div className="flex items-start justify-between gap-4 mb-1">
        <PageHeader title="Assets" subtitle="Your inventory across AWS, GCP, GitHub, and Kubernetes — an asset's risk is its findings." />
        <button
          onClick={exportCSV}
          disabled={items.length === 0}
          className="mt-1 flex shrink-0 items-center gap-1.5 rounded border border-border-subtle bg-bg px-2.5 py-1.5 text-[11px] text-text-3 hover:border-teal/40 hover:text-text-2 disabled:opacity-40 transition-colors"
          title="Export current list as CSV"
        >
          <Download className="h-3 w-3" />
          {exportLabel}
        </button>
      </div>

      {/* Mode toggle + provider filters always visible */}
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <div className="flex gap-1">
          <FilterBtn
            label="All assets"
            active={sort !== "risk"}
            onClick={() => { setSort(""); navigate({ to: "/investigate/assets", search: {} }); }}
          />
          <FilterBtn
            label="Riskiest"
            active={sort === "risk"}
            onClick={() => { setSort("risk"); navigate({ to: "/investigate/assets", search: { sort: "risk" } as Record<string,string> }); }}
          />
        </div>

        {/* Divider separates sort mode (orthogonal) from provider filter */}
        <div className="h-3 w-px bg-border-subtle" />

        {/* Provider filter — top providers stay as pills, the tail collapses into
            a dropdown. In Riskiest mode the backend rejects sort=risk combined
            with a provider filter, so the pills are disabled rather than left
            clickable-but-ignored (a selected pill would otherwise look applied
            while doing nothing). */}
        <div className={`flex items-center gap-1 ${sort === "risk" ? "pointer-events-none opacity-40" : ""}`}>
          <FilterBtn
            label={`all (${summary.data?.total ?? 0})`}
            active={!provider}
            disabled={sort === "risk"}
            onClick={() => setProvider("")}
          />
          {headProviders.map(([p, n]) => (
            <FilterBtn
              key={p}
              label={`${p} (${n})`}
              active={provider === p}
              disabled={sort === "risk"}
              onClick={() => setProvider(provider === p ? "" : p)}
            />
          ))}
          {tailProviders.length > 0 && (
            <DropdownMenu
              variant="ghost"
              active={tailActive}
              disabled={sort === "risk"}
              panelWidth="w-56"
              searchable={tailProviders.length > 8}
              searchPlaceholder="filter providers…"
              label={tailActive ? `${provider} (${summary.data?.by_provider[provider]})` : `+${tailProviders.length} more`}
              ariaLabel="More providers"
              items={tailProviders.map(([p, n]) => ({
                id: p,
                label: p,
                meta: String(n),
                checked: provider === p,
              }))}
              onSelect={(id) => setProvider(provider === id ? "" : id)}
            />
          )}
        </div>
        {sort === "risk" && (
          <span className="text-[11px] text-text-3">provider filter doesn&apos;t apply to Riskiest</span>
        )}
      </div>

      {/* Type + search + special filters — only available outside risk mode */}
      {sort !== "risk" && (
        <div className="mb-4 space-y-2">
          {/* Type filter — one searchable dropdown over every observed type */}
          <div className="flex flex-wrap items-center gap-1.5">
            <DropdownMenu
              active={!!type}
              searchable
              searchPlaceholder="search types…"
              panelWidth="w-72"
              label={`Type: ${type ? typeLabel(type) : "all"}`}
              ariaLabel={`Type filter: ${type ? typeLabel(type) : "all"}`}
              items={typeItems}
              onSelect={(id) => setType(id === type ? "" : id)}
              emptyMessage="No matching type"
            />
          </div>

          {/* Special filters row */}
          <div className="flex flex-wrap items-center gap-3">
            {/* Internet-facing toggle */}
            <button
              onClick={() => setExposed(!exposed)}
              aria-pressed={exposed}
              className={`flex items-center gap-1.5 rounded border px-2.5 py-1.5 text-[11px] transition-colors ${
                exposed
                  ? "border-amber/50 bg-amber/10 text-amber"
                  : "border-border-subtle bg-bg text-text-3 hover:text-text-2"
              }`}
            >
              <GlobeIcon className={`h-3 w-3 ${exposed ? "text-amber" : ""}`} />
              Internet-facing only
            </button>

            {/* Min score filter */}
            <div className="flex items-center gap-1.5">
              <span className="text-[11px] text-text-3">Min risk</span>
              {[0, 50, 70, 85].map((s) => (
                <button
                  key={s}
                  onClick={() => setMinScore(s)}
                  aria-pressed={minScore === s}
                  className={`rounded border px-2 py-1 text-[11px] transition-colors ${
                    minScore === s
                      ? "border-teal/50 bg-teal/10 text-teal"
                      : "border-border-subtle bg-bg text-text-3 hover:text-text-2"
                  }`}
                >
                  {s === 0 ? "any" : `≥${s}`}
                </button>
              ))}
            </div>
          </div>

          {/* Search */}
          <form
            onSubmit={(e) => { e.preventDefault(); setQ(search.trim()); }}
            className="flex-1"
          >
            <div className="relative">
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="search name, id, or IP… (press enter)"
                className="w-full rounded border border-border-subtle bg-bg px-3 py-1.5 pr-7 text-xs text-text outline-none focus:border-teal"
              />
              {search && (
                <button
                  type="button"
                  onClick={() => { setSearch(""); setQ(""); }}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-text-3 hover:text-text-2"
                >✕</button>
              )}
            </div>
          </form>
        </div>
      )}

      {isLoading && <Loading />}
      {isError && <ErrorNote message={(error as Error).message} />}
      {!isLoading && items.length === 0 && (
        <Empty message={
          sort === "risk"
            ? "No assets with scored findings yet — enrichment may be in progress. Check back after the next sync cycle."
            : "No assets match. Adjust the filters, or add a connector and sync."
        } />
      )}
      {items.length > 0 && (
        <>
          <div className="glass overflow-hidden rounded-lg">
            <table className="w-full border-collapse text-sm">
              <thead>
                <tr className="border-b border-border-subtle text-left text-[11px] uppercase tracking-wide text-text-3">
                  {/* Risk column header is a sort toggle */}
                  <th className="px-3 py-2 font-medium">
                    <button
                      onClick={() => setSort(sort === "risk" ? "" : "risk")}
                      className={`transition-colors hover:text-text-2 ${sort === "risk" ? "text-teal" : ""}`}
                      title={sort === "risk" ? "Sort: riskiest first (click to clear)" : "Sort by risk"}
                    >
                      Risk {sort === "risk" ? "▼" : ""}
                    </button>
                  </th>
                  <th className="px-3 py-2 font-medium">Name</th>
                  <th className="px-3 py-2 font-medium">Provider</th>
                  <th className="px-3 py-2 font-medium">Network</th>
                  <th className="px-3 py-2 text-right font-medium">Seen</th>
                  <th className="px-3 py-2 font-medium w-0" />
                </tr>
              </thead>
              <tbody>
                {items.map((a) => (
                  <AssetRow
                    key={a.id}
                    a={a}
                    onOpenPanel={() => setSelectedAssetId(a.id)}
                    onAskAI={() => {
                      const facts: string[] = [];
                      if (a.type) facts.push(`type: ${a.type}`);
                      if (a.provider) facts.push(`provider: ${a.provider}`);
                      if ((a.max_score ?? 0) > 0) facts.push(`risk score: ${a.max_score}`);
                      facts.push(`asset ID: ${a.id}`);
                      openAssistant({
                        subject: `Investigate asset: ${a.name || a.id}`,
                        facts,
                        question: "What is the risk? Run a graph query to find connections.",
                      });
                    }}
                  />
                ))}
              </tbody>
            </table>
          </div>
          {hasNextPage && (
            <div className="mt-4 flex justify-center">
              <Button onClick={() => fetchNextPage()} disabled={isFetchingNextPage}>
                {isFetchingNextPage ? "Loading…" : "Load more"}
              </Button>
            </div>
          )}
        </>
      )}

      <AssetDetailPanel
        assetId={selectedAssetId}
        onClose={() => setSelectedAssetId(null)}
      />
    </div>
  );
}

// useWorstFinding lazily fetches the highest-scored finding for an asset.
// Only fires when `enabled` is true (row is expanded).
function useWorstFinding(assetId: string, enabled: boolean) {
  return useQuery({
    queryKey: ["worst-finding", assetId],
    queryFn: () =>
      api
        .get<{ items: Finding[] }>(`/api/findings?resource_id=${encodeURIComponent(assetId)}&limit=1`)
        .then((r) => r.items[0] ?? null),
    enabled,
    staleTime: 60_000,
  });
}

function AssetRow({ a, onOpenPanel, onAskAI }: { a: Asset; onOpenPanel: () => void; onAskAI: () => void }) {
  const [open, setOpen] = useState(false);
  const meta = typeMetaFor(a.type);
  const Icon = meta.icon;
  const findings = a.finding_count ?? 0;
  const isExposed = !!(a.public_ip || a.domain);
  const isStale = a.last_seen && (Date.now() - new Date(a.last_seen).getTime()) > 7 * 24 * 60 * 60 * 1000;
  // Score 0 with findings present = enrichment in-flight (AHC hasn't scored them yet)
  const enrichmentPending = findings > 0 && (a.max_score ?? 0) === 0;
  // Pull a couple of high-signal tags (env/team) for inline context
  const keyTags = a.tags
    ? Object.entries(a.tags)
        .filter(([k]) => /^(env|environment|team|service|app|component|tier)$/i.test(k))
        .slice(0, 2)
    : [];

  // Normalise risk_band to a user-facing label
  const bandText = bandLabel(a.risk_band);

  // Worst finding — loaded lazily when the row is expanded
  const { data: worstFinding, isLoading: wfLoading } = useWorstFinding(a.id, open && findings > 0);
  // Full finding context (remediation + score factors) — only fetched once worstFinding.id is known
  const { data: wfCtx } = useFinding(open && worstFinding ? worstFinding.id : "");

  // Compact account display: last 12 chars is enough for AWS account IDs and GCP project IDs
  const shortAccount = a.account_id ? truncTail(a.account_id, 12) : null;

  return (
    <>
      {/* Main row — clicking anywhere navigates to the asset except the expand toggle */}
      <tr
        className="group card-hover border-b border-border-subtle/40 last:border-0 cursor-pointer"
        onClick={onOpenPanel}
        title="Open asset detail"
      >
        {/* Risk — compact single-column layout: score + optional internet pill on row 1,
            band label + finding count on row 2. Band label moved inline to save vertical
            space (was stacked as 4 separate items, now 2 tight rows). */}
        <td className="px-3 py-2" onClick={(e) => e.stopPropagation()}>
          {findings > 0 ? (
            <div className="flex flex-col gap-0.5 items-start">
              {/* Row 1: score badge + internet pill */}
              <div className="flex items-center gap-1">
                {enrichmentPending ? (
                  <span className="animate-pulse rounded border border-border-subtle bg-surface px-1.5 py-0.5 text-[11px] text-text-3">
                    enriching…
                  </span>
                ) : (
                  <ScoreBadge score={a.max_score ?? 0} band={a.risk_band} />
                )}
                {isExposed && (
                  <span
                    className="shrink-0 rounded border border-orange/30 bg-orange/10 px-1 py-0 text-[11px] font-semibold uppercase text-orange"
                    title="Internet-exposed"
                  >
                    internet
                  </span>
                )}
              </div>
              {/* Row 2: band label · N findings */}
              {!enrichmentPending && (
                <div className="flex items-center gap-1 text-[11px]">
                  {bandText && (
                    <span className={`font-medium ${bandTone(a.risk_band)}`}>{bandText}</span>
                  )}
                  {bandText && <span className="text-text-3">·</span>}
                  <span className="text-text-3">
                    {findings} {findings === 1 ? "finding" : "findings"}
                  </span>
                </div>
              )}
            </div>
          ) : (
            <span className="text-[11px] text-text-3">—</span>
          )}
        </td>

        {/* Name + type + region/account + stale badge + key tags */}
        <td className="px-3 py-2">
          <div className="flex items-center gap-2.5 min-w-0">
            {/* Expand/collapse chevron */}
            <button
              onClick={(e) => { e.stopPropagation(); setOpen((v) => !v); }}
              className="shrink-0 text-text-3 hover:text-text-2 transition-colors"
              aria-label={open ? "Collapse row" : "Expand row"}
            >
              {open
                ? <ChevronDown className="h-3 w-3" />
                : <ChevronRight className="h-3 w-3" />
              }
            </button>

            <span className="flex items-center gap-2 min-w-0">
              <span className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-md ${meta.bg}`}>
                <Icon className={`h-3.5 w-3.5 ${meta.color}`} />
              </span>
              <span className="min-w-0">
                <span className="flex items-center gap-1.5">
                  <span
                    className="block truncate font-medium text-text group-hover:text-teal transition-colors"
                    title={a.name || a.id}
                  >
                    {a.name || a.id}
                  </span>
                  {/* Version (+ commit date for pseudo-versions) differentiates identical-named packages */}
                  {a.type === "package" && a.metadata?.version && (() => {
                    const ver = cleanVersion(a.metadata.version);
                    const date = versionDate(a.metadata.version);
                    return (
                      <span className="shrink-0 font-mono text-[11px] text-text-3">
                        {ver}{date && <span className="ml-1 opacity-60">({date})</span>}
                      </span>
                    );
                  })()}
                  {isStale && (
                    <span
                      className="shrink-0 rounded border border-amber/20 bg-amber/5 px-1 py-0 text-[11px] font-medium text-amber/70"
                      title={`Not seen in 7+ days — last seen ${timeAgo(a.last_seen)}`}
                    >
                      stale
                    </span>
                  )}
                </span>
                <span className="flex items-center gap-1.5 flex-wrap">
                  <span className="text-[11px] text-text-3">{meta.label || a.type}</span>
                  {/* Region + account inline — saves columns */}
                  {a.region && (
                    <span className="font-mono text-[11px] text-text-3">{a.region}</span>
                  )}
                  {shortAccount && (
                    <span
                      className="font-mono text-[11px] text-text-3"
                      title={a.account_id}
                    >
                      {shortAccount}
                    </span>
                  )}
                  {keyTags.map(([k, v]) => (
                    <span key={k} className="rounded bg-surface-3 px-1 py-0 text-[11px] text-text-3" title={k}>
                      {v}
                    </span>
                  ))}
                </span>
              </span>
            </span>
          </div>
        </td>

        <td className="px-3 py-2">
          <span className={`inline-flex rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase ${providerClass(a.provider)}`}>
            {a.provider}
          </span>
        </td>
        <td className="px-3 py-2">
          <NetworkCell a={a} />
        </td>
        <td className="px-3 py-2 text-right text-[11px] text-text-3">{timeAgo(a.last_seen)}</td>
        {/* Per-row actions — a keyboard-focusable ⋯ menu rather than hover-only
            buttons, which were unreachable by keyboard and invisible on touch. */}
        <td className="px-2 py-2" onClick={(e) => e.stopPropagation()}>
          <DropdownMenu
            variant="icon"
            align="right"
            panelWidth="w-44"
            ariaLabel={`Actions for ${a.name || a.id}`}
            title="Row actions"
            items={[
              { id: "detail", label: "Detail", desc: "Open the asset detail panel" },
              { id: "ask", label: "Ask AI", desc: "Investigate this asset with AI" },
            ]}
            onSelect={(id) => (id === "detail" ? onOpenPanel() : onAskAI())}
          />
        </td>
      </tr>

      {/* Inline expand row — worst finding preview without full navigation */}
      {open && (
        <tr className="border-b border-border-subtle/40 bg-surface/50 last:border-0">
          <td />
          <td colSpan={5} className="px-3 py-2.5">
            {wfLoading && (
              <span className="text-[11px] text-text-3">Loading worst finding…</span>
            )}
            {!wfLoading && worstFinding && (
              <div className="space-y-1.5">
                {/* Top row: severity + title + KEV + score + check_id + "all findings" */}
                <div className="flex items-center gap-2 flex-wrap">
                  <Link
                    to="/investigate/findings/$id"
                    params={{ id: worstFinding.id }}
                    className="flex items-center gap-2 min-w-0 group/wf"
                  >
                    <SeverityBadge severity={worstFinding.severity} />
                    <span className="truncate text-[11px] text-text group-hover/wf:text-teal transition-colors font-medium">
                      {worstFinding.title}
                    </span>
                  </Link>
                  {worstFinding.known_exploited && <KevBadge className="shrink-0" />}
                  {worstFinding.score > 0 && (
                    <ScoreBadge score={worstFinding.score} band={worstFinding.score_band} />
                  )}
                  {worstFinding.check_id && (
                    <span className="inline-flex rounded border border-border-subtle bg-surface px-1.5 py-0.5 font-mono text-[11px] text-text-3">{worstFinding.check_id}</span>
                  )}
                  <Link
                    to="/investigate/assets/$id"
                    params={{ id: a.id }}
                    className="ml-auto shrink-0 text-[11px] text-text-3 hover:text-teal transition-colors"
                  >
                    all {findings} {findings === 1 ? "finding" : "findings"} →
                  </Link>
                </div>
                {/* Remediation hint — most actionable context, shown once context loads */}
                {wfCtx?.remediation && (
                  <p className="text-[11px] text-text-3 leading-snug">
                    <span className="text-teal">Fix: </span>{wfCtx.remediation.length > 140 ? wfCtx.remediation.slice(0, 138) + "…" : wfCtx.remediation}
                  </p>
                )}
                {/* Score factors — compact inline why-score line */}
                {wfCtx?.factors && wfCtx.factors.length > 0 && (
                  <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[11px] text-text-3">
                    <span className="text-text-3 text-[11px] uppercase tracking-wide self-center">why {wfCtx.score}</span>
                    {wfCtx.factors.map((f, i) => (
                      <span key={i}>
                        <span className="capitalize text-text-2">{(f.source ?? "").replace(/_/g, " ")}</span>
                        {f.points != null && <span className="ml-1 tabular-nums text-text">{f.points >= 0 ? `+${f.points}` : f.points}</span>}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}
            {!wfLoading && !worstFinding && findings > 0 && (
              <span className="text-[11px] text-text-3">Finding data unavailable.</span>
            )}
            {!wfLoading && findings === 0 && (
              <><span className="text-[11px] text-text-3">No findings on this asset. </span><Link to="/investigate/assets/$id" params={{ id: a.id }} className="text-[11px] text-teal hover:underline">View detail →</Link></>
            )}
          </td>
        </tr>
      )}
    </>
  );
}

// NetworkCell shows the most exposing address first: a public IP or domain marks
// an internet-facing asset (teal globe); otherwise the private IP / endpoint; else —.
function NetworkCell({ a }: { a: Asset }) {
  if (a.public_ip) {
    return (
      <Link to="/investigate/assets" search={{ q: a.public_ip } as Record<string,string>} className="inline-flex items-center gap-1.5" title={`Filter assets by IP: ${a.public_ip}`}>
        <GlobeIcon className="h-3 w-3 shrink-0 text-teal" />
        <span className="font-mono text-[11px] text-teal">{a.public_ip}</span>
      </Link>
    );
  }
  if (a.domain) {
    return (
      <a href={'https://'+a.domain} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1.5 min-w-0 hover:underline" title={`Open ${a.domain} in browser`}>
        <GlobeIcon className="h-3 w-3 shrink-0 text-teal" />
        <span className="truncate font-mono text-[11px] text-teal">{a.domain}</span>
      </a>
    );
  }
  if (a.private_ip) {
    return (
      <span className="font-mono text-[11px] text-text-3" title="Private IP">
        {a.private_ip}
      </span>
    );
  }
  if (a.endpoint) {
    return (
      <span className="block max-w-[200px] truncate font-mono text-[11px] text-text-3" title={a.endpoint}>
        {a.endpoint}
      </span>
    );
  }
  return <span className="text-[11px] text-text-3">—</span>;
}

// cleanVersion strips Go pseudo-version timestamps and hashes so "v0.0.0-20210813-hash" → "v0.0.0".
// Returns the base semver. If the suffix had a date, also returns it for disambiguation.
function cleanVersion(v: string): string {
  return stripVersionSuffix(v);
}

// versionDate extracts the date from a Go pseudo-version suffix: "20210813" → "2021-08-13".
function versionDate(v: string): string | undefined {
  const m = v.match(/-(\d{4})(\d{2})(\d{2})\d{6}-[0-9a-f]{12,}$/);
  return m ? `${m[1]}-${m[2]}-${m[3]}` : undefined;
}

// truncTail keeps only the tail of long ids — shows last N chars with a leading ellipsis.
// More readable for AWS account IDs (12 digits) and GCP project IDs.
function truncTail(s: string, max: number): string {
  if (!s) return "";
  if (s.length <= max) return s;
  return `…${s.slice(-max)}`;
}

function FilterBtn({ label, active, onClick, disabled }: { label: string; active: boolean; onClick: () => void; disabled?: boolean }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      aria-pressed={active}
      className={`rounded px-2 py-1 text-[11px] ${active ? "bg-surface-3 text-text" : "text-text-3 hover:text-text-2"}`}
    >
      {label}
    </button>
  );
}
