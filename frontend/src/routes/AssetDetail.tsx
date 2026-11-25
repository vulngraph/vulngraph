import { useState, useEffect, useRef } from "react";
import { Link, useNavigate, useParams } from "@tanstack/react-router";
import { useAsset, useBlastRadius, useFinding, useFindings, useAssetChanges } from "../lib/queries";
import type { Finding } from "../lib/api";
import { BackLink, Card, Empty, ErrorNote, KevBadge, Loading, ScoreBadge, SeverityBadge } from "../components/ui";
import { GraphView } from "../components/GraphView";
import { GlobeIcon, providerClass, typeMetaFor } from "../lib/assetMeta";
import { timeAgo as timeAgoBase, stripVersionSuffix } from "../lib/format";
import { environmentLabel } from "../lib/environment";
import { openAssistant } from "../lib/assistant";
import { useAssetClassification, ClassificationBadges } from "../components/DataClassification";
import { AssetChangeRows } from "../components/AssetChangeRows";
import { DiskScanPanel, isDiskScanVM } from "../components/DiskScanPanel";

const timeAgo = (iso?: string) => timeAgoBase(iso, "compact");

type BlastDir = "out" | "in" | "both";
const BLAST_DIRS: { value: BlastDir; label: string }[] = [
  { value: "out", label: "Can reach" },
  { value: "in", label: "Reached by" },
  { value: "both", label: "Both" },
];

export function AssetDetail() {
  const { id } = useParams({ from: "/investigate/assets/$id" });
  const navigate = useNavigate();
  const asset = useAsset(id);
  const [blastDir, setBlastDir] = useState<BlastDir>("out");
  const blastRef = useRef<HTMLDivElement>(null);

  // Scroll to blast-radius section when linked from a finding's "N reachable" link
  useEffect(() => {
    if (window.location.hash === "#blast-radius" && blastRef.current) {
      const timer = setTimeout(() => blastRef.current?.scrollIntoView({ behavior: "smooth", block: "start" }), 300);
      return () => clearTimeout(timer);
    }
  }, [id]);
  const blast = useBlastRadius(id, blastDir);
  const findings = useFindings({ resource_id: id });
  const findingItems = findings.data?.pages.flatMap((p) => p.items) ?? [];
  // findingItems is a single ~200-row page of an infinite query never advanced
  // here — prefer the asset's server-computed finding_count (as
  // AssetDetailPanel.tsx does), falling back to the page length only if that
  // aggregate is unavailable, so a busy asset's true count is never silently
  // clamped to the page size.
  const findingTotal = asset.data?.finding_count ?? findingItems.length;
  const classification = useAssetClassification(id);
  const classes = (classification.data?.classes ?? []).filter(Boolean);

  function openChat() {
    const a = asset.data;
    const name = a?.name || id;
    const type = a?.type ?? "";
    const score = a?.max_score ?? 0;
    const facts: string[] = [];
    if (type) facts.push(`type: ${type}`);
    if (a?.provider) facts.push(`provider: ${a.provider}`);
    if (score > 0) facts.push(`risk score: ${score}`);
    if (findingTotal > 0) facts.push(`${findingTotal} findings`);
    facts.push(`asset ID: ${id}`);
    openAssistant({
      subject: `Investigate asset: ${name}`,
      facts,
      question: "What is the risk? Run a graph query to find connections and summarise the threat.",
    });
  }

  return (
    <div>
      <BackLink to="/investigate/assets" label="Assets" />

      {asset.isLoading && <Loading />}
      {asset.isError && <ErrorNote message={(asset.error as Error).message} />}
      {asset.data && (
        <>
          {(() => {
            const meta = typeMetaFor(asset.data.type);
            const Icon = meta.icon;
            const internetFacing = Boolean(asset.data.public_ip || asset.data.domain);
            return (
              <div className="mb-4 flex items-start justify-between gap-3">
              <div className="flex items-center gap-3">
                <span className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${meta.bg}`}>
                  <Icon className={`h-5 w-5 ${meta.color}`} />
                </span>
                <div className="min-w-0">
                  <h1 className="truncate font-display text-lg text-text">{asset.data.name || asset.data.id}</h1>
                  <div className="mt-0.5 flex flex-wrap items-center gap-2 text-[11px]">
                    <span className={`inline-flex rounded border px-1.5 py-0.5 font-medium uppercase ${providerClass(asset.data.provider)}`}>
                      {asset.data.provider}
                    </span>
                    <span className="text-text-3">{meta.label || asset.data.type}</span>
                    {internetFacing && (
                      <span className="inline-flex items-center gap-1 rounded border border-teal/30 bg-teal/10 px-1.5 py-0.5 font-medium uppercase text-teal">
                        <GlobeIcon className="h-3 w-3" /> internet-facing
                      </span>
                    )}
                  </div>
                </div>
              </div>
              <button
                onClick={openChat}
                className="shrink-0 rounded-lg border border-teal/30 bg-teal/10 px-3 py-1.5 text-[11px] font-medium text-teal transition-colors hover:bg-teal/20"
              >
                Ask AI →
              </button>
              </div>
            );
          })()}
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <Card>
              <span className="mb-2 block text-[11px] uppercase text-text-3">Details</span>
              <dl className="space-y-1.5 text-xs">
                <Row label="Resource ID" value={asset.data.id} mono />
                {/* For Kubernetes the "region" IS the cluster name — label it so. */}
                <Row label={asset.data.provider === "kubernetes" ? "Cluster" : "Region"} value={asset.data.region ?? "—"} />
                <Row label="Account" value={asset.data.account_id ?? "—"} mono />
                <Row label="Environment" value={environmentLabel(asset.data.environment, asset.data.environment_source)} />
                <Row label="Last seen" value={`${timeAgo(asset.data.last_seen)} (${new Date(asset.data.last_seen).toLocaleString()})`} />
              </dl>
            </Card>
            {asset.data.metadata && Object.keys(asset.data.metadata).length > 0 && (
              <Card>
                <span className="mb-2 block text-[11px] uppercase text-text-3">Context</span>
                <dl className="space-y-1.5 text-xs">
                  {Object.entries(asset.data.metadata).map(([k, v]) =>
                    v ? <Row key={k} label={k.replace(/_/g, " ").replace(/^\w/, (c) => c.toUpperCase())} value={cleanMetaValue(k, v)} mono={/ip|selector|arn|url|link/i.test(k)} /> : null,
                  )}
                </dl>
              </Card>
            )}
            {(asset.data.public_ip || asset.data.private_ip || asset.data.domain || asset.data.endpoint) && (
              <Card>
                <span className="mb-2 block text-[11px] uppercase text-text-3">Network</span>
                <dl className="space-y-1.5 text-xs">
                  {asset.data.public_ip && <Row label="Public IP" value={asset.data.public_ip} mono accent />}
                  {asset.data.private_ip && <Row label="Private IP" value={asset.data.private_ip} mono />}
                  {asset.data.domain && <Row label="Domain" value={asset.data.domain} mono accent />}
                  {asset.data.endpoint && <Row label="Endpoint" value={asset.data.endpoint} mono />}
                </dl>
              </Card>
            )}
            {asset.data.tags && Object.keys(asset.data.tags).length > 0 && (
              <Card>
                <span className="mb-2 block text-[11px] uppercase text-text-3">Tags</span>
                <div className="flex flex-wrap gap-1.5">
                  {Object.entries(asset.data.tags).map(([k, v]) => (
                    <span key={k} className="rounded border border-border-subtle bg-surface px-1.5 py-0.5 text-[11px] text-text-2">
                      {k}: {v}
                    </span>
                  ))}
                </div>
              </Card>
            )}
            {classes.length > 0 && (
              <Card>
                <span className="mb-2 block text-[11px] uppercase text-text-3">Data classification</span>
                <ClassificationBadges row={classification.data} />
              </Card>
            )}
          </div>

          {isDiskScanVM(asset.data.type) && <DiskScanPanel assetId={id} />}

          <h2 className="mb-2 mt-6 font-display text-sm text-text">
            Findings
            {findings.data && (
              <span className="ml-2 text-[11px] text-text-3">
                {findingTotal} on this asset
                {findingItems.length < findingTotal && ` (showing top ${findingItems.length})`}
              </span>
            )}
          </h2>
          {findings.isLoading && <Loading />}
          {findings.data && findingItems.length === 0 && <Empty message="No findings on this asset." />}
          {findingItems.length > 0 && (
            <div className="space-y-px">
              {findingItems.map((f) => (
                <AssetFindingRow key={f.id} finding={f} />
              ))}
            </div>
          )}

          <AssetChangeTimeline assetId={id} />

          <div ref={blastRef} id="blast-radius" className="mb-2 mt-6 flex items-center gap-3 scroll-mt-16">
            <h2 className="font-display text-sm text-text">
              Blast radius
              {blast.data && <span className="ml-2 text-[11px] text-text-3">{blast.data.assets.length - 1} connected</span>}
            </h2>
            {!isIdentityAsset(asset.data?.type) && (
              <div className="ml-auto flex items-center gap-1">
                {BLAST_DIRS.map((d) => (
                  <button key={d.value} onClick={() => setBlastDir(d.value)}
                    className={`rounded px-1.5 py-0.5 text-[11px] ${blastDir === d.value ? "bg-surface-3 text-text" : "text-text-3 hover:text-text-2"}`}>
                    {d.label}
                  </button>
                ))}
              </div>
            )}
          </div>
          {blast.isLoading && <Loading />}
          {blast.isError && <ErrorNote message={(blast.error as Error).message} />}
          {blast.data && blast.data.assets.length <= 1 && (
            isIdentityAsset(asset.data?.type) ? (
              <div className="rounded-lg border border-border-subtle bg-surface p-4 text-[11px] text-text-2">
                <span className="mb-1 block font-medium text-text">Identity asset</span>
                Blast radius follows every edge type in the graph, identity edges (role assumption,
                role bindings, secret access) included, and found nothing reachable from this
                identity. Its risk is expressed through its{" "}
                <span className="text-text">{findingTotal} finding{findingTotal !== 1 ? "s" : ""}</span>{" "}
                — privilege-escalation paths shown above.
              </div>
            ) : (
              <Empty message={
                blastDir === "in" ? "Isolated — nothing can reach this asset."
                  : blastDir === "both" ? "Isolated — no connections to this asset."
                  : "Isolated — nothing reachable from this asset."
              } />
            )
          )}
          {blast.data && blast.data.assets.length > 1 && (
            <GraphView
              centerId={id}
              nodes={blast.data.assets.map((a) => ({ id: a.id, label: a.name || a.id, sub: a.type, risk: a.max_score ?? 0 }))}
              edges={blast.data.edges.map((e) => ({ source: e.src_id, target: e.dst_id, label: e.edge_type }))}
              onNodeClick={(nid) => nid !== id && navigate({ to: "/investigate/assets/$id", params: { id: nid } })}
              onExpand={(nid) => navigate({ to: "/investigate/assets/$id", params: { id: nid } })}
            />
          )}
          {blast.data?.truncated && (
            <p className="mt-2 text-[11px] text-text-3">Results truncated — showing the first reachable assets.</p>
          )}
        </>
      )}
    </div>
  );
}

// AssetFindingRow renders one finding on an asset's detail page with inline
// expansion — same pattern as the Findings page cluster instances.
function AssetFindingRow({ finding: f }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const detail = useFinding(open ? f.id : "");
  const ctx = detail.data;

  return (
    <div className={`rounded border border-border-subtle/50 ${open ? "border-teal/20 bg-surface/60" : "hover:bg-surface/40"} transition-colors`}>
      <button onClick={() => setOpen(v => !v)}
        className="flex w-full items-center gap-3 px-3 py-2 text-left">
        <ScoreBadge score={f.score} band={f.score_band} />
        <div className="min-w-0 flex-1">
          <span className="text-[12px] font-medium text-text">{f.title}</span>
          {f.known_exploited && <KevBadge className="ml-2" />}
        </div>
        <SeverityBadge severity={f.severity} />
        <span className="text-[11px] text-text-3">{f.check_id ?? f.type}</span>
        <span className="shrink-0 text-[11px] text-text-3">{open ? "▾" : "▸"}</span>
      </button>

      {open && (
        <div className="border-t border-border-subtle/40 px-3 pb-3 pt-2">
          {detail.isLoading && <div className="text-[11px] text-text-3">Loading…</div>}
          {ctx && (
            <div className="space-y-2">
              {ctx.remediation && (
                <div className="rounded border border-teal/20 bg-teal/5 px-2.5 py-1.5 text-[11px]">
                  <span className="font-semibold text-teal">Fix: </span><span className="text-text-2">{ctx.remediation}</span>
                </div>
              )}
              {ctx.reasoning?.summary && (
                <div className="rounded border border-border-subtle bg-surface-2 px-2.5 py-1.5 text-[11px]">
                  <div className="mb-0.5 flex items-center gap-1.5 text-[11px] uppercase tracking-wide text-text-3">
                    Agent analysis
                    {ctx.reasoning.outcome && <span className={`rounded px-1.5 py-0.5 font-medium ${ctx.reasoning.outcome === "escalated" ? "bg-orange/10 text-orange" : "bg-teal/10 text-teal"}`}>{ctx.reasoning.outcome.replace(/_/g, " ")}</span>}
                  </div>
                  <p className="text-text-2">{ctx.reasoning.summary}</p>
                </div>
              )}
              <div className="flex flex-wrap items-center gap-3 pt-1">
                {(ctx.blast?.count ?? 0) > 0 && ctx.resource_id && (
                  <Link to="/investigate/assets/$id" params={{ id: ctx.resource_id }} onClick={e => e.stopPropagation()}
                    className="text-[11px] text-teal hover:underline">
                    {ctx.blast!.count} reachable asset{ctx.blast!.count !== 1 ? "s" : ""} →
                  </Link>
                )}
                <Link to="/investigate/findings/$id" params={{ id: f.id }} onClick={e => e.stopPropagation()}
                  className="text-[11px] text-text-3 hover:text-teal">Full detail →</Link>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// cleanMetaValue makes known metadata fields human-readable.
function cleanMetaValue(key: string, value: string): string {
  if (key === "version" || key === "Version") {
    return stripVersionSuffix(value);
  }
  // IAM user/role fields
  if (key === "password_last_used_days") {
    const n = parseInt(value, 10);
    if (n < 0) return "never logged in";
    if (n === 0) return "today";
    if (n === 1) return "yesterday";
    return `${n} days ago`;
  }
  if (key === "access_key_age_days") {
    const n = parseInt(value, 10);
    if (n === 0) return "< 1 day";
    return `${n} days old`;
  }
  if (key === "active_key_count") {
    const n = parseInt(value, 10);
    if (n === 0) return "none";
    return `${n} active`;
  }
  // Decode policies JSON to a comma-separated name list.
  if (key === "policies" && value.startsWith("[")) {
    try {
      const arr = JSON.parse(value) as Array<{ name?: string; arn?: string }>;
      const names = arr.map((p) => p.name ?? p.arn ?? "?").join(", ");
      return names || value;
    } catch { return value; }
  }
  return value;
}

// Identity assets (IAM users, roles, service accounts) get their own empty
// blast-radius state: the walk follows identity edges too, so an identity with
// assume-role or secret-access edges has a non-zero radius, but one with none
// usually carries its risk in privilege-escalation findings instead.
function isIdentityAsset(type?: string): boolean {
  if (!type) return false;
  return ["iam_user", "iam_role", "gcp_service_account", "service_account"].includes(type);
}

function Row({ label, value, mono, accent }: { label: string; value: string; mono?: boolean; accent?: boolean }) {
  return (
    <div className="flex justify-between gap-4">
      <dt className="shrink-0 text-text-3">{label}</dt>
      <dd className={`min-w-0 truncate text-right ${accent ? "text-teal" : "text-text-2"} ${mono ? "font-mono text-[11px]" : ""}`} title={value}>
        {value}
      </dd>
    </div>
  );
}

// AssetChangeTimeline shows the per-field change history of an asset (drift
// timeline) — what changed, from what, to what, and when. Renders nothing when
// the asset has no recorded changes, so it stays out of the way on stable assets.
function AssetChangeTimeline({ assetId }: { assetId: string }) {
  const { data } = useAssetChanges(assetId);
  const changes = data?.changes ?? [];
  if (changes.length === 0) return null;
  return (
    <>
      <h2 className="mb-2 mt-6 font-display text-sm text-text">
        Change history
        <span className="ml-2 text-[11px] text-text-3">{changes.length} recent changes</span>
      </h2>
      <AssetChangeRows changes={changes} />
    </>
  );
}
