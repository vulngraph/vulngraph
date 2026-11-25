import { useNavigate, useParams } from "@tanstack/react-router";
import { ShieldCheck } from "lucide-react";
import {
  useBelief, useEscalationPaths, useFinding,
} from "../lib/queries";
import { BackLink, Card, ErrorNote, KevBadge, Loading, ScoreBadge, SeverityBadge } from "../components/ui";
import { MustFixBadge } from "../components/MustFixBadge";
import { BeliefPanel } from "../components/BeliefPanel";
import { GraphView } from "../components/GraphView";
import { ReasoningTrace } from "../components/ReasoningTrace";
import {
  askAIAboutFinding, ResolveControl, SafeToFixSection, ScoreFactors, SuppressControl,
} from "../components/FindingDetailPanel";
import { openVerify } from "../lib/verify";
import { bandLabel, scoreToBand, shortenId } from "../lib/format";
import type { FindingContext } from "../lib/api";

export function FindingDetail() {
  const { id } = useParams({ from: "/investigate/findings/$id" });
  const navigate = useNavigate();
  const q = useFinding(id);

  // Hooks must be called unconditionally — before any early return.
  const resourceId = q.data?.resource_id ?? undefined;
  const escalation = useEscalationPaths(resourceId);
  const belief = useBelief(id);

  if (q.isLoading) return <Loading />;
  if (q.isError) return <ErrorNote message={(q.error as Error).message} />;
  if (!q.data) return null;

  const f = q.data;
  // Blast graph data is embedded in the finding context response — no second API call needed.
  const blastAssets = f.blast.graph_assets ?? [];
  const blastEdges = f.blast.graph_edges ?? [];

  return (
    <div>
      <BackLink to="/investigate/findings" label="Findings" />

      {/* Header — title + signals at a glance */}
      <div className="mb-4">
        <div className="flex items-start justify-between gap-3">
          <h1 className="font-display text-xl text-text">{f.title}</h1>
          <div className="flex shrink-0 items-center gap-2">
            <SuppressControl finding={f} />
            <ResolveControl finding={f} />
            {f.resource_id && (
              <button
                onClick={() => openVerify(f)}
                title="Confirm or refute this finding against the live cloud state — read-only, agent-driven"
                className="flex items-center gap-1 rounded-lg border border-sky/40 bg-sky/10 px-3 py-1.5 text-[11px] font-medium text-sky transition-colors hover:bg-sky/20"
              >
                <ShieldCheck className="h-3.5 w-3.5" /> Verify live →
              </button>
            )}
            <button
              onClick={() => askAIAboutFinding(f)}
              className="rounded-lg border border-teal/30 bg-teal/10 px-3 py-1.5 text-[11px] font-medium text-teal transition-colors hover:bg-teal/20"
            >
              Ask AI →
            </button>
          </div>
        </div>
        <div className="mt-1 text-[11px] text-text-3">{f.source} · {f.check_id ?? f.type}</div>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <ScoreBadge score={f.score} band={f.score_band} />
          <SeverityBadge severity={f.severity} />
          {f.known_exploited && <KevBadge />}
          <MustFixBadge cls={f.must_fix_class} state={f.enrichment_state} />
          {f.exposure.internet_facing && <Pill label="internet-facing" className="border-amber/30 bg-amber/10 text-amber" />}
          {f.exposure.privileged && <Pill label="privileged" className="border-amber/30 bg-amber/10 text-amber" />}
          {f.resource_id && !escalation.isLoading && escalation.data && (
            escalation.data.chains > 0 ? (
              <Pill
                label={`${escalation.data.chains}${escalation.data.truncated ? "+" : ""} assumable high-risk role${escalation.data.chains !== 1 ? "s" : ""}`}
                className="border-orange/30 bg-orange/10 text-orange"
              />
            ) : (
              <Pill label="No assumable high-risk roles found" className="border-emerald/30 bg-emerald/10 text-emerald" />
            )
          )}
        </div>
      </div>

      {/* True-severity belief — the headline "is this REALLY this severe?" verdict
          with its grounded evidence chain. Leads the body: it frames the
          score factors below, and can re-frame the raw score itself. */}
      <BeliefPanel belief={belief.data} />

      {/* Attack-path narrative — the plain-English risk story, leads everything */}
      {f.narrative && (
        <div className="mb-4 rounded-lg border border-teal/30 bg-teal/5 p-3">
          <div className="mb-1 text-[11px] font-medium uppercase tracking-wide text-teal">Risk story</div>
          <p className="text-[13px] leading-relaxed text-text-1">{f.narrative}</p>
        </div>
      )}

      {/* Score factors — the WHY before the wall of text. Shared with the
          slide-over panel so both surfaces justify the score identically. */}
      <ScoreFactors finding={f} className="mb-4" />

      {/* Detection — the scanner-native "what & where": matched URL, evidence, refs.
          The single most useful context for a scan finding, so it leads. */}
      {(f.matched_url || f.evidence || f.references) && (
        <div className="mb-4 rounded-lg border border-border-subtle bg-surface p-3">
          <div className="mb-2 text-[11px] uppercase tracking-wide text-text-3">Detection</div>
          <dl className="space-y-2 text-xs">
            {f.matched_url && (
              <div>
                <dt className="mb-0.5 text-[11px] uppercase tracking-wide text-text-3">Matched at</dt>
                <dd>
                  <a
                    href={f.matched_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="break-all font-mono text-[11px] text-teal hover:underline"
                  >
                    {f.matched_url}
                  </a>
                </dd>
              </div>
            )}
            {f.evidence && (
              <div>
                <dt className="mb-0.5 text-[11px] uppercase tracking-wide text-text-3">Evidence</dt>
                <dd className="break-all rounded bg-surface-2 px-2 py-1 font-mono text-[11px] text-text-2">{f.evidence}</dd>
              </div>
            )}
            {f.references && (
              <div>
                <dt className="mb-0.5 text-[11px] uppercase tracking-wide text-text-3">References</dt>
                <dd className="space-y-0.5">
                  {f.references.split("\n").filter(Boolean).map((ref, i) => (
                    <a
                      key={i}
                      href={ref}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="block break-all text-[11px] text-teal hover:underline"
                    >
                      {ref}
                    </a>
                  ))}
                </dd>
              </div>
            )}
          </dl>
        </div>
      )}

      {/* Fix — prominently, if there is one */}
      {f.remediation && (
        <div className="mb-4 rounded-lg border border-teal/20 bg-teal/5 px-3 py-2.5">
          <span className="text-[11px] uppercase tracking-wide text-teal">Fix: </span>
          <span className="text-[12px] text-text-2">{f.remediation}</span>
        </div>
      )}

      {/* Safe to fix — how risky the fix is, what to look for, and where to apply
          it. Pairs with "Why score" above; shared with the slide-over panel. */}
      <SafeToFixSection finding={f} className="mb-4" />

      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        {/* Finding provenance */}
        <Card>
          <SectionTitle>Affected resource</SectionTitle>
          <dl className="space-y-1.5 text-xs">
            <Row label="Resource" value={cleanResourceId(f.resource_id)} mono={!!(f.resource_id)} />
            {f.resource_id && f.resource_id !== cleanResourceId(f.resource_id) && (
              <div className="flex justify-between gap-4">
                <dt className="text-text-3">Full ID</dt>
                <dd className="max-w-xs truncate font-mono text-[11px] text-text-3" title={f.resource_id}>{f.resource_id}</dd>
              </div>
            )}
            <Row label="Type" value={f.resource_type ?? f.type} />
            {f.resource_name && <Row label="Name" value={f.resource_name} />}
            <Row label="Region" value={f.region ?? f.provenance.region ?? "—"} />
            <Row label="Detected" value={new Date(f.detected_at).toLocaleString()} />
          </dl>
        </Card>

        {/* Provenance — skip empty fields */}
        <Card>
          <SectionTitle>Origin</SectionTitle>
          <dl className="space-y-1.5 text-xs">
            {(f.provenance.connector || f.source) && (
              <Row label="Source" value={f.provenance.connector || f.source} />
            )}
            {f.provenance.account_id && <Row label="Account" value={f.provenance.account_id} mono />}
            {/* Owner/environment as routed (ADR 089) — the values alerts and the
                list filters use, with the tier that named the owner. */}
            <Row label="Owner" value={routedOwner(f)} />
            {f.environment && <Row label="Environment" value={f.environment} />}
            {f.provenance.age_bucket && <Row label="Age" value={f.provenance.age_bucket} />}
            {f.provenance.source_repo && (
              <Row
                label="Repo"
                value={`${f.provenance.source_repo}${f.provenance.source_confidence ? ` (${f.provenance.source_confidence})` : ""}`}
              />
            )}
            {/* Blast summary — what can this reach? */}
            {(f.blast.count ?? 0) > 0 && (
              <div className="mt-2 border-t border-border-subtle pt-2">
                <div className="mb-1 text-[11px] uppercase tracking-wide text-text-3">Can reach</div>
                {f.blast.by_type && Object.entries(f.blast.by_type).map(([type, count]) => (
                  <div key={type} className="flex justify-between text-[11px]">
                    <span className="text-text-3 capitalize">{type.replace(/_/g, " ")}</span>
                    <span className="tabular-nums text-text-2">{count}</span>
                  </div>
                ))}
                {f.blast.can_assume && f.blast.can_assume.length > 0 && (
                  <div className="mt-1 text-[11px] text-amber">Can assume {f.blast.can_assume.length} role{f.blast.can_assume.length !== 1 ? "s" : ""}</div>
                )}
              </div>
            )}
            {(f.blast.count ?? 0) === 0 && (
              <div className="text-[11px] text-text-3 mt-1">
                {f.blast.known === false ? (
                  <span className="text-amber" title="The blast-radius walk failed — this is not evidence the resource is isolated.">
                    Blast radius unmeasured
                  </span>
                ) : (
                  "Isolated — no reachable assets"
                )}
              </div>
            )}
          </dl>
        </Card>
      </div>

      {/* Description — collapsed by default if long, shown as proper paragraphs not raw markdown */}
      {f.description && (
        <details open className="mt-3 rounded-lg border border-border-subtle bg-surface">
          <summary className="cursor-pointer select-none px-3 py-2 text-[11px] text-text-2 hover:text-text">
            Background — what is this vulnerability?
          </summary>
          <div className="px-3 pb-3 pt-1">
            {f.description.split(/\n\n+/).map((para, i) => (
              <p key={i} className="mt-2 text-[11px] leading-relaxed text-text-2">
                {para.replace(/^#+\s*/, "").replace(/`([^`]+)`/g, "$1")}
              </p>
            ))}
          </div>
        </details>
      )}

      {/* reasoning trace */}
      {f.reasoning && (
        <Card className="mt-3">
          <SectionTitle>Decision trace</SectionTitle>
          <ReasoningTrace reasoning={f.reasoning} />
        </Card>
      )}

      {/* Blast radius — what this finding can reach */}
      {(f.blast.count ?? 0) > 0 && (
        <div className="mt-4">
          <div className="mb-2 font-display text-sm text-text">
            Blast radius
            <span className="ml-2 text-[11px] text-text-3">
              {f.blast.count} reachable{f.blast.truncated ? " — showing first" : ""}
            </span>
          </div>
          {/* When there are few assets, list them as clickable rows — clearer than a tiny graph */}
          {blastAssets.length > 0 && blastAssets.length <= 3 ? (
            <div className="space-y-1.5">
              {blastAssets.filter((a) => a.id !== f.resource_id).map((a) => (
                <button key={a.id}
                  onClick={() => navigate({ to: "/investigate/assets/$id", params: { id: a.id ?? "" } })}
                  className="flex w-full items-center gap-3 rounded-lg border border-border-subtle bg-surface px-3 py-2.5 text-left hover:border-teal/30 hover:bg-teal/5 transition-colors group">
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium text-text group-hover:text-teal transition-colors">{a.name || cleanResourceId(a.id)}</div>
                    <div className="mt-0.5 text-[11px] text-text-3">{a.type?.replace(/_/g, " ")}</div>
                  </div>
                  {(a.max_score ?? 0) > 0 && (
                    <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[11px] font-medium tabular-nums ${
                      {
                        page: "border-red/30 bg-red/10 text-red",
                        high: "border-orange/30 bg-orange/10 text-orange",
                        pipeline: "border-amber/30 bg-amber/10 text-amber",
                        monitor: "border-border-subtle bg-surface text-text-3",
                      }[scoreToBand(a.max_score ?? 0)]
                    }`}>{a.max_score}</span>
                  )}
                  <span className="shrink-0 text-[11px] text-text-3 group-hover:text-teal">Open →</span>
                </button>
              ))}
              {blastAssets.filter((a) => a.id !== f.resource_id).length === 0 && (
                <p className="text-[11px] text-text-3">This package reaches 1 asset — graph relationships still building. Check the asset detail for connections.</p>
              )}
            </div>
          ) : blastAssets.length > 3 ? (
            <GraphView
              centerId={f.resource_id}
              nodes={blastAssets.map((a) => ({ id: a.id ?? "", label: a.name || a.id || "", sub: a.type ?? "", risk: a.max_score ?? 0 }))}
              edges={blastEdges.map((e) => ({ source: e.src_id ?? "", target: e.dst_id ?? "", label: e.edge_type ?? "" }))}
              onNodeClick={(nid) => navigate({ to: "/investigate/assets/$id", params: { id: nid } })}
              onExpand={(nid) => navigate({ to: "/investigate/assets/$id", params: { id: nid } })}
            />
          ) : null}
        </div>
      )}

      {/* Other CVEs on this resource */}
      {f.peers && f.peers.length > 0 && (
        <Card className="mt-3">
          <SectionTitle>Other vulnerabilities on this resource ({f.peers.length})</SectionTitle>
          <div className="space-y-0.5">
            {f.peers.map((p, i) => (
              <div key={`${p.check_id}-${i}`} className="flex items-center gap-2 rounded px-1 py-1 text-[11px] text-text-3">
                <span className="font-mono text-text-2">{p.check_id}</span>
                {p.score_band && (
                  <span className={`rounded border px-1 py-0.5 text-[11px] font-medium uppercase ${
                    p.score_band === "page" ? "border-red/30 bg-red/10 text-red"
                    : p.score_band === "high" ? "border-orange/30 bg-orange/10 text-orange"
                    : "border-border-subtle bg-surface-3 text-text-3"
                  }`}>{bandLabel(p.score_band) || p.score_band}</span>
                )}
                {p.type && <span className="text-[11px] text-text-3">{p.type}</span>}
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

// cleanResourceId makes resource IDs human-readable.
function cleanResourceId(id?: string): string {
  return shortenId(id);
}

function SectionTitle({ children }: { children: React.ReactNode }) {
  return <span className="mb-2 block text-[11px] uppercase tracking-wide text-text-3">{children}</span>;
}

function Pill({ label, className }: { label: string; className: string }) {
  return <span className={`rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase ${className}`}>{label}</span>;
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex justify-between gap-4">
      <dt className="shrink-0 text-text-3">{label}</dt>
      <dd className={`min-w-0 truncate text-right ${mono ? "font-mono text-[11px] text-text-2" : "text-text-2"}`} title={value}>{value}</dd>
    </div>
  );
}

// routedOwner names the finding's routed owner and the evidence tier, keeping
// "unowned" (resolved to nobody) apart from "not resolved yet". Before
// enrichment has stamped an owner, the resource's own owner tag is the best
// available answer and is shown as such.
function routedOwner(f: FindingContext): string {
  if (f.owner_source === "none") return "unowned";
  if (!f.owner_team) {
    const tagged = f.provenance.owner && f.provenance.owner !== "unknown" ? f.provenance.owner : "";
    return tagged || "not resolved yet";
  }
  return `@${f.owner_team} (${f.owner_source}${f.owner_confidence ? `, ${f.owner_confidence}` : ""})`;
}
