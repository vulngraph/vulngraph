import React, { useState } from "react";
import { Link } from "@tanstack/react-router";
import { ChevronDown, ChevronUp, X, Sparkles, ExternalLink } from "lucide-react";
import { useAsset, useAssetChanges, useBlastRadius, useFindings } from "../lib/queries";
import { openAssistant } from "../lib/assistant";
import { ScoreBadge, SeverityBadge } from "./ui";
import { MustFixBadge } from "./MustFixBadge";
import { providerClass, typeMetaFor } from "../lib/assetMeta";
import { SlideOver } from "./SlideOver";
import { bandTone } from "../lib/format";
import { environmentLabel } from "../lib/environment";
import { useAssetClassification, ClassificationBadges } from "./DataClassification";
import { AssetChangeRows } from "./AssetChangeRows";

// AssetDetailPanel — slide-in drawer from the right showing key asset facts,
// top findings, blast radius, and an Ask AI shortcut. Overlay, Escape, scroll
// lock and the focus trap all live in SlideOver; colours are token classes so
// the panel reads correctly in both themes.

// ── Type-specific enriched metadata section ──────────────────────────────────
// Each asset type surfaces the fields that actually matter — not a raw metadata
// dump, but synthesized context: urgency signals, relationships, security-relevant
// state. The data all lives in a.metadata; this component makes it readable.

type ChipColor = "red" | "amber" | "green" | "teal" | "muted" | "blue";

const CHIP_CLASSES: Record<ChipColor, string> = {
  red:   "border-red/30 bg-red/10 text-red",
  amber: "border-amber/30 bg-amber/10 text-amber",
  green: "border-emerald/30 bg-emerald/10 text-emerald",
  teal:  "border-teal/30 bg-teal/10 text-teal",
  blue:  "border-sky/30 bg-sky/10 text-sky",
  muted: "border-border-subtle bg-surface-2 text-text-3",
};

function chip(label: string, color: ChipColor = "muted") {
  return (
    <span
      className={`inline-flex rounded border px-2 py-[2px] text-[11px] font-semibold uppercase tracking-[0.03em] ${CHIP_CLASSES[color]}`}
    >
      {label}
    </span>
  );
}

function field(label: string, value: React.ReactNode, mono = false) {
  if (!value && value !== 0) return null;
  return (
    <div className="flex gap-1.5 text-[11px] leading-normal">
      <span className="min-w-[90px] shrink-0 text-text-3">{label}</span>
      <span className={`break-all text-[11px] text-text-2 ${mono ? "font-mono" : ""}`}>{value}</span>
    </div>
  );
}

function expiryUrgency(days: number | null): { color: ChipColor; label: string } {
  if (days === null) return { color: "muted", label: "Unknown" };
  if (days <= 0)  return { color: "red",   label: "EXPIRED" };
  if (days <= 14) return { color: "red",   label: `${days}d left` };
  if (days <= 30) return { color: "amber", label: `${days}d left` };
  if (days <= 60) return { color: "amber", label: `${days}d left` };
  return { color: "green", label: `${days}d left` };
}

// Inline code chip used across the typed sections.
const CODE_CLS = "rounded bg-surface-2 px-1.5 py-[1px] text-[11px] text-text-2";

export function TypedAssetSection({ type, meta, publicIp }: { type: string; meta: Record<string,string> | undefined; publicIp?: string; domain?: string }) {
  const m = meta ?? {};

  // ── TLS / ACM certificates ────────────────────────────────────────────────
  if (type === "acm_certificate" || type === "gcp_certificate" || type === "ssl_certificate") {
    const days = m.days_until_expiry != null ? parseInt(m.days_until_expiry) : null;
    const urgency = expiryUrgency(days);
    const sans = (m.san || m.domains || "").split(",").map(s => s.trim()).filter(Boolean);
    const inUseby = (m.in_use_by || "").split(",").map(s => s.trim()).filter(Boolean)
      .map(arn => arn.split("/").pop() ?? arn);
    return (
      <Section label="Certificate">
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap items-center gap-1.5">
            {chip(urgency.label, urgency.color)}
            {m.status && chip(m.status, m.status === "ISSUED" ? "green" : "amber")}
            {m.renewal_eligibility === "ELIGIBLE" && chip("Auto-renew ✓", "teal")}
            {m.key_algorithm && chip(m.key_algorithm, "muted")}
          </div>
          {days !== null && days > 0 && m.expires_at && (
            <div className="text-[11px] text-text-3">
              Expires {new Date(m.expires_at).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" })}
              {m.issued_at && ` · issued ${Math.round((Date.now() - new Date(m.issued_at).getTime()) / 86400000)}d ago`}
            </div>
          )}
          {field("Issuer", m.issuer || m.source)}
          {field("Subject", m.subject)}
          {sans.length > 0 && field("Domains", (
            <div className="flex flex-wrap gap-[3px]">
              {sans.map(s => <code key={s} className={CODE_CLS}>{s}</code>)}
            </div>
          ))}
          {inUseby.length > 0 && field("Used by", (
            <div className="flex flex-wrap gap-[3px]">
              {inUseby.map(r => <span key={r} className="text-[11px] text-teal">{r}</span>)}
            </div>
          ))}
        </div>
      </Section>
    );
  }

  // ── EC2 instances ──────────────────────────────────────────────────────────
  if (type === "ec2_instance") {
    const state = m.state ?? "unknown";
    const stateColor: ChipColor = state === "running" ? "green" : state === "stopped" ? "amber" : "muted";
    const sgs = (m.security_groups || "").split(",").map(s => s.trim()).filter(Boolean);
    return (
      <Section label="Instance">
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap gap-1.5">
            {chip(state, stateColor)}
            {m.instance_type && chip(m.instance_type, "muted")}
            {publicIp && chip("Internet-facing", "red")}
          </div>
          {field("Instance ID", m.instance_id, true)}
          {field("VPC", m.vpc_id, true)}
          {field("Subnet", m.subnet_id, true)}
          {sgs.length > 0 && field("Security groups", sgs.join(" · "))}
        </div>
      </Section>
    );
  }

  // ── RDS instances ──────────────────────────────────────────────────────────
  if (type === "rds_instance") {
    const pubAccess = m.publicly_accessible === "true";
    // storage_encrypted can be absent (an IaC-declared row, or a describe that did
    // not report it): that is unknown, not the alarm, so only an observed "false" is badged unencrypted.
    const encChip = m.storage_encrypted === "true" ? chip("Encrypted ✓", "green")
      : m.storage_encrypted === "false" ? chip("Unencrypted ⚠", "red")
      : chip("Encryption unknown", "muted");
    const multiAZ = m.multi_az === "true";
    const delProt = m.deletion_protection === "true";
    return (
      <Section label="Database">
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap gap-1.5">
            {pubAccess  ? chip("Publicly accessible ⚠", "red")   : chip("Private", "green")}
            {encChip}
            {multiAZ    ? chip("Multi-AZ", "teal")                : chip("Single-AZ", "amber")}
            {delProt    ? chip("Deletion protected", "green")      : chip("No deletion protect ⚠", "amber")}
          </div>
          {field("Engine", m.engine)}
          {m.port && field("Port", m.port)}
          {m.backup_retention && field("Backup retention", `${m.backup_retention} days`)}
          {m.security_groups && field("Security groups", m.security_groups)}
        </div>
      </Section>
    );
  }

  // ── Load balancers ─────────────────────────────────────────────────────────
  if (type === "load_balancer" || type === "gcp_forwarding_rule") {
    const internetFacing = m.scheme === "internet-facing" || m.scheme === "EXTERNAL";
    return (
      <Section label="Load Balancer">
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap gap-1.5">
            {internetFacing ? chip("Internet-facing", "red") : chip("Internal", "green")}
            {m.type && chip(m.type.toUpperCase(), "muted")}
            {m.state && chip(m.state, m.state === "active" ? "green" : "amber")}
          </div>
          {field("VPC", m.vpc_id, true)}
          {m.security_groups && field("Security groups", m.security_groups)}
        </div>
      </Section>
    );
  }

  // ── IAM roles ──────────────────────────────────────────────────────────────
  if (type === "iam_role" || type === "gcp_service_account") {
    // 9999 is the AWS collector's observed-never-used sentinel, not a day count —
    // rendering it verbatim showed "9999d ago", a fabricated 27 years. An absent
    // key means the collector never observed it, which is a different statement
    // again and must not be shown as a measurement either.
    const lastUsedDays = m.last_used_days != null ? parseInt(m.last_used_days) : null;
    const neverUsed = lastUsedDays === 9999;
    const staleness: ChipColor | null = lastUsedDays === null ? null
      : neverUsed || lastUsedDays > 90 ? "red" : lastUsedDays > 30 ? "amber" : "green";
    const lastUsedLabel = lastUsedDays === null ? "Not observed"
      : neverUsed ? "Never used"
      : lastUsedDays === 0 ? "Today"
      : `${lastUsedDays}d ago`;
    const policies = (m.policies || "").split(",").map(s => s.trim()).filter(Boolean);
    return (
      <Section label="Identity">
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap gap-1.5">
            {staleness && chip(`Last used: ${lastUsedLabel}`, staleness)}
          </div>
          {m.path && m.path !== "/" && field("Path", m.path, true)}
          {policies.length > 0 && field("Policies", (
            <div className="flex flex-col gap-0.5">
              {policies.slice(0, 5).map(p => (
                <code key={p} className={`block ${CODE_CLS}`}>{p}</code>
              ))}
              {policies.length > 5 && <span className="text-[11px] text-text-3">+{policies.length - 5} more</span>}
            </div>
          ))}
        </div>
      </Section>
    );
  }

  // ── Security groups ────────────────────────────────────────────────────────
  if (type === "security_group") {
    return (
      <Section label="Security Group">
        <div className="flex flex-col gap-2">
          {m.description && <div className="text-[11px] italic text-text-2">{m.description}</div>}
          {field("VPC", m.vpc_id, true)}
          {m.ingress && field("Ingress rules", m.ingress)}
        </div>
      </Section>
    );
  }

  // ── GitHub repos ───────────────────────────────────────────────────────────
  if (type === "github_repo") {
    const isPublic = m.visibility === "public";
    return (
      <Section label="Repository">
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap gap-1.5">
            {isPublic ? chip("Public ⚠", "amber") : chip("Private", "green")}
            {m.language && chip(m.language, "blue")}
          </div>
          {m.default_branch && field("Default branch", m.default_branch)}
        </div>
      </Section>
    );
  }

  // ── Kubernetes workloads ───────────────────────────────────────────────────
  if (type === "k8s_pod" || type === "k8s_deployment" || type === "k8s_service") {
    const usesLatest = m.uses_latest_image === "true";
    return (
      <Section label="Workload">
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap gap-1.5">
            {usesLatest && chip("Uses :latest ⚠", "amber")}
            {m.exec_role && chip("IRSA role attached", "teal")}
          </div>
          {m.exec_role && field("IAM role (IRSA)", m.exec_role, true)}
          {m.image_ids && field("Image digest", m.image_ids.split(",")[0], true)}
        </div>
      </Section>
    );
  }

  // ── CloudTrail ─────────────────────────────────────────────────────────────
  if (type === "aws_cloudtrail") {
    const logging = m.is_logging === "true";
    return (
      <Section label="Audit Trail">
        <div className="flex flex-col gap-2">
          <div className="flex flex-wrap gap-1.5">
            {logging ? chip("Logging ON", "green") : chip("Logging OFF ⚠", "red")}
          </div>
          {m.cloudwatch_log_group && field("Log group", m.cloudwatch_log_group, true)}
          {m.latest_delivery && field("Last delivery", new Date(m.latest_delivery).toLocaleString())}
          {m.delivery_error && <div className="text-[11px] text-red">⚠ {m.delivery_error}</div>}
        </div>
      </Section>
    );
  }

  return null;
}

interface Props {
  assetId: string | null;
  onClose: () => void;
}

export function AssetDetailPanel({ assetId, onClose }: Props) {
  return (
    <SlideOver open={assetId !== null} onClose={onClose} title="Asset detail" width="520px">
      {assetId && <PanelBody assetId={assetId} onClose={onClose} />}
    </SlideOver>
  );
}

function PanelBody({ assetId, onClose }: { assetId: string; onClose: () => void }) {
  const asset = useAsset(assetId);
  const blast = useBlastRadius(assetId, "out");
  const changes = useAssetChanges(assetId);
  const changeItems = changes.data?.changes ?? [];
  const findings = useFindings({ resource_id: assetId });
  const topFindings = findings.data?.pages.flatMap((p) => p.items).slice(0, 5) ?? [];

  const a = asset.data;

  function openChat() {
    const name = a?.name || assetId;
    const type = a?.type ?? "";
    const score = a?.max_score ?? 0;
    const findingCount = topFindings.length;
    const facts: string[] = [];
    if (type) facts.push(`type: ${type}`);
    if (a?.provider) facts.push(`provider: ${a.provider}`);
    if (score > 0) facts.push(`risk score: ${score}`);
    if (findingCount > 0) facts.push(`${findingCount} findings`);
    facts.push(`asset ID: ${assetId}`);
    openAssistant({
      subject: `Investigate asset: ${name}`,
      facts,
      question: "What is the risk? Run a graph query to find connections and summarise the threat.",
    });
    onClose();
  }

  const worstFinding = topFindings.reduce((max, f) => Math.max(max, f.score ?? 0), 0);
  const findingTotal = a?.finding_count ?? topFindings.length;
  const findingsSummary = findings.isLoading
    ? "Loading…"
    : findingTotal === 0
      ? "No findings"
      : `${findingTotal} finding${findingTotal !== 1 ? "s" : ""}${worstFinding > 0 ? ` · worst ${worstFinding}` : ""}`;

  const blastOthers = blast.data ? blast.data.assets.filter((x) => x.id !== assetId) : [];
  const blastSummary = blast.isLoading
    ? "Loading…"
    : !blast.data
      ? "—"
      : blastOthers.length === 0
        ? "No outbound reach"
        : `Reaches ${blastOthers.length}${blast.data.truncated ? "+" : ""} asset${blastOthers.length !== 1 ? "s" : ""}`;

  return (
    <>
      {/* Header */}
      <div className="flex shrink-0 items-start justify-between gap-3 border-b border-border-subtle px-[18px] pt-4 pb-3.5">
        <div className="min-w-0">
          {a ? (
            <>
              <div className="break-all font-display text-[14px] font-semibold leading-tight tracking-[-0.01em] text-text">
                {a.name || a.id}
              </div>
              <div className="mt-1 flex flex-wrap gap-1">
                <span
                  className={`inline-flex rounded border px-1.5 py-0.5 text-[11px] font-medium uppercase ${providerClass(a.provider)}`}
                >
                  {a.provider}
                </span>
                <span className="inline-flex rounded border border-border-subtle bg-surface px-1.5 py-[1px] text-[11px] text-text-3">
                  {typeMetaFor(a.type).label || a.type.replace(/_/g, " ")}
                </span>
              </div>
            </>
          ) : asset.isLoading ? (
            <span className="text-[13px] text-text-3">Loading…</span>
          ) : (
            <span className="text-[13px] text-text-3">{assetId}</span>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-1.5">
          <Link
            to="/investigate/assets/$id"
            params={{ id: assetId }}
            className="inline-flex items-center gap-1.5 rounded border border-border-subtle px-2 py-1 text-[11px] font-medium text-teal transition-colors hover:bg-teal/10 hover:text-teal"
          >
            <ExternalLink className="h-3 w-3" />
            Open full detail
          </Link>
          <button
            onClick={onClose}
            aria-label="Close panel"
            className="flex h-7 w-7 items-center justify-center rounded-md border border-border-subtle bg-transparent text-text-3 transition-colors hover:bg-surface-2 hover:text-text"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      {/* Body */}
      <div className="flex flex-1 flex-col gap-[18px] overflow-y-auto px-[18px] py-4">
        {asset.isError && (
          <p className="text-[12px] text-text-3">Failed to load asset data.</p>
        )}

        {a && (
          <>
            {/* Meta row */}
            <Section label="Details">
              <MetaGrid>
                {a.region && <MetaItem label="Region" value={a.region} />}
                {a.account_id && <MetaItem label="Account" value={a.account_id} mono />}
                <MetaItem label="Environment" value={environmentLabel(a.environment, a.environment_source)} />
                <MetaItem label="Type" value={typeMetaFor(a.type).label || a.type.replace(/_/g, " ")} />
                {a.max_score != null && a.max_score > 0 && (
                  <MetaItem label="Risk score" value={
                    <ScoreBadge score={a.max_score} band={a.risk_band} />
                  } />
                )}
              </MetaGrid>
            </Section>

            {/* Status: exposed + risk bar */}
            <Section label="Status">
              <div className="flex flex-col gap-2">
                {(a.public_ip || a.domain) ? (
                  <div className="flex items-center gap-1.5">
                    <span className="rounded border border-red/40 bg-red/10 px-2 py-[2px] text-[11px] font-semibold uppercase tracking-[0.04em] text-red">
                      Internet-exposed
                    </span>
                    <span className="font-mono text-[11px] text-text-3">
                      {a.public_ip || a.domain}
                    </span>
                  </div>
                ) : (
                  <span className="text-[11px] text-text-3">
                    Private — not internet-exposed
                  </span>
                )}

                {/* Risk score bar */}
                {a.max_score != null && a.max_score > 0 && (
                  <div>
                    <div className="mb-1 flex justify-between">
                      <span className="text-[11px] text-text-3">Risk score</span>
                      <span className={`text-[11px] font-semibold ${bandTone(a.risk_band)}`}>
                        {a.max_score}
                      </span>
                    </div>
                    <div className="h-1 overflow-hidden rounded-sm bg-surface-2">
                      <div
                        className={`h-full rounded-sm transition-[width] duration-400 ${bandBarClass(a.risk_band)}`}
                        style={{ width: `${Math.min(a.max_score, 100)}%` }}
                      />
                    </div>
                  </div>
                )}
              </div>
            </Section>

            {/* Type-specific enriched metadata */}
            <TypedAssetSection
              type={a.type}
              meta={a.metadata as Record<string,string> | undefined}
              publicIp={a.public_ip}
              domain={a.domain}
            />

            {/* DSPM data classification (only for classified data stores) */}
            <DataClassificationSection assetId={assetId} />

            {/* Top findings — collapsed by default */}
            <Disclosure
              label={`Findings${findingTotal > 5 ? ` (top 5 of ${findingTotal})` : ""}`}
              summary={findingsSummary}
            >
              {findings.isLoading && (
                <span className="text-[11px] text-text-3">Loading…</span>
              )}
              {!findings.isLoading && topFindings.length === 0 && (
                <span className="text-[11px] text-text-3">No findings.</span>
              )}
              {topFindings.map((f) => (
                <Link
                  key={f.id}
                  to="/investigate/findings/$id"
                  params={{ id: f.id }}
                  className="flex items-center gap-2 rounded-md border border-border-subtle bg-surface px-2 py-1.5 no-underline transition-colors hover:border-teal/20 hover:bg-teal/[0.07]"
                >
                  {f.score > 0 && (
                    <ScoreBadge score={f.score} band={f.score_band} />
                  )}
                  <SeverityBadge severity={f.severity} />
                  <MustFixBadge cls={f.must_fix_class} state={f.enrichment_state} />
                  <span
                    className="min-w-0 flex-1 truncate text-[12px] text-text-2"
                    title={f.title}
                  >
                    {f.title}
                  </span>
                </Link>
              ))}
            </Disclosure>

            {/* Blast radius — collapsed by default */}
            <Disclosure label="Blast radius" summary={blastSummary}>
              {blast.isLoading && (
                <span className="text-[11px] text-text-3">Loading…</span>
              )}
              {blast.data && blastOthers.length > 0 && (
                <div className="flex flex-col gap-1.5">
                  <span className="text-[12px] text-text-2">
                    Reaches <strong className="text-text">{blastOthers.length}</strong>
                    {blast.data.truncated ? "+" : ""} asset{blastOthers.length !== 1 ? "s" : ""}
                  </span>
                  {blastOthers.slice(0, 5).map((x) => (
                    <Link
                      key={x.id}
                      to="/investigate/assets/$id"
                      params={{ id: x.id }}
                      className="flex items-center gap-1.5 rounded border border-border-subtle bg-surface px-1.5 py-[3px] text-[11px] text-text-3 no-underline transition-colors hover:text-teal"
                    >
                      <span className="text-[11px] font-semibold uppercase tracking-[0.04em] text-text-3">
                        {typeMetaFor(x.type).label || x.type}
                      </span>
                      <span className="truncate">{x.name || x.id}</span>
                    </Link>
                  ))}
                  {blastOthers.length > 5 && (
                    <span className="text-[11px] text-text-3">
                      …and {blastOthers.length - 5}{blast.data.truncated ? "+" : ""} more
                    </span>
                  )}
                </div>
              )}
              {!blast.isLoading && blast.data && blastOthers.length === 0 && (
                <span className="text-[11px] text-text-3">
                  No outbound reachability recorded.
                </span>
              )}
            </Disclosure>

            {/* Change history — collapsed by default, matches AssetDetail.tsx */}
            {changeItems.length > 0 && (
              <Disclosure
                label="Change history"
                summary={`${changeItems.length} recent change${changeItems.length !== 1 ? "s" : ""}`}
              >
                <AssetChangeRows changes={changeItems} />
              </Disclosure>
            )}
          </>
        )}
      </div>

      {/* Footer: Ask AI */}
      <div className="shrink-0 border-t border-border-subtle px-[18px] pt-3 pb-4">
        <button
          onClick={openChat}
          disabled={!a}
          className="flex w-full items-center justify-center gap-[7px] rounded-lg border border-teal/30 bg-teal/[0.08] px-4 py-2.5 font-body text-[13px] font-semibold text-teal transition-colors hover:border-teal/50 hover:bg-teal/15 disabled:cursor-not-allowed disabled:opacity-60"
        >
          <Sparkles className="h-4 w-4" />
          Ask AI about this asset
        </button>
      </div>
    </>
  );
}

// ── helpers ──────────────────────────────────────────────────────────────────

const BAND_BAR: Record<string, string> = { page: "bg-red", high: "bg-orange", pipeline: "bg-amber" };

function bandBarClass(band?: string): string {
  return BAND_BAR[band ?? ""] ?? "bg-surface-3";
}

// DataClassificationSection surfaces a data store's DSPM posture inline — its
// sensitivity classes plus the toxic-combination reasons (public / exposed /
// unencrypted). Self-contained: queries the graph by id and renders nothing for
// assets that carry no ContainsData edge, so it's inert for non-storage assets.
// Query + badge markup live in ./DataClassification, shared with AssetDetail.tsx.
function DataClassificationSection({ assetId }: { assetId: string }) {
  const q = useAssetClassification(assetId);
  const classes = (q.data?.classes ?? []).filter(Boolean);
  if (!q.data || classes.length === 0) return null;

  return (
    <Section label="Data classification">
      <ClassificationBadges row={q.data} />
    </Section>
  );
}

function Section({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-2 text-[11px] font-semibold uppercase tracking-[0.07em] text-text-3 opacity-70">
        {label}
      </div>
      <div className="flex flex-col gap-1">
        {children}
      </div>
    </div>
  );
}

// Disclosure — a Section whose body is collapsed by default, showing a one-line
// summary in the header instead. Keeps the drawer scannable: the heavy lists
// (findings, blast radius) stay one click away.
function Disclosure({ label, summary, children }: { label: string; summary: string; children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="flex w-full items-center gap-1.5 text-[11px] font-semibold uppercase tracking-[0.07em] text-text-3 transition-colors hover:text-text-2"
      >
        {open ? <ChevronUp className="h-3 w-3 shrink-0" /> : <ChevronDown className="h-3 w-3 shrink-0" />}
        <span>{label}</span>
        {!open && (
          <span className="ml-auto truncate font-normal normal-case tracking-normal text-text-3">
            {summary}
          </span>
        )}
      </button>
      {open && <div className="mt-2 flex flex-col gap-1">{children}</div>}
    </div>
  );
}

function MetaGrid({ children }: { children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-2 gap-x-4 gap-y-2">
      {children}
    </div>
  );
}

function MetaItem({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div>
      <div className="mb-0.5 text-[11px] uppercase tracking-[0.05em] text-text-3">
        {label}
      </div>
      <div className={`break-all text-[12px] text-text-2 ${mono ? "font-mono" : ""}`}>
        {value}
      </div>
    </div>
  );
}
