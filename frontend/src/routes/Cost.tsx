import { useMemo, useState } from "react";
import { Link } from "@tanstack/react-router";
import { useQueries, useQuery } from "@tanstack/react-query";
import { DollarSign, AlertTriangle, Server, Database, Cylinder, Box, TrendingUp, ShieldAlert, Zap } from "lucide-react";
import { useConnectors } from "../lib/queries";
import {
  api,
  type CostAnomaly,
  type CostAnomalyPage,
  type CostAtRiskItem,
  type CostAtRiskResponse,
  type CostStatusResponse,
} from "../lib/api";
import { Loading, PageHeader } from "../components/ui";
import { AssetDetailPanel } from "../components/AssetDetailPanel";
import { SCORE_THRESHOLDS } from "../lib/format";

// Everything here is server-computed: cost-bearing resources carrying findings
// (/api/findings/cost-at-risk, a real COUNT), the state of AWS billing
// collection (/api/cost/status) and each collected connector's spend anomalies
// (/api/cost/anomalies). Waste estimates or staleness belong server-side
// on a signal that exists (Cost Explorer usage rows, an inventory-wide query),
// never on client-side check_id matching or filtering of this risk page.

const AT_RISK_MIN_SCORE = SCORE_THRESHOLDS.high;
// Chips are a sample of the population, never the population: the header count
// comes from by_provider, this only bounds how many we draw.
const CHIPS_PER_PROVIDER = 12;

// outcomeCopy turns a collection outcome into a sentence an operator can act on.
// Every branch names a cause; none of them says "no anomalies".
function outcomeCopy(outcome: string, requiredPermission: string): string {
  switch (outcome) {
    case "ok":
      return "collecting normally";
    case "empty":
      return "AWS Cost Explorer answered with no cost entries for the last 30 days";
    case "permission_denied":
      return `AWS denied the Cost Explorer call — the connector role is missing ${requiredPermission}`;
    case "config_error":
      return "the connector config could not build an AWS session, so no billing call was made";
    case "api_error":
      return "the Cost Explorer call failed (see the serve log for the AWS error)";
    case "store_error":
      return "billing data was fetched but could not be written to Postgres";
    case "":
      return "no collection attempt recorded since this process started";
    default:
      return outcome;
  }
}

function formatUsd(n: number): string {
  return n % 1 === 0 ? `$${n.toFixed(0)}` : `$${n.toFixed(2)}`;
}

function formatCount(n: number): string {
  return n.toLocaleString("en-US");
}

// ── Component ─────────────────────────────────────────────────────────────────

export function Cost() {
  // Single-asset rows/chips open the shared asset slide-over (house convention)
  // rather than navigating away from the cost view.
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);

  // The true count of cost-bearing resources at risk, plus a ranked page of it.
  const atRiskQ = useQuery({
    queryKey: ["cost-at-risk", AT_RISK_MIN_SCORE],
    queryFn: () =>
      api.get<CostAtRiskResponse>(`/api/findings/cost-at-risk?min_score=${AT_RISK_MIN_SCORE}&limit=200`),
    staleTime: 5 * 60 * 1000,
  });

  // Why the billing panels are (or are not) empty.
  const statusQ = useQuery({
    queryKey: ["cost-status"],
    queryFn: () => api.get<CostStatusResponse>("/api/cost/status"),
    staleTime: 60 * 1000,
    retry: false,
  });

  const connectorsQ = useConnectors();
  const awsConnectors = useMemo(
    () => (connectorsQ.data ?? []).filter((c) => c.type === "aws"),
    [connectorsQ.data],
  );

  // Anomalies for EVERY AWS connector that has stored billing data — showing
  // only the first AWS connector would make an anomaly in any other account
  // invisible by construction.
  const collectedConnectorIDs = useMemo(() => {
    const stored = new Map((statusQ.data?.connectors ?? []).map((c) => [c.connector_id, c.snapshots_stored]));
    return awsConnectors.map((c) => c.id).filter((id) => (stored.get(id) ?? 0) > 0);
  }, [awsConnectors, statusQ.data]);

  const anomalyQueries = useQueries({
    queries: collectedConnectorIDs.map((id) => ({
      queryKey: ["cost-anomalies", id],
      queryFn: () => api.get<CostAnomalyPage>(`/api/cost/anomalies?connector_id=${encodeURIComponent(id)}`),
      staleTime: 5 * 60 * 1000,
    })),
  });
  const liveAnomalies: CostAnomaly[] = anomalyQueries.flatMap((q) => q.data?.items ?? []);
  const anomaliesLoading = anomalyQueries.some((q) => q.isLoading);

  const atRisk = atRiskQ.data;
  const connectorName = useMemo(() => {
    const m = new Map<string, string>();
    for (const c of awsConnectors) m.set(c.id, c.name);
    return m;
  }, [awsConnectors]);

  // Chips per provider, drawn from the ranked page; the count in each header is
  // the server-side total for that provider, not chips.length.
  const byProvider = useMemo(() => {
    if (!atRisk) return [];
    const shown = new Map<string, CostAtRiskItem[]>();
    for (const item of atRisk.items) {
      const list = shown.get(item.provider) ?? [];
      if (list.length < CHIPS_PER_PROVIDER) list.push(item);
      shown.set(item.provider, list);
    }
    return Object.entries(atRisk.by_provider)
      .map(([provider, total]) => ({ provider, total, items: shown.get(provider) ?? [] }))
      .sort((a, b) => b.total - a.total);
  }, [atRisk]);

  const byType = useMemo(() => {
    if (!atRisk) return [];
    return Object.entries(atRisk.by_type).sort((a, b) => b[1] - a[1]);
  }, [atRisk]);

  const status = statusQ.data;
  const notCollecting = useMemo(
    () => (status?.connectors ?? []).filter((c) => c.outcome !== "" && c.outcome !== "ok"),
    [status],
  );

  if (atRiskQ.isLoading) return <Loading />;

  return (
    <div style={{ fontFamily: "var(--font-body)" }}>
      <PageHeader
        title="Cost signals"
        subtitle="Billed resources carrying serious findings — where remediation and spend decisions meet — plus the state of AWS billing collection."
      />

      {/* ── Summary bar ─────────────────────────────────────────────────── */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(3, 1fr)",
          gap: "12px",
          marginBottom: "28px",
        }}
      >
        <MetricCard
          icon={<AlertTriangle style={{ width: 14, height: 14 }} />}
          label="Cost-bearing at risk"
          value={atRisk && atRisk.total > 0 ? formatCount(atRisk.total) : atRiskQ.isError ? "?" : "0"}
          accent="orange"
          note={
            atRiskQ.isError
              ? "count unavailable — the rollup query failed"
              : atRisk && atRisk.total > 0
                ? `billed resources at score ≥ ${AT_RISK_MIN_SCORE}, across ${byType.length} resource types`
                : `no billed resource carries a finding at score ≥ ${AT_RISK_MIN_SCORE}`
          }
        />
        <MetricCard
          icon={<DollarSign style={{ width: 14, height: 14 }} />}
          label="Billing data collected"
          value={status ? (status.collected ? formatCount(status.snapshots_total) : "none") : "—"}
          accent="teal"
          note={
            !status
              ? "collection status unavailable"
              : status.collected
                ? `cost snapshots stored across ${status.connectors.filter((c) => c.snapshots_stored > 0).length} account(s)`
                : "no cost snapshot has ever been stored — dollar figures are not available"
          }
        />
        <MetricCard
          icon={<TrendingUp style={{ width: 14, height: 14 }} />}
          label="Spend anomalies"
          value={status?.collected ? formatCount(liveAnomalies.length) : "n/a"}
          accent="amber"
          note={
            status?.collected
              ? "services above 2× their 7-day average"
              : "requires billing data — see collection status below"
          }
        />
      </div>

      {/* ── Billing collection status ───────────────────────────────────── */}
      <SectionLabel>AWS billing collection</SectionLabel>
      <p style={{ fontSize: 11, color: "var(--graph-text-3)", marginBottom: 16, marginTop: 4 }}>
        Cost figures on this page come from AWS Cost Explorer (<code>{status?.required_iam_permission ?? "ce:GetCostAndUsage"}</code>),
        collected per connector every 6 hours. This panel reports whether that is actually happening.
      </p>

      {statusQ.isError ? (
        <EmptyState
          icon={<ShieldAlert style={{ width: 14, height: 14, color: "var(--graph-text-3)" }} />}
          message="Collection status endpoint unavailable — cannot say whether billing data is being collected."
        />
      ) : status && !status.collected ? (
        <div
          style={{
            background: "rgba(249,115,22,0.06)",
            border: "1px solid rgba(249,115,22,0.25)",
            borderRadius: 12,
            padding: "16px 18px",
            marginBottom: 28,
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8, color: "var(--graph-orange)" }}>
            <ShieldAlert style={{ width: 14, height: 14 }} />
            <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.06em", textTransform: "uppercase" }}>
              No billing data collected
            </span>
          </div>
          <p style={{ fontSize: 12, color: "var(--graph-text-2)", margin: "0 0 10px" }}>
            {`Zero cost snapshots are stored, so no dollar amount and no spend anomaly can be shown for any account — this is an absence of data, not an absence of waste.`}
          </p>
          <p style={{ fontSize: 12, color: "var(--graph-text-2)", margin: "0 0 10px" }}>
            The most likely cause is a missing IAM permission: the connector role needs{" "}
            <code style={{ fontFamily: "var(--font-mono)" }}>{status.required_iam_permission}</code>. See{" "}
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>docs/iam/cost-explorer-permission.md</span>.
          </p>
          {notCollecting.length > 0 && (
            <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 6 }}>
              {notCollecting.slice(0, 10).map((c) => (
                <div key={c.connector_id} style={{ fontSize: 11, color: "var(--graph-text-3)" }}>
                  <span style={{ fontFamily: "var(--font-mono)", color: "var(--graph-text-2)" }}>
                    {connectorName.get(c.connector_id) ?? c.account_id ?? c.connector_id}
                  </span>
                  {" — "}
                  {outcomeCopy(c.outcome, status.required_iam_permission)}
                </div>
              ))}
              {notCollecting.length > 10 && (
                <div style={{ fontSize: 11, color: "var(--graph-text-3)" }}>
                  +{notCollecting.length - 10} more connector(s) with the same class of failure
                </div>
              )}
            </div>
          )}
          {notCollecting.length === 0 && (
            <div style={{ fontSize: 11, color: "var(--graph-text-3)" }}>
              No collection attempt has been recorded yet in this server process. The loop runs on startup and every 6h;
              outcomes appear here and in <span style={{ fontFamily: "var(--font-mono)" }}>graph_cost_collect_total</span>.
            </div>
          )}
        </div>
      ) : anomaliesLoading ? (
        <div style={{ fontSize: 12, color: "var(--graph-text-3)", marginBottom: 28 }}>Loading spend anomalies…</div>
      ) : liveAnomalies.length === 0 ? (
        <EmptyState message="Billing data is being collected and no service is above 2× its 7-day average right now." />
      ) : (
        <div
          style={{
            background: "var(--graph-surface-2)",
            border: "1px solid var(--graph-border)",
            borderRadius: 12,
            overflow: "hidden",
            marginBottom: 28,
          }}
        >
          {liveAnomalies.map((a, i) => (
            <AnomalyRow
              key={`${a.connector_id}-${a.service}`}
              anomaly={a}
              account={connectorName.get(a.connector_id) ?? a.connector_id}
              isLast={i === liveAnomalies.length - 1}
            />
          ))}
        </div>
      )}

      {/* ── Cost-bearing resources at risk ──────────────────────────────── */}
      <SectionLabel>Cost-bearing resources at risk</SectionLabel>
      <p style={{ fontSize: 11, color: "var(--graph-text-3)", marginBottom: 16, marginTop: 4 }}>
        {atRisk
          ? `${formatCount(atRisk.total)} billed resources — compute, storage, databases, load balancers and other invoiced types — carry a finding scoring ≥ ${atRisk.min_score}. Packages, identities and IaC declarations are excluded: they carry risk but no bill. Showing the ${formatCount(atRisk.returned)} worst.`
          : "Counting billed resources that carry serious findings."}
      </p>

      {atRiskQ.isError ? (
        <EmptyState message="The cost-bearing risk rollup failed — this is an error, not a clean result." />
      ) : byProvider.length === 0 ? (
        <EmptyState message={`No billed resource currently carries a finding at score ≥ ${AT_RISK_MIN_SCORE}.`} />
      ) : (
        <>
          <div style={{ display: "flex", flexDirection: "column", gap: 16, marginBottom: 20 }}>
            {byProvider.map(({ provider, total, items }) => (
              <ProviderAtRiskCard
                key={provider}
                provider={provider}
                total={total}
                assets={items}
                minScore={AT_RISK_MIN_SCORE}
                onSelect={setSelectedAssetId}
              />
            ))}
          </div>
          <CompositionTable rows={byType} total={atRisk?.total ?? 0} />
        </>
      )}

      <AssetDetailPanel assetId={selectedAssetId} onClose={() => setSelectedAssetId(null)} />
    </div>
  );
}

// ── Sub-components ─────────────────────────────────────────────────────────────

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 0 }}>
      <span
        style={{
          fontSize: 10,
          fontWeight: 600,
          letterSpacing: "0.08em",
          textTransform: "uppercase",
          color: "var(--graph-teal)",
        }}
      >
        {children}
      </span>
      <div style={{ flex: 1, height: 1, background: "var(--graph-border)" }} />
    </div>
  );
}

type MetricAccent = "teal" | "orange" | "amber";

const accentMap: Record<MetricAccent, { text: string; bg: string; border: string; glow: string }> = {
  teal:   { text: "var(--graph-teal)", bg: "rgba(13,148,136,0.08)",  border: "rgba(13,148,136,0.25)", glow: "rgba(13,148,136,0.15)" },
  orange: { text: "var(--graph-orange)", bg: "rgba(249,115,22,0.08)",  border: "rgba(249,115,22,0.25)", glow: "rgba(249,115,22,0.15)" },
  amber:  { text: "var(--graph-amber)", bg: "rgba(245,158,11,0.08)",  border: "rgba(245,158,11,0.25)", glow: "rgba(245,158,11,0.15)" },
};

function MetricCard({
  icon, label, value, accent, note,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  accent: MetricAccent;
  note?: string;
}) {
  const a = accentMap[accent];
  return (
    <div
      style={{
        background: a.bg,
        border: `1px solid ${a.border}`,
        borderRadius: 12,
        padding: "16px 18px",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 10, color: a.text }}>
        {icon}
        <span style={{ fontSize: 10, fontWeight: 600, letterSpacing: "0.06em", textTransform: "uppercase" }}>
          {label}
        </span>
      </div>
      <div
        style={{
          fontFamily: "var(--font-display)",
          fontSize: 26,
          fontWeight: 700,
          letterSpacing: "-0.03em",
          color: value === "—" || value === "n/a" || value === "none" ? "var(--graph-text-3)" : "var(--graph-text)",
          marginBottom: 4,
        }}
      >
        {value}
      </div>
      {note && (
        <div style={{ fontSize: 11, color: "var(--graph-text-3)" }}>{note}</div>
      )}
    </div>
  );
}

// CompositionTable publishes what the headline count is made of. The previous
// version of this page showed a headline of "100" over a list that was 50
// packages and 50 service accounts — the composition IS the audit trail.
function CompositionTable({ rows, total }: { rows: Array<[string, number]>; total: number }) {
  if (rows.length === 0) return null;
  const max = rows[0][1] || 1;
  return (
    <div
      style={{
        background: "var(--graph-surface-2)",
        border: "1px solid var(--graph-border)",
        borderRadius: 12,
        overflow: "hidden",
        marginBottom: 28,
      }}
    >
      <div style={{ padding: "12px 18px", borderBottom: "1px solid var(--graph-border)", fontSize: 11, color: "var(--graph-text-3)" }}>
        Composition of the {formatCount(total)} at-risk billed resources, by type
      </div>
      {rows.map(([type, n], i) => (
        <div
          key={type}
          style={{
            display: "grid",
            gridTemplateColumns: "180px 1fr 70px",
            gap: 12,
            alignItems: "center",
            padding: "9px 18px",
            borderBottom: i === rows.length - 1 ? "none" : "1px solid var(--graph-border)",
          }}
        >
          <span style={{ fontSize: 11, color: "var(--graph-text-2)", fontFamily: "var(--font-mono)" }}>
            {type}
          </span>
          <div style={{ height: 3, background: "var(--graph-surface-3)", borderRadius: 2, overflow: "hidden" }}>
            <div
              style={{
                height: "100%",
                width: `${Math.max(2, Math.round((n / max) * 100))}%`,
                background: "linear-gradient(90deg, var(--graph-teal), rgba(13,148,136,0.5))",
                borderRadius: 2,
              }}
            />
          </div>
          <span style={{ fontSize: 11, textAlign: "right", fontFamily: "var(--font-mono)", color: "var(--graph-text)" }}>
            {formatCount(n)}
          </span>
        </div>
      ))}
    </div>
  );
}

function ProviderAtRiskCard({
  provider, total, assets, minScore, onSelect,
}: {
  provider: string;
  total: number;
  assets: CostAtRiskItem[];
  minScore: number;
  onSelect: (id: string) => void;
}) {
  const providerColor: Record<string, { text: string; border: string; bg: string }> = {
    aws:        { text: "var(--graph-orange)", border: "rgba(249,115,22,0.2)",  bg: "rgba(249,115,22,0.05)"  },
    gcp:        { text: "var(--graph-sky)", border: "rgba(14,165,233,0.2)",  bg: "rgba(14,165,233,0.05)"  },
    azure:      { text: "#60a5fa", border: "rgba(96,165,250,0.2)",  bg: "rgba(96,165,250,0.05)"  },
    github:     { text: "var(--graph-text)", border: "var(--graph-border-2)", bg: "var(--graph-surface)" },
    kubernetes: { text: "var(--graph-teal)", border: "rgba(13,148,136,0.2)",  bg: "rgba(13,148,136,0.05)"  },
  };
  const c = providerColor[provider] ?? providerColor.github;

  return (
    <div
      style={{
        background: c.bg,
        border: `1px solid ${c.border}`,
        borderRadius: 12,
        padding: "14px 18px",
      }}
    >
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
        <span
          style={{
            fontSize: 10,
            fontWeight: 700,
            letterSpacing: "0.06em",
            textTransform: "uppercase",
            color: c.text,
          }}
        >
          {provider || "unattributed"}
        </span>
        {/* total is the server-side count for this provider; the chips below are
            a sample of it. Printing assets.length here (after a .slice) is the
            bug this line replaces. */}
        <span style={{ fontSize: 11, color: "var(--graph-text-3)" }}>
          {formatCount(total)} billed {total === 1 ? "resource" : "resources"} at score ≥ {minScore}
          {assets.length < total ? ` · showing ${assets.length}` : ""}
        </span>
      </div>
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
        {assets.map((a) => (
          <AssetChip key={a.id} asset={a} onSelect={onSelect} />
        ))}
      </div>
    </div>
  );
}

function AssetChip({ asset, onSelect }: { asset: CostAtRiskItem; onSelect: (id: string) => void }) {
  const score = asset.max_score;
  const scoreColor =
    score >= SCORE_THRESHOLDS.page ? "var(--graph-red)" :
    score >= SCORE_THRESHOLDS.high ? "var(--graph-orange)" :
    score >= SCORE_THRESHOLDS.pipeline ? "var(--graph-amber)" :
    "var(--graph-text-3)";

  const typeIcon: Record<string, React.ElementType> = {
    ec2_instance:       Server,
    gce_instance:       Server,
    rds_instance:       Database,
    cloudsql_instance:  Database,
    s3_bucket:          Cylinder,
    gcs_bucket:         Cylinder,
    ebs_volume:         Cylinder,
    lambda_function:    Zap,
    cloud_function:     Zap,
  };
  const Icon = typeIcon[asset.type] ?? Box;

  return (
    <Link
      to="/investigate/assets/$id"
      params={{ id: asset.id }}
      // Plain click opens the slide-over; the href stays real so modifier-clicks
      // (new tab / new window) still work as a secondary affordance.
      onClick={(e) => { if (e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return; e.preventDefault(); onSelect(asset.id); }}
      style={{ textDecoration: "none" }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          background: "var(--graph-surface-2)",
          border: "1px solid var(--graph-border)",
          borderRadius: 8,
          padding: "5px 9px",
          fontSize: 11,
          color: "var(--graph-text-2)",
          cursor: "pointer",
          transition: "border-color 0.15s",
        }}
        className="card-hover"
      >
        <Icon style={{ width: 11, height: 11, color: "var(--graph-text-3)" }} />
        <span style={{ maxWidth: 140, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {asset.name || asset.id}
        </span>
        <span
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: 10,
            fontWeight: 700,
            color: scoreColor,
            marginLeft: 2,
          }}
        >
          {score}
        </span>
      </div>
    </Link>
  );
}

function AnomalyRow({ anomaly, account, isLast }: { anomaly: CostAnomaly; account: string; isLast: boolean }) {
  return (
    <div
      style={{
        padding: "14px 18px",
        borderBottom: isLast ? "none" : "1px solid var(--graph-border)",
        display: "grid",
        gridTemplateColumns: "1fr auto",
        gap: "12px",
        alignItems: "center",
      }}
    >
      <div>
        <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
          <TrendingUp style={{ width: 12, height: 12, color: "var(--graph-red)", flexShrink: 0 }} />
          <span style={{ fontSize: 12, fontWeight: 500, color: "var(--graph-text)" }}>
            {anomaly.service}
          </span>
          <span style={{ fontSize: 10, color: "var(--graph-text-3)", fontFamily: "var(--font-mono)" }}>
            {account}
          </span>
        </div>
        <div style={{ fontSize: 11, color: "var(--graph-text-3)" }}>
          7-day avg: <span style={{ fontFamily: "var(--font-mono)" }}>{formatUsd(anomaly.rolling_avg_usd)}/day</span>
          {" · "}period: <span style={{ fontFamily: "var(--font-mono)" }}>{anomaly.period_date}</span>
        </div>
      </div>
      <div style={{ textAlign: "right", flexShrink: 0 }}>
        <div
          style={{
            fontFamily: "var(--font-mono)",
            fontSize: 15,
            fontWeight: 600,
            color: "var(--graph-red)",
            letterSpacing: "-0.01em",
          }}
        >
          {formatUsd(anomaly.latest_cost_usd)}<span style={{ fontSize: 10, color: "var(--graph-text-3)", fontWeight: 400 }}>/day</span>
        </div>
        <div style={{ fontSize: 11, color: "var(--graph-text-3)", marginTop: 2 }}>
          +{formatUsd(anomaly.delta_usd)} above avg
        </div>
      </div>
    </div>
  );
}

function EmptyState({ message, icon }: { message: string; icon?: React.ReactNode }) {
  return (
    <div
      style={{
        border: "1px dashed var(--graph-border)",
        borderRadius: 12,
        padding: "36px 24px",
        textAlign: "center",
        marginBottom: 28,
      }}
    >
      <div
        style={{
          width: 36, height: 36, borderRadius: "50%",
          background: "var(--graph-surface-2)",
          border: "1px solid var(--graph-border)",
          display: "flex", alignItems: "center", justifyContent: "center",
          margin: "0 auto 12px",
        }}
      >
        {icon ?? <DollarSign style={{ width: 14, height: 14, color: "var(--graph-text-3)" }} />}
      </div>
      <p style={{ fontSize: 12, color: "var(--graph-text-3)", margin: 0 }}>{message}</p>
    </div>
  );
}
