import { useEffect, useMemo, useState, type ReactNode } from "react";
import { Link, useNavigate } from "@tanstack/react-router";
import { useMutation } from "@tanstack/react-query";
import {
  AlertTriangle, Bot, ChevronRight, GitBranch, Globe, KeyRound,
  Network, Shield, ShieldAlert, Swords, Users, Zap,
} from "lucide-react";
import { api, type GraphResult, type IdentityCensus } from "../lib/api";
import type { Asset } from "../lib/api";
import { useAssets, useIdentityCensus } from "../lib/queries";
import { GraphView } from "../components/GraphView";
import { AssetDetailPanel } from "../components/AssetDetailPanel";
import { NLQBar } from "../components/NLQBar";
import { PresetPicker } from "../components/PresetPicker";
import { Empty, ErrorNote, Loading, PageHeader } from "../components/ui";
import { timeAgo as timeAgoBase, bandLabel, SCORE_THRESHOLDS } from "../lib/format";

const timeAgo = (iso?: string) => timeAgoBase(iso, "compact");

const HIGH_SCORE_CUTOFF_NOTE =
  ` — a lower cutoff than the platform's usual ${SCORE_THRESHOLDS.high}/${SCORE_THRESHOLDS.page} high/critical bands`;

// ── Preset definitions ────────────────────────────────────────────────────────
// badge distinguishes what kind of identity question the preset answers:
//   human   = queries about real people federating into cloud
//   machine = workloads / service roles / non-human principals
//   attack  = lateral movement / privilege escalation paths
//   mixed   = both human + machine in one graph

type Badge = "human" | "machine" | "attack" | "mixed";
type ColorKey = "sky" | "teal" | "purple" | "amber" | "red" | "orange";

// mergeGraphResults unions several graph results into one, deduping nodes by id
// and edges by (src,dst,type). Used to assemble multi-source presets that Ladybug
// can't express as a single UNION ALL query.
function mergeGraphResults(results: GraphResult[]): GraphResult {
  const nodes = new Map<string, GraphResult["nodes"][number]>();
  const edges = new Map<string, GraphResult["edges"][number]>();
  let truncated = false;
  for (const r of results) {
    for (const n of r.nodes ?? []) if (!nodes.has(n.id)) nodes.set(n.id, n);
    for (const e of r.edges ?? []) edges.set(`${e.src_id}|${e.dst_id}|${e.edge_type}`, e);
    truncated = truncated || !!r.truncated;
  }
  return { nodes: [...nodes.values()], edges: [...edges.values()], truncated, columns: [], rows: [] };
}

const BADGE_CLS: Record<Badge, string> = {
  human:   "text-teal bg-teal/10 border-teal/30",
  machine: "text-sky bg-sky/10 border-sky/30",
  attack:  "text-red bg-red/10 border-red/30",
  mixed:   "text-purple-400 bg-purple-400/10 border-purple-400/30",
};
const BADGE_LABEL: Record<Badge, string> = {
  human:   "human",
  machine: "machine",
  attack:  "attack",
  mixed:   "mixed",
};

const PRESETS = [
  {
    id: "overview",
    icon: Network,
    label: "Identity landscape",
    description: "All human + machine principals mapped to their IAM roles — the complete picture of who runs as what",
    color: "purple" as ColorKey,
    badge: "mixed" as Badge,
    // Two source shapes (machine via ExecutesAs/HasRole, human/CI via FederatedAccess
    // which is typed Repo→IamRole). Ladybug's engine 500s on UNION ALL, so the two
    // are run as separate statements (split on ";;") and merged client-side.
    cypher: `MATCH (src:Asset)-[r:ExecutesAs|HasRole]->(role:IamRole)
RETURN src, r, role
ORDER BY role.score DESC
LIMIT 60
;;
MATCH (src:Repo)-[r:FederatedAccess]->(role:IamRole)
RETURN src, r, role
ORDER BY role.score DESC
LIMIT 40`,
  },
  {
    id: "workloads",
    icon: Bot,
    label: "Workload identities",
    description: "Lambdas, ECS tasks, K8s pods, GCE instances running as IAM roles — the non-human agent surface",
    color: "sky" as ColorKey,
    badge: "machine" as Badge,
    cypher: `MATCH (w:Asset)-[r:ExecutesAs|HasRole]->(role:IamRole)
RETURN w, r, role
ORDER BY role.score DESC
LIMIT 100`,
  },
  {
    id: "human",
    icon: Users,
    label: "Human → cloud IAM",
    description: "Repos and CI/CD pipelines federating into cloud roles via OIDC — who can assume what",
    color: "teal" as ColorKey,
    badge: "human" as Badge,
    // FederatedAccess sources are Repo nodes (GitHub OIDC/IRSA/WIF); an :Asset
    // source label matches nothing.
    cypher: `MATCH (h:Repo)-[f:FederatedAccess]->(role:IamRole)
RETURN h, f, role
ORDER BY role.score DESC
LIMIT 100`,
  },
  {
    id: "assume-chains",
    icon: GitBranch,
    label: "CanAssume chains",
    description: "Role trust policy chains — one assumed role becoming the launchpad for the next",
    color: "purple" as ColorKey,
    badge: "machine" as Badge,
    cypher: `MATCH (a:IamRole)-[r:CanAssume]->(b:IamRole)
RETURN a, r, b
ORDER BY b.score DESC
LIMIT 50`,
  },
  {
    id: "privesc",
    icon: Zap,
    label: "Privilege escalation",
    description: "CIEM technique-based escalation: CreatePolicyVersion, PassRole, SSM SendCommand, and 58 more",
    color: "amber" as ColorKey,
    badge: "attack" as Badge,
    cypher: `MATCH (a:IamRole)-[r:CanEscalateTo]->(b:IamRole)
RETURN a, r, b
ORDER BY b.score DESC
LIMIT 50`,
  },
  {
    id: "attack-chain",
    icon: Swords,
    label: "Full attack chains",
    description: "Internet → workload → IAM role → escalation or assumption → high-risk role (risk score ≥ 70). Risk score ranks findings and reachability, not the permissions a role holds",
    color: "red" as ColorKey,
    badge: "attack" as Badge,
    cypher: `MATCH (entry:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})
MATCH (entry)-[r1:ExecutesAs|HasRole]->(role:IamRole)
MATCH (role)-[r2:CanEscalateTo|CanAssume]->(target:IamRole)
WHERE target.score >= 70
RETURN entry, r1, role, r2, target
ORDER BY target.score DESC
LIMIT 25`,
  },
  {
    id: "shared-iam",
    icon: Shield,
    label: "Shared IAM identity",
    description: "Roles executed by multiple workloads — compromise one, you own the role and everything else using it",
    color: "orange" as ColorKey,
    badge: "machine" as Badge,
    // Pre-aggregate to multi-executor roles before expanding: the naive
    // (w1)-[:ExecutesAs|HasRole]->(role)<-[:ExecutesAs|HasRole]-(w2) self-join fans out over
    // every workload pair and times out on a large Ladybug graph; this shape
    // answers quickly.
    cypher: `MATCH (w1:Asset)-[:ExecutesAs|HasRole]->(role:IamRole)
WITH role, count(w1) AS execs
WHERE execs > 1
WITH role, execs ORDER BY role.score DESC LIMIT 15
MATCH (a:Asset)-[r:ExecutesAs|HasRole]->(role)
RETURN role, r, a
LIMIT 60`,
  },
  {
    id: "cross-account",
    icon: Globe,
    label: "Cross-account",
    description: "Roles that can assume roles in OTHER AWS accounts — the boundary-crossing lateral movement path",
    color: "teal" as ColorKey,
    badge: "attack" as Badge,
    cypher: `MATCH (a:IamRole)-[r:CanAssume]->(b:IamRole)
WHERE a.account_id <> b.account_id AND b.account_id <> ''
RETURN a, r, b
ORDER BY b.score DESC
LIMIT 50`,
  },
] as const;

type PresetId = typeof PRESETS[number]["id"];

// ── Graph tab ─────────────────────────────────────────────────────────────────

function IdentityGraph({ census }: { census?: IdentityCensus }) {
  const navigate = useNavigate();
  const [activeId, setActiveId] = useState<PresetId>("overview");
  const [nlqLabel, setNlqLabel] = useState<string | null>(null); // set when AI generates a query
  const [result, setResult] = useState<GraphResult | undefined>();

  // A preset may carry multiple statements joined by ";;" (Ladybug 500s on UNION
  // ALL, so multi-source graphs are fetched separately and merged). Failed
  // branches are dropped rather than failing the whole view.
  const runQuery = useMutation({
    mutationFn: async (cypher: string): Promise<GraphResult> => {
      const parts = cypher.split(";;").map((s) => s.trim()).filter(Boolean);
      const settled = await Promise.allSettled(
        parts.map((c) => api.post<GraphResult>("/api/graph/cypher", { query: c, max_nodes: 300, max_edges: 600 })),
      );
      const ok = settled.filter((s) => s.status === "fulfilled").map((s) => (s as PromiseFulfilledResult<GraphResult>).value);
      if (ok.length === 0) throw (settled[0] as PromiseRejectedResult).reason;
      return mergeGraphResults(ok);
    },
    onSuccess: setResult,
  });

  const activePreset = PRESETS.find((p) => p.id === activeId)!;

  useEffect(() => {
    setNlqLabel(null);
    runQuery.mutate(activePreset.cypher);
  }, [activeId]);

  function handleNLQ(cypher: string, label: string) {
    setNlqLabel(label);
    runQuery.mutate(cypher);
  }

  const gvNodes = useMemo(
    () =>
      (result?.nodes ?? []).map((n) => ({
        id: n.id,
        label: n.name || n.id,
        sub: n.type,
        provider: n.provider,
        account: n.account_id,
        risk: n.max_score,
        exposed: n.exposed,
        hasKev: n.has_kev,
        exploitable: n.exploitable,
        toxicCombo: n.toxic_combo,
      })),
    [result],
  );
  const gvEdges = useMemo(
    () => (result?.edges ?? []).map((e) => ({ source: e.src_id, target: e.dst_id, label: e.edge_type })),
    [result],
  );

  // Derive human vs machine from graph result nodes (ExecutesAs/HasRole sources are machine, FederatedAccess sources are human)
  const humanEdges  = result?.edges.filter(e => e.edge_type === "FederatedAccess").length ?? 0;
  const machineEdges = result?.edges.filter(e => e.edge_type === "ExecutesAs" || e.edge_type === "HasRole").length ?? 0;

  return (
    <div>
      {/* Census tiles — server-computed, see CensusTiles */}
      {census && <CensusTiles census={census} />}

      {/* AI query bar */}
      <NLQBar
        onQuery={handleNLQ}
        placeholder="Ask AI — e.g. 'show me Lambdas whose roles can escalate to another role' or 'GitHub repos that federate into AWS'"
        className="mb-4"
      />

      {/* Preset picker — one dropdown instead of an 8-card grid */}
      <PresetPicker
        className="mb-4"
        presets={PRESETS.map((p) => ({
          id: p.id,
          label: p.label,
          desc: p.description,
          badge: BADGE_LABEL[p.badge],
        }))}
        activeId={activeId}
        onSelect={(id) => setActiveId(id as PresetId)}
      />

      {/* Graph canvas */}
      <div className="rounded-xl border border-border-subtle bg-surface overflow-hidden">
        <div className="flex items-center justify-between border-b border-border-subtle px-3 py-2">
          <div className="flex items-center gap-2">
            {(() => { const Icon = activePreset.icon; return <Icon className="h-3.5 w-3.5 text-text-3" />; })()}
            <span className="text-[11px] font-medium text-text">{nlqLabel ?? activePreset.label}</span>
            {nlqLabel ? (
              <span className="rounded border px-1 py-0.5 text-[11px] font-bold uppercase text-purple-400 bg-purple-400/10 border-purple-400/30">AI</span>
            ) : (
              <span className={`rounded border px-1 py-0.5 text-[11px] font-bold uppercase ${BADGE_CLS[activePreset.badge]}`}>
                {BADGE_LABEL[activePreset.badge]}
              </span>
            )}
            {result && (
              <span className="text-[11px] text-text-3">
                · {result.nodes.length} nodes · {result.edges.length} edges
                {result.truncated && " · truncated"}
              </span>
            )}
            {/* Human vs machine breakdown when both are present */}
            {humanEdges > 0 && machineEdges > 0 && (
              <span className="flex items-center gap-1 text-[11px] text-text-3">
                · <span className="text-teal">{humanEdges} human</span>
                <span className="text-sky">{machineEdges} machine</span> edges
              </span>
            )}
          </div>
          {runQuery.isPending && (
            <span className="text-[11px] text-text-3 animate-pulse">Loading…</span>
          )}
        </div>

        {runQuery.isPending && !result && (
          <div className="flex h-64 items-center justify-center"><Loading /></div>
        )}
        {runQuery.isError && (
          <div className="flex h-32 items-center justify-center">
            <span className="text-[11px] text-red">Query failed — graph may not be ready</span>
          </div>
        )}
        {result && result.nodes.length === 0 && (
          <div className="flex h-32 items-center justify-center">
            <span className="text-[11px] text-text-3">No results — try a different preset or run a correlate sweep</span>
          </div>
        )}
        {result && result.nodes.length > 0 && (
          <GraphView
            nodes={gvNodes}
            edges={gvEdges}
            height={520}
            onNodeClick={(id) => navigate({ to: "/investigate/assets/$id", params: { id } })}
          />
        )}
      </div>

      <p className="mt-2 text-[11px] text-text-3">
        Click any node to open asset detail. Double-click to expand its neighbourhood.{" "}
        <Link to="/investigate/graph" className="text-teal hover:underline">Open full Cypher workbench →</Link>
      </p>
    </div>
  );
}

// ── Census tiles ──────────────────────────────────────────────────────────────
//
// Everything below comes from GET /api/identity/summary, which computes it
// server-side with the principal metadata and graph edges the browser cannot
// see. These numbers must not be arithmetic on /api/assets/summary's by_type
// counts, which is wrong in both directions at once:
//
//   iam_user + human_identity is not "human identities". Some of those rows are
//   account ROOT principals, others are programmatic (CI systems, service
//   accounts for tools), and a row is not a person — the same human holds an
//   IAM user in every AWS account they work in, so the raw row count
//   over-states the deduplicated headcount. It also counts zero federated
//   humans, who can be most of an organization's users.
//
//   gcp_service_account is not "workload identities": it is one cloud under a
//   cross-cloud label, missing K8s service accounts, Azure service principals
//   and the AWS roles the graph proves Lambdas and ECS tasks run as.
//
//   An IAM role is not necessarily a machine identity: roles can also be SSO
//   permission-set roles (the human federation surface), AWS/IaC plumbing, or
//   stale.
//
// Each tile shows its own decomposition so a narrowed headline never hides
// the population it narrowed away.

function nonZeroEntries(m: Record<string, number> | undefined): [string, number][] {
  return Object.entries(m ?? {}).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]);
}

function sumValues(m: Record<string, number> | undefined): number {
  return Object.values(m ?? {}).reduce((s, n) => s + n, 0);
}

const PROVIDER_LABEL: Record<string, string> = {
  aws: "AWS", gcp: "GCP", azure: "Azure", kubernetes: "K8s",
  okta: "Okta", google_workspace: "Workspace", github: "GitHub",
};
const providerLabel = (p: string) => PROVIDER_LABEL[p] ?? p;

const ROLE_CLASS_LABEL: Record<string, string> = {
  workload: "workload",
  human_federation: "SSO (human)",
  platform: "AWS/IaC plumbing",
  unattributed: "unattributed",
};

function CensusTiles({ census }: { census: IdentityCensus }) {
  const { humans, workloads, roles, staleness } = census;
  const staleRoles = Object.entries(roles.stale_by_class ?? {}).reduce((s, [, n]) => s + n, 0);

  return (
    <div className="mb-4 space-y-2">
      <div className="grid gap-2 sm:grid-cols-3">
        {/* People, not principal rows. */}
        <Tile
          title="People with cloud access"
          value={humans.distinct}
          cls="text-teal border-teal/20 bg-teal/5"
          detail={[
            `${humans.console_principals} IAM principals across accounts`,
            `${humans.with_corporate_email} with a corporate email`,
            ...nonZeroEntries(humans.by_provider).map(([p, n]) => `${n} via ${providerLabel(p)}`),
          ]}
          excluded={[
            `${humans.excluded.root_principals} account root`,
            `${humans.excluded.programmatic_distinct} programmatic (key-only)`,
            ...(humans.excluded.console_access_unknown > 0
              ? [`${humans.excluded.console_access_unknown} console access unknown`]
              : []),
            ...(humans.excluded.inactive_principals > 0 ? [`${humans.excluded.inactive_principals} inactive`] : []),
          ]}
        />

        {/* Cross-cloud, and it says which clouds. */}
        <Tile
          title="Workload identities (all clouds)"
          value={workloads.total}
          cls="text-sky border-sky/20 bg-sky/5"
          detail={nonZeroEntries(workloads.by_provider).map(([p, n]) => `${n} ${providerLabel(p)}`)}
          excluded={[
            ...(workloads.gcp_default_service_accounts > 0
              ? [`${workloads.gcp_default_service_accounts} GCP auto-created defaults (included)`] : []),
            ...(workloads.roles_referenced_not_collected > 0
              ? [`${workloads.roles_referenced_not_collected} roles used by a workload but not collected`] : []),
          ]}
        />

        {/* The count was always right; the label wasn't. */}
        <Tile
          title="AWS IAM roles by purpose"
          value={roles.total}
          cls="text-purple-400 border-purple-400/20 bg-purple-400/5"
          detail={nonZeroEntries(roles.by_class).map(([c, n]) => `${n} ${ROLE_CLASS_LABEL[c] ?? c}`)}
          excluded={staleRoles > 0 ? [`${staleRoles} not seen in ${staleness.threshold_days}d`] : []}
        />
      </div>

      <StalenessBanner staleness={staleness} />
      <FederationNote federation={humans.federation} distinct={humans.distinct} />
    </div>
  );
}

function Tile({ title, value, cls, detail, excluded }: {
  title: string;
  value: number;
  cls: string;
  detail: string[];
  excluded?: string[];
}) {
  return (
    <div className={`rounded-lg border px-3 py-2 ${cls}`}>
      <div className="flex items-baseline gap-2">
        <span className="text-[22px] font-bold tabular-nums leading-none">{value.toLocaleString()}</span>
        <span className="text-[11px] leading-tight text-text-2">{title}</span>
      </div>
      {detail.length > 0 && (
        <div className="mt-1 text-[11px] text-text-3">{detail.join(" · ")}</div>
      )}
      {/* Nothing narrowed out of the headline is silently dropped — under-counting
          identities hides attack surface, so the excluded population is named. */}
      {excluded && excluded.length > 0 && (
        <div className="mt-0.5 text-[11px] text-text-3">excl. {excluded.join(" · ")}</div>
      )}
    </div>
  );
}

// A single account that stopped being collected keeps contributing its whole
// identity population to every tile above. Saying so is the difference between a
// current figure and a historical one.
function StalenessBanner({ staleness }: { staleness: IdentityCensus["staleness"] }) {
  const accounts = staleness.stale_accounts ?? [];
  if (accounts.length === 0) return null;
  const worst = accounts[0];
  const total = accounts.reduce((s, a) => s + a.count, 0);
  return (
    <div className="flex items-start gap-2 rounded-lg border border-amber/30 bg-amber/5 px-3 py-2 text-[11px] text-amber">
      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
      <span>
        {accounts.length} account{accounts.length > 1 ? "s" : ""} stopped being collected —{" "}
        {total.toLocaleString()} identities above are last-known state, not current.
        Worst: <span className="font-mono">{worst.account_id}</span> ({worst.count.toLocaleString()} identities,
        last seen {worst.age_days}d ago).
      </span>
    </div>
  );
}

// The understatement, made visible. Permission sets and groups with zero
// collected people means humans reach the cloud through a path the inventory
// cannot yet name.
function FederationNote({ federation, distinct }: {
  federation: IdentityCensus["humans"]["federation"];
  distinct: number;
}) {
  const f = federation;
  if (f.sso_permission_sets === 0 && f.sso_groups === 0) return null;
  const blind = f.directory_identities === 0 && f.sso_groups > 0;
  return (
    <div className={`rounded-lg border px-3 py-2 text-[11px] ${blind ? "border-red/30 bg-red/5 text-red" : "border-border-subtle bg-surface text-text-3"}`}>
      {blind ? (
        <>
          <span className="font-medium">Federated humans are not collected.</span>{" "}
          {f.sso_permission_sets} SSO permission sets are granted to {f.sso_groups} groups
          ({f.sso_group_assignments} assignments, {f.sso_user_assignments} direct to a user),
          materialising {f.sso_federation_roles} AWSReservedSSO_* roles — but 0 people were
          collected from them, so the {distinct} above are IAM console users only.
        </>
      ) : (
        <>
          {f.directory_identities} federated {f.directory_identities === 1 ? "person" : "people"}
          {nonZeroEntries(f.directory_by_provider).length > 0 &&
            ` (${nonZeroEntries(f.directory_by_provider).map(([p, n]) => `${n} ${providerLabel(p)}`).join(" · ")})`}
          {" · "}{f.sso_permission_sets} permission sets · {f.sso_groups} groups ·{" "}
          {f.sso_federation_roles} AWSReservedSSO_* roles
        </>
      )}
    </div>
  );
}

// ── People tab — directory (human_identity) + IAM users ───────────────────────

const DIR_PROVIDER: Record<string, { label: string; cls: string }> = {
  okta:             { label: "Okta",       cls: "text-sky border-sky/30 bg-sky/10" },
  google:           { label: "Google",     cls: "text-red border-red/30 bg-red/10" },
  google_workspace: { label: "Google",     cls: "text-red border-red/30 bg-red/10" },
  github:           { label: "GitHub",     cls: "text-text-2 border-border-subtle bg-surface" },
  aws:              { label: "AWS IAM",    cls: "text-amber border-amber/30 bg-amber/10" },
};

function dirProviderStyle(p: string) {
  return DIR_PROVIDER[p] ?? { label: p, cls: "text-text-3 border-border-subtle bg-surface" };
}

function initials(asset: Asset): string {
  const full = asset.metadata?.["full_name"] ?? asset.metadata?.["display_name"] ?? asset.name ?? "";
  const parts = full.trim().split(/\s+/);
  if (parts.length >= 2) return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
  return full.slice(0, 2).toUpperCase() || "?";
}

function avatarColor(id: string): string {
  const colors = ["bg-teal/20 text-teal", "bg-sky/20 text-sky", "bg-purple-500/20 text-purple-400", "bg-amber/20 text-amber"];
  let h = 0;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0;
  return colors[h % colors.length];
}

function PersonRow({ asset, isIamUser, onOpen }: { asset: Asset; isIamUser?: boolean; onOpen: (id: string) => void }) {
  const ps = dirProviderStyle(asset.provider);
  const isAdmin = asset.metadata?.["is_admin"] === "true" || asset.tags?.["is_admin"] === "true";
  const consoleAccess = asset.metadata?.["console_access"];
  const mfaEnabled = asset.metadata?.["mfa_enabled"];
  const noMfa = consoleAccess === "true" && mfaEnabled === "false";
  // An IAM user whose console access or MFA was not read (the account root
  // needs the credential report) is unknown, not clean.
  const mfaUnknown = isIamUser && !noMfa && consoleAccess !== "false" && mfaEnabled !== "true";
  const suspended = asset.metadata?.["suspended"] === "true" || asset.metadata?.["status"] === "SUSPENDED";
  const inactive = isIamUser && asset.metadata?.["inactive"] === "true";
  const lastActivity = asset.metadata?.["last_login"] ?? asset.metadata?.["last_sign_in"] ?? asset.metadata?.["password_last_used"];
  const pwLastUsedDays = isIamUser ? parseInt(asset.metadata?.["password_last_used_days"] ?? "-1", 10) : -1;
  const activeKeyCount = isIamUser ? parseInt(asset.metadata?.["active_key_count"] ?? "0", 10) : 0;
  const orgUnit = asset.metadata?.["org_unit"] ?? asset.metadata?.["department"] ?? "";
  const fullName = asset.metadata?.["full_name"] ?? asset.metadata?.["display_name"] ?? "";
  const displayName = isIamUser ? asset.name : (fullName || asset.name);

  function lastUsedLabel(): string | null {
    if (!isIamUser) return null;
    if (pwLastUsedDays < 0) return "never logged in";
    if (pwLastUsedDays === 0) return "logged in today";
    return `${pwLastUsedDays}d ago`;
  }
  const lastUsed = lastUsedLabel();
  const isStaleUser = isIamUser && (pwLastUsedDays < 0 || pwLastUsedDays > 90);

  return (
    <button type="button" onClick={() => onOpen(asset.id)}
      className="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left transition-colors hover:bg-surface/60">
      <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-[11px] font-bold ${avatarColor(asset.id)} ${suspended || inactive ? "opacity-40" : ""}`}>
        {isIamUser ? <KeyRound className="h-4 w-4" /> : initials(asset)}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <span className="truncate text-[13px] font-medium text-text">{displayName}</span>
          {inactive && <Chip cls="text-text-3 border-border-subtle bg-surface">inactive</Chip>}
          {suspended && <Chip cls="text-amber border-amber/30 bg-amber/10">suspended</Chip>}
          {isAdmin && <Chip cls="text-red border-red/30 bg-red/10">admin</Chip>}
          {noMfa && !inactive && <Chip cls="text-red border-red/30 bg-red/10">no MFA</Chip>}
          {mfaUnknown && !inactive && <Chip cls="text-text-3 border-border-subtle bg-surface">MFA unknown</Chip>}
        </div>
        <div className="flex items-center gap-2 mt-0.5">
          <span className="truncate text-[11px] text-text-3 font-mono">{isIamUser ? asset.account_id : (asset.domain || asset.name)}</span>
          {orgUnit && <span className="text-[11px] text-text-3">· {orgUnit}</span>}
          {isIamUser && !inactive && activeKeyCount > 0 && (
            <span className="text-[11px] text-text-3">{activeKeyCount} key{activeKeyCount > 1 ? "s" : ""}</span>
          )}
        </div>
      </div>
      <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[11px] font-medium ${ps.cls}`}>{ps.label}</span>
      {isIamUser ? (
        lastUsed && <span className={`shrink-0 text-[11px] w-28 text-right ${isStaleUser ? "text-amber" : "text-text-3"}`}>{lastUsed}</span>
      ) : (
        lastActivity && <span className="shrink-0 text-[11px] text-text-3 w-24 text-right">{timeAgo(lastActivity)}</span>
      )}
      {(asset.finding_count ?? 0) > 0 && (
        <span className="flex shrink-0 items-center gap-1 text-[11px] text-amber">
          <ShieldAlert className="h-3 w-3" />{asset.finding_count}
        </span>
      )}
      <ChevronRight className="h-3.5 w-3.5 shrink-0 text-text-3" />
    </button>
  );
}

// ── Cloud IAM list ────────────────────────────────────────────────────────────

const CLOUD_TYPE: Record<string, { label: string; cls: string }> = {
  iam_role:            { label: "IAM Role",     cls: "text-purple-400 border-purple-400/30 bg-purple-400/10" },
  gcp_service_account: { label: "Service Acct", cls: "text-sky border-sky/30 bg-sky/10" },
};
const CLOUD_PROVIDER: Record<string, { label: string; cls: string }> = {
  aws: { label: "AWS", cls: "text-amber border-amber/30 bg-amber/10" },
  gcp: { label: "GCP", cls: "text-sky border-sky/30 bg-sky/10" },
};
function cloudTypeStyle(t: string) { return CLOUD_TYPE[t] ?? { label: t, cls: "text-text-3 border-border-subtle bg-surface" }; }
function cloudProviderStyle(p: string) { return CLOUD_PROVIDER[p] ?? { label: p, cls: "text-text-3 border-border-subtle bg-surface" }; }

function isHighPrivilege(asset: Asset): boolean {
  const policies = asset.metadata?.["policies"] ?? asset.metadata?.["roles"] ?? "";
  const perms = asset.metadata?.["permissions"] ?? "";
  return /AdministratorAccess|FullAccess|roles\/owner|roles\/editor|iam\.serviceAccounts\.actAs/i.test(policies + perms);
}
function isStale(asset: Asset): boolean {
  const keyAge = parseInt(asset.metadata?.["access_key_age_days"] ?? "0", 10);
  const lastUsed = parseInt(asset.metadata?.["last_used_days"] ?? "0", 10);
  return asset.type === "iam_role" ? lastUsed > 90 : keyAge > 90;
}
function riskPriority(asset: Asset): number {
  return (asset.max_score ?? 0) * 1000 + (asset.finding_count ?? 0);
}

// Local ScoreBadge — visually distinct from ui.tsx's ScoreBadge (a bordered
// rectangle that hides entirely at score 0, vs. ui.tsx's pill showing "—"), so
// kept separate rather than swapped for the shared component. The colour is the
// server's band for the asset's worst finding (risk_band).
function ScoreBadge({ score, band }: { score: number; band?: string }) {
  if (score <= 0) return null;
  const cls = band === "page" ? "text-red border-red/30 bg-red/10"
    : band === "high" ? "text-orange border-orange/30 bg-orange/10"
    : band === "pipeline" ? "text-amber border-amber/30 bg-amber/10"
    : "text-teal border-teal/30 bg-teal/10";
  const label = bandLabel(band);
  return (
    <span title={`Risk score ${score}${label ? ` — ${label}` : ""}`}
      className={`shrink-0 w-8 text-right text-[12px] font-bold tabular-nums rounded border px-1 py-0.5 ${cls}`}>
      {score}
    </span>
  );
}

function CloudRow({ asset, onOpen }: { asset: Asset; onOpen: (id: string) => void }) {
  const typeStyle = cloudTypeStyle(asset.type);
  const provStyle = cloudProviderStyle(asset.provider);
  const stale = isStale(asset);
  const highPriv = isHighPrivilege(asset);
  const disabled = asset.metadata?.["disabled"] === "true";
  return (
    <button type="button" onClick={() => onOpen(asset.id)}
      className="flex w-full items-center gap-3 rounded-lg px-3 py-2.5 text-left transition-colors hover:bg-surface/60">
      <span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-full ${disabled ? "opacity-40" : ""} ${highPriv ? "bg-red/10 text-red" : "bg-surface-2 text-text-3"}`}>
        {asset.type === "gcp_service_account" ? <Bot className="h-4 w-4" /> : <Shield className="h-4 w-4" />}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <span className="truncate text-[13px] font-medium text-text">{asset.name}</span>
          {highPriv && <Chip cls="text-red border-red/30 bg-red/10">admin</Chip>}
          {disabled && <Chip cls="text-text-3 border-border-subtle bg-surface">disabled</Chip>}
        </div>
        <span className="text-[11px] text-text-3 font-mono">{asset.account_id}</span>
      </div>
      <div className="flex shrink-0 items-center gap-1.5">
        {stale && <span title="Stale (>90 days)" className="flex items-center gap-0.5 text-[11px] text-amber"><AlertTriangle className="h-3 w-3" /> stale</span>}
      </div>
      <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[11px] font-medium ${typeStyle.cls}`}>{typeStyle.label}</span>
      <span className={`shrink-0 rounded border px-1.5 py-0.5 text-[11px] font-medium ${provStyle.cls}`}>{provStyle.label}</span>
      <ScoreBadge score={asset.max_score ?? 0} band={asset.risk_band} />
      {(asset.finding_count ?? 0) > 0 && (
        <span className="flex shrink-0 items-center gap-1 text-[11px] text-amber"><ShieldAlert className="h-3 w-3" />{asset.finding_count}</span>
      )}
      <ChevronRight className="h-3.5 w-3.5 shrink-0 text-text-3" />
    </button>
  );
}

// ── Shared ────────────────────────────────────────────────────────────────────

function Chip({ cls, children }: { cls: string; children: ReactNode }) {
  return <span className={`rounded border px-1 py-0.5 text-[11px] font-medium uppercase ${cls}`}>{children}</span>;
}

type Tab = "graph" | "people" | "list";

// ── Page ──────────────────────────────────────────────────────────────────────

export function Identity() {
  const [tab, setTab] = useState<Tab>("graph");
  const [search, setSearch] = useState("");
  const [selectedAssetId, setSelectedAssetId] = useState<string | null>(null);

  // Directory identities (Okta, GW, GitHub)
  const people    = useAssets({ type: "human_identity", ...(search ? { q: search } : {}) });
  const allPeople = people.data?.pages.flatMap((p) => p.items) ?? [];

  // IAM users (humans with AWS console/programmatic access)
  const iamUsers    = useAssets({ type: "iam_user", ...(search && tab === "people" ? { q: search } : {}) });
  const allIamUsers = iamUsers.data?.pages.flatMap((p) => p.items) ?? [];

  // Machine identities — sorted server-side by risk so that when the infinite
  // query is left on page 1 (as it is here), the loaded page is the highest-risk
  // subset rather than an arbitrary one, and any "top N" disclosure below is
  // honest about which N.
  const gcpSAs      = useAssets({ type: "gcp_service_account", sort: "risk" });
  const iamRoles    = useAssets({ type: "iam_role", sort: "risk" });
  const allGcpSAs   = gcpSAs.data?.pages.flatMap((p) => p.items) ?? [];
  const allIamRoles = iamRoles.data?.pages.flatMap((p) => p.items) ?? [];

  // Headline counts come from the backend census (GET /api/identity/summary),
  // never from arithmetic on /api/assets/summary's by_type. Those are raw asset
  // rows: a person is not a row, "workload identity" is not one asset type, and
  // a stale account's rows are not current identities. See CensusTiles.
  const census = useIdentityCensus().data;
  const peopleCount   = census?.humans.distinct ?? 0;
  const workloadCount = census?.workloads.total ?? 0;

  // Real server aggregates for the two populations below — allGcpSAs/allIamRoles
  // are only the first page (~100 rows, backend cap) of an infinite query that
  // is never advanced here, so their .length badly undercounts once the real
  // population passes one page.
  const gcpTotal  = census?.workloads.by_type?.["gcp_service_account"] ?? allGcpSAs.length;
  const roleTotal = census?.roles.total ?? allIamRoles.length;
  const roleStaleTotal = sumValues(census?.roles.stale_by_class);

  const machineIdentities = allGcpSAs.sort((a, b) => riskPriority(b) - riskPriority(a));
  const machineLoading    = gcpSAs.isLoading;
  // highScoreRoles is counted over the loaded page only — no server aggregate
  // for "roles scoring >=70" exists yet (roles.total/stale_by_class are the only
  // real aggregates the census exposes). Sorting the query by risk (above) means
  // this count is exact as long as the true count fits in one page; iamRolesSampled
  // discloses when it might not.
  const iamRolesSampled = allIamRoles.length < roleTotal;
  const highScoreRoles    = allIamRoles.filter(a => (a.max_score ?? 0) >= 70).length;

  // Merge people + IAM users for the People tab
  const allHumans = [
    ...allPeople,
    ...allIamUsers.filter(u => !allPeople.some(p => p.id === u.id)),
  ].sort((a, b) => riskPriority(b) - riskPriority(a));

  return (
    <div>
      <PageHeader
        title="Identity"
        subtitle="Workload agents, human federation, IAM attack chains — who is human, who is machine, who can escalate."
      />

      {/* Tab bar */}
      <div className="mb-4 flex items-center gap-1 border-b border-border-subtle pb-0">
        <TabBtn active={tab === "graph"} onClick={() => setTab("graph")}>
          <Network className="h-3.5 w-3.5" />
          Graph
        </TabBtn>
        <TabBtn active={tab === "people"} onClick={() => setTab("people")}>
          <Users className="h-3.5 w-3.5" />
          People
          {peopleCount > 0 && (
            <span className="ml-1 rounded bg-teal/10 px-1 py-0.5 text-[11px] font-medium text-teal">{peopleCount} people</span>
          )}
        </TabBtn>
        <TabBtn active={tab === "list"} onClick={() => setTab("list")}>
          <Bot className="h-3.5 w-3.5" />
          Machine roles
          {/* One number, not machineCount + roleCount. Those two populations
              OVERLAP — many of the IAM roles ARE the workload identities — so
              adding them double-counted every AWS workload. workloads.total is
              the deduplicated cross-cloud figure. */}
          {workloadCount > 0 && (
            <span className="ml-1 text-[11px] text-text-3">({workloadCount.toLocaleString()} workload identities)</span>
          )}
          {highScoreRoles > 0 && (
            <span
              className="ml-1 rounded bg-red/10 px-1 py-0.5 text-[11px] font-medium text-red"
              title={
                `IAM roles with risk score ≥70, among the ${allIamRoles.length.toLocaleString()} highest-risk roles loaded (sorted by risk)` +
                (iamRolesSampled ? ` out of ${roleTotal.toLocaleString()} total — more may qualify beyond what's loaded` : "") +
                HIGH_SCORE_CUTOFF_NOTE
              }
            >
              {highScoreRoles} ≥70{iamRolesSampled ? "+" : ""}
            </span>
          )}
        </TabBtn>
      </div>

      {/* ── Graph tab ── */}
      {tab === "graph" && <IdentityGraph census={census} />}

      {/* ── People tab — all human identities ── */}
      {tab === "people" && (
        <>
          <input type="search" placeholder="Search by name or email…" value={search} onChange={(e) => setSearch(e.target.value)}
            className="mb-4 h-8 w-64 rounded border border-border-subtle bg-surface px-3 text-[12px] text-text placeholder-text-3 focus:outline-none focus:ring-1 focus:ring-teal/40" />

          {(people.isLoading || iamUsers.isLoading) && <Loading />}

          {(people.isError || iamUsers.isError) && (
            <ErrorNote message="Could not load human identities — the service may be temporarily busy. Refresh to retry." />
          )}

          {!people.isLoading && !iamUsers.isLoading && !people.isError && !iamUsers.isError && allHumans.length === 0 && (
            <Empty message="No human identities found. Connect AWS, Okta, or Google Workspace in Settings → Connectors." />
          )}

          {allHumans.length > 0 && (
            <div className="rounded-xl border border-border-subtle bg-surface">
              <div className="border-b border-border-subtle px-3 py-2 flex items-center gap-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-text-3">
                  Principals ({allHumans.length})
                </span>
                {/* Rows, not people: one person holds an IAM user in every AWS
                    account they work in, and root/programmatic users live in
                    this namespace too. The deduplicated headcount is the tile
                    on the Graph tab. */}
                <span className="text-[11px] text-text-3">
                  — one row per (identity, account): IAM users incl. root and key-only service users, plus directory accounts
                  {peopleCount > 0 && ` · ${peopleCount} distinct people`}
                </span>
              </div>
              <div className="divide-y divide-border-subtle/50">
                {allHumans.map((a) => (
                  <PersonRow key={a.id} asset={a} isIamUser={a.type === "iam_user"} onOpen={setSelectedAssetId} />
                ))}
              </div>
              {(people.hasNextPage || iamUsers.hasNextPage) && (
                <div className="p-3 text-center">
                  <button
                    onClick={() => { people.fetchNextPage(); iamUsers.fetchNextPage(); }}
                    disabled={people.isFetchingNextPage || iamUsers.isFetchingNextPage}
                    className="text-[11px] text-teal hover:underline disabled:opacity-50">
                    {(people.isFetchingNextPage || iamUsers.isFetchingNextPage) ? "Loading…" : "Load more"}
                  </button>
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* ── Machine roles tab ── */}
      {tab === "list" && (
        <>
          {machineLoading && <Loading />}
          {(gcpSAs.isError || iamRoles.isError) && (
            <ErrorNote message="Could not load machine identities — the service may be temporarily busy. Refresh to retry." />
          )}
          {!machineLoading && !gcpSAs.isError && !iamRoles.isError && machineIdentities.length === 0 && allIamRoles.length === 0 && (
            <Empty message="No machine identities found. Connect AWS or GCP in Settings → Connectors." />
          )}

          {machineIdentities.length > 0 && (
            <div className="mb-4 rounded-xl border border-border-subtle bg-surface">
              <div className="border-b border-border-subtle px-3 py-2">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-text-3">
                  GCP Service Accounts ({gcpTotal.toLocaleString()})
                </span>
                {machineIdentities.length < gcpTotal && (
                  <span className="ml-1 text-[11px] text-text-3">— showing top {machineIdentities.length} by risk</span>
                )}
              </div>
              <div className="divide-y divide-border-subtle/50">
                {machineIdentities.map((a) => <CloudRow key={a.id} asset={a} onOpen={setSelectedAssetId} />)}
              </div>
            </div>
          )}

          {allIamRoles.length > 0 && (
            <IamRoleSection
              roles={allIamRoles.sort((a, b) => riskPriority(b) - riskPriority(a))}
              onOpen={setSelectedAssetId}
              byClass={census?.roles.by_class}
              total={roleTotal}
              staleTotal={roleStaleTotal}
            />
          )}
        </>
      )}

      <AssetDetailPanel assetId={selectedAssetId} onClose={() => setSelectedAssetId(null)} />
    </div>
  );
}

// ── IAM Roles collapsible section ─────────────────────────────────────────────

function IamRoleSection({ roles, onOpen, byClass, total, staleTotal }: {
  roles: Asset[];
  onOpen: (id: string) => void;
  byClass?: Record<string, number>;
  // Real server aggregates from the census (roles.total / sum of
  // stale_by_class) — undefined only if the census request itself failed, in
  // which case we fall back to the loaded page and disclose the sample below.
  total?: number;
  staleTotal?: number;
}) {
  const [open, setOpen] = useState(false);
  // roles.length is a page of an infinite query never advanced past page 1
  // (backend cap ~100), sorted by risk server-side. `sampled` is true whenever
  // that page is not the whole population, so every count below that is only
  // computed over the loaded page discloses itself as a sample rather than a
  // total.
  const headingTotal = total ?? roles.length;
  const sampled = roles.length < headingTotal;
  const staleCount    = staleTotal ?? roles.filter(isStale).length;
  // No server aggregate exists yet for "admin policy" / "score ≥70" roles —
  // these remain counts over the loaded (risk-sorted) page only.
  const highPrivCount = roles.filter(isHighPrivilege).length;
  const highScoreCount = roles.filter(r => (r.max_score ?? 0) >= 70).length;
  // "machine roles assumed by workloads" was false for most of this population:
  // the census splits it into workload / SSO-human / AWS-IaC-plumbing /
  // unattributed, and only the first is a machine identity.
  const split = nonZeroEntries(byClass).map(([c, n]) => `${n} ${ROLE_CLASS_LABEL[c] ?? c}`).join(" · ");
  const sampleNote = sampled
    ? `Among the ${roles.length.toLocaleString()} highest-risk roles loaded (sorted by risk), out of ${headingTotal.toLocaleString()} total — more may qualify beyond what's loaded.`
    : undefined;
  return (
    <div className="rounded-xl border border-border-subtle bg-surface">
      <button onClick={() => setOpen(o => !o)} className="flex w-full items-center justify-between px-3 py-2.5 text-left">
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-text-3">IAM Roles ({headingTotal.toLocaleString()})</span>
          {sampled && (
            <span className="text-[11px] text-text-3" title={sampleNote}>showing top {roles.length.toLocaleString()} by risk</span>
          )}
          <span className="text-[11px] text-text-3">{split ? `— ${split}` : "— mixed purpose: workload, SSO-human, IaC plumbing"}</span>
          {highScoreCount > 0 && (
            <span
              className="rounded border border-red/30 bg-red/10 px-1.5 py-0.5 text-[11px] font-medium text-red"
              title={`Risk score ≥70${sampleNote ? ` — ${sampleNote}` : ""} ${HIGH_SCORE_CUTOFF_NOTE}`}
            >
              {highScoreCount} score ≥70{sampled ? "+" : ""}
            </span>
          )}
          {highPrivCount > 0 && (
            <span
              className="rounded border border-red/30 bg-red/10 px-1.5 py-0.5 text-[11px] font-medium text-red"
              title={sampleNote}
            >
              {highPrivCount}{sampled ? "+" : ""} admin policy
            </span>
          )}
          {staleCount > 0 && <span className="rounded border border-amber/30 bg-amber/10 px-1.5 py-0.5 text-[11px] font-medium text-amber">{staleCount} stale</span>}
        </div>
        <ChevronRight className={`h-3.5 w-3.5 text-text-3 transition-transform ${open ? "rotate-90" : ""}`} />
      </button>
      {open && (
        <div className="divide-y divide-border-subtle/50 border-t border-border-subtle">
          {roles.map((a) => <CloudRow key={a.id} asset={a} onOpen={onOpen} />)}
        </div>
      )}
    </div>
  );
}

// ── Tab button ────────────────────────────────────────────────────────────────

function TabBtn({ active, onClick, children }: { active: boolean; onClick: () => void; children: ReactNode }) {
  return (
    <button onClick={onClick}
      className={`flex items-center gap-1.5 rounded-t px-3 py-2 text-[12px] font-medium transition-colors ${active ? "border-b-2 border-teal text-teal" : "text-text-3 hover:text-text-2"}`}>
      {children}
    </button>
  );
}
