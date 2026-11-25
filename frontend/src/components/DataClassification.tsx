import { useQuery } from "@tanstack/react-query";
import { api, type GraphResult } from "../lib/api";
import { dataClassStyle, isSensitive } from "../lib/dataClasses";

// Shared DSPM classification lookup — used by both AssetDetailPanel's slide-over
// and AssetDetail's full page. Query logic and badge markup live here once; each
// caller supplies its own section wrapper (Section vs Card).

export interface AssetClassificationRow {
  encrypted?: number;
  public?: number;
  public_tier?: number;
  exposed?: number;
  classes?: string[];
}

export function useAssetClassification(assetId: string) {
  return useQuery({
    queryKey: ["asset-classification", assetId],
    queryFn: async () => {
      const esc = assetId.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
      const query = `MATCH (a:Asset {id: '${esc}'}) OPTIONAL MATCH (a)-[:ContainsData]->(dc:DataClass) RETURN a.encrypted AS encrypted, a.public AS public, a.public_tier AS public_tier, a.exposed AS exposed, collect(dc.id) AS classes`;
      const res = await api.post<GraphResult>("/api/graph/cypher", { query, max_nodes: 5, max_edges: 5 });
      return (res.rows?.[0] ?? null) as AssetClassificationRow | null;
    },
    staleTime: 2 * 60 * 1000,
    retry: false,
  });
}

// ClassificationBadges renders a data store's sensitivity classes plus the
// toxic-combination reasons (public / exposed / unencrypted). Renders nothing
// for assets that carry no ContainsData edge, so it's inert for non-storage
// assets — callers should render nothing around it when this returns null.
export function ClassificationBadges({ row }: { row: AssetClassificationRow | null | undefined }) {
  const classes = (row?.classes ?? []).filter(Boolean);
  if (!row || classes.length === 0) return null;

  // a.encrypted is tri-state (0 unencrypted, 1 encrypted, 2 unknown): only an
  // observed 0 is the alarm, and anything but an observed 0 or 1 is unknown,
  // marked as such rather than rendered like an encrypted store.
  const unencrypted = row.encrypted === 0;
  const encryptionUnknown = row.encrypted !== 0 && row.encrypted !== 1;
  const isPublic = !!row.public;
  // Tier 1 = public access merely possible (S3 public-access-block unlocked, no
  // public policy/ACL observed); anything else public is confirmed unauthenticated.
  const publicPossible = isPublic && row.public_tier === 1;
  const exposed = !!row.exposed;
  const sensitive = isSensitive(classes);

  const reasons: string[] = [];
  if (isPublic) reasons.push(publicPossible ? "public access possible (config permits it, not confirmed)" : "publicly accessible");
  if (exposed) reasons.push("internet-reachable");
  if (sensitive && unencrypted) reasons.push("no encryption-at-rest");

  return (
    <>
      <div className="flex flex-wrap gap-1">
        {classes.map((c) => {
          const s = dataClassStyle(c);
          return <span key={c} className={`rounded border px-1.5 py-0.5 text-[11px] font-medium ${s.cls}`}>{s.label}</span>;
        })}
        {isPublic && (publicPossible
          ? <span title="Public access possible: configuration permits exposure (unlocked public-access-block, network-public database, API behind optional auth) but unauthenticated access wasn't confirmed." className="rounded border border-amber/30 bg-amber/10 px-1.5 py-0.5 text-[11px] font-medium uppercase text-amber">public?</span>
          : <span title="Confirmed public: unauthenticated access via policy/ACL or a publicly-accessible endpoint." className="rounded border border-red/30 bg-red/10 px-1.5 py-0.5 text-[11px] font-medium uppercase text-red">public</span>)}
        {sensitive && unencrypted && <span className="rounded border border-amber/30 bg-amber/10 px-1.5 py-0.5 text-[11px] font-medium uppercase text-amber">unencrypted</span>}
        {sensitive && encryptionUnknown && <span title="Encryption unknown: encryption at rest was never observed for this store (not collected for its type, or the describe call failed). A coverage gap, not an observed pass or failure." className="rounded border border-border-subtle bg-surface-2 px-1.5 py-0.5 text-[11px] font-medium uppercase text-text-3">encryption&nbsp;?</span>}
      </div>
      {reasons.length > 0 && (
        <span className="mt-1.5 text-[11px] text-text-2">
          Holds {sensitive ? "sensitive" : "internal"} data · {reasons.join(" · ")}.
        </span>
      )}
    </>
  );
}
