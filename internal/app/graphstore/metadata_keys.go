package graphstore

import (
	"sort"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// SyncMetadataKeys declares every asset metadata key the Ladybug loader reads. It is
// the projection the bulk sync asks ClickHouse-side readers for, so anything absent
// here arrives as an empty string in the graph.
//
// It is a declared projection rather than "load all of it" because the raw
// metadata JSON is dominated by keys this loader never touches (large
// permission/policy blobs on IAM and k8s asset types) and decoding all of it
// is the worker's largest single heap item at scale.
// The loader needs a handful of small keys per asset.
//
// It is a registry with a guard test rather than a literal at the call site
// because an incomplete projection does NOT fail — it silently empties a graph
// column, the same defect class as the label-promotion drops and the identity
// suppression bug. TestSyncMetadataKeysCoverNodeLoader derives the real set
// from the package's own source and fails on any drift in either direction,
// so adding a Metadata read without declaring it here breaks the build rather
// than the graph.
//
// Keep sorted — the guard test compares against a sorted derivation.
var SyncMetadataKeys = []string{
	"classification",      // storage node data classification
	"days_until_expiry",   // certificate expiry (appendCertValues)
	"ecosystem",           // package node
	"encryption",          // S3 SSE algorithm (assetEncrypted)
	"expires_at",          // certificate expiry
	"expiring_soon",       // certificate expiry
	"grants_admin",        // trust/permission node
	"public",              // config-level public exposure (assetPublic)
	"public_access",       // public tier: confirmed vs possible (assetPublicTier)
	"publicly_accessible", // RDS/CloudSQL network reachability
	"storage_encrypted",   // RDS encryption (assetEncrypted)
	"trust_entry",         // identity trust node
	"version",             // package node
}

// SyncProjection is what the bulk sync asks asset readers to materialise: the
// metadata keys above, and no Tags at all.
//
// Tags are skipped because nothing under internal/app/graphstore reads them —
// the loader's column list (nodeCSVCols) has no tag column, and decoding them
// just to discard them is real heap cost at corpus scale. Other consumers DO
// need Tags (the asset API, correlate's deploys_to label matching, enrich's
// production-traffic safety guard, the respond context pack) and they read
// through different queries, so this narrows only the graph's own read.
func SyncProjection() asset.SyncProjection {
	return asset.SyncProjection{
		MetadataKeys:     SyncMetadataKeys,
		SkipTags:         true,
		EdgePropertyKeys: SyncEdgePropertyKeys(),
	}
}

// SyncEdgePropertyKeys is every edge property key the graph loader reads, DERIVED from
// the rel specs rather than listed, so a new rel column cannot silently lose its value.
//
// Three sources, and all three are load-bearing:
//   - ladybugRelSpec rowKeys — the property columns each rel table declares. Missing one
//     here loads that column empty on every row.
//   - "origin" and "matched" — edgeRowValue's fallback chain for "via" (dns_points_to
//     stamps "matched"), so they are read even though no spec names them.
//   - asset.EdgePropPublicAccess — the exposure TIER, read by reach.go and node_rows.go
//     to tell a confirmed public path from one that is merely permitted. Dropping it
//     would silently promote every "possible" exposure to confirmed.
//
// A large share of raw edge property entries are keys nothing in this package
// reads (correlate provenance that never reaches Ladybug), so projecting is worth
// the plumbing.
func SyncEdgePropertyKeys() []string {
	seen := map[string]bool{
		"origin":                   true, // edgeRowValue via-fallback
		"matched":                  true, // dns_points_to via-fallback
		asset.EdgePropPublicAccess: true, // exposure tier (reach.go, node_rows.go)
	}
	for _, spec := range ladybugRelSpec {
		for _, p := range spec.prop {
			seen[p.rowKey] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
