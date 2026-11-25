package graphstore

import (
	"strconv"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// Node row construction for the Ladybug loaders: one pass over the asset slice that
// emits each node's property values in nodeCSVCols order. bulkSyncCopy streams
// those values straight into the per-label COPY CSVs; bulkSync (the reference
// UNWIND loader) and the tests zip them back into row maps via buildNodeRows.

// buildNodeRows groups assets by Ladybug node label and constructs the per-row
// property maps (keyed on DDL column names). Used by bulkSync (the reference
// UNWIND loader) and by tests; bulkSyncCopy streams the same rows straight to
// CSV via streamNodeRows and never materialises these maps — at large scale
// (over a million nodes) a map per node is gigabytes of live heap held concurrently
// with the asset slice it is built from.
func buildNodeRows(assets []asset.Asset, edges []asset.Edge, sigByResource map[string]NodeSignals, reachComplete bool) map[string][]map[string]any {
	byLabel := map[string][]map[string]any{}
	_ = streamNodeRows(assets, newReachOverlay(edges), sigByResource, reachComplete, map[string]string{},
		func(label, _ string, vals []any) error {
			cols := nodeCSVCols[label]
			row := make(map[string]any, len(cols))
			for i, c := range cols {
				row[c] = vals[i]
			}
			byLabel[label] = append(byLabel[label], row)
			return nil
		})
	return byLabel
}

// maxNodeCols bounds the per-row value buffer streamNodeRows reuses. It is the
// widest entry in nodeCSVCols (NodeAsset); TestNodeValueBufferFitsEveryLabel
// pins it.
const maxNodeCols = 20

// exposedSeedSet is the CONFIRMED-tier internet-exposure set: the node ids whose
// `exposed` column is true and, with PrivescCount, the sole input to toxic_combo.
//
// One function so there is exactly ONE definition of "exposed". It is deliberately NOT
// derivable from the reach map even though the two look interchangeable: internetHops
// seeds from the possible tier as well (graded to possibleSeedDepth rather than 0, see
// seedDepthFor) and additionally filters InternetNodeID and empty SrcID, which this
// does not. So `hops[id] == 0` and `exposed[id]` agree on today's data and are not the
// same predicate — inferring one from the other would couple two independently
// maintained filters, a fragile coupling.
func exposedSeedSet(edges []asset.Edge) map[string]bool {
	exposed := map[string]bool{}
	for _, e := range edges {
		if e.EdgeType != "exposed_to_internet" || graphschema.IsIdentityType(e.SrcType) {
			continue
		}
		if e.Properties[asset.EdgePropPublicAccess] == asset.PublicAccessPossible {
			continue
		}
		exposed[e.SrcID] = true
	}
	return exposed
}

// streamNodeRows walks the assets once and emits one node row per surviving
// asset: its label and its property values in nodeCSVCols[label] order. The
// values slice is a buffer reused across calls — emit must consume it before
// returning, never retain it.
//
// ov carries the edge-derived exposure set and hop counts. It is PASSED IN rather
// than derived here because one sweep walks the node set twice (the load digest,
// then the loader) and needs the same pair a third time for the signal-cache
// prewarm — deriving it inside meant three full passes over a million-plus edges and three
// copies of both maps. See reachOverlay.
//
// nodeLabel is filled with id→label for every emitted node AND doubles as the
// dedup set: the same logical asset can surface under two type variants (e.g. a
// serviceaccount under both an old and a canonical type) that map to one Ladybug
// label + primary key, and COPY aborts the whole table on a duplicate primary
// key, so first occurrence wins. Callers that need the index (bulkSyncCopy, for
// the rel endpoint pre-filter) get it for free instead of building a second and
// third copy of every ID.
//
// reachComplete=false means the reach edge fetch was truncated or failed: a
// not-reached node then gets ReachUnknown (fail-open, no must-fix signal)
// instead of ReachNone — asserting "definitively unreachable" over a partial
// edge set silently demoted real must-fix findings to "contained".
func streamNodeRows(assets []asset.Asset, ov reachOverlay, sigByResource map[string]NodeSignals, reachComplete bool, nodeLabel map[string]string, emit func(label, id string, vals []any) error) error {
	// ov.exposed is the CONFIRMED-tier exposure set. INV-1: an identity (IAM
	// user/role, service account) is a principal, never itself a node on the
	// internet, so identity sources are excluded from it (the same invariant
	// internetHops enforces for the BFS seed).
	//
	// `exposed` is an assertion, not a distance: it labels the node in the UI, it
	// is the toxic-combo input, and it is the independent witness the adjudicator
	// corroborates a demotion against (cmd/graph/ladybug_blast.go IsExposedEdge).
	// The possible tier also produces an exposed_to_internet edge, but only so
	// the BFS can start from it one hop in (seedDepthFor) — not to claim observed
	// unauthenticated exposure. The tier grades the claim; it does not decide
	// whether the topology is drawn.
	notReached := ReachNone
	if !reachComplete {
		notReached = ReachUnknown
	}
	nodeSignals := func(id string) NodeSignals {
		return ov.signalsFor(id, sigByResource[id], notReached)
	}

	vals := make([]any, 0, maxNodeCols)
	for i := range assets {
		a := &assets[i]
		label := NodeLabelFor(a.Type)
		if _, ok := nodeUnwindQ[label]; !ok {
			continue // skip unsupported labels (Identity, Device, etc.)
		}
		if _, dup := nodeLabel[a.ID]; dup || !csvSafeID(a.ID) {
			continue
		}
		nodeLabel[a.ID] = label
		if err := emit(label, a.ID, appendNodeValues(vals[:0], label, a, nodeSignals(a.ID))); err != nil {
			return err
		}
	}
	return nil
}

// appendNodeValues appends one node's property values to vals in
// nodeCSVCols[label] order. Order is load-bearing twice over — it is the CSV
// column order COPY reads and the key order buildNodeRows zips back into a map —
// so TestNodeRowKeysMatchCSVColumns pins every label's output against
// nodeCSVCols.
func appendNodeValues(vals []any, label string, a *asset.Asset, sig NodeSignals) []any {
	switch label {
	case NodeIamRole:
		vals = append(vals, a.ID, a.Name, string(a.Provider), a.AccountID, int32(a.RiskScore), a.Type, a.Region)
		vals = appendSignalValues(vals, sig)
		// Inbound assumability (collector trust_entry): public/mixed/federated/
		// cross_account/same_account/service — lets Cypher and narratives see
		// that a privesc-capable role is IdP- or cross-account-gated.
		return append(vals, a.Metadata["trust_entry"])
	case NodeRepo:
		return append(vals, a.ID, a.Name, string(a.Provider))
	case NodePackage:
		// Package signals come from supply-chain findings keyed on the package purl.
		// HasKEV=true here means a KEV advisory affects this exact package version.
		// cve_id is the highest-scoring supply-chain CVE; epss_score is its 30-day
		// exploitation probability from the EPSS catalog, and is only meaningful
		// alongside a CVE.
		epss := float64(0)
		if sig.CveID != "" {
			epss = sig.EPSSScore
		}
		return append(vals, a.ID, a.Name, a.Metadata["ecosystem"], a.Metadata["version"],
			int32(sig.MaxScore), b2i(sig.HasKEV), b2i(sig.Exploitable), sig.CveID, epss) //nolint:gosec // MaxScore is a bounded 0-100 risk score
	case NodeSubnet:
		// Infrastructure label: basic fields only (no signal columns in its DDL).
		return append(vals, a.ID, a.Name, a.Type, string(a.Provider), a.Region, a.AccountID, int32(a.RiskScore))
	case NodeK8sWorkload:
		// K8sWorkload carries signal fields so DeploysTo queries can filter by
		// exposure (e.g. w.exposed = 1). Same fields as Asset minus cert columns.
		vals = append(vals, a.ID, a.Name, a.Type, string(a.Provider), a.Region, a.AccountID, int32(a.RiskScore))
		return appendSignalValues(vals, sig)
	case NodeDataClass:
		// The DSPM classification targets are seeded as sentinels, not collected —
		// no collector emits assets of type data_class. The case exists so every label
		// with a node loader produces its own column count rather than falling into
		// the Asset branch and mismatching nodeCSVCols.
		return append(vals, a.ID, a.Metadata["classification"])
	case NodeCloudAccount: // Owns/GrantsAccessTo/GrantsAdmin anchor, not a scannable asset.
		return append(vals, a.ID, a.Name, string(a.Provider), a.AccountID)
	case NodeSSOGroup: // id/name/provider only.
		return append(vals, a.ID, a.Name, string(a.Provider))
	case NodeSSOPermSet: // grants_admin lets Cypher filter `p.grants_admin = 1` directly.
		return append(vals, a.ID, a.Name, string(a.Provider), a.AccountID, b2i(a.Metadata["grants_admin"] == "true"))
	default: // NodeAsset
		vals = append(vals, a.ID, a.Name, a.Type, string(a.Provider), a.Region, a.AccountID, int32(a.RiskScore))
		vals = appendSignalValues(vals, sig)
		vals = append(vals, assetEncrypted(a.Metadata), assetPublic(a.Metadata), assetPublicTier(a.Metadata))
		return appendCertValues(vals, a.Metadata)
	}
}

// appendSignalValues appends the finding-derived security signals in the shared
// exposed…internet_hops column order every signal-carrying label uses. The bool
// flags are stored as INT32 0/1 rather than BOOL for compatibility: saved user
// queries and the named queries filter with `n.has_kev = 1` (see schemaDDL).
func appendSignalValues(vals []any, sig NodeSignals) []any {
	return append(vals, b2i(sig.Exposed), b2i(sig.HasKEV), b2i(sig.Exploitable), b2i(sig.ToxicCombo),
		int32(sig.MaxScore), int32(sig.PrivescCount), int32(sig.InternetHops)) //nolint:gosec // bounded scores/hop counts
}

// appendCertValues appends the certificate expiry columns (expires_at,
// days_until_expiry, expiring_soon) from the asset Metadata map. These fields
// are only meaningful for certificate asset types (k8s_certificate,
// acm_certificate, gcp_ssl_certificate); all other assets get zero/empty
// defaults so every Asset row carries the required columns.
func appendCertValues(vals []any, meta map[string]string) []any {
	days := int32(0)
	if d := meta["days_until_expiry"]; d != "" {
		if n, err := strconv.ParseInt(d, 10, 32); err == nil {
			days = int32(n)
		}
	}
	expiringSoon := int32(0)
	if meta["expiring_soon"] == "true" {
		expiringSoon = 1
	}
	return append(vals, meta["expires_at"], days, expiringSoon)
}
