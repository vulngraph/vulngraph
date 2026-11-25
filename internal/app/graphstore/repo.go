package graphstore

import (
	"context"
	"fmt"
	"strings"

	ladybug "github.com/vulngraph/vulngraph/internal/graphdb/ladybug"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/graphschema"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// secretWildcardID is the sentinel node a role with a wildcard ("*") secret grant
// points to, instead of fanning an accesses_secret edge to every secret.
const secretWildcardID = "secret:*"

// dataClassSentinelIDs are the synthetic DSPM classification target node IDs.
var dataClassSentinelIDs = []string{
	"dataclass:pii", "dataclass:financial", "dataclass:credentials",
	"dataclass:health", "dataclass:pci", "dataclass:internal",
}

// bulkSync loads nodes+edges into the (empty) write connection via per-row
// UNWIND…MATCH…CREATE. Retained for tests and as a reference loader; production
// rebuilds use bulkSyncCopy. Both share buildNodeRows/buildEdgeRows.
func bulkSync(ctx context.Context, conn *ladybug.Connection, assets []asset.Asset, edges []asset.Edge, sigByResource map[string]NodeSignals) error {
	logger := log.FromContext(ctx)

	// Test/reference loader: assume a complete reach edge set (production goes
	// through bulkSyncCopy, which receives the real flag).
	byLabel := buildNodeRows(assets, edges, sigByResource, true)
	inserted := 0
	for label, rows := range byLabel {
		n, err := unwindInsert(conn, nodeUnwindQ[label], rows)
		if err != nil {
			logger.Warn().Err(err).Str("label", label).Msg("graphstore: node unwind failed")
		}
		inserted += n
	}

	if err := seedSentinels(conn); err != nil {
		logger.Warn().Err(err).Msg("graphstore: sentinel seed")
	}

	byRel := buildEdgeRows(edges)
	edgeCount := 0
	for relTable, rr := range byRel {
		n, err := unwindInsert(conn, edgeUnwindQ[relTable], rr.rows)
		if err != nil {
			logger.Warn().Err(err).Str("rel", relTable).Msg("graphstore: edge unwind failed")
		}
		edgeCount += n
	}

	logger.Info().Int("nodes", inserted).Int("edges", edgeCount).Msg("graphstore: bulk sync complete")
	return nil
}

// relRows is one rel table's output from buildEdgeRows: the property rows plus,
// index-parallel, the edge_type each row came from. The edge types are kept
// alongside the rows rather than inside them so nothing extra leaks into the
// COPY CSV or the UNWIND payload, while the per-edge_type load accounting behind
// the CH-vs-Ladybug parity gauge stays exact — several edge types share one rel
// table (runs_in/targets/routes_to all land in Accesses), so rel-level counts
// cannot answer "did THIS edge type make it in".
type relRows struct {
	rows      []map[string]any
	edgeTypes []string
}

func (r *relRows) add(e asset.Edge, row map[string]any) {
	r.rows = append(r.rows, row)
	r.edgeTypes = append(r.edgeTypes, e.EdgeType)
}

// buildEdgeRows groups edges by Ladybug rel table and constructs per-row maps
// (keyed "src","dst", plus prop keys). Rel tables not loaded into Ladybug (
// high-volume/topology context edges with no named-query usage) are skipped here
// — they remain in the Go edge slice for BFS (propagateRisk) and the snapshot.
func buildEdgeRows(edges []asset.Edge) map[string]relRows {
	byRel := map[string]relRows{}
	for _, e := range edges {
		relTable := relTableForEdge(e)
		if relTable == "" {
			continue
		}
		row := map[string]any{"src": e.SrcID, "dst": e.DstID}
		for _, p := range ladybugRelSpec[relTable].prop {
			row[p.rowKey] = edgeRowValue(e, p.rowKey)
		}
		rr := byRel[relTable]
		rr.add(e, row)
		byRel[relTable] = rr
	}
	return byRel
}

// relTableForEdge resolves the Ladybug rel table an edge loads into, or "" when the edge
// does not load at all (no UNWIND template, or a rel deliberately gated out of Ladybug).
//
// This is the routing authority, factored out of buildEdgeRows so the streaming
// CSV writer routes identically instead of reimplementing the chain. Every
// branch below exists because a mis-routed edge is dropped SILENTLY at COPY on
// an endpoint-label mismatch: a producer's endpoint type has been promoted to a
// more specific node label than the default rel table's declared FROM/TO, so
// the default table's typed MATCH finds nothing and the row vanishes with no
// error. Each branch below is one such case, rerouted to the table typed for
// the endpoint label that actually occurs.
func relTableForEdge(e asset.Edge) string {
	var relTable string
	// runs_in from a package source is a true Package→Asset relationship (RunsIn).
	// The same edge_type from non-package sources is topology (pod→namespace,
	// EC2→subnet) and maps to Accesses via the normal edgeTypeToRel lookup.
	if e.EdgeType == "runs_in" && e.SrcType == "package" {
		relTable = RelRunsIn
	} else if e.EdgeType == "deploys_to" && NodeLabelFor(e.DstType) != NodeK8sWorkload {
		// deploys_to to non-k8s destinations (ECS, Lambda, Cloud Run, etc.) routes
		// to DeploysToService (Repo→Asset). DeploysTo is typed Repo→K8sWorkload and
		// would silently drop these edges.
		relTable = RelDeploysToService
	} else if e.EdgeType == "executes_as" && NodeLabelFor(e.SrcType) == NodeK8sWorkload && NodeLabelFor(e.DstType) == NodeK8sWorkload {
		// executes_as between two K8sWorkload-labeled endpoints is the
		// pod→ServiceAccount hop (correlate/k8s_service_account.go). Both the
		// default ExecutesAs (Asset→IamRole) and the K8sWorkload reroute below
		// (K8sWorkload→IamRole) would drop it on the destination label. Ordered
		// before that branch, which matches on the source alone.
		relTable = RelExecutesAsK8sServiceAccount
	} else if e.EdgeType == "executes_as" && NodeLabelFor(e.SrcType) == NodeK8sWorkload {
		// executes_as from a K8sWorkload source routes to the dedicated K8sWorkload→IamRole
		// rel table. The standard ExecutesAs REL TABLE is typed Asset→IamRole and will
		// silently drop K8sWorkload sources because Ladybug checks endpoint label constraints.
		relTable = "ExecutesAsK8sWorkload"
	} else if e.EdgeType == "defined_in" && NodeLabelFor(e.SrcType) == NodeIamRole {
		// defined_in from an IamRole source (repo-declared role) routes to the
		// typed IamRole→Repo table; the default DefinedInAsset is Asset→Repo
		// and would drop these at the endpoint pre-filter.
		relTable = RelDefinedInIamRole
	} else if e.EdgeType == "defined_in" && NodeLabelFor(e.SrcType) == NodeK8sWorkload {
		// defined_in from a live k8s workload (K8sWorkload label) routes to the
		// typed K8sWorkload→Repo table; the default DefinedInAsset is Asset→Repo
		// and would drop these at the endpoint pre-filter.
		relTable = RelDefinedInK8sWorkload
	} else if e.EdgeType == "targets" && NodeLabelFor(e.DstType) == NodeK8sWorkload {
		// targets (k8s service selector-matches workload, exposure-chain last hop) to a
		// K8sWorkload destination routes to the dedicated Asset→K8sWorkload table —
		// the default Accesses table is Asset→Asset and would silently drop
		// K8sWorkload dsts. routes_to (the other Accesses-mapped edge_type)
		// never has a K8sWorkload dst — its only emitter always targets a k8s_service,
		// which stays generic Asset — so it's intentionally excluded from this reroute.
		relTable = "AccessesK8sWorkload"
	} else if e.EdgeType == "binds" && NodeLabelFor(e.SrcType) == NodeK8sWorkload {
		// binds from a ServiceAccount source routes to the dedicated
		// K8sWorkload→Asset table. The default Binds table is Asset→Asset and
		// k8s_service_account is K8sWorkload-labeled, so every
		// ServiceAccount→ClusterRoleBinding row would be silently discarded at
		// COPY — removing the identity half of every RBAC chain.
		relTable = RelBindsK8sWorkload
	} else if e.EdgeType == "federated_access" && NodeLabelFor(e.SrcType) == NodeK8sWorkload {
		// federated_access from a k8s ServiceAccount source (GKE Workload
		// Identity / IRSA) routes to the dedicated K8sWorkload→IamRole table.
		// The default FederatedAccess table is Repo→IamRole — correct for the
		// github_repo producer, fatal for this one since k8s_service_account is
		// K8sWorkload-labeled: those SA→cloud-role rows would be discarded at
		// COPY while the repo-sourced rows kept the table looking healthy.
		relTable = RelFederatedAccessK8sWorkload
	} else if e.EdgeType == "federated_access" && NodeLabelFor(e.SrcType) == NodeAsset {
		// federated_access from a catch-all Asset source — today a human_identity
		// federating into a cloud role (correlate/human_identity.go). The default
		// FederatedAccess table is Repo→IamRole, so these rows would be discarded
		// at COPY on the source label exactly as the k8s_service_account ones above.
		relTable = RelFederatedAccessAsset
	} else if e.EdgeType == "owns" && NodeLabelFor(e.SrcType) == NodeAsset {
		// owns from a catch-all Asset source — today a human_identity owning a
		// github_repo (correlate/human_identity.go). The default Owns table is
		// CloudAccount→Asset (the real cloud_account→ec2_instance producer) and
		// would drop these on the source label. Dormant today because Owns is
		// bfs_only (neither Owns nor OwnsAsset is in ladybugRelSpec, so
		// ladybugQueryableRelTable rejects both below) — kept correct so promoting
		// either to Loaded does not silently reintroduce the mismatch.
		relTable = RelOwnsAsset
	} else if e.EdgeType == "member_of" && NodeLabelFor(e.SrcType) == NodeSSOGroup {
		// member_of from a group source is the Okta→Identity Center group join.
		// The default MemberOf table is Asset→Group (the human half of the same
		// edge type) and would drop it on the source label.
		relTable = RelMemberOfGroup
	} else if e.EdgeType == "exposed_to_internet" && NodeLabelFor(e.SrcType) == NodeK8sWorkload {
		// exposed_to_internet from a k8s workload (hostNetwork pod, NodePort,
		// LoadBalancer service resolving straight to the pod) routes to the
		// dedicated K8sWorkload→Asset table. The default ExposedToInternet table
		// is Asset→Asset and k8s_pod/k8s_deployment are K8sWorkload-labeled, so
		// those rows would be discarded at COPY — the workload absent from every
		// "what is on the internet" traversal even though the reach BFS (which
		// runs in Go over the pre-COPY edge slice) still seeded from it.
		relTable = RelExposedToInternetK8sWorkload
	} else if e.EdgeType == "runs_image" && NodeLabelFor(e.SrcType) != NodeK8sWorkload {
		// runs_image from a non-k8s workload (ECS service, Cloud Run service —
		// both catch-all Asset) routes to the Asset→Asset table. The default
		// RunsImage is K8sWorkload→Asset and would drop these at COPY, cutting
		// the image off from the service whose exposure it inherits.
		relTable = RelRunsImageAsset
	} else {
		relTable, _ = RelTableFor(e.EdgeType)
	}
	if _, ok := edgeUnwindQ[relTable]; !ok {
		return ""
	}
	if !ladybugQueryableRelTable(relTable) {
		return "" // not traversed by any named query — keep out of Ladybug
	}
	return relTable
}

// edgeRowValue is the single authority for the value of a rel property column.
//
// Every property is read straight from Properties[rowKey] — RunsImage.image_ref,
// FederatedAccess.trust_type, the SSO-graph confidence/provenance/path — with exactly one
// exception: "via" falls back through origin and then matched (dns_points_to stamps
// "matched"). TestEdgeRowKeysMatchRelSpec pins that over 233 rel-table routings, keys
// AND values, which is what makes it safe for both the map form above and the streaming
// CSV writer to derive rows from ladybugRelSpec rather than hand-writing a map per rel.
func edgeRowValue(e asset.Edge, rowKey string) any {
	if rowKey != "via" {
		return e.Properties[rowKey]
	}
	via := e.Properties["via"]
	if via == "" {
		via = e.Properties["origin"]
	}
	if via == "" {
		via = e.Properties["matched"] // dns_points_to
	}
	return via
}

// seedSentinels creates the synthetic nodes that edges MATCH against: the
// internet exposure target, the wildcard-secret target, and the DSPM DataClass
// classification targets. Idempotent (MERGE / fresh-DB CREATE).
func seedSentinels(conn *ladybug.Connection) error {
	if res, err := conn.Query(
		`MERGE (n:Asset {id: 'internet'}) ` +
			`SET n.name = 'internet', n.type = 'internet', n.provider = '', ` +
			`n.region = '', n.account_id = '', n.score = 0`); err != nil {
		return fmt.Errorf("internet sentinel: %w", err)
	} else {
		res.Close()
	}

	if res, err := conn.Query(
		`MERGE (n:Asset {id: 'secret:*'}) ` +
			`SET n.name = 'all secrets (wildcard)', n.type = 'secret_wildcard', n.provider = '', ` +
			`n.region = '', n.account_id = '', n.score = 0`); err != nil {
		return fmt.Errorf("secret-wildcard sentinel: %w", err)
	} else {
		res.Close()
	}

	rows := make([]map[string]any, len(dataClassSentinelIDs))
	for i, id := range dataClassSentinelIDs {
		rows[i] = map[string]any{"id": id, "classification": id[len("dataclass:"):]}
	}
	if _, err := unwindInsert(conn, nodeUnwindQ[NodeDataClass], rows); err != nil {
		return fmt.Errorf("dataclass sentinels: %w", err)
	}
	return nil
}

// b2i maps a bool to the INT32 0/1 the signal columns store.
func b2i(b bool) int32 {
	if b {
		return 1
	}
	return 0
}

// ─── Query functions ──────────────────────────────────────────────────────────

const maxQueryItems = 500 // hard cap on IN-list length to prevent huge Cypher strings

// nodeSignalByID looks up signal columns for a single asset ID: one id point
// lookup per table (Asset, then IamRole), stopping at the first hit, with the row
// read by index via GetAsSlice.
//
// Column indices are fixed by seedCols (order must match):
//
//	0=nid 1=nname 2=ntype 3=nprov 4=nreg 5=nacct 6=nscore
//	7=exposed 8=has_kev 9=exploitable 10=toxic_combo 11=max_score 12=privesc_count 13=internet_hops
func nodeSignalByID(conn *ladybug.Connection, id string) (explore.Node, bool, error) {
	tables := []string{"Asset", "IamRole"}
	for _, table := range tables {
		q := fmt.Sprintf(`MATCH (n:%s) WHERE n.id = $id RETURN %s LIMIT 1`, table, seedCols)
		prepared, err := conn.Prepare(q)
		if err != nil {
			return explore.Node{}, false, fmt.Errorf("nodeSignalByID prepare (%s): %w", table, err)
		}
		res, err := conn.Execute(prepared, map[string]any{"id": id})
		prepared.Close()
		if err != nil {
			return explore.Node{}, false, fmt.Errorf("nodeSignalByID execute (%s): %w", table, err)
		}
		if res.HasNext() {
			row, rowErr := res.Next()
			if rowErr != nil {
				res.Close()
				return explore.Node{}, false, fmt.Errorf("nodeSignalByID next row (%s): %w", table, rowErr)
			}
			// Read row values BEFORE closing res — res.Close() frees the backing
			// memory that row references.
			vals, sliceErr := row.GetAsSlice()
			row.Close()
			res.Close()
			if sliceErr != nil {
				return explore.Node{}, false, fmt.Errorf("nodeSignalByID read row (%s): %w", table, sliceErr)
			}
			if len(vals) < 14 {
				continue
			}
			n := explore.Node{
				ID:           strVal(vals[0]),
				Name:         strVal(vals[1]),
				Type:         strVal(vals[2]),
				Provider:     strVal(vals[3]),
				Region:       strVal(vals[4]),
				AccountID:    strVal(vals[5]),
				Score:        intVal(vals[6]),
				Exposed:      intVal(vals[7]) != 0,
				HasKEV:       intVal(vals[8]) != 0,
				Exploitable:  intVal(vals[9]) != 0,
				ToxicCombo:   intVal(vals[10]) != 0,
				MaxScore:     intVal(vals[11]),
				PrivescCount: intVal(vals[12]),
				InternetHops: intVal(vals[13]),
			}
			return n, true, nil
		}
		res.Close()
	}
	return explore.Node{}, false, nil
}

// seedCols is the common SELECT list for matchSeed's per-label queries. The signal
// columns are aliased to their schema names so readSignals can map them uniformly
// with the neighbors and execCypher paths.
const seedCols = `n.id AS nid, n.name AS nname, n.type AS ntype, n.provider AS nprov, n.region AS nreg, n.account_id AS nacct, n.score AS nscore, ` +
	`n.exposed AS exposed, n.has_kev AS has_kev, n.exploitable AS exploitable, n.toxic_combo AS toxic_combo, n.max_score AS max_score, n.privesc_count AS privesc_count, n.internet_hops AS internet_hops`

// seedColsBasic is seedCols without the signal columns (exposed/has_kev/
// exploitable/toxic_combo/max_score/privesc_count/internet_hops) — those don't
// exist on Subnet (schema.go only gives it
// id/name/type/provider/region/account_id/score), so selecting seedCols against
// those labels throws a Binder exception. readSignals/InternetHops already
// degrade a missing map key to a zero value (ReachUnknown for hops), so omitting
// the columns here is safe — the node just carries no signal data, same as any
// asset the signal projection never reached.
const seedColsBasic = `n.id AS nid, n.name AS nname, n.type AS ntype, n.provider AS nprov, n.region AS nreg, n.account_id AS nacct, n.score AS nscore`

// seedColsPackage / seedColsRepo are the per-label column sets for the two labels
// that carry neither seedCols nor seedColsBasic. Package has no type/provider/
// region/account_id and no exposed/toxic_combo/internet_hops (schema.go); Repo has
// only id/name/provider. Both project only real columns; matchSeed stamps the
// missing Type in Go instead (seedTypeByLabel).
const seedColsPackage = `n.id AS nid, n.name AS nname, n.score AS nscore, n.has_kev AS has_kev, n.exploitable AS exploitable`

const seedColsRepo = `n.id AS nid, n.name AS nname, n.provider AS nprov`

// seedTypeByLabel supplies the asset `type` for labels whose node table has no
// type column, so a seeded/hydrated Package or Repo comes back typed rather than
// blank — the frontend and the impact reasoner both switch on Node.Type.
var seedTypeByLabel = map[string]string{
	NodePackage: "package",
	NodeRepo:    "github_repo",
}

// encryptionState maps the Asset-only tri-state `encrypted` column to its wire
// form. Absent on other labels, where it stays "". Only an exact 0 or 1 is an
// observation: 2, NULL, or any unexpected value is unknown — never encrypted, and
// never the unencrypted alarm either.
func encryptionState(m map[string]any) string {
	v, ok := m["encrypted"]
	if !ok {
		return ""
	}
	switch v {
	case int64(encryptionUnencrypted), encryptionUnencrypted, int(encryptionUnencrypted):
		return explore.EncryptionUnencrypted
	case int64(encryptionEncrypted), encryptionEncrypted, int(encryptionEncrypted):
		return explore.EncryptionEncrypted
	default:
		return explore.EncryptionUnknown
	}
}

// readSignals maps the six projected signal columns (INT32 0/1 for the flags) from
// a column/property map into the explore.Node. Works for both row.GetAsMap output
// (matchSeed, neighbors — aliased to schema names) and ladybug.Node.Properties (execCypher).
func readSignals(n *explore.Node, m map[string]any) {
	n.Exposed = intVal(m["exposed"]) != 0
	n.HasKEV = intVal(m["has_kev"]) != 0
	n.Exploitable = intVal(m["exploitable"]) != 0
	n.ToxicCombo = intVal(m["toxic_combo"]) != 0
	n.MaxScore = intVal(m["max_score"])
	n.PrivescCount = intVal(m["privesc_count"])
	n.Encryption = encryptionState(m)
	n.Public = intVal(m["public"]) != 0
	n.PublicTier = intVal(m["public_tier"])
	// trust_entry is an IamRole-only column (inbound assumability class);
	// absent on other labels, where it stays "".
	if s, ok := m["trust_entry"].(string); ok {
		n.TrustEntry = s
	}
	if _, ok := m["internet_hops"]; ok {
		// Clamp out-of-domain values to ReachUnknown (fail-open): a corrupt or
		// unexpected hop count must never be trusted as a concrete reach distance.
		hops, _ := clampInternetHops(intVal(m["internet_hops"]))
		n.InternetHops = hops
	} else {
		// A node label without the signal column is UNKNOWN, not "unreachable":
		// defaulting to ReachNone would falsely assert non-reachability for any node
		// missing the projection, poisoning must-fix demotion the other direction.
		n.InternetHops = ReachUnknown
	}
}

// seedLabelCols is the per-label seed projection: which column list to select and
// which asset `type` to stamp in Go for labels whose table has no type column.
// Order is the branch order matchSeed runs.
//
// Package and Repo matter here beyond ordinary seeding: blastRadiusGraph
// hydrates its FINAL visited set through matchSeed, and its hop queries are
// untyped (`MATCH (n:Asset)-[]->(m)`), so a blast radius walk that reaches a
// package or repo through RunsPackage/DefinedInAsset would silently drop every
// one of them at hydration if their labels were missing here — the caller
// would see a smaller blast radius with no error and no way to tell.
var seedLabelCols = []struct {
	label string
	cols  string
	// hasType is false for labels with no `type` column — those cannot be
	// filtered by a $types list and are matched by label alone instead.
	hasType bool
	// hasProvider is false for Package, which carries no provider column.
	hasProvider bool
}{
	{NodeAsset, seedCols, true, true},
	{NodeIamRole, seedCols, true, true},
	{NodeK8sWorkload, seedCols, true, true},
	{NodeSubnet, seedColsBasic, true, true},
	{NodePackage, seedColsPackage, false, false},
	{NodeRepo, seedColsRepo, false, true},
}

// matchSeed returns nodes matching the given ids, types, or provider filter.
// One query per label: each label is its own node table with its own column set
// (seedLabelCols), which a single UNION ALL could not project uniformly.
//
// CloudAccount/ElasticIP/DNSZone/IamPolicy/DataClass/SSOGroup/SSOPermSet are still
// not queried here: they are anchor/sentinel labels no GraphQuerySpec seeds on and
// no loaded rel points at from a seedable label. Add a seedLabelCols entry if one
// starts to.
func matchSeed(conn *ladybug.Connection, ids []string, types []string, provider string, limit int) ([]explore.Node, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}

	type querySpec struct {
		q     string
		args  map[string]any
		label string
	}

	var queries []querySpec

	switch {
	case len(ids) > 0:
		// Chunked rather than cut at maxQueryItems: a cut silently dropped every id
		// past the 500th, and the caller's limit is the only intended bound.
		for start := 0; start < len(ids); start += maxQueryItems {
			chunk := ids[start:min(start+maxQueryItems, len(ids))]
			idList := make([]any, len(chunk))
			for i, id := range chunk {
				idList[i] = id
			}
			a := map[string]any{"ids": idList}
			for _, s := range seedLabelCols {
				queries = append(queries, querySpec{
					fmt.Sprintf(`MATCH (n:%s) WHERE n.id IN $ids RETURN %s LIMIT %d`, s.label, s.cols, limit), a, s.label,
				})
			}
		}
	case len(types) > 0:
		if len(types) > maxQueryItems {
			types = types[:maxQueryItems]
		}
		typeList := make([]any, len(types))
		wantType := make(map[string]bool, len(types))
		for i, t := range types {
			typeList[i] = t
			wantType[t] = true
		}
		a := map[string]any{"types": typeList}
		if provider != "" {
			a["provider"] = provider
		}
		for _, s := range seedLabelCols {
			var where string
			switch {
			case s.hasType && provider != "" && s.hasProvider:
				where = `WHERE n.type IN $types AND n.provider = $provider`
			case s.hasType:
				where = `WHERE n.type IN $types`
			case !wantType[seedTypeByLabel[s.label]]:
				continue // typeless label whose one implicit type wasn't asked for
			case provider != "" && s.hasProvider:
				where = `WHERE n.provider = $provider`
			}
			queries = append(queries, querySpec{
				strings.TrimSpace(fmt.Sprintf(`MATCH (n:%s) %s RETURN %s LIMIT %d`, s.label, where, s.cols, limit)), a, s.label,
			})
		}
	default:
		return nil, nil
	}

	var out []explore.Node
	for _, qs := range queries {
		prepared, err := conn.Prepare(qs.q)
		if err != nil {
			return nil, fmt.Errorf("matchSeed prepare: %w", err)
		}
		res, err := conn.Execute(prepared, qs.args)
		prepared.Close()
		if err != nil {
			return nil, fmt.Errorf("matchSeed execute: %w", err)
		}
		for res.HasNext() {
			if len(out) >= limit {
				res.Close()
				return out, nil
			}
			row, err := res.Next()
			if err != nil {
				res.Close()
				return nil, fmt.Errorf("matchSeed %s: next row: %w", qs.label, err)
			}
			m, err := row.GetAsMap()
			row.Close()
			if err != nil {
				res.Close()
				return nil, fmt.Errorf("matchSeed %s: read row: %w", qs.label, err)
			}
			n := explore.Node{
				ID:        strVal(m["nid"]),
				Name:      strVal(m["nname"]),
				Type:      strVal(m["ntype"]),
				Provider:  strVal(m["nprov"]),
				Region:    strVal(m["nreg"]),
				AccountID: strVal(m["nacct"]),
				Score:     intVal(m["nscore"]),
			}
			if n.Type == "" {
				n.Type = seedTypeByLabel[qs.label]
			}
			readSignals(&n, m)
			out = append(out, n)
		}
		res.Close()
	}
	return out, nil
}

// neighborNodeCols is the neighbour-node projection used when m is Asset or
// IamRole, both of which carry the full type/region/account_id/score/signal
// shape. Signal columns are aliased to their schema names so readSignals maps
// them.
const neighborNodeCols = `m.id AS m_id, m.name AS m_name, m.type AS m_type, m.provider AS m_prov, ` +
	`m.region AS m_reg, m.account_id AS m_acct, m.score AS m_score, ` +
	`m.exposed AS exposed, m.has_kev AS has_kev, m.exploitable AS exploitable, ` +
	`m.toxic_combo AS toxic_combo, m.max_score AS max_score, m.privesc_count AS privesc_count`

// neighborNodeColsMinimal is for labels lacking the shape above — the SSO graph's
// Group/PermissionSet/CloudAccount/Repo Expand endpoints have no type/region/
// account_id/score/signal columns, so projecting neighborNodeCols against them
// is a Ladybug binder error ("Cannot find property exposed for m"), not a
// zero-row result — it would abort the whole neighbors() call. Fields absent
// here read back as zero-value on explore.Node.
const neighborNodeColsMinimal = `m.id AS m_id, m.name AS m_name, m.provider AS m_prov`

// neighborFullShapeLabels are the node labels neighborNodeCols can safely
// project against. Every other label used as a neighbors() endpoint falls
// back to neighborNodeColsMinimal. K8sWorkload carries the same signal columns
// as Asset/IamRole (schema.go) — included so expanding through
// ExecutesAsK8sWorkload/AccessesK8sWorkload doesn't silently lose score/exposed/
// etc. for the K8sWorkload-labeled endpoint.
var neighborFullShapeLabels = map[string]bool{NodeAsset: true, NodeIamRole: true, NodeK8sWorkload: true}

// neighborNodeColsPackage is the Package endpoint projection. Package is the one
// expand endpoint that has no `provider` column either (schema.go gives it
// id/name/ecosystem/version/score/has_kev/exploitable/cve_id/epss_score), so even
// neighborNodeColsMinimal is a Ladybug binder error against it — "Cannot find
// property provider for m", which aborts the whole neighbors() call rather than
// returning zero rows for that one branch.
const neighborNodeColsPackage = `m.id AS m_id, m.name AS m_name, m.score AS m_score, ` +
	`m.has_kev AS has_kev, m.exploitable AS exploitable`

// neighborColsFor returns the widest projection a given endpoint label can bind.
func neighborColsFor(label string) string {
	switch {
	case neighborFullShapeLabels[label]:
		return neighborNodeCols
	case label == NodePackage:
		return neighborNodeColsPackage
	default:
		return neighborNodeColsMinimal
	}
}

// relSpec is a populated rel table and its fixed endpoint node labels.
type relSpec struct{ label, from, to string }

// neighborRels are the rel tables among Asset/IamRole that neighbors traverses —
// the expand view, derived from the graphschema registry's Expand flag.
// ConnectedViaSG is intentionally not flagged Expand: a security group is a hub
// node shared by every instance attached to it, so expanding one fans out to the
// whole membership rather than showing a meaningful neighbourhood — reachability
// through security groups is the lateral_movement_via_sg Cypher query instead.
// neighbors queries each rel table separately, so the edge label comes from the
// relSpec in Go rather than from the row. TestNeighborRelsMatchSchema pins
// labels/endpoints to schemaDDL.
var neighborRels = buildNeighborRels()

func buildNeighborRels() []relSpec {
	var out []relSpec
	for _, r := range graphschema.ExpandRels() {
		out = append(out, relSpec{r.Name, r.From, r.To})
	}
	return out
}

func neighbors(conn *ladybug.Connection, ids []string, edgeTypes []string, dir string, budget QueryBudget) ([]explore.Edge, []explore.Node, bool, error) {
	if len(ids) == 0 {
		return nil, nil, false, nil
	}
	truncated := false
	if len(ids) > maxQueryItems {
		ids = ids[:maxQueryItems]
		truncated = true
	}
	idList := make([]any, len(ids))
	for i, id := range ids {
		idList[i] = id
	}

	limit := budget.MaxEdges
	if limit <= 0 {
		limit = 2000
	}

	// Direction: "both" walks both ways; "in" only inbound; anything else outbound.
	var includeOut, includeIn bool
	switch dir {
	case "in":
		includeIn = true
	case "both":
		includeIn, includeOut = true, true
	default:
		includeOut = true
	}

	// edgeTypes (Ladybug rel-table labels, e.g. "ExposedToInternet") narrows the branch
	// set, so the LIMIT applies after filtering — no over-fetch, no post-hoc Go filter.
	var wantTypes map[string]bool
	if len(edgeTypes) > 0 {
		wantTypes = make(map[string]bool, len(edgeTypes))
		for _, t := range edgeTypes {
			wantTypes[t] = true
		}
	}

	var outEdges []explore.Edge
	var outNodes []explore.Node
	seenNodes := map[string]bool{}
	args := map[string]any{"ids": idList}

	// One query per rel table (and direction): the rel label and the neighbour's
	// node table are known in Go from neighborRels, so each query projects that
	// table's columns (neighborColsFor) over a bound $ids list, and the edge
	// filter (wantTypes) skips whole branches instead of filtering rows.
	//
	// inbound=true means m is the edge's SOURCE: the edge is reported in its
	// stored orientation (m→seed), exactly as the ClickHouse fallback reports it,
	// so a caller can tell an inbound edge from an outbound one.
	run := func(pattern, label, mLabel string, inbound bool) error {
		if len(outEdges) >= limit {
			return nil
		}
		q := fmt.Sprintf(`%s WHERE n.id IN $ids RETURN n.id AS src_id, %s LIMIT %d`,
			pattern, neighborColsFor(mLabel), limit)
		prepared, err := conn.Prepare(q)
		if err != nil {
			return fmt.Errorf("neighbors prepare %s: %w", label, err)
		}
		defer prepared.Close()
		res, err := conn.Execute(prepared, args)
		if err != nil {
			return fmt.Errorf("neighbors execute %s: %w", label, err)
		}
		defer res.Close()
		for res.HasNext() {
			row, err := res.Next()
			if err != nil {
				return fmt.Errorf("neighbors %s: next row: %w", label, err)
			}
			m, err := row.GetAsMap()
			row.Close()
			if err != nil {
				return fmt.Errorf("neighbors %s: read row: %w", label, err)
			}
			seedID := strVal(m["src_id"])
			nodeID := strVal(m["m_id"])
			e := explore.Edge{SrcID: seedID, DstID: nodeID, EdgeType: label}
			if inbound {
				e.SrcID, e.DstID = nodeID, seedID
			}
			outEdges = append(outEdges, e)
			if nodeID != "" && !seenNodes[nodeID] {
				seenNodes[nodeID] = true
				n := explore.Node{
					ID:        nodeID,
					Name:      strVal(m["m_name"]),
					Type:      strVal(m["m_type"]),
					Provider:  strVal(m["m_prov"]),
					Region:    strVal(m["m_reg"]),
					AccountID: strVal(m["m_acct"]),
					Score:     intVal(m["m_score"]),
				}
				if n.Type == "" {
					// Package/Repo node tables have no `type` column; stamp the asset
					// type in Go so a neighbour comes back typed rather than blank.
					n.Type = seedTypeByLabel[mLabel]
				}
				readSignals(&n, m)
				outNodes = append(outNodes, n)
			}
		}
		return nil
	}

	for _, rs := range neighborRels {
		if wantTypes != nil && !wantTypes[rs.label] {
			continue
		}
		// m is the far endpoint in either direction (outbound: TO side; inbound:
		// FROM side). quoteLabel backtick-escapes "Group", which the Cypher parser
		// rejects bare.
		if includeOut {
			if err := run(fmt.Sprintf(`MATCH (n:%s)-[:%s]->(m:%s)`, quoteLabel(rs.from), rs.label, quoteLabel(rs.to)), rs.label, rs.to, false); err != nil {
				return nil, nil, false, err
			}
		}
		if includeIn {
			if err := run(fmt.Sprintf(`MATCH (m:%s)-[:%s]->(n:%s)`, quoteLabel(rs.from), rs.label, quoteLabel(rs.to)), rs.label, rs.from, true); err != nil {
				return nil, nil, false, err
			}
		}
	}
	// Reaching the edge limit means later branches (or rows) were not read.
	return outEdges, outNodes, truncated || len(outEdges) >= limit, nil
}
