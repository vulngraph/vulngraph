package graphstore

import (
	"context"
	"encoding/csv"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	ladybug "github.com/vulngraph/vulngraph/internal/graphdb/ladybug"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/graphschema"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// ─── Phase B: COPY-based parallel bulk load ─────────────────────────────────────
//
// bulkSyncCopy loads a fresh in-memory graph via Ladybug's parallel COPY bulk
// loader instead of per-row UNWIND…MATCH…CREATE. COPY resolves FROM/TO node
// primary keys in bulk and partitions the rel-table build across worker
// threads, making it far faster than the per-row path at scale.
//
// Preconditions COPY relies on (all satisfied here): tables are EMPTY (every
// rebuild opens a fresh :memory: DB), and every rel's FROM/TO node already
// exists. We replicate UNWIND MATCH's "skip silently when an endpoint is
// absent" semantics by pre-filtering edge rows to endpoints that were actually
// loaded under the rel's typed FROM/TO label — COPY would otherwise abort the
// whole rel table on a missing primary key.

// defaultLoadThreads is the COPY parallelism when LADYBUG_LOAD_THREADS is unset.
// Capped at 4: the worker pod's CPU limit is small, and COPY's partitioned
// rel-batch insert saturates a handful of cores well before diminishing returns.
func defaultLoadThreads() int {
	n := runtime.NumCPU()
	if n > 4 {
		n = 4
	}
	if n < 1 {
		n = 1
	}
	return n
}

// nodeCSVCols is the CSV header (and value order) per node label. It MUST match
// the schemaDDL column order exactly — COPY maps CSV columns to table columns by
// the HEADER=true header names. Row maps already key on these column names.
var nodeCSVCols = map[string][]string{
	NodeAsset:        {"id", "name", "type", "provider", "region", "account_id", "score", "exposed", "has_kev", "exploitable", "toxic_combo", "max_score", "privesc_count", "internet_hops", "encrypted", "public", "public_tier", "expires_at", "days_until_expiry", "expiring_soon"},
	NodeIamRole:      {"id", "name", "provider", "account_id", "score", "type", "region", "exposed", "has_kev", "exploitable", "toxic_combo", "max_score", "privesc_count", "internet_hops", "trust_entry"},
	NodeRepo:         {"id", "name", "provider"},
	NodePackage:      {"id", "name", "ecosystem", "version", "score", "has_kev", "exploitable", "cve_id", "epss_score"},
	NodeK8sWorkload:  {"id", "name", "type", "provider", "region", "account_id", "score", "exposed", "has_kev", "exploitable", "toxic_combo", "max_score", "privesc_count", "internet_hops"},
	NodeSubnet:       {"id", "name", "type", "provider", "region", "account_id", "score"},
	NodeDataClass:    {"id", "classification"},
	NodeCloudAccount: {"id", "name", "provider", "account_id"},
	NodeSSOGroup:     {"id", "name", "provider"},
	NodeSSOPermSet:   {"id", "name", "provider", "account_id", "grants_admin"},
}

// relProp names a rel CSV property column and the row-map key it reads from.
// (Some DDL columns differ from the row key, e.g. DnsPointsTo.matched ← "via".)
type relProp struct {
	col    string // CSV header / DDL column name
	rowKey string // key in the byRel row map
}

// relEndpoints records the typed FROM/TO node labels per rel table, used to
// pre-filter edges to existing endpoints (replicating UNWIND MATCH skip).
type relEndpoints struct {
	from string
	to   string
	prop []relProp
}

// ladybugRelProps overrides the CSV property columns for rel tables whose DDL
// column names differ from the default single {via ← via}. Keys must be Loaded
// rels in the graphschema registry; TestLadybugRelSpecMatchesDDL pins every column
// name to its CREATE REL TABLE statement.
var ladybugRelProps = map[string][]relProp{
	"DnsPointsTo": {{"matched", "via"}},
	// RunsImage carries the pod's resolved image reference, not a `via` — the
	// kubernetes collector emits Properties{"image_ref": …}.
	"RunsImage":        {{"image_ref", "image_ref"}},
	"RunsImageAsset":   {{"image_ref", "image_ref"}},
	"DeploysTo":        {{"confidence", "via"}},
	"DeploysToService": {{"confidence", "via"}},
	"FederatedAccess": {
		{"trust_type", "trust_type"}, {"subject", "subject"},
		{"provenance", "provenance"}, {"confidence", "confidence"}, {"workflow_path", "workflow_path"},
	},
	// FederatedAccessK8sWorkload/FederatedAccessAsset are the K8sWorkload- and
	// Asset-sourced splits of federated_access (workload identity, and a human
	// identity federating into a cloud role) — same five properties, different
	// FROM label.
	"FederatedAccessK8sWorkload": {
		{"trust_type", "trust_type"}, {"subject", "subject"},
		{"provenance", "provenance"}, {"confidence", "confidence"}, {"workflow_path", "workflow_path"},
	},
	"FederatedAccessAsset": {
		{"trust_type", "trust_type"}, {"subject", "subject"},
		{"provenance", "provenance"}, {"confidence", "confidence"}, {"workflow_path", "workflow_path"},
	},
	// ContainsData (Asset→DataClass, DSPM classification) is low-volume: bounded
	// by data-storing assets × a handful of DataClass sentinels, not topology.
	// confidence distinguishes an operator-tagged class from a name guess.
	"ContainsData": {{"classification", "classification"}, {"confidence", "confidence"}},
	// SSO graph: Group→PermissionSet assignment and PermissionSet→CloudAccount
	// access grants carry the confidence/provenance shape the Identity Center
	// collector emits (collect/aws/identitycenter.go).
	"AssignedTo":     {{"confidence", "confidence"}, {"provenance", "provenance"}},
	"GrantsAccessTo": {{"confidence", "confidence"}, {"provenance", "provenance"}},
	"GrantsAdmin":    {{"confidence", "confidence"}, {"provenance", "provenance"}},
	// DefinedInK8sWorkload/DefinedInAsset (IaC ownership) carry the same
	// confidence/provenance shape plus a manifest path (the file the
	// K8sManifestOwnership correlate rule anchored the edge to).
	"DefinedInK8sWorkload": {{"confidence", "confidence"}, {"provenance", "provenance"}, {"path", "path"}},
	"DefinedInAsset":       {{"confidence", "confidence"}, {"provenance", "provenance"}, {"path", "path"}},
	// DefinedInIamRole (IAM-role ownership) has no path column, unlike the
	// manifest-sourced ownership edges above.
	"DefinedInIamRole": {{"confidence", "confidence"}, {"provenance", "provenance"}},
}

// ladybugRelSpec is the per-rel-table schema for the COPY path. It covers ONLY the
// rel tables loaded into Ladybug — derived from the graphschema registry's Loaded
// flag (each unloaded rel carries a DropReason there). Edges mapping
// to any rel table absent here are skipped at insert time; they remain in the
// Go edge slice for BFS (propagateRisk) and the snapshot.
var ladybugRelSpec = buildLadybugRelSpec()

func buildLadybugRelSpec() map[string]relEndpoints {
	spec := map[string]relEndpoints{}
	for _, r := range graphschema.LoadedRels() {
		props, ok := ladybugRelProps[r.Name]
		if !ok {
			props = []relProp{{"via", "via"}}
		}
		spec[r.Name] = relEndpoints{r.From, r.To, props}
	}
	return spec
}

// ladybugQueryableRelTable reports whether a rel table is loaded into Ladybug. Source
// of truth is ladybugRelSpec; TestLadybugQueryableRelTablesCoverNamedQueries pins it to
// the rel types named_queries.go actually traverses.
func ladybugQueryableRelTable(relTable string) bool {
	_, ok := ladybugRelSpec[relTable]
	return ok
}

// expiredEphemeralVerifier checks a batch of candidate ids against the asset
// table and reports which ones are a CONFIRMED corpse — a real asset row that
// fails the ephemeral-liveness gate — rather than a declared-type inference.
// asset.Service.VerifyExpiredEphemeral implements it outside tests; nil means
// "no verifier available", which bulkSyncCopy treats as an empty result (every
// missing ephemeral-typed endpoint reports relRowEndpointAbsent rather than
// relRowEndpointExpired) — never as licence to trust the declared type again.
type expiredEphemeralVerifier func(ctx context.Context, ids []string) (map[string]bool, error)

// bulkSyncCopy loads nodes then rels into the (empty) write connection's database
// via COPY. threads<=0 uses defaultLoadThreads(). reachComplete=false degrades
// not-reached nodes to ReachUnknown (see buildNodeRows). verifyExpired may be nil
// (see expiredEphemeralVerifier).
func bulkSyncCopy(ctx context.Context, conn *ladybug.Connection, assets []asset.Asset, edges []asset.Edge, ov reachOverlay, sigByResource map[string]NodeSignals, reachComplete bool, threads int, verifyExpired expiredEphemeralVerifier) (copyStats, error) {
	logger := log.FromContext(ctx)
	if threads <= 0 {
		threads = defaultLoadThreads()
	}
	conn.SetMaxNumThreads(uint64(threads)) //nolint:gosec // small positive bound

	dir, err := os.MkdirTemp(copyTmpDir(), "ladybug-copy-")
	if err != nil {
		return copyStats{}, fmt.Errorf("bulkSyncCopy: temp dir: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }() // best-effort cleanup of transient CSVs

	// ── Nodes ────────────────────────────────────────────────────────────────
	//
	// Rows stream straight from the asset slice into the per-label CSVs. Nothing
	// materialises a second copy of the node set: the source assets slice is
	// still needed afterwards by propagateRisk, internetHops and WriteSnapshot,
	// so holding a second full-size copy alongside it is memory the rebuild
	// cannot afford at scale.
	//
	// nodeLabel is the single id→label index of everything loaded. It is the dedup
	// set during the walk, the endpoint pre-filter for rel rows (COPY aborts on a
	// missing FROM/TO primary key, so rows to absent endpoints must be dropped
	// exactly as the UNWIND MATCH skipped them), and the evidence writeRelCSV uses
	// to tell "endpoint is not in Ladybug" (expected) from "endpoint is in Ladybug under a
	// different label than the rel declares" (always a bug).
	nodeLabel := make(map[string]string, len(assets))
	csvs := newNodeCSVSet(dir)
	err = streamNodeRows(assets, ov, sigByResource, reachComplete, nodeLabel, csvs.write)
	if cerr := csvs.close(); err == nil {
		err = cerr
	}
	if err != nil {
		return copyStats{}, fmt.Errorf("bulkSyncCopy: write nodes: %w", err)
	}
	nodes := 0
	for _, label := range csvs.labels {
		if err := copyFrom(conn, label, csvs.files[label].path); err != nil {
			return copyStats{}, fmt.Errorf("bulkSyncCopy: COPY %s: %w", label, err)
		}
		nodes += csvs.files[label].rows
	}

	// ── Sentinels (created after node COPY, before rel COPY) ─────────────────
	if err := seedSentinels(conn); err != nil {
		logger.Warn().Err(err).Msg("graphstore: sentinel seed")
	}
	// Sentinels are :Asset/:DataClass unconditionally — they are MERGE'd under those
	// labels above, so the index must agree even in the degenerate case where an
	// asset claimed a sentinel ID.
	nodeLabel[InternetNodeID] = NodeAsset
	nodeLabel[secretWildcardID] = NodeAsset
	for _, dc := range dataClassSentinelIDs {
		nodeLabel[dc] = NodeDataClass
	}

	// ── Rels ─────────────────────────────────────────────────────────────────
	byType := map[string]edgeTypeLoad{}
	for i := range edges {
		l := byType[edges[i].EdgeType]
		l.fetched++
		byType[edges[i].EdgeType] = l
	}

	// Verify "expired" against the asset table BEFORE classifying a single row,
	// rather than trusting each edge's own declared src_type/dst_type. One bulk
	// query over every candidate id — never one per edge: a missing endpoint is a
	// candidate only if its declared type is ephemeral (ephemeralEndpointType).
	// verifyExpired == nil (LoadFromSnapshot's fast-boot path, which deliberately
	// avoids a ClickHouse round trip) degrades to an empty verified set: every such
	// row reports relRowEndpointAbsent instead of relRowEndpointExpired for that
	// one build, corrected by the background refresh that follows it.
	verifiedExpired := map[string]bool{}
	if verifyExpired != nil {
		candidates := make(map[string]struct{}, 64)
		for i := range edges {
			e := &edges[i]
			if _, loaded := nodeLabel[e.SrcID]; !loaded && ephemeralEndpointType[e.SrcType] {
				candidates[e.SrcID] = struct{}{}
			}
			if _, loaded := nodeLabel[e.DstID]; !loaded && ephemeralEndpointType[e.DstType] {
				candidates[e.DstID] = struct{}{}
			}
		}
		if len(candidates) > 0 {
			ids := make([]string, 0, len(candidates))
			for id := range candidates {
				ids = append(ids, id)
			}
			verifiedExpired, err = verifyExpired(ctx, ids)
			if err != nil {
				return copyStats{}, fmt.Errorf("bulkSyncCopy: verify expired ephemeral endpoints: %w", err)
			}
		}
	}

	// Stream the edges into per-rel CSVs in ONE pass, rather than materialising a
	// map[string]any per loadable edge first (buildEdgeRows) and holding them all
	// alongside the asset slice, the edge slice and nodeLabel — that transient,
	// not the graph engine itself, would be the dominant memory cost of a rebuild.
	// Equivalence with the map-based form rests on TestEdgeRowKeysMatchRelSpec.
	relSet := newRelCSVSet(dir)
	for i := range edges {
		if err := relSet.add(&edges[i], nodeLabel, verifiedExpired); err != nil {
			_ = relSet.closeAll()
			return copyStats{}, fmt.Errorf("bulkSyncCopy: write rel rows: %w", err)
		}
	}
	// Must close before COPY: COPY reads each file by path.
	if err := relSet.closeAll(); err != nil {
		return copyStats{}, fmt.Errorf("bulkSyncCopy: close rel csvs: %w", err)
	}

	edgeCount := 0
	dropMismatch, dropAbsent, dropExpired := 0, 0, 0
	reachMismatched := map[string]int{}
	for relTable, rw := range relSet.writers {
		rs := rw.stats
		path := rw.path
		dropMismatch += rs.labelMismatch
		dropAbsent += rs.endpointAbsent
		dropExpired += rs.endpointExpired
		for et, l := range rs.byType {
			agg := byType[et]
			agg.loaded += l.loaded
			agg.labelMismatch += l.labelMismatch
			agg.endpointAbsent += l.endpointAbsent
			agg.endpointExpired += l.endpointExpired
			byType[et] = agg
		}
		// Per-rel accounting, not just the total: a Reach rel losing rows to a
		// label mismatch degrades the reach signal AND is always a bug, while the
		// same rel losing rows to a dangling endpoint is normal attrition.
		if rs.labelMismatch > 0 && reachRels[relTable] {
			reachMismatched[relTable] = rs.labelMismatch
		}
		if rs.written == 0 {
			continue
		}
		if err := copyFrom(conn, relTable, path); err != nil {
			return copyStats{}, fmt.Errorf("bulkSyncCopy: COPY %s: %w", relTable, err)
		}
		edgeCount += rs.written
	}

	tableRows, err := countNodeTables(conn)
	if err != nil {
		return copyStats{}, fmt.Errorf("bulkSyncCopy: %w", err)
	}

	stats := copyStats{
		nodeTableRows:        tableRows,
		edgesLoaded:          edgeCount,
		droppedNotLoaded:     len(edges) - edgeCount - dropMismatch - dropAbsent - dropExpired,
		droppedEndpointMiss:  dropAbsent,
		droppedEndpointGone:  dropExpired,
		droppedLabelMismatch: dropMismatch,
		droppedUnsafeID:      countUnsafeIDs(assets),
		reachRelsMismatched:  reachMismatched,
		byType:               byType,
		// verifiedExpiry records whether THIS build's expired/absent split rests
		// on a real ClickHouse verification, or degrades to "everything reads
		// absent" because verifyExpired was nil (LoadFromSnapshot's fast-boot
		// path). expiredShareStepChanges must never compare a verified build
		// against an unverified one: the unverified side's expired share is
		// artificially 0 by construction, not because expiry actually dropped.
		verifiedExpiry: verifyExpired != nil,
	}
	logEvent := logger.Info().Int("nodes", nodes).Int("edges", edgeCount).
		Int("dropped_not_loaded", stats.droppedNotLoaded).
		Int("dropped_endpoint_missing", stats.droppedEndpointMiss).
		Int("dropped_endpoint_expired", stats.droppedEndpointGone).
		Int("dropped_label_mismatch", stats.droppedLabelMismatch).
		Int("threads", threads)
	if stats.droppedUnsafeID > 0 {
		logger.Warn().Int("dropped_unsafe_id", stats.droppedUnsafeID).
			Msg("graphstore: assets whose id contains a pipe or line break were not loaded into Ladybug (the COPY format cannot carry them); their edges drop as endpoint-missing")
	}
	if over := stats.danglingOverBudget(); len(over) > 0 {
		// Warn, not Info: an edge type losing more of its rows to unknown ids than
		// the registry says to expect is either a producer emitting ids nothing
		// collects, or a load-set exclusion that should not be there.
		logger.Warn().Interface("edge_types_over_dangling_budget", over).
			Msg("graphstore: edge rows dropped because their endpoint is not in the inventory at all, above the budget declared in internal/graphschema — a producer is emitting ids nothing collects, or an endpoint type is being excluded from the graph that should not be")
	}
	if stats.droppedSecurityEdges() {
		// Warn, not Info: this is the signature of the label-mismatch bug class, and
		// it means blast radius and every Cypher traversal over these rels is
		// understated for this build.
		logger.Warn().Interface("reach_rels_label_mismatched", reachMismatched).
			Msg("graphstore: security-critical edges dropped at load because their endpoint carries a different node label than the rel declares — blast radius and attack-path queries are understated; fix the producer/rel label agreement")
	}
	logEvent.Msg("graphstore: bulk sync complete (COPY)")
	return stats, nil
}

// copyFrom issues a COPY <table> FROM "<path>" on the connection.
//
// PARALLEL=FALSE is required: Ladybug's parallel CSV reader does NOT correctly
// honor RFC-4180 quoting at scale — it splits quoted fields containing the
// delimiter across columns and rejects quoted newlines, both of which corrupt
// or abort the load. The serial reader parses quotes/commas/newlines
// correctly and still does the bulk CSR rel build, so it stays far faster
// than per-row UNWIND…MATCH…CREATE.
func copyFrom(conn *ladybug.Connection, table, path string) error {
	// Pipe delimiter: Ladybug's CSV reader (parallel and serial) does not honour
	// RFC-4180 quoting when the delimiter appears inside a quoted field — a
	// name containing a comma causes column-shift or abort with comma as
	// delimiter. Pipes never appear in AWS ARNs, resource names, IPs, k8s
	// names, or package identifiers, so DELIM='|' sidesteps the parser bug
	// without altering any stored values.
	res, err := conn.Query(fmt.Sprintf(`COPY %s FROM "%s" (HEADER=true, PARALLEL=false, DELIM='|')`, quoteLabel(table), csvQueryPath(path)))
	if err != nil {
		return err
	}
	res.Close()
	return nil
}

// nodeCSVFile is one label's open COPY staging file.
type nodeCSVFile struct {
	path string
	f    *os.File
	w    *csv.Writer
	rec  []string // reused record buffer, sized to the label's column count
	rows int
}

// nodeCSVSet writes node rows to one RFC-4180 CSV per label as they are produced,
// opening each file on its first row. Streaming is the point: the row set is
// never held in memory, so peak heap during a rebuild is the asset slice alone
// rather than the asset slice plus a full second copy of every node.
type nodeCSVSet struct {
	dir    string
	files  map[string]*nodeCSVFile
	labels []string // first-seen order, so COPY order is deterministic
}

func newNodeCSVSet(dir string) *nodeCSVSet {
	return &nodeCSVSet{dir: dir, files: map[string]*nodeCSVFile{}}
}

// write appends one row; vals must be in nodeCSVCols[label] order. It matches the
// emit signature streamNodeRows calls, and must not retain vals.
func (s *nodeCSVSet) write(label, _ string, vals []any) error {
	e := s.files[label]
	if e == nil {
		cols := nodeCSVCols[label]
		path := filepath.Join(s.dir, "node_"+label+".csv")
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		w := csv.NewWriter(f)
		w.Comma = '|' // pipe delimiter avoids Ladybug's quoted-comma parser bug
		if err := w.Write(cols); err != nil {
			_ = f.Close()
			return err
		}
		e = &nodeCSVFile{path: path, f: f, w: w, rec: make([]string, len(cols))}
		s.files[label] = e
		s.labels = append(s.labels, label)
	}
	if len(vals) != len(e.rec) {
		return fmt.Errorf("node %s: got %d values for %d columns", label, len(vals), len(e.rec))
	}
	for i, v := range vals {
		e.rec[i] = formatCSVValue(v)
	}
	if err := e.w.Write(e.rec); err != nil {
		return err
	}
	e.rows++
	return nil
}

// close flushes and closes every open file, returning the first error. A
// flush-on-close failure must not be swallowed, or COPY would read a truncated
// file.
func (s *nodeCSVSet) close() error {
	var firstErr error
	for _, label := range s.labels {
		e := s.files[label]
		e.w.Flush()
		if err := e.w.Error(); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := e.f.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// relLoadStats is the outcome of writing one rel table's CSV, split by WHY each
// unwritten row was dropped and broken down per edge_type.
type relLoadStats struct {
	written         int
	labelMismatch   int
	endpointAbsent  int
	endpointExpired int
	byType          map[string]edgeTypeLoad
}

// writeRelCSV writes rel rows whose FROM/TO endpoints both exist under the label
// the rel declares. Header is from,to,<prop cols>.
//
// nodeLabel is the id→label index of everything loaded into Ladybug, and answers
// both questions at once. A row whose endpoint carries a label other than the one
// the rel declares is a label mismatch — the rel table and the producer disagree
// about what the node is, and Ladybug drops the row with no error. A row whose
// endpoint is in nodeLabel not at all is simply dangling (a cross-account root
// principal, a resource outside the inventory) and is expected. Reporting the two
// as one number is what made the drop alarm fire on every build and therefore
// mean nothing.
//
// KNOWN LIMIT of that split — it can only see nodes that survived
// filterLadybugAssets. nodeLabel is built from the pruned asset set, so an endpoint
// that is BOTH mislabelled and pruned reads as endpointAbsent: the outcome
// operators are told not to alert on. A type that would otherwise hit this gap
// needs an entry in retentionEdgeTypes to stay visible as a mismatch instead.
//
// Not fixable here (the pre-prune type map is gone by this point) and deliberately
// not papered over, because the per-edge-type parity gauge covers it from the
// other side: a type whose rows all vanish reads as loaded=0 with fetched>0
// whichever bucket the drops land in. Anyone adding a type to retentionEdgeTypes
// is also tightening this detector.
func writeRelCSV(path string, spec relEndpoints, rr relRows, nodeLabel map[string]string, verifiedExpired map[string]bool) (stats relLoadStats, err error) {
	stats.byType = map[string]edgeTypeLoad{}
	record := func(i int, f func(*edgeTypeLoad)) {
		et := ""
		if i < len(rr.edgeTypes) {
			et = rr.edgeTypes[i]
		}
		l := stats.byType[et]
		f(&l)
		stats.byType[et] = l
	}

	f, err := os.Create(path)
	if err != nil {
		return stats, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	w := csv.NewWriter(f)
	w.Comma = '|' // pipe delimiter avoids Ladybug's quoted-comma parser bug
	header := append([]string{"from", "to"}, propCols(spec.prop)...)
	if err = w.Write(header); err != nil {
		return stats, err
	}
	rec := make([]string, len(header))
	for i, r := range rr.rows {
		src, _ := r["src"].(string)
		dst, _ := r["dst"].(string)
		if out := classifyRelEndpoints(spec, src, dst, verifiedExpired, nodeLabel); out != relRowLoads {
			switch out {
			case relRowLabelMismatch:
				stats.labelMismatch++
				record(i, func(l *edgeTypeLoad) { l.labelMismatch++ })
			case relRowEndpointExpired:
				stats.endpointExpired++
				record(i, func(l *edgeTypeLoad) { l.endpointExpired++ })
			default: // relRowEndpointAbsent
				stats.endpointAbsent++
				record(i, func(l *edgeTypeLoad) { l.endpointAbsent++ })
			}
			continue
		}
		rec[0], rec[1] = src, dst
		for j, p := range spec.prop {
			rec[2+j] = formatCSVValue(r[p.rowKey])
		}
		if err = w.Write(rec); err != nil {
			return stats, err
		}
		stats.written++
		record(i, func(l *edgeTypeLoad) { l.loaded++ })
	}
	w.Flush()
	return stats, w.Error()
}

func propCols(props []relProp) []string {
	cols := make([]string, len(props))
	for i, p := range props {
		cols[i] = p.col
	}
	return cols
}

// csvSanitizer strips characters that would break the pipe-delimited COPY files.
// Pipe is the field delimiter, so a literal | in a value would desync the column
// parser. Newlines/CRs are stripped for completeness (Ladybug rejects them even in
// serial mode). None of these characters are meaningful in node names or edge
// properties — replacing with a space is lossless for graph traversal.
var csvSanitizer = strings.NewReplacer("|", " ", "\r\n", " ", "\r", " ", "\n", " ")

// csvSafeID reports whether id survives the COPY files unchanged. An id that
// does not is never loaded (streamNodeRows skips it, so rel rows to it drop as
// endpoint-absent): sanitizing it like a property value would load a
// different id — one by-id lookups miss and that can collide with a real
// node's primary key — while writing it raw makes COPY abort the whole rebuild.
func csvSafeID(id string) bool { return !strings.ContainsAny(id, "|\r\n") }

// countUnsafeIDs counts the assets streamNodeRows will skip for csvSafeID.
func countUnsafeIDs(assets []asset.Asset) int {
	n := 0
	for i := range assets {
		if !csvSafeID(assets[i].ID) {
			n++
		}
	}
	return n
}

// formatCSVValue renders a row value for CSV. Numeric columns always carry a
// value (defaults are set during row building); strings may be empty.
func formatCSVValue(v any) string {
	switch n := v.(type) {
	case nil:
		return ""
	case string:
		return csvSanitizer.Replace(n)
	case int:
		return strconv.FormatInt(int64(n), 10)
	case int32:
		return strconv.FormatInt(int64(n), 10)
	case int64:
		return strconv.FormatInt(n, 10)
	case float64:
		return strconv.FormatFloat(n, 'g', -1, 64)
	case bool:
		if n {
			return "1"
		}
		return "0"
	default:
		return fmt.Sprintf("%v", n)
	}
}

// copyMinShmFreeBytes is the free-space floor on /dev/shm below which COPY
// staging falls back to the (disk-backed) OS temp dir. A container's default
// /dev/shm can be far smaller than the transient rel CSVs for a large graph;
// writing them to an undersized tmpfs fails with ENOSPC and wedges every
// rebuild in a retry loop. Requiring real headroom keeps the fast tmpfs path
// where /dev/shm is generously sized and falls back to disk (slower, but
// correct) where it is not.
const copyMinShmFreeBytes = 512 << 20 // 512 MiB

// copyTmpDir chooses the staging dir for the transient COPY CSVs. LADYBUG_COPY_TMPDIR
// overrides everything. Otherwise it prefers /dev/shm (tmpfs — the serialize→COPY
// round-trip never touches disk) ONLY when it exists and has enough free space;
// an undersized /dev/shm falls back to the OS temp dir so a rebuild can never
// wedge on ENOSPC.
func copyTmpDir() string {
	if d := os.Getenv("LADYBUG_COPY_TMPDIR"); d != "" {
		return d
	}
	if fi, err := os.Stat("/dev/shm"); err == nil && fi.IsDir() && shmHasHeadroom("/dev/shm") {
		return "/dev/shm"
	}
	return os.TempDir()
}

// shmHasHeadroom reports whether path has at least copyMinShmFreeBytes available.
// A statfs failure is treated as "no headroom" (fail-safe → use disk).
func shmHasHeadroom(path string) bool {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return false
	}
	return st.Bavail*uint64(st.Bsize) >= copyMinShmFreeBytes //nolint:gosec // Bsize is a small positive block size
}

// csvQueryPath normalizes a path for embedding in a COPY query string.
func csvQueryPath(p string) string { return p }
