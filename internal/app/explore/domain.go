// Package explore is the graph-query engine behind the Explore UI: a safe,
// bounded query contract (GraphQuerySpec) compiled into ClickHouse traversals
// over the asset graph, plus click-to-expand. Translate turns NL into a
// GraphQuerySpec for client review without running it. NL (POST /api/graph/nl)
// has the configured LLM provider write Cypher, checks it with
// graphquery.IsReadOnly, runs it within the hard node/edge caps, and returns
// the generated Cypher alongside the result.
package explore

import (
	"errors"
	"time"
)

// Direction is the edge direction a traversal step follows.
type Direction string

const (
	DirectionOut  Direction = "out"
	DirectionIn   Direction = "in"
	DirectionBoth Direction = "both"
)

// NodeMatch selects seed assets. Empty fields are wildcards; IDs (when set)
// take precedence over Types/Provider.
type NodeMatch struct {
	IDs      []string `json:"ids,omitempty"`
	Types    []string `json:"types,omitempty"`
	Provider string   `json:"provider,omitempty"`
}

// Traverse is one ordered hop expansion from the current frontier.
type Traverse struct {
	EdgeTypes []string  `json:"edge_types,omitempty"` // empty = any edge type
	Direction Direction `json:"direction,omitempty"`  // default "out"
	MaxHops   int       `json:"max_hops,omitempty"`   // default 1, clamped
}

// GraphQuerySpec is the safe, structured query contract. Produced by the UI
// builder, a DSL, or AI translation; compiled into parameterized ClickHouse.
type GraphQuerySpec struct {
	Seed     NodeMatch  `json:"seed"`
	Traverse []Traverse `json:"traverse,omitempty"`
	MaxNodes int        `json:"max_nodes,omitempty"`
	MaxEdges int        `json:"max_edges,omitempty"`
}

// Node.Encryption states.
const (
	EncryptionUnencrypted = "unencrypted"
	EncryptionEncrypted   = "encrypted"
	EncryptionUnknown     = "unknown"
)

// Node is a result node (an asset surfaced by the query). AccountID is the
// cloud ownership boundary (AWS account / GCP project / Azure subscription) —
// surfaced so the UI can cluster nodes by account ("products" grouping). The
// signal fields (Exposed…PrivescCount) are the per-asset security context
// projected onto the graph node so callers can filter/badge without a join.
type Node struct {
	ID           string `json:"id"`
	Type         string `json:"type"`
	Name         string `json:"name"`
	Provider     string `json:"provider"`
	Region       string `json:"region,omitempty"`
	AccountID    string `json:"account_id,omitempty"`
	Score        int    `json:"score,omitempty"`
	Exposed      bool   `json:"exposed,omitempty"`
	HasKEV       bool   `json:"has_kev,omitempty"`
	Exploitable  bool   `json:"exploitable,omitempty"`
	ToxicCombo   bool   `json:"toxic_combo,omitempty"`
	MaxScore     int    `json:"max_score,omitempty"`
	PrivescCount int    `json:"privesc_count,omitempty"`
	// Encryption is the Asset-only encryption-at-rest state: EncryptionUnencrypted,
	// EncryptionEncrypted, or EncryptionUnknown (never observed — every asset type
	// but S3 buckets, RDS instances and RDS/DocumentDB/Neptune clusters, and any of
	// those whose describe did not report it). Empty on labels that
	// carry no such column. A string rather than a bool so an unobserved store can
	// never serialise as encrypted. See graphstore.assetEncrypted.
	Encryption string `json:"encryption,omitempty"`
	// Public reports config-level public accessibility of a data store (public S3
	// bucket, publicly_accessible RDS, CloudSQL public IP) — distinct from Exposed
	// (a graph ExposedToInternet path). See graphstore.assetPublic.
	Public bool `json:"public,omitempty"`
	// PublicTier grades Public: 0 not public, 1 possible (S3 public-access-block
	// missing/unlocked but no public policy/ACL observed), 2 confirmed
	// (unauthenticated access per policy status / ACL, or publicly_accessible DB).
	// See graphstore.assetPublicTier.
	PublicTier int `json:"public_tier,omitempty"`
	// TrustEntry classifies WHO can assume an IAM role (inbound assumability,
	// from its trust policy): "public" (wildcard), "mixed", "federated" (IdP-only:
	// Okta/Identity Center/OIDC), "cross_account", "same_account", "service".
	// Empty for non-role nodes. See collect/aws trustEntryClass.
	TrustEntry string `json:"trust_entry,omitempty"`
	// InternetHops is the shortest attacker-movement distance from an internet-
	// exposed node to this one: 0 = directly exposed, 1–3 = transitively reachable,
	// -1 = not reachable from the internet (also the default for nodes without the
	// signal). Computed at graph rebuild (see graphstore reach.go).
	InternetHops int `json:"internet_hops,omitempty"`
}

// Edge is a result edge between two nodes.
type Edge struct {
	SrcID    string `json:"src_id"`
	DstID    string `json:"dst_id"`
	EdgeType string `json:"edge_type"`
	// Confidence is the rel's own `confidence` property when it has one — "high"
	// (asserted: an operator tag, or the resource type itself), "medium" (guessed
	// from a resource name), "low" (a default floor). Empty for rel tables that do
	// not carry it.
	//
	// It exists so a DSPM ContainsData classification is distinguishable at the
	// point of display. The correlator computed this for every classification and
	// the graph then dropped it, so an operator-confirmed `data-classification:
	// pii` tag and a bucket whose name merely contained "pii" looked identical in
	// the UI.
	Confidence string `json:"confidence,omitempty"`
}

// Result is a compiled query's output. Nodes/Edges carry graph-shaped results;
// Columns/Rows carry scalar/tabular results (aggregates like count/sum, or any
// RETURN of properties rather than whole nodes) so "how many …?" questions
// aren't silently dropped. A query populates one shape or the other.
type Result struct {
	Nodes     []Node           `json:"nodes"`
	Edges     []Edge           `json:"edges"`
	Truncated bool             `json:"truncated"` // hit the node/edge budget
	Columns   []string         `json:"columns"`   // scalar/tabular column order
	Rows      []map[string]any `json:"rows"`      // one entry per scalar result row
	// MultiHopMayBeIncomplete is set by the graph engine that answered: one of
	// its node tables is above one engine node group, so a multi-hop or
	// variable-length match in this query may have missed relationships
	// (GraphHealth.MultiHopMayBeIncomplete). Results that did not come from
	// the graph engine never set it.
	MultiHopMayBeIncomplete bool `json:"multi_hop_may_be_incomplete,omitempty"`
}

// NonNil guarantees the slices marshal as JSON arrays, never null. The OpenAPI
// contract (and the frontend) treat them as required arrays; a nil Go slice
// would serialize to null and crash array access on the client.
func (r Result) NonNil() Result {
	if r.Nodes == nil {
		r.Nodes = []Node{}
	}
	if r.Edges == nil {
		r.Edges = []Edge{}
	}
	if r.Columns == nil {
		r.Columns = []string{}
	}
	if r.Rows == nil {
		r.Rows = []map[string]any{}
	}
	return r
}

// GraphHealth is the graph engine's build state as the engine's owner reports
// it, read without running a query. Ready means a build completed and loaded at
// least one node. A zero LastBuiltAt means the graph was never built, never that
// it was built just now.
type GraphHealth struct {
	Ready       bool
	NodeCount   int64
	LastBuiltAt time.Time
	// NodeTablesMeasured is true once a loaded build recorded its per-table
	// row counts. OversizedNodeTables then names every node table holding more
	// rows than one engine node group, with its row count.
	NodeTablesMeasured  bool
	OversizedNodeTables map[string]int64
}

// MultiHopMayBeIncomplete reports whether multi-hop and variable-length
// matches on this graph can miss relationships: the pinned engine release
// does so once a node table exceeds one node group (ladybug#1341). known is
// false when no build's table sizes were recorded, which is unknown, not
// complete.
func (h GraphHealth) MultiHopMayBeIncomplete() (incomplete, known bool) {
	return len(h.OversizedNodeTables) > 0, h.NodeTablesMeasured
}

var (
	ErrInvalidSpec = errors.New("explore: invalid query spec")
	ErrNoSeed      = errors.New("explore: query must match at least one seed node")
	// ErrInvalidQuery matches every *QueryRejection: Cypher the engine (or the
	// read-only guard) refused to run. The caller's mistake, not a failure.
	ErrInvalidQuery = errors.New("explore: invalid graph query")
	// ErrQueryTimeout is a Cypher query that ran out of time in the engine.
	ErrQueryTimeout = errors.New("explore: graph query timed out")
)

// QueryRejection is a Cypher query the graph engine refused: a parse, binder
// or catalog error, or the read-only guard. Reason is the engine's message —
// it can quote the query, which is the caller's own input, so it is safe to
// return to that caller.
type QueryRejection struct{ Reason string }

func (e *QueryRejection) Error() string { return "explore: invalid graph query: " + e.Reason }

// Is makes errors.Is(err, ErrInvalidQuery) match any rejection.
func (e *QueryRejection) Is(target error) bool { return target == ErrInvalidQuery }
