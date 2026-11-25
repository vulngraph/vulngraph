package explore

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/correlate"
	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// ── DSPM (Data Security) API ──────────────────────────────────────────────────
//
// Every number on the Data Security page is computed here, never assembled in
// the browser from raw Cypher rows: a security claim assembled in a React
// component has nowhere to hang a test. Each is a separate, named, tested
// number, because the obvious shapes are wrong:
//
//   - "exposed sensitive" and "public sensitive" must not be the SAME FACT
//     twice. Defining `exposed` as sensitive AND (exposed=1 OR public=1) makes
//     it a strict superset of `public`, so one number would show in two red
//     tiles and overstate the apparent exposure.
//   - The public count needs a tier filter, or tier-1 "possible" stores are
//     presented as public.
//   - The "unencrypted" count must not default an unobserved store to
//     encrypted, or it becomes a floor over only the store types whose
//     encryption is collected.
//
// The queries are deliberately GROUP BY aggregates with count(DISTINCT a): each
// asset lands in exactly one group per query, so a store carrying two data
// classes cannot be counted twice (row-by-row parsing would double-count it).

// dspmSensitiveWhere selects genuinely sensitive classes. `internal` is the floor
// every classified store receives, so it is not a finding.
const dspmSensitiveWhere = "dc.id <> 'dataclass:internal'"

// DSPM heuristic caveat, served with the payload so the UI cannot render a
// substring-derived classification as a scan result: the classifier reads
// resource names and tags, never file contents.
const (
	DSPMMethodHeuristic = "resource names and operator tags — no file contents are read"
	DSPMCaveat          = "Classifications are inferred from resource names and operator tags. Nothing here reads object contents, so an inferred class is a lead to verify, not a scan result."
)

// dspmAttrQuery counts sensitive stores by the attributes every exposure and
// encryption tile is built from. One row per (type, tier, exposed, encrypted)
// combination, so no asset is counted twice regardless of how many classes it
// carries.
const dspmAttrQuery = `MATCH (a:Asset)-[:ContainsData]->(dc:DataClass)
WHERE ` + dspmSensitiveWhere + `
RETURN a.type AS type, a.public_tier AS public_tier, a.exposed AS exposed,
       a.encrypted AS encrypted, count(DISTINCT a) AS n`

// dspmClassQuery counts stores per data class AND per classification confidence.
// The confidence column on the ContainsData rel is what makes an
// operator-confirmed tag distinguishable from a name guess.
const dspmClassQuery = `MATCH (a:Asset)-[r:ContainsData]->(dc:DataClass)
RETURN dc.id AS class, r.confidence AS confidence, a.type AS type,
       count(DISTINCT a) AS n`

// dspmTotalQuery counts every classified store by type (sensitive or not).
const dspmTotalQuery = `MATCH (a:Asset)-[:ContainsData]->(dc:DataClass)
RETURN a.type AS type, count(DISTINCT a) AS n`

// Public tiers, mirroring graphstore's Asset.public_tier column. Duplicated as
// ints because explore must not import graphstore (graphstore imports explore).
const (
	dspmTierNone      = 0
	dspmTierPossible  = 1
	dspmTierConfirmed = 2
	dspmTierUnknown   = 3
)

// Encryption states, mirroring graphstore's Asset.encrypted column.
const (
	dspmEncUnencrypted = 0
	dspmEncEncrypted   = 1
	dspmEncUnknown     = 2
)

// encryptionObservedTypes are the only classified store types (those the
// data_classification correlator gives ContainsData edges) whose encryption-at-rest
// is actually collected; RDS/DocumentDB/Neptune clusters carry it too but are never
// classified, so they never reach a DSPM count. The "unencrypted sensitive" tile
// is a measurement over these two types and nothing else; saying so is the
// difference between a count and a claim.
var encryptionObservedTypes = []string{"rds_instance", "s3_bucket"}

// DSPMStoreCounts is the classified-store population, split by what the
// classification actually rests on.
type DSPMStoreCounts struct {
	// Total is every store carrying a ContainsData edge, sensitive or not.
	Total int `json:"total"`
	// Sensitive is the actionable number: stores whose CONTENTS were inferred or
	// tagged sensitive. Excludes credential stores, which are sensitive by
	// resource type and are counted separately — a secrets-manager inventory is
	// not a data-classification result, and letting vault entries into this number
	// would bury the buckets and databases anyone can act on under a much larger
	// count of "sensitive stores".
	Sensitive int `json:"sensitive"`
	// SecretVault is credential stores by resource type (Secrets Manager, SSM
	// parameters, GCP Secret Manager). Counted, never hidden.
	SecretVault int `json:"secret_vault"`
	// Internal is stores with no sensitive class — the floor.
	Internal int `json:"internal"`
}

// DSPMConfidenceCounts splits sensitive data stores by how the class was reached.
type DSPMConfidenceCounts struct {
	// Asserted: an operator tag, or the resource type itself. Trustworthy.
	Asserted int `json:"asserted"`
	// Inferred: a resource-name pattern. A lead, not a finding.
	Inferred int `json:"inferred"`
	// Unknown: an edge with no confidence recorded. Reported rather than
	// silently folded into either bucket.
	Unknown int `json:"unknown"`
}

// DSPMExposureCounts separates the three genuinely different exposure facts,
// which must not be conflated.
type DSPMExposureCounts struct {
	// PublicConfirmed: a collector OBSERVED unauthenticated access (public bucket
	// policy or ACL). This is the number that deserves a red tile.
	PublicConfirmed int `json:"public_confirmed"`
	// PublicPossible: configuration permits exposure but nothing proved it — an
	// unlocked public-access-block, a network-reachable but credential-gated DB.
	PublicPossible int `json:"public_possible"`
	// PublicUnobserved: the collector could not read the exposure configuration at
	// all. A coverage gap to fix, NOT an exposure to remediate: never graded
	// "possible" or badged PUBLIC? on the strength of an AccessDenied.
	PublicUnobserved int `json:"public_unobserved"`
	// NetworkExposed: a graph ExposedToInternet PATH reaches this store. This is a
	// different measurement from Public (config) — which is the whole point: an
	// `exposed OR public` tile would be a superset of the public tile, one fact
	// shown twice.
	NetworkExposed int `json:"network_exposed"`
	// PublicOrExposed is the union, kept only so a caller that genuinely wants
	// "reachable somehow" does not recompute it wrongly. It is NOT a tile.
	PublicOrExposed int `json:"public_or_exposed"`
}

// DSPMEncryptionCounts is a three-state measurement with its own coverage stated.
type DSPMEncryptionCounts struct {
	// Unencrypted: OBSERVED to have no encryption at rest.
	Unencrypted int `json:"unencrypted"`
	// Encrypted: OBSERVED encrypted.
	Encrypted int `json:"encrypted"`
	// Unknown: never observed. Not an alarm and not a pass.
	Unknown int `json:"unknown"`
	// ObservedTypes names the store types whose encryption is collected at all.
	ObservedTypes []string `json:"observed_types"`
	// Coverage is Unencrypted+Encrypted over the sensitive population, as a
	// percentage — the honest denominator for the unencrypted count.
	CoveragePct int `json:"coverage_pct"`
}

// DSPMClassCount is one data class with its population and confidence split.
type DSPMClassCount struct {
	Class     string `json:"class"` // "pii", "financial", … (sentinel prefix stripped)
	Stores    int    `json:"stores"`
	Asserted  int    `json:"asserted"`
	Inferred  int    `json:"inferred"`
	Sensitive bool   `json:"sensitive"`
}

// DSPMSummary is the whole Data Security tile row, computed server-side.
type DSPMSummary struct {
	Stores     DSPMStoreCounts      `json:"stores"`
	Confidence DSPMConfidenceCounts `json:"confidence"`
	Exposure   DSPMExposureCounts   `json:"exposure"`
	Encryption DSPMEncryptionCounts `json:"encryption"`
	Classes    []DSPMClassCount     `json:"classes"`
	// Method and Caveat are served with the numbers so no client can render an
	// inference as a scan.
	Method string `json:"method"`
	Caveat string `json:"caveat"`
}

// DSPMSummaryFrom computes the summary from a CypherRunner. Split out from the
// handler so the whole calculation is unit-testable against canned rows — which
// is the point of moving it out of the browser.
func DSPMSummaryFrom(ctx context.Context, runner CypherRunner) (DSPMSummary, error) {
	out := DSPMSummary{
		Method: DSPMMethodHeuristic,
		Caveat: DSPMCaveat,
		Encryption: DSPMEncryptionCounts{
			ObservedTypes: encryptionObservedTypes,
		},
	}

	attr, err := runDSPMAggregate(ctx, runner, dspmAttrQuery)
	if err != nil {
		return out, fmt.Errorf("dspm attributes: %w", err)
	}
	for _, row := range attr.Rows {
		n := rowInt(row["n"])
		if n == 0 {
			continue
		}
		typ := rowString(row["type"])
		vault := correlate.IsSecretStoreType(typ)
		if vault {
			out.Stores.SecretVault += n
		} else {
			out.Stores.Sensitive += n
		}

		// Exposure and encryption tiles describe DATA STORES. A credential vault
		// entry has no bucket policy and no encryption config of its own, and
		// including it here is what let the exposure numbers drift.
		if vault {
			continue
		}
		switch rowInt(row["public_tier"]) {
		case dspmTierConfirmed:
			out.Exposure.PublicConfirmed += n
		case dspmTierPossible:
			out.Exposure.PublicPossible += n
		case dspmTierUnknown:
			out.Exposure.PublicUnobserved += n
		}
		exposed := rowInt(row["exposed"]) == 1
		public := rowInt(row["public_tier"]) == dspmTierConfirmed || rowInt(row["public_tier"]) == dspmTierPossible
		if exposed {
			out.Exposure.NetworkExposed += n
		}
		if exposed || public {
			out.Exposure.PublicOrExposed += n
		}
		switch rowInt(row["encrypted"]) {
		case dspmEncUnencrypted:
			out.Encryption.Unencrypted += n
		case dspmEncEncrypted:
			out.Encryption.Encrypted += n
		default:
			out.Encryption.Unknown += n
		}
	}

	total, err := runDSPMAggregate(ctx, runner, dspmTotalQuery)
	if err != nil {
		return out, fmt.Errorf("dspm totals: %w", err)
	}
	for _, row := range total.Rows {
		out.Stores.Total += rowInt(row["n"])
	}
	out.Stores.Internal = out.Stores.Total - out.Stores.Sensitive - out.Stores.SecretVault
	if out.Stores.Internal < 0 {
		out.Stores.Internal = 0
	}

	classes, err := runDSPMAggregate(ctx, runner, dspmClassQuery)
	if err != nil {
		return out, fmt.Errorf("dspm classes: %w", err)
	}
	byClass := map[string]*DSPMClassCount{}
	for _, row := range classes.Rows {
		n := rowInt(row["n"])
		if n == 0 {
			continue
		}
		key := strings.TrimPrefix(rowString(row["class"]), "dataclass:")
		c := byClass[key]
		if c == nil {
			c = &DSPMClassCount{Class: key, Sensitive: key != "internal"}
			byClass[key] = c
		}
		c.Stores += n
		asserted := rowString(row["confidence"]) == "high"
		inferred := rowString(row["confidence"]) == "medium"
		switch {
		case asserted:
			c.Asserted += n
		case inferred:
			c.Inferred += n
		}
		// The page-level confidence split describes the sensitive data-store
		// population only — the same scope as Stores.Sensitive.
		if key == "internal" || correlate.IsSecretStoreType(rowString(row["type"])) {
			continue
		}
		switch {
		case asserted:
			out.Confidence.Asserted += n
		case inferred:
			out.Confidence.Inferred += n
		default:
			out.Confidence.Unknown += n
		}
	}
	out.Classes = make([]DSPMClassCount, 0, len(byClass))
	for _, c := range byClass {
		out.Classes = append(out.Classes, *c)
	}
	sort.Slice(out.Classes, func(i, j int) bool {
		if out.Classes[i].Stores != out.Classes[j].Stores {
			return out.Classes[i].Stores > out.Classes[j].Stores
		}
		return out.Classes[i].Class < out.Classes[j].Class
	})

	observed := out.Encryption.Unencrypted + out.Encryption.Encrypted
	if denom := observed + out.Encryption.Unknown; denom > 0 {
		out.Encryption.CoveragePct = observed * 100 / denom
	}
	return out, nil
}

// dspmAggregateBudget is the row budget for the summary aggregates. The engine
// truncates SCALAR ROWS at MaxNodes as well as graph nodes (execCypher tests
// `len(rows) >= budget.MaxNodes`), so a small budget here would silently drop
// aggregate groups and undercount a tile — the exact failure mode this whole
// change exists to remove. Real cardinality is store types × tiers × exposure ×
// encryption ≈ 240; this leaves an order of magnitude of headroom, and a
// truncated result is treated as an error rather than reported as a count.
const dspmAggregateBudget = 2000

// runDSPMAggregate runs one summary aggregate and refuses to return a truncated
// one. A partial aggregate is a wrong security number, not a slightly stale one.
func runDSPMAggregate(ctx context.Context, runner CypherRunner, query string) (Result, error) {
	res, err := runner.RunCypher(ctx, query, dspmAggregateBudget, dspmAggregateBudget)
	if err != nil {
		return res, err
	}
	if res.Truncated {
		return res, fmt.Errorf("aggregate hit the %d-row budget — the result would undercount", dspmAggregateBudget)
	}
	return res, nil
}

// DSPMSummaryHandler serves GET /api/dspm/summary.
func (h *Handler) DSPMSummary(w http.ResponseWriter, r *http.Request) {
	if h.cypher == nil {
		errs.WriteHTTPError(w, errs.Internal("graph engine not available"))
		return
	}
	out, err := DSPMSummaryFrom(r.Context(), h.cypher)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("dspm summary failed")
		errs.WriteHTTPError(w, errs.Internal("dspm summary failed: "+err.Error()))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, out)
}

// ── Store worklist ────────────────────────────────────────────────────────────

// DSPMLens is one worklist filter. Server-side so the predicate behind each tile
// is the SAME expression the tile counted — the browser version had a Cypher
// query and a separate JS `matchesFilter` that could and did disagree.
type DSPMLens string

const (
	LensSensitive         DSPMLens = "sensitive"
	LensSecretVault       DSPMLens = "secret-vault"
	LensPublicConfirmed   DSPMLens = "public-confirmed"
	LensPublicPossible    DSPMLens = "public-possible"
	LensPublicUnobserved  DSPMLens = "public-unobserved"
	LensNetworkExposed    DSPMLens = "network-exposed"
	LensUnencrypted       DSPMLens = "unencrypted"
	LensEncryptionUnknown DSPMLens = "encryption-unknown"
	LensAll               DSPMLens = "all"
)

// dspmLensWhere is the WHERE fragment per lens. Vault entries are excluded from
// every data-store lens for the same reason they are excluded from the tiles.
var dspmLensWhere = map[DSPMLens]string{
	LensAll:               "",
	LensSensitive:         dspmSensitiveWhere + " AND NOT " + dspmVaultPredicate,
	LensSecretVault:       dspmSensitiveWhere + " AND " + dspmVaultPredicate,
	LensPublicConfirmed:   dspmSensitiveWhere + " AND NOT " + dspmVaultPredicate + " AND a.public_tier = 2",
	LensPublicPossible:    dspmSensitiveWhere + " AND NOT " + dspmVaultPredicate + " AND a.public_tier = 1",
	LensPublicUnobserved:  dspmSensitiveWhere + " AND NOT " + dspmVaultPredicate + " AND a.public_tier = 3",
	LensNetworkExposed:    dspmSensitiveWhere + " AND NOT " + dspmVaultPredicate + " AND a.exposed = 1",
	LensUnencrypted:       dspmSensitiveWhere + " AND NOT " + dspmVaultPredicate + " AND a.encrypted = 0",
	LensEncryptionUnknown: dspmSensitiveWhere + " AND NOT " + dspmVaultPredicate + " AND a.encrypted = 2",
}

// dspmVaultPredicate matches credential-store resource types.
var dspmVaultPredicate = vaultPredicate()

func vaultPredicate() string {
	types := correlate.SecretStoreTypes()
	quoted := make([]string, len(types))
	for i, t := range types {
		quoted[i] = "'" + t + "'"
	}
	return "(a.type IN [" + strings.Join(quoted, ", ") + "])"
}

// dspmStoresQuery builds the worklist for a lens.
//
// The ORDER BY is a CASE, not `a.public_tier DESC`. Tier 3 (unobserved) is
// numerically the largest but is the LEAST urgent — a raw DESC on the column
// would put every unreadable bucket above every confirmed-public one. The CASE
// ranks confirmed (2) above possible (1) above unobserved (3).
func dspmStoresQuery(lens DSPMLens, limit int) (string, error) {
	where, ok := dspmLensWhere[lens]
	if !ok {
		return "", fmt.Errorf("unknown lens %q", lens)
	}
	clause := ""
	if where != "" {
		clause = "\nWHERE " + where
	}
	return fmt.Sprintf(`MATCH (a:Asset)-[r:ContainsData]->(dc:DataClass)%s
RETURN a, r, dc
ORDER BY CASE a.public_tier WHEN 2 THEN 3 WHEN 1 THEN 2 WHEN 3 THEN 1 ELSE 0 END DESC,
         a.exposed DESC, a.encrypted ASC, a.score DESC
LIMIT %d`, clause, limit), nil
}

// DSPMStores serves GET /api/dspm/stores?lens=…&limit=…, returning the same
// {nodes, edges} shape as /api/graph/cypher so the worklist rendering is
// unchanged — only the predicate and the ranking move server-side.
func (h *Handler) DSPMStores(w http.ResponseWriter, r *http.Request) {
	if h.cypher == nil {
		errs.WriteHTTPError(w, errs.Internal("graph engine not available"))
		return
	}
	lens := DSPMLens(r.URL.Query().Get("lens"))
	if lens == "" {
		lens = LensSensitive
	}
	limit := 500
	query, err := dspmStoresQuery(lens, limit)
	if err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput(err.Error()))
		return
	}
	res, err := h.cypher.RunCypher(r.Context(), query, limit, limit)
	if err != nil {
		log.FromContext(r.Context()).Error().Err(err).Str("lens", string(lens)).Msg("dspm stores failed")
		errs.WriteHTTPError(w, errs.Internal("dspm stores failed: "+err.Error()))
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, res.NonNil())
}

// rowInt reads a numeric scalar out of a Cypher row. Ladybug/JSON round-trips
// integers as float64 or int64 depending on the path, and a wrong type here would
// silently zero a tile.
func rowInt(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case int32:
		return int(n)
	case int64:
		return int(n)
	case float64:
		return int(n)
	case float32:
		return int(n)
	}
	return 0
}

func rowString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
