package explore

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// dspmFake answers each of the three DSPM aggregates with canned rows, keyed by a
// distinctive fragment of the query. This is the whole reason the tile maths moved
// out of the browser: the numbers are now assertable.
type dspmFake struct {
	attr    []map[string]any
	classes []map[string]any
	total   []map[string]any
	err     error
	queries []string
}

func (f *dspmFake) RunCypher(_ context.Context, q string, _, _ int) (Result, error) {
	f.queries = append(f.queries, q)
	if f.err != nil {
		return Result{}, f.err
	}
	switch {
	case strings.Contains(q, "r.confidence"):
		return Result{Rows: f.classes}, nil
	case strings.Contains(q, "a.public_tier AS public_tier"):
		return Result{Rows: f.attr}, nil
	default:
		return Result{Rows: f.total}, nil
	}
}

// row builds one aggregate row with float64 counts — the shape a JSON round-trip
// produces, which rowInt must handle (an int-only reader would zero every tile).
func row(kv map[string]any) map[string]any { return kv }

// sampleShape is a synthetic population with the shape a large graph produces
// (vault entries far outnumbering data stores), with the graded data signals applied. It is the fixture for the tile assertions below.
func sampleShape() *dspmFake {
	return &dspmFake{
		attr: []map[string]any{
			// Credential vault entries: counted, but never in an exposure or
			// encryption tile.
			row(map[string]any{"type": "secretsmanager_secret", "public_tier": float64(0), "exposed": float64(0), "encrypted": float64(2), "n": float64(4000)}),
			row(map[string]any{"type": "ssm_parameter", "public_tier": float64(0), "exposed": float64(0), "encrypted": float64(2), "n": float64(500)}),
			row(map[string]any{"type": "gcp_secret", "public_tier": float64(0), "exposed": float64(0), "encrypted": float64(2), "n": float64(300)}),
			// Real data stores.
			row(map[string]any{"type": "s3_bucket", "public_tier": float64(2), "exposed": float64(1), "encrypted": float64(0), "n": float64(1)}),
			row(map[string]any{"type": "s3_bucket", "public_tier": float64(1), "exposed": float64(0), "encrypted": float64(1), "n": float64(20)}),
			row(map[string]any{"type": "s3_bucket", "public_tier": float64(3), "exposed": float64(0), "encrypted": float64(2), "n": float64(20)}),
			row(map[string]any{"type": "rds_instance", "public_tier": float64(0), "exposed": float64(0), "encrypted": float64(0), "n": float64(4)}),
			row(map[string]any{"type": "gcs_bucket", "public_tier": float64(0), "exposed": float64(0), "encrypted": float64(2), "n": float64(45)}),
			row(map[string]any{"type": "cloudsql_instance", "public_tier": float64(0), "exposed": float64(0), "encrypted": float64(2), "n": float64(10)}),
		},
		total: []map[string]any{
			row(map[string]any{"type": "s3_bucket", "n": float64(4000)}),
			row(map[string]any{"type": "secretsmanager_secret", "n": float64(4000)}),
			row(map[string]any{"type": "ssm_parameter", "n": float64(500)}),
			row(map[string]any{"type": "gcp_secret", "n": float64(300)}),
			row(map[string]any{"type": "gcs_bucket", "n": float64(300)}),
			row(map[string]any{"type": "rds_instance", "n": float64(50)}),
			row(map[string]any{"type": "cloudsql_instance", "n": float64(50)}),
		},
		classes: []map[string]any{
			row(map[string]any{"class": "dataclass:credentials", "confidence": "high", "type": "secretsmanager_secret", "n": float64(4000)}),
			row(map[string]any{"class": "dataclass:credentials", "confidence": "high", "type": "ssm_parameter", "n": float64(500)}),
			row(map[string]any{"class": "dataclass:credentials", "confidence": "high", "type": "gcp_secret", "n": float64(300)}),
			row(map[string]any{"class": "dataclass:financial", "confidence": "medium", "type": "s3_bucket", "n": float64(30)}),
			row(map[string]any{"class": "dataclass:pii", "confidence": "medium", "type": "s3_bucket", "n": float64(10)}),
			row(map[string]any{"class": "dataclass:pii", "confidence": "high", "type": "gcs_bucket", "n": float64(5)}),
			row(map[string]any{"class": "dataclass:internal", "confidence": "low", "type": "s3_bucket", "n": float64(3500)}),
		},
	}
}

func TestDSPMSummary_StorePopulationSplitsVaultFromDataStores(t *testing.T) {
	got, err := DSPMSummaryFrom(context.Background(), sampleShape())
	require.NoError(t, err)

	// The headline number. Thousands of credential-vault entries no longer masquerade as
	// classified data stores — they are counted, separately, as what they are.
	require.Equal(t, 4800, got.Stores.SecretVault)
	require.Equal(t, 1+20+20+4+45+10, got.Stores.Sensitive)
	require.Equal(t, 4000+4000+500+300+300+50+50, got.Stores.Total)
	require.Greater(t, got.Stores.Internal, 0)
	require.Equal(t, got.Stores.Total-got.Stores.Sensitive-got.Stores.SecretVault, got.Stores.Internal)
}

// TestDSPMSummary_ExposedAndPublicAreDifferentFacts is the regression guard for
// the duplicated tile: "exposed sensitive" and "public sensitive" showed the
// same fact, because exposed was defined as (exposed OR public) — a superset.
func TestDSPMSummary_ExposedAndPublicAreDifferentFacts(t *testing.T) {
	got, err := DSPMSummaryFrom(context.Background(), sampleShape())
	require.NoError(t, err)

	require.Equal(t, 1, got.Exposure.PublicConfirmed, "only observed unauthenticated access is confirmed")
	require.Equal(t, 20, got.Exposure.PublicPossible, "possible is its own number, not folded into public")
	require.Equal(t, 20, got.Exposure.PublicUnobserved, "unreadable exposure config is a coverage gap, not an exposure")
	require.Equal(t, 1, got.Exposure.NetworkExposed, "a graph exposure PATH — a different measurement from config-public")

	// The two tiles must not be able to show the same number by construction.
	require.NotEqual(t, got.Exposure.PublicConfirmed+got.Exposure.PublicPossible, got.Exposure.PublicOrExposed+1)
	require.Equal(t, 21, got.Exposure.PublicOrExposed, "the union is available but is not a tile")
}

// TestDSPMSummary_EncryptionIsThreeStateWithStatedCoverage guards the other
// direction of the encryption fix: unknowns must not become unencrypted either.
func TestDSPMSummary_EncryptionIsThreeStateWithStatedCoverage(t *testing.T) {
	got, err := DSPMSummaryFrom(context.Background(), sampleShape())
	require.NoError(t, err)

	require.Equal(t, 5, got.Encryption.Unencrypted, "observed negatives only")
	require.Equal(t, 20, got.Encryption.Encrypted)
	require.Equal(t, 75, got.Encryption.Unknown, "never observed — neither an alarm nor a pass")
	require.Equal(t, []string{"rds_instance", "s3_bucket"}, got.Encryption.ObservedTypes,
		"the tile is a measurement over these types and must say so")
	require.Equal(t, 25, got.Encryption.CoveragePct, "25 observed of 100 sensitive stores")
	require.Equal(t, got.Stores.Sensitive,
		got.Encryption.Unencrypted+got.Encryption.Encrypted+got.Encryption.Unknown,
		"every sensitive store lands in exactly one encryption state")
}

func TestDSPMSummary_ConfidenceSeparatesTagsFromGuesses(t *testing.T) {
	got, err := DSPMSummaryFrom(context.Background(), sampleShape())
	require.NoError(t, err)

	// Page-level split covers sensitive DATA stores only (vault entries excluded,
	// same scope as Stores.Sensitive).
	require.Equal(t, 5, got.Confidence.Asserted, "operator-tagged")
	require.Equal(t, 40, got.Confidence.Inferred, "name-pattern guesses")
	require.Equal(t, 0, got.Confidence.Unknown)

	byClass := map[string]DSPMClassCount{}
	for _, c := range got.Classes {
		byClass[c.Class] = c
	}
	require.Equal(t, 4800, byClass["credentials"].Stores)
	require.Equal(t, 4800, byClass["credentials"].Asserted)
	require.Equal(t, 15, byClass["pii"].Stores)
	require.Equal(t, 5, byClass["pii"].Asserted)
	require.Equal(t, 10, byClass["pii"].Inferred)
	require.True(t, byClass["pii"].Sensitive)
	require.False(t, byClass["internal"].Sensitive)
	// Sorted by population, descending.
	require.Equal(t, "credentials", got.Classes[0].Class)
}

// TestDSPMSummary_PreV53ConfidenceIsReportedNotGuessed: a snapshot written before
// the confidence column existed has an empty confidence, and that must surface as
// unknown rather than being counted as either asserted or inferred.
func TestDSPMSummary_PreV53ConfidenceIsReportedNotGuessed(t *testing.T) {
	f := sampleShape()
	f.classes = []map[string]any{
		row(map[string]any{"class": "dataclass:pii", "confidence": "", "type": "s3_bucket", "n": float64(9)}),
	}
	got, err := DSPMSummaryFrom(context.Background(), f)
	require.NoError(t, err)
	require.Equal(t, 9, got.Confidence.Unknown)
	require.Zero(t, got.Confidence.Asserted)
	require.Zero(t, got.Confidence.Inferred)
}

func TestDSPMSummary_CarriesTheHeuristicCaveat(t *testing.T) {
	got, err := DSPMSummaryFrom(context.Background(), sampleShape())
	require.NoError(t, err)
	require.Contains(t, got.Caveat, "not a scan result")
	require.Contains(t, got.Method, "no file contents are read")
}

// TestDSPMSummary_RefusesTruncatedAggregates: the engine truncates scalar ROWS at
// the node budget, so a small budget would silently drop aggregate groups. A
// partial aggregate is a wrong security number, not a stale one.
func TestDSPMSummary_RefusesTruncatedAggregates(t *testing.T) {
	f := &truncatingFake{}
	_, err := DSPMSummaryFrom(context.Background(), f)
	require.ErrorContains(t, err, "would undercount")
}

func TestDSPMSummary_BudgetHasHeadroom(t *testing.T) {
	f := sampleShape()
	_, err := DSPMSummaryFrom(context.Background(), f)
	require.NoError(t, err)
	require.Equal(t, 2000, dspmAggregateBudget,
		"a budget near the real cardinality (types x tiers x exposure x encryption) would truncate a tile")
}

func TestDSPMSummary_QueriesUseDistinctAssetCounts(t *testing.T) {
	f := sampleShape()
	_, err := DSPMSummaryFrom(context.Background(), f)
	require.NoError(t, err)
	require.Len(t, f.queries, 3)
	for _, q := range f.queries {
		require.Contains(t, q, "count(DISTINCT a)",
			"a store with two data classes must not be counted twice")
	}
}

type truncatingFake struct{}

func (truncatingFake) RunCypher(context.Context, string, int, int) (Result, error) {
	return Result{Rows: []map[string]any{{"n": float64(1)}}, Truncated: true}, nil
}

func TestDSPMSummaryHandler(t *testing.T) {
	h := NewHandler(nil, sampleShape())
	rec := httptest.NewRecorder()
	h.DSPMSummary(rec, httptest.NewRequest(http.MethodGet, "/api/dspm/summary", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var out DSPMSummary
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.Equal(t, 4800, out.Stores.SecretVault)
}

func TestDSPMSummaryHandler_NoEngine(t *testing.T) {
	h := NewHandler(nil, nil)
	rec := httptest.NewRecorder()
	h.DSPMSummary(rec, httptest.NewRequest(http.MethodGet, "/api/dspm/summary", nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestDSPMSummaryHandler_QueryError(t *testing.T) {
	h := NewHandler(nil, &dspmFake{err: errors.New("ladybug down")})
	rec := httptest.NewRecorder()
	h.DSPMSummary(rec, httptest.NewRequest(http.MethodGet, "/api/dspm/summary", nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

// TestDSPMStoresQuery_RanksConfirmedAboveUnobserved is the ordering fix. A raw
// `ORDER BY a.public_tier DESC` puts tier 3 (unobserved — the least urgent) on
// top, and the old client-side scorer had the inverse bug: it gave a *possible*
// bucket a higher risk bonus than a *confirmed* one, under a comment claiming the
// opposite.
func TestDSPMStoresQuery_RanksConfirmedAboveUnobserved(t *testing.T) {
	q, err := dspmStoresQuery(LensSensitive, 500)
	require.NoError(t, err)
	require.NotContains(t, q, "ORDER BY a.public_tier DESC",
		"a raw DESC on the tier column ranks unobserved above confirmed")
	require.Contains(t, q, "CASE a.public_tier WHEN 2 THEN 3 WHEN 1 THEN 2 WHEN 3 THEN 1 ELSE 0 END DESC")
}

func TestDSPMStoresQuery_LensPredicates(t *testing.T) {
	for lens, want := range map[DSPMLens]string{
		LensPublicConfirmed:   "a.public_tier = 2",
		LensPublicPossible:    "a.public_tier = 1",
		LensPublicUnobserved:  "a.public_tier = 3",
		LensNetworkExposed:    "a.exposed = 1",
		LensUnencrypted:       "a.encrypted = 0",
		LensEncryptionUnknown: "a.encrypted = 2",
	} {
		q, err := dspmStoresQuery(lens, 10)
		require.NoError(t, err, lens)
		require.Contains(t, q, want, lens)
		require.Contains(t, q, "dc.id <> 'dataclass:internal'", lens)
		require.Contains(t, q, "NOT (a.type IN [", string(lens)+" must exclude credential vaults")
	}

	// The vault lens is the only one that INCLUDES them.
	q, err := dspmStoresQuery(LensSecretVault, 10)
	require.NoError(t, err)
	require.NotContains(t, q, "NOT (a.type IN [")
	require.Contains(t, q, "(a.type IN [")

	// "all" has no WHERE at all — the raw classified inventory.
	all, err := dspmStoresQuery(LensAll, 10)
	require.NoError(t, err)
	require.NotContains(t, all, "WHERE")

	_, err = dspmStoresQuery(DSPMLens("nope"), 10)
	require.Error(t, err)
}

func TestDSPMStoresHandler_BadLens400(t *testing.T) {
	h := NewHandler(nil, sampleShape())
	rec := httptest.NewRecorder()
	h.DSPMStores(rec, httptest.NewRequest(http.MethodGet, "/api/dspm/stores?lens=bogus", nil))
	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestDSPMStoresHandler_DefaultsToSensitive(t *testing.T) {
	f := sampleShape()
	h := NewHandler(nil, f)
	rec := httptest.NewRecorder()
	h.DSPMStores(rec, httptest.NewRequest(http.MethodGet, "/api/dspm/stores", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, f.queries[0], "dc.id <> 'dataclass:internal'")
}

func TestRowInt(t *testing.T) {
	require.Equal(t, 5, rowInt(float64(5)))
	require.Equal(t, 5, rowInt(int64(5)))
	require.Equal(t, 5, rowInt(int32(5)))
	require.Equal(t, 5, rowInt(5))
	require.Equal(t, 0, rowInt("5"), "a string count must not be silently coerced")
	require.Equal(t, 0, rowInt(nil))
}
