package asset

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeMap_RoundTrip(t *testing.T) {
	m := map[string]string{"env": "prod", "team": "sec"}
	got := decodeMap(encodeMap(m))
	require.Equal(t, m, got)
}

func TestEncodeMap_Empty(t *testing.T) {
	require.Equal(t, "{}", encodeMap(nil))
	require.Equal(t, "{}", encodeMap(map[string]string{}))
}

// TestFirstDiscoveredAt_Floor pins the repo-level floor: a caller that never
// set FirstDiscoveredAt (a collector emitting a brand-new resource, a test, a
// future source) gets DiscoveredAt written instead of zero — writing zero
// would poison firstDiscoveredAtAgg's minIf-over-nonzero read and mean a
// genuinely-new asset has no recorded first observation until something else
// re-writes it. Mirrors finding.firstDetectedAt's own guard.
func TestFirstDiscoveredAt_Floor(t *testing.T) {
	discovered := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	require.Equal(t, discovered, firstDiscoveredAt(Asset{DiscoveredAt: discovered}),
		"unset FirstDiscoveredAt falls back to DiscoveredAt, never zero")

	pinned := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	require.Equal(t, pinned, firstDiscoveredAt(Asset{DiscoveredAt: discovered, FirstDiscoveredAt: pinned}),
		"an already-pinned FirstDiscoveredAt is never overwritten by the floor")
}

func TestDecodeMap_EmptyAndInvalid(t *testing.T) {
	require.Nil(t, decodeMap(""))
	require.Nil(t, decodeMap("{}"))
	require.Nil(t, decodeMap("not json"))
}

// TestClampExternalLimit pins ListExternal's outer ceiling by content, not just
// existence: a caller passing more than defaultExternalLimit is silently
// reduced to it, not errored. A caller passing 2000 and expecting it to take
// effect would silently get defaultExternalLimit=1000 instead, and without a
// test exercising the real repo method that mismatch goes unnoticed.
func TestClampExternalLimit(t *testing.T) {
	require.Equal(t, defaultExternalLimit, clampExternalLimit(0), "zero falls back to the default")
	require.Equal(t, defaultExternalLimit, clampExternalLimit(-5), "negative falls back to the default")
	require.Equal(t, defaultExternalLimit, clampExternalLimit(defaultExternalLimit+1000),
		"a caller asking for more than the ceiling is silently reduced to it, not errored")
	require.Equal(t, defaultExternalLimit, clampExternalLimit(defaultExternalLimit),
		"exactly the ceiling passes through unchanged")
	require.Equal(t, 500, clampExternalLimit(500), "anything under the ceiling passes through unchanged")
}

// TestNeverSyncTypes_ExcludesDeclaredK8sWorkload pins that the
// manifest-ingest intermediate is a correlate-only join input and must never
// become a Ladybug Asset node (graphstore.neverKeepTypes derives from this list).
func TestNeverSyncTypes_ExcludesDeclaredK8sWorkload(t *testing.T) {
	require.Contains(t, NeverSyncTypes, "declared_k8s_workload")
}

// TestNeverSyncTypes_ExcludesDeclaredCIAccess pins that the workflow-parse
// intermediate is a correlate-only join input and must never become a Ladybug
// Asset node (graphstore.neverKeepTypes derives from this list).
func TestNeverSyncTypes_ExcludesDeclaredCIAccess(t *testing.T) {
	require.Contains(t, NeverSyncTypes, "declared_ci_access")
}

// TestNeverSyncTypes_ExcludesGitHubHarvestIntermediates pins the fix for the one
// inconsistency in the declared_* family: declared_cloud_identity and
// declared_image_build are IaC/CI declarations exactly like the four above, but
// were the only ones missing from this list — so the graph never had them while
// the Assets page counted them as inventory. Both are consumed by correlate
// through its own load query, never through the Ladybug sync.
func TestNeverSyncTypes_ExcludesGitHubHarvestIntermediates(t *testing.T) {
	require.Contains(t, NeverSyncTypes, "declared_cloud_identity")
	require.Contains(t, NeverSyncTypes, "declared_image_build")
}

// TestNonInventoryTypesAreAllNeverSynced keeps the two exclusion lists from
// drifting apart in the direction that matters: anything we refuse to COUNT as
// inventory (because it is a declaration, not a resource) must also be refused
// as a graph node. The reverse does not hold — NeverSyncTypes also holds real
// resources (ebs_volume, vpc) that are graph noise but genuine inventory.
func TestNonInventoryTypesAreAllNeverSynced(t *testing.T) {
	for _, t2 := range NonInventoryTypes {
		require.Contains(t, NeverSyncTypes, t2,
			"%s is excluded from inventory as an IaC declaration, so it must not be a graph node either", t2)
	}
}

// TestNonInventoryTypesCoversEveryDeclaredProducer walks the collectors and
// requires every asset type they emit whose name starts with declared_ to be in
// NonInventoryTypes. A new IaC parser is the exact way this list goes stale: it
// lands with a collector, nobody touches asset/repo.go, and its parsed lines
// quietly become "assets we own" on the inventory page.
func TestNonInventoryTypesCoversEveryDeclaredProducer(t *testing.T) {
	declaredType := regexp.MustCompile(`Type:\s*"(declared_[a-z0-9_]+)"`)
	known := make(map[string]bool, len(NonInventoryTypes))
	for _, ty := range NonInventoryTypes {
		known[ty] = true
	}

	found := map[string]string{} // type -> file that emits it
	err := filepath.WalkDir("../../collect", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, m := range declaredType.FindAllStringSubmatch(string(b), -1) {
			found[m[1]] = path
		}
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, found, "found no declared_* producers at all — the walk or the pattern is broken, not the code")

	for ty, file := range found {
		require.True(t, known[ty],
			"%s emits asset type %q, which is an IaC declaration rather than a resource, "+
				"but it is not in NonInventoryTypes — the Assets page will count it as inventory "+
				"and double-count the real resource it declares", file, ty)
	}
}

// assetReadersRequiringLiveness are the UI-facing asset reads. Every one must
// apply EphemeralLivenessCond: asset rows stay until their 180-day TTL, so an
// ungated read of this ReplacingMergeTree reports corpses as inventory. Live
// before the gate: the Assets page reported many times more assets than nodes
// in the platform's own graph, built from the same table WITH the gate.
//
// This mirrors graphschema's TestGraphEdgesReadersApplyFreshness for edges.
var assetReadersRequiringLiveness = map[string]string{
	"assetSummary": assetSummary,
}

// livenessExemptAssetQueries are the query values in this package that read the
// assets table WITHOUT the liveness gate, each with a reason. A reader missing
// from both maps fails TestAssetReadersApplyLiveness.
var livenessExemptAssetQueries = map[string]string{
	"firstObservationsByIDs":     "history carry-forward for a new observation, not an inventory listing. It must retain dates from expired ephemeral rows when a resource reappears. TestObservationHistoryUsesNarrowReads checks the newest persisted date for a reappearing pod.",
	"blastAccountsByIDs":         "the account-only projection of the existing ByIDs detail read. It must preserve the same account assignment for every endpoint selected by the freshness-filtered blast walk, including historical detail rows. TestBlastAccountProjectionMatchesFullWalk pins this parity; this query does not list inventory or populate the native graph.",
	"retireAssetVersions":        "a conditional DELETE applying complete-enumeration proof to all stored versions, not an inventory reader",
	"retirementLastSeen":         "checks the latest observation against a deletion proof; includes every version to preserve resurrection",
	"insertAssets":               "an INSERT, not a read",
	"selectChangeLog":            "reads asset_change_log, a plain append-only audit log — not the assets table",
	"assetArgMaxSelect":          "the shared id-lookup SELECT prefix; the gate belongs to whichever reader composes it, and its two composers (selectAsset, ByIDs) are exempt below",
	"selectAsset":                "GetAsset is a by-id detail read. An asset page reached from a link, an alert or a finding must still render for a resource that has stopped being collected — that is exactly when an operator needs to see last_seen. Absence here would be a 404 that looks like the asset never existed.",
	"selectAssetByName":          "FindByExactName backs ResolveID, the same by-name detail read as selectAsset's by-id case — a finding's blast-radius resolution must still find a role that has stopped being collected, not silently treat it as absent.",
	"assetSelect":                "the shared row SELECT prefix. Its UI composer (listQuery) applies the gate — asserted directly below — and its sync composer (listAllForSyncQ) applies it too.",
	"externalAssetIDs":           "the scan target set, not a UI read. Gating it is a plausible improvement (scanning a deleted pod's address wastes work) but it changes what the scanner does, so it is deliberately out of this change.",
	"assetIDsByType":             "the OSV feed's per-type page — a background pipeline, not a UI read. Packages, its only real caller, are not an ephemeral type, so the gate would be a no-op for it.",
	"packageCoordsAfter":         "the advisory feeds' keyset package page; type='package' is never ephemeral, so the gate cannot change its result. Packages carry their own liveness gate instead (livePackageIDs, applied once per pass by ScanLivePackages).",
	"packageCount":               "the OSV staleness gauge's denominator over packages, which are never ephemeral; gated on package liveness (livePackageIDs) instead, pinned by TestPackageReadersGateOnLiveness.",
	"existingAssetIDs":           "answers 'does a row exist', deliberately without liveness. The dangling-finding sweep asks the liveness question through LiveIDs instead, which embeds the condition.",
	"providerHighWater":          "computes the high-water mark that liveness cutoffs are anchored to. Gating it on a cutoff derived from itself is circular.",
	"listAllForSyncQ":            "applies the gate; pinned separately by TestListAllForSyncAppliesEphemeralLiveness",
	"criticalEdgesQ":             "an edge query. Its `FROM assets` is a dst_id membership subquery over security_group, which is not an ephemeral type.",
	"liveAssetIDs":               "IS the liveness check (optimize.go); pinned by TestQueriesEmbeddingLivenessDoNotShadowItsColumns",
	"typeHighWater":              "computes a type's high-water mark — the input to the cutoff, same circularity as providerHighWater",
	"optimizeTable":              "an OPTIMIZE statement, not a read",
	"tableBaseStats":             "reads system.parts",
	"tableProjectionParts":       "reads system.projection_parts",
	"assetProviderDimensions":    "a connector-coverage health check over every stored row, not an inventory read.",
	"scopeStalenessByRegionType": "IS the per-connector absence measurement behind forget; gating on liveness would hide the absent rows it counts.",
	"purgeAccountCount":          "counts every row an admin-confirmed account purge will delete, dead or alive.",
	"purgeAccountDelete":         "an ALTER TABLE DELETE, not a read",
	"assetIDsByAccount":          "lists every id an account purge deletes, so their findings are resolved first; dead rows included on purpose.",
	"scopeCandidateIDs":          "selects confirmed-absent ids for forget; those are exactly the rows the liveness gate would exclude.",
}

// TestFilteredAssetReadersAvoidFINAL guards the cross-verification
// sweep finding: externalAssetIDs, assetIDsByType, and the package page query
// (now packageCoordsAfter) previously read
// `assets FINAL WHERE public_ip != ” / type = ?` — a filtered lookup on
// columns with no skip index, forcing a full unindexed dedup-merge scan of the
// whole table on every correlate sweep / OSV feed page (the same CPU-saturation
// class documented on assetSelect above, on two more queries). FINAL is only safe for a genuine
// full-table read (assetSelect); any predicate on an unindexed
// column must use the argMax+HAVING form instead.
func TestFilteredAssetReadersAvoidFINAL(t *testing.T) {
	for name, q := range map[string]string{
		"externalAssetIDs":   externalAssetIDs,
		"assetIDsByType":     assetIDsByType,
		"packageCoordsAfter": packageCoordsAfter,
	} {
		require.NotContains(t, q, "FINAL",
			"%s filters on an unindexed column and must not use FINAL — see assetArgMaxSelect's argMax+GROUP BY pattern", name)
	}
}

// TestAssetReadersApplyLiveness is the regression guard for the bug this file's
// inventoryReadCond fixes: EphemeralLivenessCond existed, was applied on every
// write-side/graph-side path, and was applied by NOTHING the UI read.
//
// Three assertions, in increasing order of how much they would have caught:
//  1. the declared UI readers contain the condition;
//  2. listQuery contains it for EVERY filter combination, cursor page included;
//  3. every named query declaration in a non-test file of this package that
//     reads the assets table (FROM assets or JOIN assets) either contains the
//     condition or a predicate that carries it, or is exempt with a reason.
//     The check is textual: it sees that the predicate is present, not where
//     in the query it applies. A query written inline as a call argument is
//     not seen; package-level query declarations are the convention (CLAUDE.md).
func TestAssetReadersApplyLiveness(t *testing.T) {
	for name, q := range assetReadersRequiringLiveness {
		require.Contains(t, q, EphemeralLivenessCond,
			"%s is a UI-facing asset read and must exclude dead ephemeral resources", name)
		require.Contains(t, q, "declared_cloud_identity",
			"%s must exclude the IaC declaration types from inventory (inventoryReadCond)", name)
	}

	// The inventory list, across the filter matrix. The cursor page is included on
	// purpose: the WHERE/AND branch it used to need is where this reader has
	// already been broken once.
	cursor := EncodeCursor(Asset{ID: "i-abc", LastSeen: time.Unix(1_700_000_000, 0).UTC()})
	for _, f := range []Filter{
		{},
		{Provider: "aws"},
		{Type: "k8s_pod"},
		{Region: "eu-west-1", AccountID: "1234"},
		{Search: "prod"},
		{Exposed: true},
		{MinScore: 70},
		{Cursor: cursor},
		{Provider: "aws", Type: "k8s_pod", Search: "prod", Exposed: true, MinScore: 70, Cursor: cursor},
	} {
		q, _, err := listQuery(f)
		require.NoError(t, err)
		require.Contains(t, q, EphemeralLivenessCond,
			"listQuery(%+v) reads inventory without the liveness gate", f)
		require.Contains(t, q, "declared_cloud_identity",
			"listQuery(%+v) counts IaC declarations as inventory", f)
		// Exactly one top-level WHERE, attached to the table. (" WHERE " also occurs
		// inside the gate's own high-water subquery, so counting the keyword is not
		// the assertion — the shape is.)
		require.Contains(t, q, "FROM asset_current_with_derivations WHERE ",
			"listQuery(%+v) must open its predicate with WHERE: %s", f, q)
		require.NotContains(t, q, "asset_current_with_derivations AND",
			"listQuery(%+v) produced `assets FINAL AND (...)` — invalid SQL: %s", f, q)
	}

	// Every asset-table query in every non-test file of the package is
	// accounted for.
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		b, err := os.ReadFile(file)
		require.NoError(t, err)
		if !readsAssetsTable.Match(b) {
			continue
		}
		for name, decl := range namedQueryDecls(t, file) {
			if !readsAssetsTable.MatchString(decl) {
				continue
			}
			// Gated either by embedding the SQL directly or by composing one of the
			// two shared predicates that carry it.
			if strings.Contains(decl, EphemeralLivenessCond) ||
				strings.Contains(decl, "EphemeralLivenessCond") ||
				strings.Contains(decl, "inventoryReadCond") {
				continue
			}
			if reason, ok := livenessExemptAssetQueries[name]; ok {
				t.Logf("exempt: %s (%s)", name, reason)
				continue
			}
			require.Failf(t, "ungated asset reader",
				"%s (%s) queries the assets table without EphemeralLivenessCond. Asset rows are "+
					"kept until their 180-day TTL, so an ungated read reports deleted resources as inventory. "+
					"Apply inventoryReadCond, or add %q to livenessExemptAssetQueries with a reason.",
				name, file, name)
		}
	}
}

// readsAssetsTable matches SQL that reads the assets table, as the FROM table
// or as a JOIN operand.
var readsAssetsTable = regexp.MustCompile(`\b(?:FROM|JOIN)\s+(?:assets|asset_current_with_derivations|asset_versions_with_derivations)\b`)

// namedQueryDecls returns, for one source file in this package, each named
// declaration whose value contains a raw-string literal, mapped to that
// declaration's SOURCE text (literals, the identifiers it concatenates, and its
// comment tail up to the next blank line).
//
// Source text, not the evaluated SQL: a query that composes inventoryReadCond
// holds the gate as an IDENTIFIER, so a scan of literal contents alone would
// report the correctly-gated readers as ungated. Textual on purpose — the point
// is to notice a query someone ADDS, which no reflective enumeration of package
// consts can do.
func namedQueryDecls(t *testing.T, file string) map[string]string {
	t.Helper()
	b, err := os.ReadFile(file)
	require.NoError(t, err)
	src := string(b)

	// name = `…  /  var name = `…  /  name = fmt.Sprintf(`…
	decl := regexp.MustCompile("(\\w+)\\s*=\\s*(?:fmt\\.Sprintf\\()?\\s*`")
	out := map[string]string{}
	for _, loc := range decl.FindAllStringSubmatchIndex(src, -1) {
		name := src[loc[2]:loc[3]]
		// The declaration runs to the next blank line; every query in this package is
		// separated from the next by one (a doc comment always follows).
		end := strings.Index(src[loc[0]:], "\n\n")
		if end < 0 {
			end = len(src) - loc[0]
		}
		out[name] += src[loc[0] : loc[0]+end]
	}
	require.NotEmpty(t, out, "%s: found no named query declarations — the pattern is broken, not the code", file)
	return out
}
