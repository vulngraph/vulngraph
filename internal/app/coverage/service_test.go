package coverage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/checks"
)

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	require.NoError(t, err)
	return v
}

type fakeLive struct {
	facts LiveFacts
	err   error
}

func (f fakeLive) Facts(context.Context) (LiveFacts, error) { return f.facts, f.err }

// applicableKeys is every metadata key the real registry reads for a
// provider/type — computed, so these tests move with the registry instead of
// pinning a snapshot of it.
func applicableKeys(reg *checks.Registry, provider, assetType string) []string {
	var out []string
	for _, c := range reg.All() {
		if string(c.Provider) != provider || (c.AssetType != "" && c.AssetType != assetType) {
			continue
		}
		for _, k := range c.RequiredKeys {
			out = appendUnique(out, k)
		}
	}
	return out
}

// assertableKeyReadElsewhere finds a key the registry asserts on somewhere but
// not for this provider/type — the population of the check axis.
func assertableKeyReadElsewhere(reg *checks.Registry, provider, assetType string) string {
	local := map[string]bool{}
	for _, k := range applicableKeys(reg, provider, assetType) {
		local[k] = true
	}
	for _, c := range reg.All() {
		for _, k := range c.RequiredKeys {
			if !local[k] {
				return k
			}
		}
	}
	return ""
}

// bucketFacts builds a live picture in which aws/s3_bucket is fully collected,
// fully evidenced, fully asserted on and carries a scoring edge — i.e. covered.
// Each axis test then breaks exactly one thing.
func bucketFacts(reg *checks.Registry, assets uint64) LiveFacts {
	f := LiveFacts{
		Assets:    []TypeCount{{Provider: "aws", AssetType: "s3_bucket", Count: assets}},
		CheckOpen: map[string]uint64{},
		EdgeTotals: map[string]uint64{
			ScoringSeedEdgeTypes[0]: 1,
		},
		EdgesBySrc: []EdgeEndpointCount{
			{EdgeType: ScoringSeedEdgeTypes[0], EndpointType: "s3_bucket", Rows: 1, Distinct: 1},
		},
		Bands:     []BandSplit{{Source: "cspm", Type: "exposure", Open: 10}},
		Resources: []ResourceTypeCount{{Source: "cspm", Type: "exposure", ResourceType: "s3_bucket", Open: 10}},
		// The category's findings are attributed to the check that emits them.
		// Without this join the evidence rule answers for whatever check happens
		// to share the resource type.
		CategoryChecks: []CategoryCheck{
			{Source: "cspm", Type: "exposure", CheckID: "aws-s3-public-bucket", Open: 10},
		},
	}
	for _, k := range applicableKeys(reg, "aws", "s3_bucket") {
		f.Keys = append(f.Keys, KeyPresence{Provider: "aws", AssetType: "s3_bucket", Key: k, Assets: assets})
	}
	return f
}

func axisOf(t *testing.T, reg *checks.Registry, f LiveFacts) CategoryFact {
	t.Helper()
	cats := newIndex(reg, f, true).categoryFacts()
	require.Len(t, cats, 1)
	return cats[0]
}

func TestDeriveAxis_CoveredWhenNothingIsMissing(t *testing.T) {
	reg := checks.Default()
	c := axisOf(t, reg, bucketFacts(reg, 100))
	assert.Equal(t, AxisCovered, c.Axis, "because: %s", c.Because)
}

func TestDeriveAxis_CollectedWinsWhenTheAssetTypeIsEmpty(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 100)
	f.Assets = nil // the type has no rows at all
	c := axisOf(t, reg, f)
	assert.Equal(t, AxisCollected, c.Axis)
	assert.Contains(t, c.Because, "zero fresh assets")
	assert.Contains(t, c.Target, "collector")
}

func TestDeriveAxis_EvidenceWhenARequiredKeyIsThin(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 2000)
	// The s3 posture key present on a fraction of buckets: the shape that closed
	// many findings as "fixed" on assets that still exist and still lack it.
	for i := range f.Keys {
		if f.Keys[i].Key == "public" {
			f.Keys[i].Assets = 500
		}
	}
	c := axisOf(t, reg, f)
	assert.Equal(t, AxisEvidence, c.Axis)
	assert.Contains(t, c.Because, "`public`")
	assert.Contains(t, c.Because, "500 of 2000")
}

// Defect 1: the evidence rule used to scan every check sharing a resource type
// with the category, so the six categories carrying `github_repo` were all told
// to go emit `branch_protection` — including `iac_terraform /
// unreadable_tf_state`, which branch protection has nothing to do with.
func TestEvidenceRuleAnswersOnlyForChecksThatProduceTheCategory(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 2000)
	// A second check on the same asset type, with a key present on nobody. It
	// does not produce this category's findings, so it must not answer for it.
	for i := range f.Keys {
		if f.Keys[i].Key == "logging" {
			f.Keys[i].Assets = 0
		}
	}
	c := axisOf(t, reg, f)
	require.Equal(t, AxisCovered, c.Axis,
		"aws-s3-access-logging-disabled shares s3_bucket but emits nothing here: %s", c.Because)
	assert.NotContains(t, c.Target, "logging")

	// Attribute the category to that check and the same measurement now answers.
	f.CategoryChecks = append(f.CategoryChecks,
		CategoryCheck{Source: "cspm", Type: "exposure", CheckID: "aws-s3-access-logging-disabled", Open: 1})
	c = axisOf(t, reg, f)
	assert.Equal(t, AxisEvidence, c.Axis)
	assert.Contains(t, c.Because, "aws-s3-access-logging-disabled")
	assert.Contains(t, c.Because, "produces these findings")
}

// A category no registered check emits says the evidence axis does not apply,
// rather than borrowing an unrelated concern's check.
func TestCategoryWithNoRegisteredProducerSaysTheEvidenceAxisDoesNotApply(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 2000)
	for i := range f.Keys {
		if f.Keys[i].Key == "public" {
			f.Keys[i].Assets = 0
		}
	}
	f.CategoryChecks = []CategoryCheck{
		{Source: "cspm", Type: "exposure", CheckID: "CVE-2026-0001", Open: 10},
	}
	c := axisOf(t, reg, f)
	assert.Equal(t, AxisCovered, c.Axis)
	assert.Contains(t, c.Because, "the registry does not know")
	assert.Contains(t, c.Because, "evidence axis does not apply")
	assert.NotContains(t, c.Target, "must emit")
}

func TestCategoryWithNoCheckIDAtAllSaysSo(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 2000)
	f.CategoryChecks = nil
	c := axisOf(t, reg, f)
	assert.Equal(t, AxisCovered, c.Axis)
	assert.Contains(t, c.Because, "no open finding in this category carries a check_id")
}

// Defect 2: `ns_psa_enforce` is read ONLY to suppress the three k8s pod checks
// in PSA-privileged namespaces. It is absent on every pod by design, so a
// presence rule reported it as the worst evidence gap and advised the collector
// to emit it — which would switch those checks OFF where they fire today.
func TestSuppressorKeysAreNotEvidenceGaps(t *testing.T) {
	reg := checks.Default()
	c, ok := reg.ByID("k8s-privileged-container")
	require.True(t, ok)
	require.Contains(t, c.RequiredKeys, "ns_psa_enforce")

	evidence, suppressor := evidenceKeys(c, "k8s_pod")
	assert.Contains(t, suppressor, "ns_psa_enforce",
		"ns_psa_enforce only ever exempts the check; no value of it fires what its absence did not")
	assert.Contains(t, suppressor, "namespace",
		"a system namespace exempts the pod, so absence is already the most-firing case")
	assert.Equal(t, []string{"privileged"}, evidence,
		"privileged is the only key whose absence can hide a violation (phase only exempts finished pods)")
}

func TestSuppressorOnlyExemptionIsNotBlanket(t *testing.T) {
	reg := checks.Default()
	c, ok := reg.ByID("github-no-branch-protection")
	require.True(t, ok)
	evidence, suppressor := evidenceKeys(c, "github_repo")
	assert.Equal(t, []string{"branch_protection"}, evidence,
		"branch_protection absent genuinely hides violations — no repos carry it")
	assert.Equal(t, []string{"archived"}, suppressor,
		"absent `archived` correctly means not archived")
}

// The exemption must never be granted by accident. A predicate that cannot fire
// on a probe at all — because it also reads a structural asset field, or
// compares against a constant the probe values lack — proves nothing about its
// keys, and every one of them stays an evidence key.
func TestUnfirablePredicateExemptsNoKey(t *testing.T) {
	c := checks.Check{
		ID:           "test-unfirable",
		Provider:     asset.ProviderAWS,
		AssetType:    "lambda_function",
		RequiredKeys: []string{"public_access"},
		ProbeValues:  []string{"", "true", "false"},
		// Region is a structural field the probe never sets, so no metadata
		// assignment can make this fire.
		Violates: func(a asset.Asset) bool {
			return a.Region == "probe-unreachable" && a.Metadata["public_access"] == "true"
		},
	}
	require.False(t, firable(c, "lambda_function"))

	evidence, suppressor := evidenceKeys(c, "lambda_function")
	assert.Equal(t, c.RequiredKeys, evidence)
	assert.Empty(t, suppressor)
}

// A public-access check whose comparand is now a declared probe value can fire,
// so its keys are classified on evidence rather than all kept.
func TestPublicAccessCheckIsFirable(t *testing.T) {
	c, ok := checks.Default().ByID("aws-lambda-public-access")
	require.True(t, ok)
	require.True(t, firable(c, "lambda_function"))
}

// The whole-check consequence: a check whose gap is a suppressor reports the
// evidence key instead, and never advises emitting the suppressor.
func TestCheckFactWorstKeyIgnoresSuppressors(t *testing.T) {
	reg := checks.Default()
	f := LiveFacts{
		Assets:    []TypeCount{{Provider: "kubernetes", AssetType: "k8s_pod", Count: 60000}},
		CheckOpen: map[string]uint64{},
		Keys: []KeyPresence{
			{Provider: "kubernetes", AssetType: "k8s_pod", Key: "privileged", Assets: 60000},
			{Provider: "kubernetes", AssetType: "k8s_pod", Key: "namespace", Assets: 60000},
			{Provider: "kubernetes", AssetType: "k8s_pod", Key: "phase", Assets: 60000},
			// ns_psa_enforce: absent on every pod, by design.
		},
	}
	byID := map[string]CheckFact{}
	for _, c := range newIndex(reg, f, true).checkFacts() {
		byID[c.ID] = c
	}
	priv := byID["k8s-privileged-container"]
	assert.Contains(t, []string{"phase", "privileged"}, priv.WorstKey, "an evidence key, never the absent-by-design suppressor")
	assert.Equal(t, uint64(60000), priv.WorstKeyPresent)
	assert.InDelta(t, 1.0, priv.EvidenceBound(), 0.0001)
	assert.Contains(t, priv.RequiredKeys, "ns_psa_enforce", "the AST-derived list is unchanged")
}

func TestDeriveAxis_CheckWhenCollectedDataIsAssertedOnNowhere(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 100)
	key := assertableKeyReadElsewhere(reg, "aws", "s3_bucket")
	require.NotEmpty(t, key)
	f.Keys = append(f.Keys, KeyPresence{Provider: "aws", AssetType: "s3_bucket", Key: key, Assets: 100})
	c := axisOf(t, reg, f)
	assert.Equal(t, AxisCheck, c.Axis)
	assert.Contains(t, c.Because, key)
	assert.Contains(t, c.Target, "register a check")
}

func TestDeriveAxis_GraphWhenNoScoringEdgeReachesTheType(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 100)
	f.EdgesBySrc = nil // collected, evidenced, asserted on — and unreachable by the BFS
	c := axisOf(t, reg, f)
	assert.Equal(t, AxisGraph, c.Axis)
	assert.Contains(t, c.Because, "internet-hops BFS")
}

// A non-reach, non-seed edge must not satisfy the graph axis: row volume on a
// context edge has never meant scoring can reach the node.
func TestDeriveAxis_GraphIgnoresNonScoringEdges(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 100)
	f.EdgesBySrc = []EdgeEndpointCount{{EdgeType: "contains_data", EndpointType: "s3_bucket", Rows: 900, Distinct: 900}}
	c := axisOf(t, reg, f)
	assert.Equal(t, AxisGraph, c.Axis)
}

func TestDeriveAxis_CategoryWithNoResourceTypeIsCollected(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 100)
	f.Resources = nil
	c := axisOf(t, reg, f)
	assert.Equal(t, AxisCollected, c.Axis)
	assert.Contains(t, c.Because, "resource type")
}

// A fully-covered category whose remaining population the classifier WEIGHED
// (routine) is asking a prioritisation question, which coverage data cannot
// answer — so it must say "decision", not invent an engineering task.
func TestCoveredCategoryWithRoutineNeedsADecisionNotEngineering(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 100)
	f.Bands[0].Routine = 4
	c := axisOf(t, reg, f)
	require.Equal(t, AxisCovered, c.Axis)
	assert.True(t, c.NeedsDecision)
	assert.Contains(t, c.Target, "decision")
}

// The mirror case: a blank must_fix_class is the ABSENCE of a verdict. The
// classifier's fall-through is `routine`, so a blank means enrichment has not run
// on those rows (the enrich sweep closes that) or failed open on missing evidence
// — telling a human it is a product decision sends them nowhere.
func TestCoveredCategoryWithBlanksIsTheEnrichBacklogNotADecision(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 100)
	f.Bands[0].Blank = 4
	c := axisOf(t, reg, f)
	require.Equal(t, AxisCovered, c.Axis)
	assert.False(t, c.NeedsDecision)
	assert.Contains(t, c.Target, "enrich sweep")
}

func TestUnreadKeysExcludeKeysNoCheckAssertsOnAnywhere(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 100)
	f.Keys = append(f.Keys, KeyPresence{Provider: "aws", AssetType: "s3_bucket", Key: "arn_not_a_posture_key", Assets: 100})
	keys, total := newIndex(reg, f, true).unreadKeys()
	assert.Equal(t, 0, total, "a key nothing asserts on anywhere is descriptive metadata, not a gap")
	assert.Empty(t, keys)
}

func TestUnreadKeysReportTheCheckThatReadsThemElsewhere(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 100)
	key := assertableKeyReadElsewhere(reg, "aws", "s3_bucket")
	f.Keys = append(f.Keys, KeyPresence{Provider: "aws", AssetType: "s3_bucket", Key: key, Assets: 100})
	keys, total := newIndex(reg, f, true).unreadKeys()
	require.Equal(t, 1, total)
	require.Len(t, keys, 1)
	assert.Equal(t, key, keys[0].Key)
	assert.NotEmpty(t, keys[0].ReadBy)
}

func TestStageFactsMeasureEdgeEndpointsInBothDirections(t *testing.T) {
	reg := checks.Default()
	f := LiveFacts{
		Assets: []TypeCount{{Provider: "github", AssetType: "github_repo", Count: 3000}},
		EdgesBySrc: []EdgeEndpointCount{
			{EdgeType: "depends_on", EndpointType: "github_repo", Distinct: 1350},
			{EdgeType: "deploys_to", EndpointType: "github_repo", Distinct: 150},
		},
		EdgesByDst: []EdgeEndpointCount{
			{EdgeType: "defined_in", EndpointType: "github_repo", Distinct: 200},
		},
	}
	byName := map[string]StageFact{}
	for _, s := range newIndex(reg, f, true).stageFacts() {
		byName[s.Name] = s
	}
	assert.Equal(t, uint64(3000), byName["repos"].Count)
	assert.Equal(t, uint64(1350), byName["repos with an SBOM"].Count)
	assert.InDelta(t, 45.0, byName["repos with an SBOM"].Pct(), 0.1)
	assert.Equal(t, uint64(150), byName["repos linked to a runtime"].Count)
	assert.Equal(t, uint64(200), byName["repos owning an asset"].Count,
		"defined_in points resource → repo, so the repo side is the DESTINATION")
}

// Freshness is applied in SQL, so a stage counting an edge type filters on the
// endpoint type and nothing else — an endpoint filter that leaked would count
// the whole edge type and inflate the chain.
func TestStageCountsRespectTheEndpointFilter(t *testing.T) {
	reg := checks.Default()
	f := LiveFacts{
		EdgesBySrc: []EdgeEndpointCount{
			{EdgeType: "runs_package", EndpointType: "container_image", Distinct: 500},
			{EdgeType: "runs_package", EndpointType: "ec2_instance", Distinct: 0},
		},
	}
	byName := map[string]StageFact{}
	for _, s := range newIndex(reg, f, true).stageFacts() {
		byName[s.Name] = s
	}
	assert.Equal(t, uint64(500), byName["things with a package inventory"].Count)
	assert.Equal(t, uint64(0), byName["VMs with a package inventory"].Count,
		"the VM stage must not pick up container_image rows")
}

func TestBuildOfflineOmitsLiveSectionsButKeepsTheRegistry(t *testing.T) {
	svc := NewService(checks.Default(), nil, "../../..")
	r, err := svc.Build(context.Background())
	require.NoError(t, err)

	assert.False(t, r.Live)
	assert.Equal(t, ErrNoLiveData.Error(), r.LiveErr)
	assert.NotEmpty(t, r.Checks, "the registry half must survive without a connection")
	assert.NotEmpty(t, r.Edges)
	assert.NotEmpty(t, r.Sources)
	assert.Empty(t, r.Categories, "categories cannot be invented offline")
	assert.Empty(t, r.Stages)
	for _, c := range r.Checks {
		assert.False(t, c.EvidenceKnown, "offline evidence must read as unknown, never as zero")
	}
}

func TestBuildDegradesToOfflineWhenTheMeasurementFails(t *testing.T) {
	svc := NewService(checks.Default(), fakeLive{err: errors.New("clickhouse unreachable")}, "../../..")
	r, err := svc.Build(context.Background())
	require.NoError(t, err, "an unreachable cluster must not fail the generator")
	assert.False(t, r.Live)
	assert.Contains(t, r.LiveErr, "clickhouse unreachable")
	assert.NotEmpty(t, r.Checks)
}

func TestBuildRecordsPartialMeasurementFailures(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 100)
	f.QueryErrors = []string{"fresh edges: timeout"}
	svc := NewService(reg, fakeLive{facts: f}, "../../..")
	r, err := svc.Build(context.Background())
	require.NoError(t, err)
	assert.True(t, r.Live)
	assert.Contains(t, r.LiveErr, "fresh edges: timeout")
}

func TestCheckFactsCarryTheAstDerivedRequiredKeys(t *testing.T) {
	reg := checks.Default()
	r, err := NewService(reg, fakeLive{facts: bucketFacts(reg, 100)}, "../../..").Build(context.Background())
	require.NoError(t, err)

	byID := map[string]CheckFact{}
	for _, c := range r.Checks {
		byID[c.ID] = c
	}
	pub, ok := byID["aws-s3-public-bucket"]
	require.True(t, ok)
	assert.Equal(t, []string{"bpa_all_enabled", "public", "public_read", "public_write"}, pub.RequiredKeys)
	assert.False(t, pub.StructuralOnly())
	assert.Equal(t, uint64(100), pub.Applicable)
	assert.Equal(t, uint64(100), pub.WorstKeyPresent)
}

func TestEmptyAssetTypesAreTheCollectedAxisAtCheckGranularity(t *testing.T) {
	reg := checks.Default()
	r, err := NewService(reg, fakeLive{facts: bucketFacts(reg, 100)}, "../../..").Build(context.Background())
	require.NoError(t, err)
	assert.NotContains(t, r.EmptyAssetTypes, "s3_bucket")
	assert.Contains(t, r.EmptyAssetTypes, "ec2_instance", "every other targeted type has no rows in this fixture")
}

// A category no registered check produces must not be given a `check` verdict.
//
// checkRule works on resource TYPES, so for a source the registry knows nothing
// about — an external scanner, the OSV matcher, the CIEM engine — it reported
// whichever key on a shared type happened to be unread and blamed this category
// for it. That produced several verdicts over a large number of open findings,
// every one a category error (`instance_id` on ec2_instance blamed on GuardDuty,
// `version` on package blamed on supply_chain, and so on). The findings existing
// at all is proof something reads the data.
func TestCheckAxisDoesNotApplyToASourceWithNoRegisteredCheck(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 100)
	// An unread-but-assertable key on the shared resource type: exactly what used
	// to produce the spurious verdict.
	key := assertableKeyReadElsewhere(reg, "aws", "s3_bucket")
	require.NotEmpty(t, key)
	f.Keys = append(f.Keys, KeyPresence{Provider: "aws", AssetType: "s3_bucket", Key: key, Assets: 100})
	// The findings come from a check_id the registry does not know.
	f.CategoryChecks = []CategoryCheck{
		{Source: "cspm", Type: "exposure", CheckID: "some-external-scanner-rule", Open: 10},
	}
	c := axisOf(t, reg, f)
	assert.NotEqual(t, AxisCheck, c.Axis,
		"a category with no registered producer cannot fail the check axis on a key that belongs to another category's checks")
	assert.Equal(t, AxisCovered, c.Axis)
	assert.Contains(t, c.Because, "the registry does not know")
}

// The gate is "no registered producer", not "the evidence rule had something to
// say" — a category whose producers all decide on structural fields still earns
// a check verdict when collected data goes unasserted.
func TestCheckAxisStillAppliesWhenAProducerIsRegistered(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 100)
	key := assertableKeyReadElsewhere(reg, "aws", "s3_bucket")
	require.NotEmpty(t, key)
	f.Keys = append(f.Keys, KeyPresence{Provider: "aws", AssetType: "s3_bucket", Key: key, Assets: 100})
	c := axisOf(t, reg, f)
	assert.Equal(t, AxisCheck, c.Axis)
}

// The graph axis asks whether a type can RECEIVE a hop count, and which side of
// an edge delivers one depends on the mechanism. A type that is only ever a
// destination — a package inside an image — is scorable, and reading the source
// side alone said it was not.
func TestGraphAxisAcceptsAnInheritDestination(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 100)
	f.EdgesBySrc = nil
	f.EdgesByDst = []EdgeEndpointCount{
		{EdgeType: "runs_package", EndpointType: "s3_bucket", Rows: 5, Distinct: 5},
	}
	c := axisOf(t, reg, f)
	assert.NotEqual(t, AxisGraph, c.Axis,
		"a type that inherits its hop count as an Inherit destination is reachable by the BFS")
}

// The mirror: an InheritReverse SOURCE (a repo deploying to a workload) receives
// its hop count too. Without this the repo-reachability fix would not have moved
// a single row in the artifact that measures it.
func TestGraphAxisAcceptsAnInheritReverseSource(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 100)
	f.EdgesBySrc = []EdgeEndpointCount{
		{EdgeType: "deploys_to", EndpointType: "s3_bucket", Rows: 5, Distinct: 5},
	}
	c := axisOf(t, reg, f)
	assert.NotEqual(t, AxisGraph, c.Axis,
		"a type that inherits backwards along deploys_to is reachable by the BFS")
}

// And a reach edge delivers to its DESTINATION, not its source.
func TestGraphAxisAcceptsAReachDestination(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 100)
	f.EdgesBySrc = nil
	f.EdgesByDst = []EdgeEndpointCount{
		{EdgeType: "can_assume", EndpointType: "s3_bucket", Rows: 5, Distinct: 5},
	}
	c := axisOf(t, reg, f)
	assert.NotEqual(t, AxisGraph, c.Axis)
}

// evidenceRule must not cite whichever producer has the lowest raw evidence
// PERCENTAGE regardless of how many open findings it accounts for. A check
// with a thin denominator and a handful of open findings could otherwise
// out-rank a check carrying 400x its open volume, pointing the "Because" at
// the wrong check. The fixture gives aws-s3-public-bucket 5 open findings at
// 0.25% evidence and aws-s3-access-logging-disabled 2000 at 50%; the latter
// must be cited.
func TestEvidenceRulePrefersTheCheckWithMoreOpenFindingsOverTheWorstPercentage(t *testing.T) {
	reg := checks.Default()
	f := bucketFacts(reg, 2000)
	for i := range f.Keys {
		switch f.Keys[i].Key {
		case "public":
			f.Keys[i].Assets = 5 // thin: 0.25% evidence, but tiny open volume
		case "logging":
			f.Keys[i].Assets = 1000 // 50% evidence, but the real volume driver
		}
	}
	f.CategoryChecks = []CategoryCheck{
		{Source: "cspm", Type: "exposure", CheckID: "aws-s3-public-bucket", Open: 5},
		{Source: "cspm", Type: "exposure", CheckID: "aws-s3-access-logging-disabled", Open: 2000},
	}
	f.CheckOpen = map[string]uint64{
		"aws-s3-public-bucket":           5,
		"aws-s3-access-logging-disabled": 2000,
	}
	c := axisOf(t, reg, f)
	require.Equal(t, AxisEvidence, c.Axis)
	assert.Contains(t, c.Because, "aws-s3-access-logging-disabled",
		"the check accounting for 2000 of 2005 open findings must be cited, not the 5-finding check with the worse raw percentage: %s", c.Because)
	assert.NotContains(t, c.Because, "aws-s3-public-bucket")
}
