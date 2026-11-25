package enrich

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// A fleet-canonical package finding is capped below page even over its KEV
// floor: the fleets page per fleet, so ten fleets are ten pages, not eleven.
// No other ceiling may breach a page floor.
func TestAggregate_RootCauseCapsBelowPageOverAPageFloor(t *testing.T) {
	kev := Factor{Source: sourceKEV, Points: 30, Floor: ThresholdPage}
	base := Factor{Source: sourceBaseSeverity, Points: 40}

	s := Aggregate([]Factor{kev, base, {Source: "supply_chain_exposure", RootCause: true}})
	assert.Equal(t, uint8(ThresholdPage-1), s.Value)
	assert.Equal(t, BandHigh, s.Band)

	s = Aggregate([]Factor{kev, base, {Source: "hygiene_ceiling", Ceiling: ThresholdPage}})
	assert.Equal(t, BandPage, s.Band, "an ordinary ceiling still never beats a page floor")
}

func TestSupplyChainExposure_FleetCanonicalFactorIsRootCause(t *testing.T) {
	pkg := "pkg:deb/ubuntu/openssl@3.0.2"
	f := finding.Finding{ID: "pkg-f", Source: "supply_chain", ResourceType: "package", ResourceID: pkg, CheckID: "CVE-1", KnownExploited: true}
	g := fakeLineage{into: map[string][]asset.Edge{pkg: {{SrcID: "i-a", SrcType: "ec2_instance", DstID: pkg, EdgeType: "runs_package"}}}}
	fleets := fakeFleetLister{findings: []finding.Finding{{ID: "fl", Source: "vm_vuln", CheckID: "CVE-1",
		Metadata: map[string]string{"package_finding_id": "pkg-f", "affected_instances": "1"}}}}
	factor, applied, err := SupplyChainExposure{Graph: g, Fleets: fleets}.Evaluate(context.Background(), f)
	require.NoError(t, err)
	require.True(t, applied)
	require.True(t, factor.RootCause)

	score := Aggregate([]Factor{factor, {Source: sourceKEV, Points: 30, Floor: ThresholdPage}, {Source: sourceBaseSeverity, Points: 30}})
	require.NotEqual(t, BandPage, score.Band, "the fleets page; the package copy must not")
}

// manyVMs is a package installed on n VMs, where only the LAST one is exposed —
// the one a capped walk never visits.
func manyVMs(pkg string, n int) fakeLineage {
	g := fakeLineage{into: map[string][]asset.Edge{}, from: map[string][]asset.Edge{}}
	for i := range n {
		id := fmt.Sprintf("i-%04d", i)
		g.into[pkg] = append(g.into[pkg], asset.Edge{SrcID: id, SrcType: "ec2_instance", DstID: pkg, EdgeType: "runs_package"})
	}
	last := fmt.Sprintf("i-%04d", n-1)
	g.from[last] = []asset.Edge{{SrcID: last, DstID: "internet", EdgeType: "exposed_to_internet"}}
	return g
}

// A capped lineage walk that found no exposure is a sample. It reports
// truncated, and the classifier never stamps "contained" on it.
func TestSupplyChain_TruncatedWalkNeverContained(t *testing.T) {
	pkg := "pkg:deb/ubuntu/glibc@2.35"
	deployed, exposed, truncated, err := SupplyChainExposure{Graph: manyVMs(pkg, maxSupplyChainVMs+1)}.PackageDeployExposure(context.Background(), pkg)
	require.NoError(t, err)
	require.True(t, deployed)
	require.False(t, exposed, "the exposed VM is past the cap")
	require.True(t, truncated)

	_, _, truncated, err = SupplyChainExposure{Graph: manyVMs(pkg, maxSupplyChainVMs)}.PackageDeployExposure(context.Background(), pkg)
	require.NoError(t, err)
	require.False(t, truncated, "a walk that fit under the cap is a measurement")

	f := finding.Finding{Source: "supply_chain", ResourceType: "package", ResourceID: pkg}
	class, _ := assessSupplyChainMustFix(context.Background(), f, fakeSupplyChainReach{anyDeployed: true, truncated: true}, nil)
	assert.Empty(t, class, "a truncated walk must not demote to contained")
	class, _ = assessSupplyChainMustFix(context.Background(), f, fakeSupplyChainReach{anyDeployed: true}, nil)
	assert.Equal(t, MustFixContained, class, "a complete negative walk still contains")

	code := finding.Finding{Source: "ghas_code_scanning", ResourceType: "github_repo", ResourceID: "org/app"}
	class, _ = assessGHASCodeScanningMustFix(context.Background(), code, fakeSupplyChainReach{repoDeployed: true, repoTruncated: true})
	assert.Empty(t, class)
}

// KEV and malicious packages are never contained, whatever the deploy walk said.
func TestSupplyChain_KEVAndMaliciousNeverContained(t *testing.T) {
	notExposed := fakeSupplyChainReach{anyDeployed: true}
	kev := finding.Finding{Source: "supply_chain", ResourceType: "package", ResourceID: "pkg:npm/x@1", KnownExploited: true}
	class, reason := assessSupplyChainMustFix(context.Background(), kev, notExposed, fakeReach{hops: reachNone, ok: true})
	assert.Equal(t, MustFixElevated, class)
	assert.Contains(t, reason, "KEV")

	mal := finding.Finding{Source: "supply_chain", ResourceType: "package", ResourceID: "pkg:npm/y@1", CheckID: "MAL-2026-1"}
	class, _ = assessSupplyChainMustFix(context.Background(), mal, notExposed, nil)
	assert.Equal(t, MustFixElevated, class)

	// No deployment evidence at all: no claim either way, KEV or not.
	class, _ = assessSupplyChainMustFix(context.Background(), kev, fakeSupplyChainReach{}, nil)
	assert.Empty(t, class)
}

func TestIsTestModeCredential_WholeToken(t *testing.T) {
	secret := func(id string) finding.Finding { return finding.Finding{Source: "ghas_secrets", CheckID: id} }
	assert.True(t, isTestModeCredential(secret("stripe_test_secret_key")))
	assert.True(t, isTestModeCredential(secret("Stripe-Test-API-Key")))
	assert.False(t, isTestModeCredential(secret("testrail_api_key")), "a provider named *test* issues live keys")
	assert.False(t, isTestModeCredential(secret("stripe_api_key")))
	assert.False(t, isTestModeCredential(finding.Finding{Source: "nuclei", CheckID: "test_template"}), "only secrets have a test mode")
}

// The signal floor and the must-fix class agree on a test-mode key: floored
// into reasoning, not the actionable band it used to share with "contained".
func TestSignalFloor_TestModeSecretNotActionable(t *testing.T) {
	live := finding.Finding{Source: "ghas_secrets", CheckID: "stripe_secret_key", Severity: finding.SeverityHigh}
	test := live
	test.CheckID = "stripe_test_secret_key"
	assert.Equal(t, ThresholdHigh, signalFloor(live))
	assert.Equal(t, ThresholdPipeline, signalFloor(test))
}

// A key GitHub's validity check reports inactive is floored like a test-mode
// key (it is contained); unknown or absent validity is never read as inactive.
func TestSignalFloor_InactiveSecretNotActionable(t *testing.T) {
	withValidity := func(v string) finding.Finding {
		return finding.Finding{Source: "ghas_secrets", CheckID: "stripe_secret_key", Severity: finding.SeverityHigh,
			Metadata: map[string]string{finding.SecretValidityKey: v}}
	}
	assert.Equal(t, ThresholdPipeline, signalFloor(withValidity(finding.SecretValidityInactive)))
	assert.Equal(t, ThresholdHigh, signalFloor(withValidity(finding.SecretValidityActive)))
	assert.Equal(t, ThresholdHigh, signalFloor(withValidity(finding.SecretValidityUnknown)))
	assert.Equal(t, ThresholdHigh, signalFloor(withValidity("")))
}

func TestRootCauseKEV(t *testing.T) {
	rc := func(kev string) finding.Finding {
		return finding.Finding{Source: baseImageSource, CheckID: baseImageRootCauseID, Metadata: map[string]string{"base_layer_kev": kev}}
	}
	factor, applied, err := RootCauseKEV{}.Evaluate(context.Background(), rc("2"))
	require.NoError(t, err)
	require.True(t, applied)
	assert.Equal(t, ThresholdPage, factor.Floor)
	for _, kev := range []string{"0", "", "x"} {
		_, applied, _ = RootCauseKEV{}.Evaluate(context.Background(), rc(kev))
		assert.False(t, applied, "base_layer_kev=%q", kev)
	}
	_, applied, _ = RootCauseKEV{}.Evaluate(context.Background(), finding.Finding{Source: "supply_chain", Metadata: map[string]string{"base_layer_kev": "3"}})
	assert.False(t, applied)
}

func TestAlertCarrier(t *testing.T) {
	ctx := context.Background()
	osPkg := "pkg:deb/debian/openssl@3.0.11"
	appPkg := "pkg:npm/lodash@4.17.15"
	pkgFinding := func(purl string) finding.Finding {
		return finding.Finding{ID: "pkg-f", Source: "supply_chain", ResourceType: "package", ResourceID: purl, CheckID: "CVE-1"}
	}
	img := func(purl, id string) asset.Edge {
		return asset.Edge{SrcID: id, SrcType: "container_image", DstID: purl, EdgeType: "runs_package"}
	}
	rootCauseAt := func(ids, running string, band Band) finding.Finding {
		return finding.Finding{ID: "rc-debian", Source: baseImageSource, CheckID: baseImageRootCauseID, ScoreBand: string(band),
			Metadata: map[string]string{"affected_image_ids": ids, "running_images": running}}
	}
	rootCause := func(ids, running string) finding.Finding { return rootCauseAt(ids, running, BandPage) }
	covered := fakeFleetLister{findings: []finding.Finding{rootCause("img-a,img-b", "2")}}

	tests := []struct {
		name    string
		purl    string
		runners []asset.Edge
		fleets  fakeFleetLister
		want    string
		band    Band // the member's band; zero = page
	}{
		{"base-layer package on covered images", osPkg, []asset.Edge{img(osPkg, "img-a"), img(osPkg, "img-b")}, covered, "base-image root cause rc-debian", ""},
		{"an image on no identified base", osPkg, []asset.Edge{img(osPkg, "img-a"), img(osPkg, "img-z")}, covered, "", ""},
		{"application-layer package: a rebuild does not fix it", appPkg, []asset.Edge{img(appPkg, "img-a")}, covered, "", ""},
		{"capped root-cause listing", osPkg, []asset.Edge{img(osPkg, "img-a")}, fakeFleetLister{findings: []finding.Finding{rootCause("img-a", "60")}}, "", ""},
		{"a repo also depends on it", osPkg, []asset.Edge{img(osPkg, "img-a"), {SrcID: "org/app", DstID: osPkg, EdgeType: "depends_on"}}, covered, "", ""},
		{"root cause below the member's band: it never raised this page (a member paging on points, or newly KEV before the base recount)", osPkg, []asset.Edge{img(osPkg, "img-a")}, fakeFleetLister{findings: []finding.Finding{rootCauseAt("img-a", "1", BandHigh)}}, "", BandPage},
		{"root cause at the member's band carries it", osPkg, []asset.Edge{img(osPkg, "img-a")}, fakeFleetLister{findings: []finding.Finding{rootCauseAt("img-a", "1", BandHigh)}}, "base-image root cause rc-debian", BandHigh},
		{"never-enriched root cause carries nothing", osPkg, []asset.Edge{img(osPkg, "img-a")}, fakeFleetLister{findings: []finding.Finding{rootCauseAt("img-a", "1", "")}}, "", BandPage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := SupplyChainExposure{Graph: fakeLineage{into: map[string][]asset.Edge{tt.purl: tt.runners}}, Fleets: tt.fleets}
			band := tt.band
			if band == "" {
				band = BandPage
			}
			got, err := s.AlertCarrier(ctx, pkgFinding(tt.purl), band)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	t.Run("fleet-canonical", func(t *testing.T) {
		g := fakeLineage{into: map[string][]asset.Edge{osPkg: {{SrcID: "i-a", SrcType: "ec2_instance", DstID: osPkg, EdgeType: "runs_package"}}}}
		fleet := func(band Band) fakeFleetLister {
			return fakeFleetLister{findings: []finding.Finding{{ID: "fl", Source: "vm_vuln", CheckID: "CVE-1", ScoreBand: string(band),
				Metadata: map[string]string{"package_finding_id": "pkg-f", "affected_instances": "1"}}}}
		}
		got, err := SupplyChainExposure{Graph: g, Fleets: fleet(BandPage)}.AlertCarrier(ctx, pkgFinding(osPkg), BandHigh)
		require.NoError(t, err)
		assert.Contains(t, got, "vm_vuln")
		got, err = SupplyChainExposure{Graph: g, Fleets: fleet(BandPipeline)}.AlertCarrier(ctx, pkgFinding(osPkg), BandHigh)
		require.NoError(t, err)
		assert.Empty(t, got, "a fleet below the member's band does not carry it")
	})

	t.Run("failed read is an error, not a carrier", func(t *testing.T) {
		g := fakeLineage{into: map[string][]asset.Edge{osPkg: {img(osPkg, "img-a")}}}
		got, err := SupplyChainExposure{Graph: g, Fleets: fakeFleetLister{err: context.DeadlineExceeded}}.AlertCarrier(ctx, pkgFinding(osPkg), BandPage)
		require.Error(t, err)
		assert.Empty(t, got)
	})
}

// fakeRunnerLineage serves a package's runners for packageRouting.
type fakeRunnerLineage struct {
	fakeLineage
	assets map[string]asset.Asset
	err    error
}

func (f fakeRunnerLineage) ByIDs(_ context.Context, ids []string) ([]asset.Asset, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []asset.Asset
	for _, id := range ids {
		if a, ok := f.assets[id]; ok {
			out = append(out, a)
		}
	}
	return out, nil
}

// tagOwnerResolver resolves an asset's owner from its "team" tag.
type tagOwnerResolver struct{ err error }

func (r tagOwnerResolver) ResolveOwner(_ context.Context, a asset.Asset, _ []string) (asset.Ownership, error) {
	if r.err != nil {
		return asset.Ownership{}, r.err
	}
	if t := a.Tags["team"]; t != "" {
		return asset.Ownership{Team: t, Source: asset.OwnerSourceTag, Confidence: asset.OwnerConfidenceHigh, Evidence: "tag:team"}, nil
	}
	return asset.Ownership{Source: asset.OwnerSourceNone}, nil
}

// A package finding routes to what runs it: the owner of its exposed runners
// first (they are why it is urgent), the most production-like environment.
func TestRoutingOf_PackageFindingRoutesToRunners(t *testing.T) {
	ctx := context.Background()
	pkg := "pkg:deb/debian/openssl@3.0.11"
	f := finding.Finding{ID: "f", Source: "supply_chain", ResourceType: "package", ResourceID: pkg}
	runsOn := func(ids ...string) []asset.Edge {
		var out []asset.Edge
		for _, id := range ids {
			out = append(out, asset.Edge{SrcID: id, DstID: pkg, EdgeType: "runs_package"})
		}
		return out
	}
	lineage := fakeRunnerLineage{
		fakeLineage: fakeLineage{
			into: map[string][]asset.Edge{pkg: runsOn("vm-batch1", "vm-batch2", "vm-web")},
			from: map[string][]asset.Edge{"vm-web": {{SrcID: "vm-web", DstID: "internet", EdgeType: "exposed_to_internet"}}},
		},
		assets: map[string]asset.Asset{
			"vm-batch1": {ID: "vm-batch1", Tags: map[string]string{"team": "data", "env": "dev"}},
			"vm-batch2": {ID: "vm-batch2", Tags: map[string]string{"team": "data", "env": "dev"}},
			"vm-web":    {ID: "vm-web", Tags: map[string]string{"team": "web", "env": "prod"}},
		},
	}
	s := NewService(&fakeFindingWriter{}, &fakeSignalRepo{}, nil, WithOwnerResolver(tagOwnerResolver{}, nil), WithPackageRunners(lineage))
	o, env := s.routingOf(ctx, f, seedRead{fetched: true, err: asset.ErrNotFound}, ThresholdPage)
	assert.Equal(t, "web", o.Team, "the exposed runner's owner wins over the more common unexposed one")
	assert.Equal(t, asset.OwnerConfidenceMedium, o.Confidence, "inferred one hop away: capped at medium")
	assert.Contains(t, o.Evidence, "runner:vm-web")
	assert.Equal(t, "prod", env)

	// No exposed runner: the most common owner among any.
	lineage.from = nil
	s = NewService(&fakeFindingWriter{}, &fakeSignalRepo{}, nil, WithOwnerResolver(tagOwnerResolver{}, nil), WithPackageRunners(lineage))
	o, _ = s.routingOf(ctx, f, seedRead{fetched: true}, ThresholdPage)
	assert.Equal(t, "data", o.Team)

	// A failed read leaves routing unresolved — never "unowned".
	lineage.err = context.DeadlineExceeded
	s = NewService(&fakeFindingWriter{}, &fakeSignalRepo{}, nil, WithOwnerResolver(tagOwnerResolver{}, nil), WithPackageRunners(lineage))
	o, env = s.routingOf(ctx, f, seedRead{fetched: true}, ThresholdPage)
	assert.False(t, o.Resolved())
	assert.Empty(t, env)

	// Nothing runs it: resolved unowned, environment unknown.
	s = NewService(&fakeFindingWriter{}, &fakeSignalRepo{}, nil, WithOwnerResolver(tagOwnerResolver{}, nil), WithPackageRunners(fakeRunnerLineage{}))
	o, env = s.routingOf(ctx, f, seedRead{fetched: true}, ThresholdPage)
	assert.True(t, o.Unowned())
	assert.Equal(t, "unknown", env)

	// Below the high band the finding cannot alert: no runner reads at all.
	lineage.err = context.DeadlineExceeded // would surface as unresolved if read
	s = NewService(&fakeFindingWriter{}, &fakeSignalRepo{}, nil, WithOwnerResolver(tagOwnerResolver{}, nil), WithPackageRunners(lineage))
	o, _ = s.routingOf(ctx, f, seedRead{fetched: true, err: asset.ErrNotFound}, ThresholdHigh-1)
	assert.True(t, o.Resolved(), "a sub-high package finding keeps the purl's own routing")
}

func TestUrgentRegardlessOfReach(t *testing.T) {
	for _, src := range []string{sourceThreatFloor, sourceSignalFloor, sourceDNSTakeover} {
		assert.True(t, UrgentRegardlessOfReach([]Factor{{Source: src, Floor: ThresholdHigh}}), src)
		assert.False(t, UrgentRegardlessOfReach([]Factor{{Source: src, Floor: ThresholdPipeline}}), src+" pipeline floor")
	}
	assert.False(t, UrgentRegardlessOfReach([]Factor{{Source: "identity_hygiene", Floor: ThresholdHigh}}), "graph-derived floors are not reach-independent")
}

// The fleets carry a member only if EVERY covering fleet holds its band: one
// paging fleet does not speak for a sibling fleet that never paged.
func TestAlertCarrier_FleetBandIsTheMinimumOverFleets(t *testing.T) {
	pkg := "pkg:deb/ubuntu/openssl@3"
	f := finding.Finding{ID: "pkg-f", Source: "supply_chain", ResourceType: "package", ResourceID: pkg, CheckID: "CVE-1"}
	g := fakeLineage{into: map[string][]asset.Edge{pkg: {
		{SrcID: "i-a", SrcType: "ec2_instance", DstID: pkg, EdgeType: "runs_package"},
		{SrcID: "i-b", SrcType: "ec2_instance", DstID: pkg, EdgeType: "runs_package"},
	}}}
	fleet := func(id string, band Band) finding.Finding {
		return finding.Finding{ID: id, Source: "vm_vuln", CheckID: "CVE-1", ScoreBand: string(band),
			Metadata: map[string]string{"package_finding_id": "pkg-f", "affected_instances": "1"}}
	}
	for _, order := range [][]finding.Finding{
		{fleet("a", BandPage), fleet("b", BandPipeline)},
		{fleet("b", BandPipeline), fleet("a", BandPage)},
	} {
		got, err := SupplyChainExposure{Graph: g, Fleets: fakeFleetLister{findings: order}}.AlertCarrier(context.Background(), f, BandHigh)
		require.NoError(t, err)
		assert.Empty(t, got)
	}
	got, err := SupplyChainExposure{Graph: g, Fleets: fakeFleetLister{findings: []finding.Finding{fleet("a", BandPage), fleet("b", BandHigh)}}}.AlertCarrier(context.Background(), f, BandHigh)
	require.NoError(t, err)
	assert.NotEmpty(t, got)
}
