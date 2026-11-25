package respond

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/graphschema"
)

func TestAssessImpact_Dependents(t *testing.T) {
	tests := []struct {
		name     string
		deps     []asset.Edge
		wantN    int
		wantWord string // substring expected in a signal line
	}{
		{
			name:     "no dependents",
			deps:     nil,
			wantN:    0,
			wantWord: "nothing routes to or runs as",
		},
		{
			name: "dedups by source",
			deps: []asset.Edge{
				{SrcID: "dns-a"}, {SrcID: "dns-a"}, {SrcID: "role-user"},
			},
			wantN:    2,
			wantWord: "depend on this",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			imp := assessImpact(ContextPack{}, asset.Asset{}, tt.deps, true)
			require.Equal(t, tt.wantN, imp.Dependents)
			require.Contains(t, joinSignals(imp.Signals), tt.wantWord)
		})
	}
}

// A failed dependents read is not "nothing depends on it": the signal says
// unknown, the prompt says unknown, and the "removing it should not break"
// line never appears.
func TestAssessImpact_UnknownDependents(t *testing.T) {
	imp := assessImpact(ContextPack{Provenance: Provenance{AgeBucket: "stale"}}, asset.Asset{}, nil, false)
	require.False(t, imp.DependentsKnown)
	require.Contains(t, joinSignals(imp.Signals), "dependents unknown")
	require.NotContains(t, joinSignals(imp.Signals), "should not break other assets")
	lines := imp.PromptLines()
	require.Contains(t, lines[0], "dependents=unknown")
	require.NotContains(t, lines[0], "dependents=0")
}

// A read that succeeded over edges the collector never emitted (a secret whose
// IAM policy was unreadable) is not "nothing depends on it" either, and a
// non-destructive fix on it never reaches the safe band.
func TestAssessImpact_UnreadSeedDependents(t *testing.T) {
	for _, tc := range []struct {
		known     string
		wantKnown bool
	}{
		{known: "false", wantKnown: false},
		{known: "true", wantKnown: true},
	} {
		t.Run("accessors_known="+tc.known, func(t *testing.T) {
			seed := asset.Asset{Type: "gcp_secret", Metadata: map[string]string{asset.MetaAccessorsKnown: tc.known, "inactive": "true"}}
			imp := assessImpact(ContextPack{}, seed, nil, true)
			require.Equal(t, tc.wantKnown, imp.DependentsKnown)
			if tc.wantKnown {
				require.Equal(t, SafetySafe, safetyBand(ClassModify, imp, ExposureFlags{}, Provenance{}))
				return
			}
			require.NotContains(t, joinSignals(imp.Signals), "should not break other assets")
			require.Contains(t, imp.PromptLines()[0], "dependents=unknown")
			require.Equal(t, SafetyCaution, safetyBand(ClassModify, imp, ExposureFlags{}, Provenance{}))
		})
	}
}

func TestAssessImpact_UnusedSignals(t *testing.T) {
	t.Run("stale is unused", func(t *testing.T) {
		imp := assessImpact(ContextPack{Provenance: Provenance{AgeBucket: "stale"}}, asset.Asset{}, nil, true)
		require.True(t, imp.Unused)
		require.Contains(t, joinSignals(imp.Signals), "stale")
	})

	t.Run("inactive IAM principal is unused", func(t *testing.T) {
		seed := asset.Asset{Metadata: map[string]string{"inactive": "true"}}
		imp := assessImpact(ContextPack{}, seed, nil, true)
		require.True(t, imp.Unused)
		require.Contains(t, joinSignals(imp.Signals), "inactive")
	})

	t.Run("password never used", func(t *testing.T) {
		seed := asset.Asset{Metadata: map[string]string{"password_last_used_days": "-1"}}
		imp := assessImpact(ContextPack{}, seed, nil, true)
		require.Contains(t, joinSignals(imp.Signals), "never been used")
	})

	t.Run("orphan workload flags evidence but is NOT promoted to unused", func(t *testing.T) {
		// A missing deploys_to edge is a correlation gap, not proof the workload is
		// unused — it must surface as evidence to check, not flip the band to safe.
		seed := asset.Asset{Type: "k8s_pod"}
		imp := assessImpact(ContextPack{Provenance: Provenance{}}, seed, nil, true)
		require.False(t, imp.Unused, "orphan workload must not be auto-marked unused")
		require.Contains(t, joinSignals(imp.Signals), "no repo deploys to this")
	})

	t.Run("workload with a source repo is not an orphan", func(t *testing.T) {
		seed := asset.Asset{Type: "k8s_pod"}
		imp := assessImpact(ContextPack{Provenance: Provenance{SourceRepo: "example/api"}}, seed, nil, true)
		require.False(t, imp.Unused)
	})

	t.Run("active service with dependents is used", func(t *testing.T) {
		seed := asset.Asset{Type: "k8s_pod"}
		imp := assessImpact(ContextPack{Provenance: Provenance{SourceRepo: "example/api", Environment: "prod"}}, seed, []asset.Edge{{SrcID: "dns-a"}}, true)
		require.False(t, imp.Unused)
		require.Equal(t, 1, imp.Dependents)
	})
}

func TestFixLocationOf(t *testing.T) {
	tests := []struct {
		name       string
		prov       Provenance
		wantKind   string
		wantRepo   string
		wantHintIn string
	}{
		{
			name:       "high-confidence source repo",
			prov:       Provenance{SourceRepo: "example/payments-api", SourceConfidence: "high"},
			wantKind:   FixSourceRepo,
			wantRepo:   "example/payments-api",
			wantHintIn: "redeploy",
		},
		{
			name:       "medium-confidence source repo warns to verify",
			prov:       Provenance{SourceRepo: "example/guess", SourceConfidence: "medium"},
			wantKind:   FixSourceRepo,
			wantRepo:   "example/guess",
			wantHintIn: "verify it is the right repo",
		},
		{
			name:       "cloud console fallback when no repo",
			prov:       Provenance{Connector: "aws", AccountID: "1234", Region: "eu-west-1"},
			wantKind:   FixCloudConsole,
			wantHintIn: "aws console",
		},
		{
			name:     "unknown when nothing to point at",
			prov:     Provenance{},
			wantKind: FixUnknown,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fl := fixLocationOf(tt.prov)
			require.Equal(t, tt.wantKind, fl.Kind)
			if tt.wantRepo != "" {
				require.Equal(t, tt.wantRepo, fl.Repo)
			}
			if tt.wantHintIn != "" {
				require.Contains(t, fl.Hint, tt.wantHintIn)
			}
		})
	}
}

func TestSafetyBand(t *testing.T) {
	unusedNoDeps := ImpactAssessment{Dependents: 0, DependentsKnown: true, Unused: true}
	usedNoDeps := ImpactAssessment{Dependents: 0, DependentsKnown: true, Unused: false}
	withDeps := ImpactAssessment{Dependents: 3, DependentsKnown: true}
	// unusedUnknownDeps is a stale resource whose dependents read failed:
	// Dependents is 0 only because nothing was measured.
	unusedUnknownDeps := ImpactAssessment{Dependents: 0, DependentsKnown: false, Unused: true}

	prod := Provenance{Env: asset.EnvClassification{Env: asset.EnvProd, Source: "tag:env"}}
	staging := Provenance{Env: asset.EnvClassification{Env: asset.EnvStaging, Source: "tag:env"}}
	dev := Provenance{Env: asset.EnvClassification{Env: asset.EnvDev, Source: "account_id"}}
	unknown := Provenance{Env: asset.EnvClassification{Env: asset.EnvUnknown}}

	tests := []struct {
		name   string
		action ActionClass
		imp    ImpactAssessment
		exp    ExposureFlags
		prov   Provenance
		want   string
	}{
		{"observe is always safe", ClassObserve, withDeps, ExposureFlags{InternetFacing: true}, prod, SafetySafe},
		{"remediate on unused unreferenced is safe", ClassRemediate, unusedNoDeps, ExposureFlags{}, staging, SafetySafe},
		{"modify on unused unreferenced is safe", ClassModify, unusedNoDeps, ExposureFlags{}, staging, SafetySafe},
		{"non-destructive ignores environment", ClassRemediate, unusedNoDeps, ExposureFlags{}, unknown, SafetySafe},
		{"remediate on used active is caution", ClassRemediate, usedNoDeps, ExposureFlags{}, staging, SafetyCaution},
		{"remediate with dependents is caution", ClassRemediate, withDeps, ExposureFlags{}, staging, SafetyCaution},
		{"destroy with dependents is risky", ClassDestroy, withDeps, ExposureFlags{}, staging, SafetyRisky},
		{"isolate on prod is risky", ClassIsolate, usedNoDeps, ExposureFlags{}, prod, SafetyRisky},
		{"destroy on internet-facing is risky", ClassDestroy, usedNoDeps, ExposureFlags{InternetFacing: true}, staging, SafetyRisky},
		{"destroy on unused isolated staging is not risky", ClassDestroy, unusedNoDeps, ExposureFlags{}, staging, SafetySafe},
		{"destroy on unused isolated dev is not risky", ClassDestroy, unusedNoDeps, ExposureFlags{}, dev, SafetySafe},
		// Fail-closed: a destructive fix on an asset we cannot place is rated
		// as if it were production, never as safe.
		{"destroy on unknown environment is risky", ClassDestroy, unusedNoDeps, ExposureFlags{}, unknown, SafetyRisky},
		{"destroy with a zero-value environment is risky", ClassDestroy, unusedNoDeps, ExposureFlags{}, Provenance{}, SafetyRisky},
		{"the raw label alone does not escape prod caution", ClassIsolate, unusedNoDeps, ExposureFlags{}, Provenance{Environment: "dev"}, SafetyRisky},
		// Fail-closed on unknown dependents: never safe, and a destructive fix
		// is rated as if something depended on it.
		{"remediate on unused with unknown dependents is caution", ClassRemediate, unusedUnknownDeps, ExposureFlags{}, staging, SafetyCaution},
		{"modify on unused with unknown dependents is caution", ClassModify, unusedUnknownDeps, ExposureFlags{}, dev, SafetyCaution},
		{"destroy on unused with unknown dependents is risky", ClassDestroy, unusedUnknownDeps, ExposureFlags{}, dev, SafetyRisky},
		{"zero-value impact is never safe", ClassRemediate, ImpactAssessment{}, ExposureFlags{}, staging, SafetyCaution},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, safetyBand(tt.action, tt.imp, tt.exp, tt.prov))
		})
	}
}

func TestWorstSafetyBand(t *testing.T) {
	require.Equal(t, SafetyRisky, WorstSafetyBand(SafetySafe, SafetyRisky))
	require.Equal(t, SafetyRisky, WorstSafetyBand(SafetyRisky, SafetyCaution))
	require.Equal(t, SafetyCaution, WorstSafetyBand(SafetySafe, SafetyCaution))
	require.Equal(t, SafetySafe, WorstSafetyBand("", SafetySafe), "empty is unknown, does not override a known band")
	require.Equal(t, SafetySafe, WorstSafetyBand(SafetySafe, ""), "empty does not downgrade a known band")
}

// TestBuildContextPack_PopulatesImpact confirms the dependents lookup runs across
// the inbound edge types and lands on pack.Impact.
func TestBuildContextPack_PopulatesImpact(t *testing.T) {
	svc := packSvc()
	svc.lineage = fakeTypedLineage{byType: map[string][]asset.Edge{
		"dns_points_to":    {{SrcID: "dns-a"}},
		"executes_as":      {{SrcID: "workload-x"}},
		"federated_access": {{SrcID: "repo-y"}},
	}}
	br := asset.BlastRadius{Assets: []asset.Asset{{ID: "arn:role/x", Type: "iam_role"}}}
	pack := svc.buildContextPack(context.Background(), finding.Finding{ID: "f1", ResourceID: "arn:role/x"}, br, true, nil, false)
	require.Equal(t, 3, pack.Impact.Dependents)
}

func TestBuildContextPack_NilLineage_DependentsUnknown(t *testing.T) {
	br := asset.BlastRadius{Assets: []asset.Asset{{ID: "arn:role/x", Type: "iam_role"}}}
	pack := packSvc().buildContextPack(context.Background(), finding.Finding{ID: "f1", ResourceID: "arn:role/x"}, br, true, nil, false)
	require.Equal(t, 0, pack.Impact.Dependents)
	require.False(t, pack.Impact.DependentsKnown, "no lineage seam measured nothing — unknown, not zero")
}

// The failure the flag exists for: the dependents read errors on a stale
// resource. Before, that read as "nothing depends on it" + unused, and a
// destroy plan was banded safe.
func TestBuildContextPack_DependentsReadError_NeverSafe(t *testing.T) {
	svc := packSvc()
	svc.lineage = erroringLineage{}
	br := asset.BlastRadius{Assets: []asset.Asset{{ID: "arn:role/x", Type: "iam_role", Metadata: map[string]string{"inactive": "true"}}}}
	pack := svc.buildContextPack(context.Background(), finding.Finding{ID: "f1", ResourceID: "arn:role/x"}, br, true, nil, false)
	require.False(t, pack.Impact.DependentsKnown)
	require.True(t, pack.Impact.Unused)
	require.Equal(t, SafetyCaution, SafetyBandFor(ClassRemediate, pack), "the read path must not band unknown dependents safe")
	require.Equal(t, SafetyRisky, SafetyBandFor(ClassDestroy, pack))
}

func TestFingerprintExtra_DependentsChangeFlipsHash(t *testing.T) {
	base := ContextPack{Impact: ImpactAssessment{Dependents: 0, DependentsKnown: true}}
	changed := ContextPack{Impact: ImpactAssessment{Dependents: 2, DependentsKnown: true}}
	unknown := ContextPack{Impact: ImpactAssessment{}}
	require.NotEqual(t, base.fingerprintExtra(), changed.fingerprintExtra(),
		"a change in dependents must re-reason")
	require.NotEqual(t, base.fingerprintExtra(), unknown.fingerprintExtra(),
		"a plan reasoned with unknown dependents must not be reused once they are measured as zero")
}

func TestFingerprintExtra_FactorsUnknownFlipsHash(t *testing.T) {
	measured := ContextPack{FactorsKnown: true}
	unknown := ContextPack{}
	require.NotEqual(t, measured.fingerprintExtra(), unknown.fingerprintExtra(),
		"a plan reasoned while the score factors were unreadable must not be reused once they are read")
	require.Contains(t, unknown.fingerprintExtra(), "factors:unknown")
	require.NotContains(t, measured.fingerprintExtra(), "factors:unknown",
		"a measured pack's fingerprint must not change")
}

// erroringLineage fails every read, standing in for a ClickHouse error.
type erroringLineage struct{}

func (erroringLineage) EdgesInto(context.Context, string, string) ([]asset.Edge, error) {
	return nil, errors.New("clickhouse: timeout")
}

func (erroringLineage) EdgesIntoTypes(context.Context, string, []string) ([]asset.Edge, error) {
	return nil, errors.New("clickhouse: timeout")
}

// fakeTypedLineage returns different edges per edge type, unlike fakeLineage.
type fakeTypedLineage struct{ byType map[string][]asset.Edge }

func (f fakeTypedLineage) EdgesInto(_ context.Context, _ string, edgeType string) ([]asset.Edge, error) {
	return f.byType[edgeType], nil
}

func (f fakeTypedLineage) EdgesIntoTypes(_ context.Context, _ string, edgeTypes []string) ([]asset.Edge, error) {
	var out []asset.Edge
	for _, t := range edgeTypes {
		out = append(out, f.byType[t]...)
	}
	return out, nil
}

func joinSignals(s []string) string {
	out := ""
	for _, l := range s {
		out += l + "\n"
	}
	return out
}

// TestDependentEdgeTypesMatchTheSharedDeclaration pins that the reasoner's
// dependents question is the SAME question enrich asks for safety_class.
//
// They diverged once and it was documented rather than fixed: enrich widened to
// ten edge types, this file kept the original three, and the product showed a
// role with 40 dependents next to a remediation plan generated from a prompt that
// said nothing depended on it. Respond is the domain that mutates cloud state, so
// it was the one with the wrong number. The alignment moves a large share of
// resources carrying open findings from "nothing depends on this" to a real
// count in the reasoner prompt.
//
// This fails if anyone re-localizes the list here rather than editing
// graphschema.DependentEdgeTypes.
func TestDependentEdgeTypesMatchTheSharedDeclaration(t *testing.T) {
	require.Equal(t, graphschema.DependentEdgeTypes, dependentEdgeTypes,
		"respond and enrich must ask one question: edit graphschema.DependentEdgeTypes, not a local copy")
	require.Greater(t, len(dependentEdgeTypes), 3,
		"the original three ({dns_points_to, executes_as, federated_access}) scored every IAM role, "+
			"k8s Role and Service-fronted pod as having zero dependents")
}
