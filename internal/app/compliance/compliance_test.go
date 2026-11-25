package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/checks"
)

// fakeInventory groups its assets the way inventorySamples does
// (sampleByEvidence) and returns the first member of each group in input
// order, as ClickHouse's GROUP BY returns whichever row it read first.
type fakeInventory struct {
	samples []asset.Asset
	err     error
	spec    EvidenceSpec
}

func (f *fakeInventory) Samples(_ context.Context, spec EvidenceSpec) ([]asset.Asset, error) {
	f.spec = spec
	if f.err != nil {
		return nil, f.err
	}
	return sampleByEvidence(spec, f.samples), nil
}

// fullInventory holds, per (provider, type) any mapped check reads, one asset
// carrying every key those checks read, plus a CIEM-graded principal for each
// CIEM scope — an estate where everything was assessed.
func fullInventory() *fakeInventory {
	reg := checks.Default()
	type key struct {
		p asset.Provider
		t string
	}
	merged := map[key]map[string]string{}
	var order []key
	for _, c := range controls {
		for _, id := range c.CheckIDs {
			chk, ok := reg.ByID(id)
			if !ok {
				continue
			}
			k := key{chk.Provider, chk.AssetType}
			md, seen := merged[k]
			if !seen {
				md = map[string]string{}
				merged[k] = md
				order = append(order, k)
			}
			for _, rk := range chk.RequiredKeys {
				md[rk] = "observed"
				if rk == "ingress" || rk == "egress" {
					md[rk] = "[]" // rule lists must decode to count as observed
				}
			}
		}
	}
	// A type-less check applies to every asset of its provider, so every
	// sample of that provider carries its keys too.
	for k, md := range merged {
		if k.t != "" {
			continue
		}
		for o, omd := range merged {
			if o.p == k.p {
				for rk, v := range md {
					omd[rk] = v
				}
			}
		}
	}
	inv := &fakeInventory{}
	for _, k := range order {
		inv.samples = append(inv.samples, asset.Asset{Provider: k.p, Type: k.t, Metadata: merged[k]})
	}
	inv.samples = append(inv.samples,
		asset.Asset{Provider: asset.ProviderAWS, Type: "iam_role", Metadata: map[string]string{ciem.MetaPrivilegeTier: ciem.TierStandard, "policies": "[]", ciem.MetaAWSOrganizationComplete: "true"}},
		asset.Asset{Provider: asset.ProviderGCP, Type: "gcp_service_account", Metadata: map[string]string{ciem.MetaPrivilegeTier: ciem.TierStandard, "permissions": "", "permissions_complete": "true"}},
	)
	return inv
}

func newTestService(f CheckIDs) *Service {
	return NewService(f, fullInventory(), checks.Default(), &fakeConnectors{})
}

type fakeFindings struct {
	findings []finding.Finding
	err      error
}

func (f fakeFindings) DistinctCheckIDs(_ context.Context, _ string) ([]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	seen := map[string]bool{}
	for _, fnd := range f.findings {
		if fnd.CheckID != "" {
			seen[fnd.CheckID] = true
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	return out, nil
}

func TestCompute_AllPassingWhenNoFindings(t *testing.T) {
	cov, err := newTestService(fakeFindings{}).Compute(context.Background())
	require.NoError(t, err)
	require.Equal(t, cov.Total, cov.Passing)
	require.Equal(t, len(controls), cov.Total)
}

func TestCompute_ControlFailsWhenCheckHasFinding(t *testing.T) {
	svc := newTestService(fakeFindings{findings: []finding.Finding{
		{CheckID: "aws-ec2-public-ip"},
	}})
	cov, err := svc.Compute(context.Background())
	require.NoError(t, err)
	require.Equal(t, cov.Total-1, cov.Passing)

	for _, s := range cov.Controls {
		if s.Control.ID == "CIS-AWS-4.1" {
			require.False(t, s.Passing, "control with a failing check must not pass")
		} else {
			require.True(t, s.Passing)
		}
	}
}

func TestCompute_PropagatesError(t *testing.T) {
	_, err := newTestService(fakeFindings{err: errors.New("ch down")}).Compute(context.Background())
	require.ErrorContains(t, err, "ch down")
}

// livenessAwareFindings models the contract finding.CHRepo's distinctCheckIDs
// now implements in SQL: a finding is excluded from the failing set ONLY when
// its resource_id is a resource this fake has explicitly marked verified-dead.
// A finding whose resource_id is unmarked (live, or of unknown liveness — this
// fake makes no distinction between the two, exactly as distinctCheckIDs does
// not: neither is ever excluded) still counts. This is the compliance-level
// twin of TestCHRepo_DistinctCheckIDsAppliesEphemeralLiveness (finding package,
// integration-tagged, against real ClickHouse) — that test proves the SQL
// implements this contract; these prove Compute behaves correctly given it.
type livenessAwareFindings struct {
	findings []finding.Finding
	dead     map[string]bool // resource_id -> verified corpse
}

func (f livenessAwareFindings) DistinctCheckIDs(context.Context, string) ([]string, error) {
	seen := map[string]bool{}
	for _, fnd := range f.findings {
		if fnd.CheckID == "" {
			continue
		}
		if fnd.ResourceID != "" && f.dead[fnd.ResourceID] {
			continue // state 2: evidence provably gone — never counted
		}
		seen[fnd.CheckID] = true // states 1 & 3: live or unknown — always counted
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	return out, nil
}

// TestCompute_EvidenceStates covers the three evidence states that must be
// distinguished, plus a control whose evidence is split across a live and a
// dead asset.
func TestCompute_EvidenceStates(t *testing.T) {
	tests := []struct {
		name        string
		findings    []finding.Finding
		dead        map[string]bool
		wantFailing bool // does CIS-AWS-4.1 (aws-ec2-public-ip) fail?
	}{
		{
			name: "live evidence fails the control",
			findings: []finding.Finding{
				{CheckID: "aws-ec2-public-ip", ResourceID: "live-1"},
			},
			dead:        map[string]bool{},
			wantFailing: true,
		},
		{
			name: "evidence on a verified-dead asset does not fail the control",
			findings: []finding.Finding{
				{CheckID: "aws-ec2-public-ip", ResourceID: "dead-1"},
			},
			dead:        map[string]bool{"dead-1": true},
			wantFailing: false,
		},
		{
			name: "unknown liveness (no resource_id / unresolvable asset) still fails the control",
			findings: []finding.Finding{
				{CheckID: "aws-ec2-public-ip", ResourceID: ""},
			},
			dead:        map[string]bool{},
			wantFailing: true,
		},
		{
			name: "evidence split across one live and one dead asset still fails the control",
			findings: []finding.Finding{
				{CheckID: "aws-ec2-public-ip", ResourceID: "live-1"},
				{CheckID: "aws-ec2-public-ip", ResourceID: "dead-1"},
			},
			dead:        map[string]bool{"dead-1": true},
			wantFailing: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cov, err := newTestService(livenessAwareFindings{findings: tc.findings, dead: tc.dead}).
				Compute(context.Background())
			require.NoError(t, err)

			var found bool
			for _, s := range cov.Controls {
				if s.Control.ID != "CIS-AWS-4.1" {
					continue
				}
				found = true
				require.Equal(t, !tc.wantFailing, s.Passing)
			}
			require.True(t, found, "CIS-AWS-4.1 must be present in every Compute result")
		})
	}
}

func TestHandler_Get(t *testing.T) {
	h := NewHandler(newTestService(fakeFindings{findings: []finding.Finding{{CheckID: "github-public-repo"}}}))

	rec := httptest.NewRecorder()
	h.Get(rec, httptest.NewRequest(http.MethodGet, "/api/compliance", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	var cov Coverage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &cov))
	require.Equal(t, len(controls), cov.Total)
	require.Equal(t, len(controls)-1, cov.Passing)
}

func TestHandler_Get_Error500(t *testing.T) {
	h := NewHandler(newTestService(fakeFindings{err: errors.New("boom")}))
	rec := httptest.NewRecorder()
	h.Get(rec, httptest.NewRequest(http.MethodGet, "/api/compliance", nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

// TestCompute_NeverAssessedIsNotPassing pins the "no findings == compliant"
// hole: with no connector (empty inventory) every control used to report
// Passing. A control passes only when one of its checks could evaluate a live
// asset; an open finding still fails it regardless.
func TestCompute_NeverAssessedIsNotPassing(t *testing.T) {
	svc := NewService(fakeFindings{findings: []finding.Finding{{CheckID: "github-public-repo"}}}, &fakeInventory{}, checks.Default(), &fakeConnectors{})
	cov, err := svc.Compute(context.Background())
	require.NoError(t, err)
	require.Zero(t, cov.Passing, "nothing was assessed, so nothing passes")
	require.Equal(t, 1, cov.Failing, "an open finding fails its control even without inventory")
	require.Equal(t, cov.Total-1, cov.NotAssessed)
	for _, st := range cov.Controls {
		if st.Control.ID == "CIS-GH-1.1" {
			require.Equal(t, StateFailing, st.State)
			continue
		}
		require.Equal(t, StateNotAssessed, st.State, st.Control.ID)
		require.False(t, st.Passing)
	}
	for _, fw := range cov.Frameworks {
		require.Equal(t, fw.Total, fw.Passing+fw.Failing+fw.Partial+fw.NotAssessed, fw.Framework)
	}
}

func TestCompute_AssessmentNeedsAnEvaluableApplicableAsset(t *testing.T) {
	state := func(inv *fakeInventory, controlID string) string {
		t.Helper()
		cov, err := NewService(fakeFindings{}, inv, checks.Default(), &fakeConnectors{}).Compute(context.Background())
		require.NoError(t, err)
		for _, st := range cov.Controls {
			if st.Control.ID == controlID {
				return st.State
			}
		}
		t.Fatalf("control %s missing", controlID)
		return ""
	}

	// aws-s3-public-bucket reads "public" and "bpa_all_enabled": a bucket
	// collected without them could not be evaluated (some value of either
	// would have fired the check).
	blind := &fakeInventory{samples: []asset.Asset{{Provider: asset.ProviderAWS, Type: "s3_bucket", Metadata: map[string]string{}}}}
	require.Equal(t, StateNotAssessed, state(blind, "CIS-AWS-2.1"), "the check could not evaluate the only bucket")

	// The bucket carries what aws-s3-public-bucket reads, but not the ACL keys
	// aws-s3-public-read/-write read: those two checks evaluated nothing.
	seen := &fakeInventory{samples: []asset.Asset{{Provider: asset.ProviderAWS, Type: "s3_bucket", Metadata: map[string]string{"public": "false", "bpa_all_enabled": "true"}}}}
	require.Equal(t, StatePartial, state(seen, "CIS-AWS-2.1"), "two of three mapped checks evaluated nothing")
	require.NotContains(t, seen.spec.Types, "", "the inventory read is scoped to concrete types")
	require.Contains(t, seen.spec.Types, "s3_bucket")

	full := &fakeInventory{samples: []asset.Asset{{Provider: asset.ProviderAWS, Type: "s3_bucket", Metadata: map[string]string{
		"public": "false", "bpa_all_enabled": "true", "public_read": "false", "public_write": "false",
	}}}}
	require.Equal(t, StatePassing, state(full, "CIS-AWS-2.1"))

	wrongProvider := &fakeInventory{samples: []asset.Asset{{Provider: asset.ProviderGCP, Type: "s3_bucket", Metadata: map[string]string{"public": "false"}}}}
	require.Equal(t, StateNotAssessed, state(wrongProvider, "CIS-AWS-2.1"))

	// CIEM rules are not registry checks: a principal of their scope that CIEM
	// actually graded assesses them. One it never graded, or whose permission
	// set it could not read, says nothing about escalation paths.
	principal := func(tier string) asset.Asset {
		md := map[string]string{"policies": "[]", ciem.MetaAWSOrganizationComplete: "true"}
		if tier != "" {
			md[ciem.MetaPrivilegeTier] = tier
		}
		return asset.Asset{Provider: asset.ProviderAWS, Type: "iam_user", Metadata: md}
	}
	principals := func(as ...asset.Asset) *fakeInventory { return &fakeInventory{samples: as} }
	require.Equal(t, StateNotAssessed, state(&fakeInventory{}, "SOC2-CC6.3-AWS"))
	require.Equal(t, StateNotAssessed, state(principals(principal("")), "SOC2-CC6.3-AWS"), "never graded by CIEM")
	require.Equal(t, StateNotAssessed, state(principals(principal(ciem.TierUnknown)), "SOC2-CC6.3-AWS"), "permissions unread")
	require.Equal(t, StatePassing, state(principals(principal(ciem.TierStandard)), "SOC2-CC6.3-AWS"))
}

// TestCompute_OneUnevaluableAssetBlocksAssessment: a check is assessed only
// when it evaluated EVERY asset it applies to — an evaluable asset must not
// vouch for one next to it that was never observed (the requirements
// rollup's classify rule).
func TestCompute_OneUnevaluableAssetBlocksAssessment(t *testing.T) {
	fullBucket := asset.Asset{Provider: asset.ProviderAWS, Type: "s3_bucket", Metadata: map[string]string{
		"public": "false", "bpa_all_enabled": "true", "public_read": "false", "public_write": "false",
	}}
	blindBucket := asset.Asset{Provider: asset.ProviderAWS, Type: "s3_bucket", Metadata: map[string]string{}}
	graded := asset.Asset{Provider: asset.ProviderAWS, Type: "iam_user", Metadata: map[string]string{
		ciem.MetaPrivilegeTier: ciem.TierStandard, ciem.MetaPrivilegeTierSource: ciem.TierSourceCIEM, "policies": "[]", ciem.MetaAWSOrganizationComplete: "true",
	}}
	ungraded := asset.Asset{Provider: asset.ProviderAWS, Type: "iam_user", Metadata: map[string]string{
		ciem.MetaPrivilegeTier: ciem.TierUnknown, ciem.MetaPrivilegeTierSource: ciem.TierSourceNoPermData,
	}}
	collectorAdmin := asset.Asset{Provider: asset.ProviderAWS, Type: "iam_user", Metadata: map[string]string{
		ciem.MetaPrivilegeTier: ciem.TierAdmin, ciem.MetaPrivilegeTierSource: ciem.TierSourceCollector, "admin": "true",
	}}
	tests := []struct {
		name    string
		samples []asset.Asset
		control string
		want    string
	}{
		{"evaluable bucket beside a blind one", []asset.Asset{fullBucket, blindBucket}, "CIS-AWS-2.1", StateNotAssessed},
		{"only evaluable buckets", []asset.Asset{fullBucket}, "CIS-AWS-2.1", StatePassing},
		{"graded principal beside an unknown one", []asset.Asset{graded, ungraded}, "SOC2-CC6.3-AWS", StateNotAssessed},
		{"collector-only admin, permissions unread", []asset.Asset{collectorAdmin}, "SOC2-CC6.3-AWS", StateNotAssessed},
		{"graded principals only", []asset.Asset{graded}, "SOC2-CC6.3-AWS", StatePassing},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cov, err := NewService(fakeFindings{}, &fakeInventory{samples: tt.samples}, checks.Default(), &fakeConnectors{}).Compute(context.Background())
			require.NoError(t, err)
			for _, st := range cov.Controls {
				if st.Control.ID == tt.control {
					require.Equal(t, tt.want, st.State)
					return
				}
			}
			t.Fatalf("control %s missing", tt.control)
		})
	}
}

// TestCompute_CloudWithoutInventoryIsOutOfScope: SEC-DNS-1.1 maps an AWS and
// a GCP check; an AWS-only estate that evaluated the AWS one passes it rather
// than leaving it permanently partial. An AWS estate with no hosted zones at
// all is still not assessed: missing inventory in a covered cloud is unknown.
func TestCompute_CloudWithoutInventoryIsOutOfScope(t *testing.T) {
	reg := checks.Default()
	awsChk, ok := reg.ByID("dns-cname-takeover-risk")
	require.True(t, ok)
	gcpChk, ok := reg.ByID("gcp-dns-cname-takeover-risk")
	require.True(t, ok)
	evaluable := func(chk checks.Check) asset.Asset {
		md := map[string]string{}
		for _, k := range chk.RequiredKeys {
			md[k] = "observed"
		}
		return asset.Asset{Provider: chk.Provider, Type: chk.AssetType, Metadata: md}
	}
	state := func(samples ...asset.Asset) string {
		t.Helper()
		cov, err := NewService(fakeFindings{}, &fakeInventory{samples: samples}, reg, &fakeConnectors{}).Compute(context.Background())
		require.NoError(t, err)
		for _, st := range cov.Controls {
			if st.Control.ID == "SEC-DNS-1.1" {
				return st.State
			}
		}
		t.Fatal("SEC-DNS-1.1 missing")
		return ""
	}
	require.Equal(t, StatePassing, state(evaluable(awsChk)), "no GCP connector or inventory: the GCP check is out of scope")
	require.Equal(t, StatePassing, state(evaluable(awsChk), evaluable(gcpChk)))
	require.Equal(t, StatePartial, state(evaluable(awsChk), asset.Asset{Provider: asset.ProviderGCP, Type: "gcp_service_account"}),
		"GCP has inventory but nothing the GCP check evaluated")
	require.Equal(t, StateNotAssessed, state(asset.Asset{Provider: asset.ProviderAWS, Type: "iam_user"}),
		"AWS inventory without hosted zones is not evidence")
	require.Equal(t, StateNotAssessed, state(), "no inventory at all")
}

func TestControlState(t *testing.T) {
	c := Control{ID: "X", CheckIDs: []string{"a", "b", "c"}}
	tests := []struct {
		name       string
		failing    []string
		assessed   []string
		outOfScope []string
		want       string
	}{
		{"every check assessed, none failing", nil, []string{"a", "b", "c"}, nil, StatePassing},
		{"some checks assessed", nil, []string{"a"}, nil, StatePartial},
		{"all but one assessed", nil, []string{"a", "b"}, nil, StatePartial},
		{"nothing assessed", nil, nil, nil, StateNotAssessed},
		{"open finding with everything assessed", []string{"b"}, []string{"a", "b", "c"}, nil, StateFailing},
		{"open finding with nothing assessed", []string{"c"}, nil, nil, StateFailing},
		{"open finding with partial assessment", []string{"a"}, []string{"b"}, nil, StateFailing},
		{"assessed checks outside the control do not count", nil, []string{"a", "b", "z"}, nil, StatePartial},
		{"out-of-scope check leaves the denominator", nil, []string{"a", "b"}, []string{"c"}, StatePassing},
		{"out-of-scope check with the rest partial", nil, []string{"a"}, []string{"c"}, StatePartial},
		{"every check out of scope", nil, nil, []string{"a", "b", "c"}, StateNotAssessed},
		{"open finding on an out-of-scope check still fails", []string{"c"}, []string{"a", "b"}, []string{"c"}, StateFailing},
	}
	set := func(ids []string) map[string]bool {
		m := map[string]bool{}
		for _, id := range ids {
			m[id] = true
		}
		return m
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ev := assessment{evaluated: set(tt.assessed), outOfScope: set(tt.outOfScope)}
			require.Equal(t, tt.want, controlState(c, set(tt.failing), ev))
		})
	}
}

func TestCompute_InventoryErrorIsAnError(t *testing.T) {
	_, err := NewService(fakeFindings{}, &fakeInventory{err: errors.New("ch down")}, checks.Default(), &fakeConnectors{}).Compute(context.Background())
	require.ErrorContains(t, err, "ch down", "an unreadable inventory must not read as 'nothing to assess'")
}
