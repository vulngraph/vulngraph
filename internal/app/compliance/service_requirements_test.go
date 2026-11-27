package compliance

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/checks/benchmarks"
	"github.com/vulngraph/vulngraph/internal/checks/frameworks"
)

// rollupMatrices: an AWS benchmark with one control per status, and an Azure
// benchmark for the provider-scope cases.
func rollupMatrices() []benchmarks.Benchmark {
	return []benchmarks.Benchmark{
		{ID: "aws-b", Providers: []string{"aws"}, Controls: []benchmarks.Control{
			{ID: "covered", Status: benchmarks.StatusCovered, CheckIDs: []string{"c-ok"}},
			{ID: "covered2", Status: benchmarks.StatusCovered, CheckIDs: []string{"c-ok2"}},
			{ID: "fails", Status: benchmarks.StatusCovered, CheckIDs: []string{"c-fail"}},
			{ID: "partial", Status: benchmarks.StatusPartial, CheckIDs: []string{"c-ok"}},
			{ID: "missing", Status: benchmarks.StatusMissing},
			{ID: "manual", Status: benchmarks.StatusManual},
			{ID: "blind", Status: benchmarks.StatusCovered, CheckIDs: []string{"c-blind"}},
			{ID: "absent", Status: benchmarks.StatusCovered, CheckIDs: []string{"c-absent"}},
		}},
		{ID: "az-b", Providers: []string{"azure"}, Controls: []benchmarks.Control{
			{ID: "missing", Status: benchmarks.StatusMissing},
			{ID: "fails", Status: benchmarks.StatusCovered, CheckIDs: []string{"az-fail"}},
		}},
	}
}

func rollupEstate() estate {
	return estate{
		failing: map[string]bool{"c-fail": true},
		evidence: map[string]checkEvidence{
			"c-ok": evEvaluated, "c-ok2": evEvaluated, "c-fail": evEvaluated,
			"c-blind": evUnevaluated, "c-absent": evAbsent,
		},
		clouds: map[string]CloudEvidence{"aws": {Provider: "aws", Connectors: 1, HasInventory: true, EvidenceAsOf: syncedAt}},
	}
}

// TestRollupRequirement is the state table. Unknown must never be passing:
// every hole in the evidence (a control with no check, a partial check, a
// check that could not read its evidence, nothing evaluated at all) keeps a
// requirement out of "passing".
func TestRollupRequirement(t *testing.T) {
	ix := frameworks.NewIndex(rollupMatrices())
	cases := []struct {
		name     string
		controls []string
		state    string
		gaps     []string
	}{
		{"no mapping needs human evidence", nil, RequirementManual, nil},
		{"covered and evaluated passes", []string{"aws-b/covered", "aws-b/covered2"}, RequirementPassing, nil},
		{"open finding fails", []string{"aws-b/covered", "aws-b/fails"}, RequirementFailing, nil},
		{"failing beats every gap", []string{"aws-b/fails", "aws-b/missing", "aws-b/blind"}, RequirementFailing, []string{"aws-b/missing"}},
		{"a control with no check is a gap", []string{"aws-b/covered", "aws-b/missing"}, RequirementUnknown, []string{"aws-b/missing"}},
		{"a manual control is a gap", []string{"aws-b/covered", "aws-b/manual"}, RequirementUnknown, []string{"aws-b/manual"}},
		{"a partial check is a gap even when it passes", []string{"aws-b/partial"}, RequirementUnknown, []string{"aws-b/partial"}},
		{"an unevaluable check is unknown", []string{"aws-b/covered", "aws-b/blind"}, RequirementUnknown, nil},
		{"nothing evaluated is unknown, not passing", []string{"aws-b/absent"}, RequirementUnknown, nil},
		{"a check with no resources does not block a pass", []string{"aws-b/covered", "aws-b/absent"}, RequirementPassing, nil},
		{"a removed matrix row is a gap", []string{"aws-b/covered", "aws-b/gone"}, RequirementUnknown, []string{"aws-b/gone"}},
		{"another provider's gap is out of scope", []string{"aws-b/covered", "az-b/missing"}, RequirementPassing, nil},
		{"only out-of-scope controls is unknown", []string{"az-b/missing"}, RequirementUnknown, nil},
		{"an open finding brings its provider into scope", []string{"aws-b/covered", "az-b/fails"}, RequirementFailing, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			est := rollupEstate()
			if strings.Contains(tc.name, "brings its provider") {
				est.failing["az-fail"] = true
			}
			st := rollupRequirement(frameworks.Requirement{ID: "R", Title: "t", Controls: tc.controls}, ix, est)
			require.Equal(t, tc.state, st.State)
			require.Equal(t, tc.gaps, st.Gaps)
		})
	}
}

// TestRollupPartialMappingIsNeverPassing: when the source counts evidence
// graph has no control for, a clean result on the rest is not a pass.
func TestRollupPartialMappingIsNeverPassing(t *testing.T) {
	ix := frameworks.NewIndex(rollupMatrices())
	r := frameworks.Requirement{ID: "R", Title: "t", Unjoined: 5, Controls: []string{"aws-b/covered", "aws-b/covered2"}}
	st := rollupRequirement(r, ix, rollupEstate())
	require.Equal(t, RequirementUnknown, st.State)
	require.Equal(t, 5, st.UnjoinedSourceChecks)
	r.Controls = append(r.Controls, "aws-b/fails")
	require.Equal(t, RequirementFailing, rollupRequirement(r, ix, rollupEstate()).State, "a finding still fails it")
	require.Equal(t, "partial mapping: 5 source checks without a graph control", partialMapping(5))
	require.Equal(t, "partial mapping: 1 source check without a graph control", partialMapping(1))
	require.Empty(t, partialMapping(0))
}

func TestRollupRecordsEvidenceLists(t *testing.T) {
	ix := frameworks.NewIndex(rollupMatrices())
	st := rollupRequirement(frameworks.Requirement{ID: "R", Title: "t",
		Controls: []string{"aws-b/covered", "aws-b/partial", "aws-b/fails", "aws-b/blind", "az-b/missing"}}, ix, rollupEstate())
	require.Equal(t, []string{"c-ok", "c-fail", "c-blind"}, st.CheckIDs, "a check under two controls is listed once")
	require.Equal(t, []string{"c-fail"}, st.FailingChecks)
	require.Equal(t, []string{"c-blind"}, st.UnevaluatedChecks)
	require.Equal(t, []string{"az-b/missing"}, st.OutOfScope)
}

// Real registry checks, so classify runs AppliesTo/Evaluable for real.
const (
	s3Public = "aws-s3-public-bucket"
	ec2IP    = "aws-ec2-public-ip"
)

func serviceCatalog() Catalog {
	bs := []benchmarks.Benchmark{{ID: "aws-b", Providers: []string{"aws"}, Controls: []benchmarks.Control{
		{ID: "s3", Status: benchmarks.StatusCovered, CheckIDs: []string{s3Public}},
		{ID: "ec2", Status: benchmarks.StatusCovered, CheckIDs: []string{ec2IP}},
	}}}
	fws := []frameworks.Framework{{ID: "fw", Name: "FW", Version: "1", Source: "custom: fw.yaml", Requirements: []frameworks.Requirement{
		{ID: "R1", Title: "storage", Controls: []string{"aws-b/s3"}},
		{ID: "R2", Title: "both", Controls: []string{"aws-b/s3", "aws-b/ec2"}},
		{ID: "R3", Title: "manual"},
	}}}
	return NewCatalog(fws, bs)
}

func evaluableSample(t *testing.T, id string) asset.Asset {
	t.Helper()
	chk, ok := checks.Default().ByID(id)
	require.True(t, ok, id)
	md := map[string]string{}
	for _, k := range chk.RequiredKeys {
		md[k] = "observed"
	}
	return asset.Asset{Provider: chk.Provider, Type: chk.AssetType, Metadata: md}
}

type fakeOpen struct {
	byCheck map[string][]string
	err     error
	got     []string
}

func (f *fakeOpen) OpenResourcesByCheck(_ context.Context, ids []string) (map[string][]string, error) {
	f.got = ids
	return f.byCheck, f.err
}

func requirementService(t *testing.T, failing []string, samples []asset.Asset, open *fakeOpen) *Service {
	t.Helper()
	var fs []finding.Finding
	for _, id := range failing {
		fs = append(fs, finding.Finding{CheckID: id})
	}
	return NewService(fakeFindings{findings: fs}, &fakeInventory{samples: samples}, checks.Default(), freshAWS()).
		WithRequirements(serviceCatalog(), open)
}

func TestFrameworkRollupFromLiveEvidence(t *testing.T) {
	svc := requirementService(t, []string{ec2IP}, []asset.Asset{evaluableSample(t, s3Public), evaluableSample(t, ec2IP)}, &fakeOpen{})
	fs, err := svc.Framework(context.Background(), "fw")
	require.NoError(t, err)
	states := map[string]string{}
	for _, r := range fs.Requirements {
		states[r.ID] = r.State
	}
	require.Equal(t, map[string]string{"R1": RequirementPassing, "R2": RequirementFailing, "R3": RequirementManual}, states)
	require.Equal(t, FrameworkSummary{ID: "fw", Name: "FW", Version: "1", Source: "custom: fw.yaml", Total: 3, Passing: 1, Failing: 1, Manual: 1}, fs.FrameworkSummary)
}

// TestFrameworkRollupPartialEvidenceIsUnknown: one S3 bucket key set carrying
// the evidence must not vouch for buckets that were never observed.
func TestFrameworkRollupPartialEvidenceIsUnknown(t *testing.T) {
	blind := evaluableSample(t, s3Public)
	blind.Metadata = map[string]string{}
	svc := requirementService(t, nil, []asset.Asset{evaluableSample(t, s3Public), blind}, &fakeOpen{})
	fs, err := svc.Framework(context.Background(), "fw")
	require.NoError(t, err)
	require.Equal(t, RequirementUnknown, fs.Requirements[0].State)
	require.Equal(t, []string{s3Public}, fs.Requirements[0].UnevaluatedChecks)
}

func TestMissingEvidenceEntryReadsUnevaluated(t *testing.T) {
	ix := frameworks.NewIndex(rollupMatrices())
	est := rollupEstate()
	delete(est.evidence, "c-ok")
	st := rollupRequirement(frameworks.Requirement{ID: "R", Title: "t", Controls: []string{"aws-b/covered"}}, ix, est)
	require.Equal(t, RequirementUnknown, st.State, "a check absent from the evidence map is unevaluated, not 'nothing to evaluate'")
	require.Equal(t, []string{"c-ok"}, st.UnevaluatedChecks)
}

// TestFrameworkRollupNoInventoryIsNeverPassing: an empty inventory (no
// connector, or a sample read that found nothing) must read as unknown —
// "no findings" over nothing looked at is not compliance.
func TestFrameworkRollupNoInventoryIsNeverPassing(t *testing.T) {
	fws, err := requirementService(t, nil, nil, &fakeOpen{}).Frameworks(context.Background())
	require.NoError(t, err)
	require.Equal(t, []FrameworkSummary{{ID: "fw", Name: "FW", Version: "1", Source: "custom: fw.yaml", Total: 3, Unknown: 2, Manual: 1}}, fws)
}

func TestFrameworkRollupPropagatesErrors(t *testing.T) {
	svc := NewService(fakeFindings{err: errors.New("ch down")}, &fakeInventory{}, checks.Default(), freshAWS()).WithRequirements(serviceCatalog(), &fakeOpen{})
	_, err := svc.Frameworks(context.Background())
	require.ErrorContains(t, err, "ch down")
	svc = NewService(fakeFindings{}, &fakeInventory{err: errors.New("inventory down")}, checks.Default(), freshAWS()).WithRequirements(serviceCatalog(), &fakeOpen{})
	_, err = svc.Framework(context.Background(), "fw")
	require.ErrorContains(t, err, "inventory down", "an unread inventory is an error, never an all-unknown or all-passing report")
	_, err = NewService(fakeFindings{}, &fakeInventory{}, checks.Default(), &fakeConnectors{}).Frameworks(context.Background())
	require.Error(t, err, "an unwired rollup is an error, not an empty list")
}

func TestFrameworkNotFound(t *testing.T) {
	_, err := requirementService(t, nil, nil, &fakeOpen{}).Framework(context.Background(), "nope")
	require.ErrorIs(t, err, ErrFrameworkNotFound)
}

func TestExportCountsDistinctFailingResources(t *testing.T) {
	open := &fakeOpen{byCheck: map[string][]string{s3Public: {"b1", "b2"}, ec2IP: {"i1", "b2"}}}
	svc := requirementService(t, []string{s3Public, ec2IP}, []asset.Asset{evaluableSample(t, s3Public)}, open)
	fs, err := svc.ExportFramework(context.Background(), "fw")
	require.NoError(t, err)
	require.Equal(t, []string{ec2IP, s3Public}, open.got, "only failing checks are read, once each")
	counts := map[string]int{}
	for _, r := range fs.Requirements {
		counts[r.ID] = r.FailingResources
	}
	require.Equal(t, map[string]int{"R1": 2, "R2": 3, "R3": 0}, counts, "a resource failing two checks counts once")

	open.err = errors.New("ch down")
	_, err = svc.ExportFramework(context.Background(), "fw")
	require.ErrorContains(t, err, "ch down", "an unread resource count is an error, never a zero")
}

func TestFrameworkHandlers(t *testing.T) {
	open := &fakeOpen{byCheck: map[string][]string{ec2IP: {"i1"}}}
	h := NewHandler(requirementService(t, []string{ec2IP}, []asset.Asset{evaluableSample(t, s3Public), evaluableSample(t, ec2IP)}, open))

	rec := httptest.NewRecorder()
	h.ListFrameworks(rec, httptest.NewRequest(http.MethodGet, "/api/compliance/frameworks", nil))
	require.Equal(t, http.StatusOK, rec.Code)
	var list FrameworkListResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &list))
	require.Equal(t, []FrameworkSummaryResponse{{ID: "fw", Name: "FW", Version: "1", Source: "custom: fw.yaml", Total: 3, Passing: 1, Failing: 1, Manual: 1}}, list.Frameworks)

	req := httptest.NewRequest(http.MethodGet, "/api/compliance/frameworks/fw", nil)
	req.SetPathValue("id", "fw")
	rec = httptest.NewRecorder()
	h.GetFramework(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `"gaps":[]`, "lists are arrays, never null")

	req = httptest.NewRequest(http.MethodGet, "/api/compliance/frameworks/nope", nil)
	req.SetPathValue("id", "nope")
	rec = httptest.NewRecorder()
	h.GetFramework(rec, req)
	require.Equal(t, http.StatusNotFound, rec.Code)

	req = httptest.NewRequest(http.MethodGet, "/api/compliance/frameworks/fw/export", nil)
	req.SetPathValue("id", "fw")
	rec = httptest.NewRecorder()
	h.ExportFramework(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "text/csv; charset=utf-8", rec.Header().Get("Content-Type"))
	rows, err := csv.NewReader(rec.Body).ReadAll()
	require.NoError(t, err)
	require.Equal(t, exportHeader, rows[0])
	require.Equal(t, []string{"FW", "1", "R2", "both", "failing", "aws-b/s3; aws-b/ec2", s3Public + "; " + ec2IP, ec2IP, "", "", "", "", syncedAt.Format(time.RFC3339), "1"}, rows[2])
}

// TestExportFramework_NonAdmin_403: the export is gated to analysts (and
// admins) in the router; a viewer is refused before any rollup runs.
func TestExportFramework_NonAdmin_403(t *testing.T) {
	open := &fakeOpen{}
	h := NewHandler(requirementService(t, nil, nil, open))
	for role, want := range map[auth.Role]int{auth.RoleViewer: http.StatusForbidden, auth.RoleAnalyst: http.StatusOK, auth.RoleAdmin: http.StatusOK} {
		req := httptest.NewRequest(http.MethodGet, "/api/compliance/frameworks/fw/export", nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), auth.User{ID: "u", Role: role}))
		req.SetPathValue("id", "fw")
		rec := httptest.NewRecorder()
		auth.RequireRole(auth.RoleAnalyst, h.ExportFramework)(rec, req)
		require.Equal(t, want, rec.Code, string(role))
	}
}

func TestCSVSafe(t *testing.T) {
	// Every leading character a spreadsheet evaluates or treats as a formula.
	for _, lead := range []string{"=", "+", "-", "@", "\t", "\r"} {
		require.Equal(t, "'"+lead+"cmd", csvSafe(lead+"cmd"), "%q", lead)
	}
	require.Equal(t, "aws-b/s3", csvSafe("aws-b/s3"))
	require.Equal(t, "", csvSafe(""))
}

// TestEmbeddedCatalogLoads: the shipped mappings resolve against the shipped
// matrices (serve refuses to start otherwise).
func TestEmbeddedCatalogLoads(t *testing.T) {
	c, err := LoadCatalog("")
	require.NoError(t, err)
	require.NotEmpty(t, c.mappedChecks())
	for _, id := range c.mappedChecks() {
		_, ok := checks.Default().ByID(id)
		require.True(t, ok, "mapped check %s is not registered", id)
	}
}
