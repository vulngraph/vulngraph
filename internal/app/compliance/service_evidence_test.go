package compliance

import (
	"context"
	"encoding/csv"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/checks/frameworks"
)

// syncedAt is a last successful sync well inside connector.DefaultStaleAfter.
var syncedAt = time.Now().Add(-time.Hour).UTC().Truncate(time.Second)

type fakeConnectors struct {
	conns []connector.Connector
	err   error
}

func (f *fakeConnectors) List(context.Context, bool) ([]connector.Connector, error) {
	return f.conns, f.err
}

func conn(typ connector.Type, success *time.Time) connector.Connector {
	return connector.Connector{Type: typ, Enabled: true, CreatedAt: syncedAt.Add(-48 * time.Hour), LastSuccessAt: success}
}

func freshAWS() *fakeConnectors {
	return &fakeConnectors{conns: []connector.Connector{conn(connector.TypeAWS, &syncedAt)}}
}

func TestCloudEvidence(t *testing.T) {
	now := syncedAt.Add(time.Hour)
	old := now.Add(-3 * connector.DefaultStaleAfter)
	older := syncedAt.Add(-time.Hour)
	partial := conn(connector.TypeGCP, &syncedAt)
	partial.PartialStreak = connector.DefaultPartialStreakThreshold
	disabled := conn(connector.TypeKubernetes, nil)
	disabled.Enabled = false

	got := cloudEvidence([]connector.Connector{
		conn(connector.TypeAWS, &syncedAt), conn(connector.TypeAWS, &older), // fresh; as-of is the oldest
		conn(connector.TypeAzure, &old), // stale: no success within DefaultStaleAfter
		partial,                         // keeps finishing Partial
		conn(connector.TypeAWSOrg, nil), // manages accounts, collects nothing
		disabled,                        // not configured as far as evidence goes
	}, map[string]bool{"aws": true, "azure": true, "gcp": true, "kubernetes": true}, now)

	require.Equal(t, CloudEvidence{Provider: "aws", Connectors: 2, HasInventory: true, EvidenceAsOf: older}, got["aws"])
	require.True(t, got["azure"].Stale)
	require.True(t, got["gcp"].Stale, "a partially failing connector cannot vouch for its cloud")
	require.Equal(t, CloudEvidence{Provider: "kubernetes", HasInventory: true, Stale: true}, got["kubernetes"],
		"inventory no enabled connector refreshes is stale")

	never := cloudEvidence([]connector.Connector{conn(connector.TypeAWS, &syncedAt), conn(connector.TypeAWS, nil)},
		map[string]bool{"aws": true}, now)["aws"]
	require.True(t, never.Stale, "one account that never synced makes the cloud stale")
	require.True(t, never.EvidenceAsOf.IsZero(), "and its evidence age unknown, not the other account's date")

	empty := cloudEvidence([]connector.Connector{conn(connector.TypeAzure, &syncedAt)}, nil, now)["azure"]
	require.Equal(t, CloudEvidence{Provider: "azure", Connectors: 1, EvidenceAsOf: syncedAt, Stale: true}, empty,
		"a connector that produced no inventory is in scope and stale")
}

func TestRollupEvidenceGaps(t *testing.T) {
	ix := frameworks.NewIndex(rollupMatrices())
	req := frameworks.Requirement{ID: "R", Title: "t", Controls: []string{"aws-b/covered", "az-b/missing"}}

	est := rollupEstate()
	est.clouds["azure"] = CloudEvidence{Provider: "azure", Connectors: 1, Stale: true}
	st := rollupRequirement(req, ix, est)
	require.Equal(t, RequirementUnknown, st.State, "a configured cloud with no assets is in scope, not out of scope")
	require.Equal(t, []string{"az-b/missing"}, st.EvidenceGaps)
	require.True(t, st.EvidenceAsOf.IsZero(), "a cloud that never synced makes the evidence age unknown")

	est = rollupEstate()
	ce := est.clouds["aws"]
	ce.Stale = true
	est.clouds["aws"] = ce
	st = rollupRequirement(frameworks.Requirement{ID: "R", Title: "t", Controls: []string{"aws-b/covered"}}, ix, est)
	require.Equal(t, RequirementUnknown, st.State, "stale evidence is not a pass")
	require.Equal(t, []string{"aws-b/covered"}, st.EvidenceGaps)

	st = rollupRequirement(frameworks.Requirement{ID: "R", Title: "t", Controls: []string{"aws-b/covered"}}, ix, rollupEstate())
	require.Equal(t, RequirementPassing, st.State)
	require.Equal(t, syncedAt, st.EvidenceAsOf)
}

func TestFrameworkRollupConnectorWithoutAssets(t *testing.T) {
	svc := NewService(fakeFindings{}, &fakeInventory{}, checks.Default(), freshAWS()).
		WithRequirements(serviceCatalog(), &fakeOpen{})
	fs, err := svc.Framework(context.Background(), "fw")
	require.NoError(t, err)
	require.Equal(t, []CloudEvidence{{Provider: "aws", Connectors: 1, EvidenceAsOf: syncedAt, Stale: true}}, fs.Clouds)
	require.Equal(t, RequirementUnknown, fs.Requirements[0].State)
	require.Equal(t, []string{"aws-b/s3"}, fs.Requirements[0].EvidenceGaps)

	svc = NewService(fakeFindings{}, &fakeInventory{}, checks.Default(), &fakeConnectors{err: errors.New("pg down")}).
		WithRequirements(serviceCatalog(), &fakeOpen{})
	_, err = svc.Frameworks(context.Background())
	require.ErrorContains(t, err, "pg down", "an unread connector list is an error, never 'no clouds in scope'")
}

func TestExportUnmeasuredResourcesAreNotZero(t *testing.T) {
	open := &fakeOpen{byCheck: map[string][]string{}} // ec2IP fails on findings that name no resource
	svc := requirementService(t, []string{ec2IP}, []asset.Asset{evaluableSample(t, s3Public), evaluableSample(t, ec2IP)}, open)
	fs, err := svc.ExportFramework(context.Background(), "fw")
	require.NoError(t, err)
	require.False(t, fs.Requirements[1].FailingResourcesKnown)
	require.True(t, fs.Requirements[0].FailingResourcesKnown, "a requirement with no failing check measured zero")

	req := httptest.NewRequest(http.MethodGet, "/api/compliance/frameworks/fw/export", nil)
	req.SetPathValue("id", "fw")
	rec := httptest.NewRecorder()
	NewHandler(svc).ExportFramework(rec, req)
	rows, err := csv.NewReader(rec.Body).ReadAll()
	require.NoError(t, err)
	last := len(exportHeader) - 1
	require.Equal(t, "n/a", rows[2][last])
	require.Equal(t, "0", rows[1][last])
	require.Equal(t, syncedAt.Format(time.RFC3339), rows[1][last-1])
}
