package jobs

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// fakeLive is a fake liveRoleGetter.
type fakeLive struct {
	role map[string]any
	err  error
}

func (f *fakeLive) GetRole(_ context.Context, _, _ string) (map[string]any, error) {
	return f.role, f.err
}

// errNoSuchEntity mimics the smithy.APIError shape AWS's IAM SDK returns for a
// role that no longer exists — GetRole wraps this in mcp/live_aws.go with %w,
// so it must still be reachable via errors.As after wrapping.
type fakeAPIError struct{ code string }

func (e fakeAPIError) ErrorCode() string    { return e.code }
func (e fakeAPIError) ErrorMessage() string { return "not found" }
func (e fakeAPIError) ErrorFault() smithy.ErrorFault {
	return smithy.FaultUnknown
}
func (e fakeAPIError) Error() string { return e.code }

var errNoSuchEntity error = fakeAPIError{code: "NoSuchEntity"}

// fakeSink captures every asset/edge/finding write the worker makes.
type fakeSink struct {
	assets   []asset.Asset
	edges    []asset.Edge
	findings []finding.Finding
}

func (s *fakeSink) Ingest(_ context.Context, assets []asset.Asset, edges []asset.Edge) error {
	s.assets = append(s.assets, assets...)
	s.edges = append(s.edges, edges...)
	return nil
}

func (s *fakeSink) RecordObserved(_ context.Context, findings []finding.Finding) error {
	s.findings = append(s.findings, findings...)
	return nil
}

// stubConnectorByAccount fakes connectorAccountLookup: accountID maps to
// connectorID when non-empty, otherwise no connector is found.
type stubConnectorByAccount struct {
	accountID, connectorID string
}

func (s stubConnectorByAccount) ConnectorByAccountID(_ context.Context, accountID string) (string, bool, error) {
	if accountID == s.accountID && s.connectorID != "" {
		return s.connectorID, true, nil
	}
	return "", false, nil
}

func TestVerifyCIRole_RoleExists_EmitsAssetAndEdge(t *testing.T) {
	live := &fakeLive{role: map[string]any{"arn": "arn:aws:iam::999:role/mystery", "role_name": "mystery"}}
	sink := &fakeSink{}
	w := NewVerifyCIRoleWorker(live, stubConnectorByAccount{accountID: "999", connectorID: "conn-1"}, sink, sink)

	err := w.run(context.Background(), VerifyCIRoleArgs{
		RepoID: "r", TargetARN: "arn:aws:iam::999:role/mystery", AccountID: "999",
		WorkflowPath: ".github/workflows/deploy.yml",
	})

	require.NoError(t, err)
	require.Len(t, sink.edges, 1)
	assert.Equal(t, "gh_workflow+live", sink.edges[0].Properties["provenance"])
	assert.Equal(t, ".github/workflows/deploy.yml", sink.edges[0].Properties["workflow_path"])
	assert.Equal(t, "r", sink.edges[0].SrcID)
	assert.Equal(t, "arn:aws:iam::999:role/mystery", sink.edges[0].DstID)
	require.Len(t, sink.assets, 1)
	assert.Equal(t, "iam_role", sink.assets[0].Type)
	assert.Equal(t, "arn:aws:iam::999:role/mystery", sink.assets[0].ID)
	assert.Empty(t, sink.findings)
}

func TestVerifyCIRole_NoSuchEntity_Drops(t *testing.T) {
	live := &fakeLive{err: errNoSuchEntity}
	sink := &fakeSink{}
	w := NewVerifyCIRoleWorker(live, stubConnectorByAccount{accountID: "999", connectorID: "conn-1"}, sink, sink)

	err := w.run(context.Background(), VerifyCIRoleArgs{RepoID: "r", TargetARN: "arn:aws:iam::999:role/x", AccountID: "999"})

	require.NoError(t, err)
	assert.Empty(t, sink.edges)
	assert.Empty(t, sink.assets)
	assert.Empty(t, sink.findings)
}

func TestVerifyCIRole_OtherGetRoleError_ReturnsWrappedError(t *testing.T) {
	live := &fakeLive{err: errors.New("throttled")}
	sink := &fakeSink{}
	w := NewVerifyCIRoleWorker(live, stubConnectorByAccount{accountID: "999", connectorID: "conn-1"}, sink, sink)

	err := w.run(context.Background(), VerifyCIRoleArgs{RepoID: "r", TargetARN: "arn:aws:iam::999:role/x", AccountID: "999"})

	require.Error(t, err)
	assert.Empty(t, sink.edges)
	assert.Empty(t, sink.findings)
}

func TestVerifyCIRole_NoConnectorForAccount_EmitsFinding(t *testing.T) {
	sink := &fakeSink{}
	w := NewVerifyCIRoleWorker(&fakeLive{}, stubConnectorByAccount{}, sink, sink)

	err := w.run(context.Background(), VerifyCIRoleArgs{RepoID: "r", TargetARN: "arn:aws:iam::888:role/x", AccountID: "888"})

	require.NoError(t, err)
	if assert.Len(t, sink.findings, 1) {
		assert.Equal(t, "unmonitored_federation", sink.findings[0].Type)
		assert.Equal(t, "ci_access", sink.findings[0].Source)
		assert.Equal(t, "github_repo", sink.findings[0].ResourceType)
		assert.Equal(t, "r", sink.findings[0].ResourceID)
		assert.Contains(t, sink.findings[0].Description, "888")
		assert.NotContains(t, sink.findings[0].Description, "()",
			"blank WorkflowPath must not leave dangling empty parens in the finding description")
	}
	assert.Empty(t, sink.edges)
	assert.Empty(t, sink.assets)
}

func TestVerifyCIRole_NoConnectorForAccount_EmitsFinding_WithWorkflowPath(t *testing.T) {
	sink := &fakeSink{}
	w := NewVerifyCIRoleWorker(&fakeLive{}, stubConnectorByAccount{}, sink, sink)

	err := w.run(context.Background(), VerifyCIRoleArgs{
		RepoID: "r", TargetARN: "arn:aws:iam::888:role/x", AccountID: "888",
		WorkflowPath: ".github/workflows/deploy.yml",
	})

	require.NoError(t, err)
	if assert.Len(t, sink.findings, 1) {
		assert.Contains(t, sink.findings[0].Description, "(.github/workflows/deploy.yml)")
	}
}

func TestVerifyCIRoleArgs_InsertOpts(t *testing.T) {
	opts := VerifyCIRoleArgs{}.InsertOpts()
	assert.Equal(t, queueSync, opts.Queue)
	assert.Equal(t, 3, opts.MaxAttempts)
}
