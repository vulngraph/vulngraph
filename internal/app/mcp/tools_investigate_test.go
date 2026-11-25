package mcp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/alertctx"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// fakeResolver resolves one known identifier and fails the rest with err.
type fakeResolver struct {
	a   asset.Asset
	id  string
	err error
}

func (f fakeResolver) ResolveOne(_ context.Context, identifier string) (asset.Asset, alertctx.Match, error) {
	if f.err != nil {
		return asset.Asset{}, alertctx.Match{}, f.err
	}
	if identifier != f.id {
		return asset.Asset{}, alertctx.Match{}, alertctx.ErrUnresolved
	}
	return f.a, alertctx.Match{AssetID: f.a.ID, MatchType: alertctx.MatchID, Confidence: alertctx.ConfExact}, nil
}

// fixedAsset answers the blast walk for one asset, or fails it.
type fixedAsset struct {
	a        asset.Asset
	blastErr error
}

func (f fixedAsset) Get(context.Context, string) (asset.Asset, error) { return f.a, nil }
func (f fixedAsset) BlastRadius(context.Context, string, int) (asset.BlastRadius, error) {
	if f.blastErr != nil {
		return asset.BlastRadius{}, f.blastErr
	}
	return asset.BlastRadius{SeedID: f.a.ID, Assets: []asset.Asset{f.a, {ID: "reach-1"}}, Truncated: true}, nil
}

// List would be the old ILIKE fallback; investigate_resource must never call it.
func (f fixedAsset) List(context.Context, asset.Filter) ([]asset.Asset, error) {
	panic("investigate_resource must not search assets by substring")
}

// filterAwareFindings answers List by exact ResourceID + Source, the way the CH
// repo does, so a test can tell an ID-keyed query from a name-keyed one.
type filterAwareFindings struct {
	byKey  map[string][]finding.Finding // keyed "<resource_id>|<source>"
	errFor string                       // a Source whose read fails
	called []finding.Filter
}

func (f *filterAwareFindings) List(_ context.Context, flt finding.Filter) ([]finding.Finding, error) {
	f.called = append(f.called, flt)
	if f.errFor != "" && flt.Source == f.errFor {
		return nil, errors.New("clickhouse down")
	}
	return f.byKey[flt.ResourceID+"|"+flt.Source], nil
}

func investigateHandler(r ResourceResolver, assets AssetReader, findings FindingLister) *Handler {
	return newHandler().WithResourceResolver(r, assets, findings)
}

func investigateText(t *testing.T, h *Handler, identifier string) string {
	t.Helper()
	resp := rpc(t, h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"investigate_resource","arguments":{"identifier":"`+identifier+`"}}}`)
	require.Nil(t, resp.Error)
	return resp.Result.(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
}

func TestInvestigateResource_ResolvesExactly(t *testing.T) {
	a := asset.Asset{ID: "i-abc123", Name: "web", Type: "ec2_instance"}
	h := investigateHandler(fakeResolver{a: a, id: "i-abc123"}, fixedAsset{a: a}, &filterAwareFindings{})
	text := investigateText(t, h, "i-abc123")
	require.Contains(t, text, `"confidence":"exact"`)
	require.Contains(t, text, `"blast_radius_known":true`)
	require.Contains(t, text, `"blast_radius_count":1`, "the seed is not part of its own blast radius")
	require.Contains(t, text, `"blast_radius_truncated":true`)
	require.Contains(t, text, "blast radius reaches at least 1 assets")
	require.Contains(t, text, `"findings_known":true`)
}

// An identifier that names no single asset is an explicit error the client
// can act on — never the first substring match.
func TestInvestigateResource_AmbiguousOrUnresolvedIsAnError(t *testing.T) {
	for _, err := range []error{
		alertctx.ErrUnresolved,
		fmtErr(alertctx.ErrAmbiguous),
	} {
		h := investigateHandler(fakeResolver{err: err}, fixedAsset{}, &filterAwareFindings{})
		resp := rpc(t, h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"investigate_resource","arguments":{"identifier":"prod"}}}`)
		require.NotNil(t, resp.Error)
		require.Equal(t, codeInvalidParams, resp.Error.Code, err.Error())
	}

	h := investigateHandler(fakeResolver{err: fmtErr(alertctx.ErrLookupFailed)}, fixedAsset{}, &filterAwareFindings{})
	resp := rpc(t, h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"investigate_resource","arguments":{"identifier":"prod"}}}`)
	require.NotNil(t, resp.Error)
	require.Equal(t, codeInternal, resp.Error.Code, "a failed lookup is not 'not found'")

	resp = rpc(t, h, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"investigate_resource","arguments":{}}}`)
	require.NotNil(t, resp.Error)
	require.Equal(t, codeInvalidParams, resp.Error.Code)
}

func fmtErr(err error) error { return errors.Join(err, errors.New("detail")) }

// A failed findings read or blast walk is NOT MEASURED, never "0 findings" or
// "reaches 0 assets".
func TestInvestigateResource_FailedSectionsAreUnknownNotZero(t *testing.T) {
	a := asset.Asset{ID: "i-abc123", Name: "web", Type: "ec2_instance"}
	h := investigateHandler(fakeResolver{a: a, id: a.ID}, fixedAsset{a: a, blastErr: errors.New("walk failed")},
		&filterAwareFindings{errFor: ""})
	text := investigateText(t, h, a.ID)
	require.Contains(t, text, `"blast_radius_known":false`)
	require.NotContains(t, text, "blast_radius_count")
	require.Contains(t, text, "blast radius unavailable")

	role := asset.Asset{ID: "arn:aws:iam::1:role/ops", Name: "ops", Type: "iam_role"}
	h = investigateHandler(fakeResolver{a: role, id: role.ID}, fixedAsset{a: role},
		&filterAwareFindings{errFor: "aws_guardduty"})
	text = investigateText(t, h, role.ID)
	require.Contains(t, text, `"findings_known":false`, "a failed name-keyed read makes the list partial")
	require.NotContains(t, text, "0 findings")
	require.Contains(t, text, "findings unavailable")
}

// An aws_guardduty iam_user finding is keyed by the role NAME while the asset is
// keyed by ARN, so an ID-only join reports "0 findings" for a role with an active
// detection. The merge must find it — and must sort it to the front.
func TestInvestigateResource_MergesNameKeyedGuardDutyFinding(t *testing.T) {
	const (
		roleName = "orders-app-Task"
		roleARN  = "arn:aws:iam::111122223333:role/" + roleName
	)
	findings := &filterAwareFindings{byKey: map[string][]finding.Finding{
		roleARN + "|": {{ID: "low-1", Score: 10, ResourceID: roleARN}},
		roleName + "|aws_guardduty": {{
			ID: "gd-1", Score: 61, Source: "aws_guardduty",
			ResourceType: "iam_user", ResourceID: roleName,
		}},
	}}
	a := asset.Asset{ID: roleARN, Name: roleName, Type: "iam_role"}
	text := investigateText(t, investigateHandler(fakeResolver{a: a, id: roleARN}, fixedAsset{a: a}, findings), roleARN)
	require.Contains(t, text, "gd-1", "the name-keyed GuardDuty finding must be joined")
	require.Contains(t, text, "2 findings", "summary counts both")
	require.Less(t, strings.Index(text, "gd-1"), strings.Index(text, "low-1"),
		"the higher-scoring detection must sort ahead of the routine finding")
}

// Asset names are not unique — every VPC has a security group called "default".
// Only the verified name-keyed types may take the name path.
func TestInvestigateResource_DoesNotJoinByNameForNonIAMAssets(t *testing.T) {
	findings := &filterAwareFindings{byKey: map[string][]finding.Finding{
		"sg-123|": {{ID: "own-1", Score: 5, ResourceID: "sg-123"}},
	}}
	a := asset.Asset{ID: "sg-123", Name: "default", Type: "security_group"}
	investigateText(t, investigateHandler(fakeResolver{a: a, id: "sg-123"}, fixedAsset{a: a}, findings), "sg-123")
	for _, flt := range findings.called {
		require.NotEqual(t, "default", flt.ResourceID, "must never query findings by a non-unique asset name")
	}
}
