package enrich

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type fakeResolver struct {
	found bool
	err   error
}

func (f fakeResolver) Resolves(context.Context, string) (bool, error) { return f.found, f.err }

type oneAsset struct{ a asset.Asset }

func (o oneAsset) Get(context.Context, string) (asset.Asset, error) { return o.a, nil }

func takeoverFinding() finding.Finding {
	return finding.Finding{CheckID: "dns-cname-takeover-risk", ResourceID: "rec1"}
}

func recordAsset(values string) oneAsset {
	return oneAsset{a: asset.Asset{ID: "rec1", Type: "dns_record", Metadata: map[string]string{"values": values}}}
}

func TestDNSTakeover_NXDOMAINConfirms(t *testing.T) {
	src := DNSTakeover{Assets: recordAsset("old-app.herokuapp.com"), Resolver: fakeResolver{found: false}}
	f, ok, err := src.Evaluate(context.Background(), takeoverFinding())
	require.NoError(t, err)
	require.True(t, ok, "a non-resolving target confirms the takeover candidate")
	require.Equal(t, ThresholdHigh, f.Floor)
	require.Positive(t, f.Points)
	require.Contains(t, f.Detail, "old-app.herokuapp.com")
}

func TestDNSTakeover_ResolvingStaysCandidate(t *testing.T) {
	// A resolving target is NOT refuted — DNS can't prove ownership (HTTP-layer
	// takeovers still resolve). Leave the finding at its pattern severity.
	src := DNSTakeover{Assets: recordAsset("live.cloudfront.net"), Resolver: fakeResolver{found: true}}
	_, ok, err := src.Evaluate(context.Background(), takeoverFinding())
	require.NoError(t, err)
	require.False(t, ok)
}

func TestDNSTakeover_TransientErrorInconclusive(t *testing.T) {
	src := DNSTakeover{Assets: recordAsset("x.herokuapp.com"), Resolver: fakeResolver{err: errors.New("timeout")}}
	_, ok, err := src.Evaluate(context.Background(), takeoverFinding())
	require.NoError(t, err, "a transient resolver error must not surface as a source error")
	require.False(t, ok, "inconclusive — never conclude from a transient failure")
}

func TestDNSTakeover_OnlyTakeoverChecks(t *testing.T) {
	src := DNSTakeover{Assets: recordAsset("x.herokuapp.com"), Resolver: fakeResolver{found: false}}
	f := finding.Finding{CheckID: "aws-s3-public-bucket", ResourceID: "rec1"}
	_, ok, _ := src.Evaluate(context.Background(), f)
	require.False(t, ok, "non-takeover checks are out of scope")
}

func TestDNSTakeover_DisabledWithoutResolver(t *testing.T) {
	src := DNSTakeover{Assets: recordAsset("x.herokuapp.com")} // no resolver
	_, ok, _ := src.Evaluate(context.Background(), takeoverFinding())
	require.False(t, ok)
}

func TestFirstDNSValue(t *testing.T) {
	require.Equal(t, "a.example.com", firstDNSValue("a.example.com."))
	require.Equal(t, "a.example.com", firstDNSValue(" a.example.com , b.example.com"))
	require.Equal(t, "", firstDNSValue(""))
}
