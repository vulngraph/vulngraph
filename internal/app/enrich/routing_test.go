package enrich

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type fakeOwnerResolver struct {
	got  asset.Asset
	keys []string
	out  asset.Ownership
	err  error
}

func (r *fakeOwnerResolver) ResolveOwner(_ context.Context, a asset.Asset, keys []string) (asset.Ownership, error) {
	r.got, r.keys = a, keys
	return r.out, r.err
}

func TestRoutingOf(t *testing.T) {
	ctx := context.Background()
	prodSeed := asset.Asset{ID: "r1", Tags: map[string]string{"env": "prod"}}
	owned := asset.Ownership{Team: "payments", Source: asset.OwnerSourceTag, Confidence: "high"}

	tests := []struct {
		name      string
		resolver  *fakeOwnerResolver
		f         finding.Finding
		seed      seedRead
		wantOwner asset.Ownership
		wantEnv   string
		wantAsset string // the asset id the resolver was asked about
	}{
		{
			name:      "resolved owner and classified environment",
			resolver:  &fakeOwnerResolver{out: owned},
			f:         finding.Finding{ID: "f", ResourceID: "r1"},
			seed:      seedRead{asset: prodSeed, fetched: true},
			wantOwner: owned, wantEnv: "prod", wantAsset: "r1",
		},
		{
			name:      "asset not in inventory: env unknown, owner still resolved by id",
			resolver:  &fakeOwnerResolver{out: asset.Ownership{Source: asset.OwnerSourceNone}},
			f:         finding.Finding{ID: "f", ResourceID: "r2"},
			seed:      seedRead{fetched: true, err: asset.ErrNotFound},
			wantOwner: asset.Ownership{Source: asset.OwnerSourceNone}, wantEnv: "unknown", wantAsset: "r2",
		},
		{
			name:     "seed read failed: nothing is claimed",
			resolver: &fakeOwnerResolver{out: owned},
			f:        finding.Finding{ID: "f", ResourceID: "r1"},
			seed:     seedRead{fetched: true, err: errors.New("ch down")},
		},
		{
			name: "seed never fetched: nothing is claimed",
			f:    finding.Finding{ID: "f", ResourceID: "r1"},
		},
		{
			name:     "owner read failed: unresolved, not unowned",
			resolver: &fakeOwnerResolver{err: errors.New("ch down")},
			f:        finding.Finding{ID: "f", ResourceID: "r1"},
			seed:     seedRead{asset: prodSeed, fetched: true},
			wantEnv:  "prod", wantAsset: "r1",
		},
		{
			name:      "no resource: unowned",
			resolver:  &fakeOwnerResolver{out: owned},
			f:         finding.Finding{ID: "f"},
			seed:      seedRead{fetched: true},
			wantOwner: asset.Ownership{Source: asset.OwnerSourceNone}, wantEnv: "unknown",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewService(&fakeFindingWriter{}, &fakeSignalRepo{}, nil)
			if tt.resolver != nil {
				WithOwnerResolver(tt.resolver, []string{"squad"})(s)
			}
			o, env := s.routingOf(ctx, tt.f, tt.seed, 0)
			assert.Equal(t, tt.wantOwner, o)
			assert.Equal(t, tt.wantEnv, env)
			if tt.resolver != nil {
				assert.Equal(t, tt.wantAsset, tt.resolver.got.ID)
				if tt.wantAsset != "" {
					assert.Equal(t, []string{"squad"}, tt.resolver.keys)
				}
			}
		})
	}
}

// The routing context reaches the persisted enrichment row and the returned
// score, so the alert routes on exactly what was stored.
func TestEnrich_StampsRoutingContext(t *testing.T) {
	fw := &fakeFindingWriter{}
	seed := asset.Asset{ID: "r1", Tags: map[string]string{"environment": "staging", "team": "Payments"}}
	resolver := &fakeOwnerResolver{out: asset.Ownership{Team: "payments", Source: asset.OwnerSourceTag, Confidence: "high"}}
	svc := NewService(fw, &fakeSignalRepo{}, []Source{BaseSeverity{}},
		WithSafetyProvider(fakeSafetyProvider{seed: seed}),
		WithOwnerResolver(resolver, nil))

	score, err := svc.Enrich(context.Background(), finding.Finding{ID: "f", ResourceID: "r1", Severity: finding.SeverityHigh})
	require.NoError(t, err)
	require.Len(t, fw.recorded, 1)
	got := fw.recorded[0]
	assert.Equal(t, "payments", got.OwnerTeam)
	assert.Equal(t, "tag", got.OwnerSource)
	assert.Equal(t, "high", got.OwnerConfidence)
	assert.Equal(t, "staging", got.Environment)
	assert.Equal(t, "payments", score.Owner.Team)
	assert.Equal(t, "staging", score.Environment)
}
