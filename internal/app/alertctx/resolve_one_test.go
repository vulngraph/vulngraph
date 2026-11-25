package alertctx

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestResolveOne(t *testing.T) {
	// An asset anyone can name: its Name is the real instance's id, and it
	// shares the instance's public IP.
	squatter := asset.Asset{ID: "squat-1", Name: instance.ID, Type: "ec2_instance", PublicIP: instance.PublicIP}
	twin := asset.Asset{ID: "web-2", Name: "web-1", Type: "ec2_instance"}

	for _, tc := range []struct {
		name   string
		store  *fakeStore
		input  string
		wantID string
		want   error
	}{
		{name: "exact id wins over a same-named squatter", input: instance.ID, wantID: instance.ID,
			store: &fakeStore{assets: []asset.Asset{instance, squatter}}},
		{name: "a unique IP resolves", input: "10.0.1.5", wantID: instance.ID, store: standardStore()},
		{name: "a shared IP is ambiguous", input: instance.PublicIP, want: ErrAmbiguous,
			store: &fakeStore{assets: []asset.Asset{instance, squatter}}},
		{name: "a shared name is ambiguous", input: "web-1", want: ErrAmbiguous,
			store: &fakeStore{assets: []asset.Asset{instance, twin}}},
		{name: "nothing matches", input: "nothing-here", want: ErrUnresolved, store: standardStore()},
		{name: "a failed lookup is not 'not found'", input: "web-1", want: ErrLookupFailed,
			store: &fakeStore{assets: []asset.Asset{instance}, attrErr: errors.New("ch down")}},
		{name: "an exact id still resolves when the attribute lookup failed", input: "web-1", wantID: "web-1",
			store: &fakeStore{assets: []asset.Asset{{ID: "web-1", Name: "x"}, twin}, attrErr: errors.New("ch down")}},
		{name: "a cut-off scan cannot prove uniqueness", input: "10.0.1.5", want: ErrLookupFailed,
			store: &fakeStore{assets: []asset.Asset{instance}, capped: true}},
		{name: "empty", input: "  ", want: ErrEmptyIdentfier, store: standardStore()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, m, err := newSvc(tc.store, fakeBlast{}, fakeFindings{}).ResolveOne(context.Background(), tc.input)
			if tc.want != nil {
				require.ErrorIs(t, err, tc.want)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantID, a.ID)
			require.Equal(t, tc.wantID, m.AssetID)
		})
	}
}
