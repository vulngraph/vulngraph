package diskscan

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSource struct{}

func (fakeSource) ReadAt([]byte, int64) (int, error) { return 0, ErrBlockUnreadable }
func (fakeSource) Size() int64                       { return 0 }
func (fakeSource) Close() error                      { return nil }

type fakeProvider struct{}

func (fakeProvider) ListReusable(context.Context, VolumeRef) ([]Snapshot, error) { return nil, nil }
func (fakeProvider) Open(context.Context, Snapshot) (BlockSource, error)         { return fakeSource{}, nil }
func (fakeProvider) Changed(context.Context, Snapshot, Snapshot) ([]Extent, error) {
	return nil, ErrNoDiff
}

type fakeSnapshotter struct{}

func (fakeSnapshotter) CreateTagged(context.Context, OptIn, VolumeRef, string) (Snapshot, error) {
	return Snapshot{}, nil
}
func (fakeSnapshotter) DeleteTagged(context.Context, OptIn, Snapshot) error { return nil }
func (fakeSnapshotter) ListTagged(context.Context, OptIn) ([]Snapshot, error) {
	return nil, nil
}

var (
	_ BlockSource = fakeSource{}
	_ Provider    = fakeProvider{}
	_ Snapshotter = fakeSnapshotter{}
)

func TestAuthorize(t *testing.T) {
	tests := []struct {
		name  string
		grant ConnectorGrant
		ok    bool
	}{
		{"mode off", ConnectorGrant{DiskScanRole: "arn:ds"}, false},
		{"existing snapshots", ConnectorGrant{Mode: "existing_snapshots", DiskScanRole: "arn:ds"}, false},
		{"empty role", ConnectorGrant{Mode: ModeCreateSnapshots}, false},
		{"role equals collection role", ConnectorGrant{Mode: ModeCreateSnapshots, DiskScanRole: "arn:a", OtherRoles: []string{"arn:b", "arn:a"}}, false},
		{"authorized", ConnectorGrant{Mode: ModeCreateSnapshots, DiskScanRole: "arn:ds", OtherRoles: []string{"arn:a", ""}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			optIn, err := Authorize(tc.grant)
			if !tc.ok {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ErrNotAuthorized))
				assert.False(t, optIn.Valid())
				return
			}
			require.NoError(t, err)
			assert.True(t, optIn.Valid())
			assert.Equal(t, tc.grant.DiskScanRole, optIn.Role())
		})
	}
}

func TestZeroValuesAreUnknown(t *testing.T) {
	assert.False(t, OptIn{}.Valid())
	assert.False(t, DiskResult{}.InventoryKnown)
	assert.Nil(t, DiskResult{}.Packages)
}

func TestAuthorizeRead(t *testing.T) {
	tests := []struct {
		name  string
		grant ConnectorGrant
		ok    bool
	}{
		{"mode off", ConnectorGrant{DiskScanRole: "client-ds"}, false},
		{"unknown mode", ConnectorGrant{Mode: "snapshots", DiskScanRole: "client-ds"}, false},
		{"empty principal, existing", ConnectorGrant{Mode: ModeExistingSnapshots}, false},
		{"empty principal, create", ConnectorGrant{Mode: ModeCreateSnapshots}, false},
		{"principal equals collection", ConnectorGrant{Mode: ModeExistingSnapshots, DiskScanRole: "a", OtherRoles: []string{"b", "a"}}, false},
		{"existing snapshots", ConnectorGrant{Mode: ModeExistingSnapshots, DiskScanRole: "client-ds", OtherRoles: []string{"a", ""}}, true},
		{"create snapshots", ConnectorGrant{Mode: ModeCreateSnapshots, DiskScanRole: "client-ds"}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in, err := AuthorizeRead(tc.grant)
			if !tc.ok {
				require.ErrorIs(t, err, ErrNotAuthorized)
				assert.False(t, in.Valid())
				assert.Empty(t, in.Principal())
				return
			}
			require.NoError(t, err)
			assert.True(t, in.Valid())
			assert.Equal(t, "client-ds", in.Principal())
		})
	}
	assert.False(t, ReadOptIn{}.Valid(), "the zero value authorizes nothing")
}

// A read opt-in and a create opt-in are different types: a ReadOptIn can never
// be passed where snapshot creation or deletion is authorized, and existing
// snapshots mode yields a ReadOptIn but never an OptIn.
func TestReadOptInNeverAuthorizesWrites(t *testing.T) {
	g := ConnectorGrant{Mode: ModeExistingSnapshots, DiskScanRole: "client-ds"}
	_, err := AuthorizeRead(g)
	require.NoError(t, err)
	_, err = Authorize(g)
	require.ErrorIs(t, err, ErrNotAuthorized)
}
