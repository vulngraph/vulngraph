package snapshotter

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan"
)

const (
	azSubPrefix = "/subscriptions/sub/resourceGroups/"
	azDiskID    = azSubPrefix + "rg-disks/providers/Microsoft.Compute/disks/osdisk"
	azSnapID    = azSubPrefix + "rg-scan/providers/Microsoft.Compute/snapshots/s1"
)

// countingAzure records every call and can fail chosen operations.
type countingAzure struct {
	calls   []string
	live    map[string]armcompute.Snapshot
	failOn  map[string]error
	sas     string
	created int
}

func newCountingAzure() *countingAzure {
	return &countingAzure{live: map[string]armcompute.Snapshot{}, failOn: map[string]error{}, sas: "https://x/sas"}
}

func (f *countingAzure) count(op string) int {
	n := 0
	for _, c := range f.calls {
		if c == op {
			n++
		}
	}
	return n
}

func (f *countingAzure) do(op string) error {
	f.calls = append(f.calls, op)
	return f.failOn[op]
}

func (f *countingAzure) create(_ context.Context, rg, name string, s armcompute.Snapshot) (armcompute.Snapshot, error) {
	if err := f.do("create"); err != nil {
		return armcompute.Snapshot{}, err
	}
	f.created++
	s.ID = new(azSubPrefix + rg + "/providers/Microsoft.Compute/snapshots/" + name)
	f.live[name] = s
	return s, nil
}

func (f *countingAzure) remove(_ context.Context, _, name string) error {
	if err := f.do("delete"); err != nil {
		return err
	}
	delete(f.live, name)
	return nil
}

func (f *countingAzure) grantRead(context.Context, string, string, int32) (string, error) {
	if err := f.do("grant_read"); err != nil {
		return "", err
	}
	return f.sas, nil
}

func (f *countingAzure) revokeRead(context.Context, string, string) error { return f.do("revoke_read") }

func (f *countingAzure) get(_ context.Context, _, name string) (armcompute.Snapshot, error) {
	f.calls = append(f.calls, "get")
	if err := f.failOn["get"]; err != nil {
		return armcompute.Snapshot{}, err
	}
	s, ok := f.live[name]
	if !ok {
		return armcompute.Snapshot{}, errAzureNotFound
	}
	return s, nil
}

func (f *countingAzure) list(context.Context, string) ([]*armcompute.Snapshot, error) {
	f.calls = append(f.calls, "list")
	var out []*armcompute.Snapshot
	for _, s := range f.live {
		out = append(out, &s)
	}
	return out, nil
}

func azOptIn(t *testing.T) diskscan.OptIn {
	t.Helper()
	o, err := diskscan.Authorize(diskscan.ConnectorGrant{Mode: diskscan.ModeCreateSnapshots, DiskScanRole: "scan-client", OtherRoles: []string{"collect"}})
	require.NoError(t, err)
	return o
}

func azReadIn(t *testing.T) diskscan.ReadOptIn {
	t.Helper()
	o, err := diskscan.AuthorizeRead(diskscan.ConnectorGrant{Mode: diskscan.ModeExistingSnapshots, DiskScanRole: "scan-client", OtherRoles: []string{"collect"}})
	require.NoError(t, err)
	return o
}

func newTestReader(t *testing.T, api azureReadAPI) *AzureReader {
	t.Helper()
	r, err := newAzureReader(azReadIn(t), AzureConfig{SubscriptionID: "sub"}, api)
	require.NoError(t, err)
	return r
}

func newTestAzure(t *testing.T, api azureSnapshotAPI) *Azure {
	t.Helper()
	a, err := newAzure(azOptIn(t), AzureConfig{ResourceGroup: "rg-scan", SubscriptionID: "sub"}, api)
	require.NoError(t, err)
	return a
}

func TestAzure_RequiresValidOptIn(t *testing.T) {
	api := newCountingAzure()
	_, err := newAzure(diskscan.OptIn{}, AzureConfig{ResourceGroup: "rg"}, api)
	require.ErrorIs(t, err, diskscan.ErrNotAuthorized)
	_, err = NewAzure(diskscan.OptIn{}, AzureConfig{ClientID: "c", ClientSecret: "s", TenantID: "t"})
	require.ErrorIs(t, err, diskscan.ErrNotAuthorized)
	_, err = NewAzure(azOptIn(t), AzureConfig{ClientID: "other", ClientSecret: "s", TenantID: "t"})
	require.ErrorIs(t, err, diskscan.ErrNotAuthorized)
	_, err = NewAzure(azOptIn(t), AzureConfig{ClientID: "scan-client"})
	require.Error(t, err)

	a := newTestAzure(t, api)
	other, err := diskscan.Authorize(diskscan.ConnectorGrant{Mode: diskscan.ModeCreateSnapshots, DiskScanRole: "another"})
	require.NoError(t, err)
	snap := diskscan.Snapshot{ID: azSnapID}
	ctx := context.Background()
	for name, opt := range map[string]diskscan.OptIn{"zero": {}, "foreign": other} {
		t.Run(name, func(t *testing.T) {
			_, err := a.CreateTagged(ctx, opt, diskscan.VolumeRef{VolumeID: azDiskID, Region: "r"}, "run")
			require.ErrorIs(t, err, diskscan.ErrNotAuthorized)
			require.ErrorIs(t, a.DeleteTagged(ctx, opt, snap), diskscan.ErrNotAuthorized)
			_, err = a.ListTagged(ctx, opt)
			require.ErrorIs(t, err, diskscan.ErrNotAuthorized)
		})
	}
	assert.Empty(t, api.calls, "no Azure call may happen without a matching opt-in")
}

// The read grant needs a ReadOptIn: a missing or foreign one makes zero API calls,
// and the create OptIn cannot be passed in its place (the types differ).
func TestAzure_ReadRequiresValidReadOptIn(t *testing.T) {
	foreign, err := diskscan.AuthorizeRead(diskscan.ConnectorGrant{Mode: diskscan.ModeExistingSnapshots, DiskScanRole: "another"})
	require.NoError(t, err)
	ctx := context.Background()
	snap := diskscan.Snapshot{ID: azSnapID}

	api := newCountingAzure()
	for name, r := range map[string]*AzureReader{"full snapshotter": newTestAzure(t, api).AzureReader, "reader": newTestReader(t, api)} {
		for in, opt := range map[string]diskscan.ReadOptIn{"zero": {}, "foreign": foreign} {
			t.Run(name+"/"+in, func(t *testing.T) {
				_, err := r.GrantRead(ctx, opt, snap)
				require.ErrorIs(t, err, diskscan.ErrNotAuthorized)
				require.ErrorIs(t, r.RevokeRead(ctx, opt, snap), diskscan.ErrNotAuthorized)
			})
		}
	}
	assert.Empty(t, api.calls, "no Azure call may happen without a matching read opt-in")

	_, err = newAzureReader(diskscan.ReadOptIn{}, AzureConfig{}, api)
	require.ErrorIs(t, err, diskscan.ErrNotAuthorized)
	_, err = NewAzureReader(diskscan.ReadOptIn{}, AzureConfig{ClientID: "c", ClientSecret: "s", TenantID: "t", SubscriptionID: "sub"})
	require.ErrorIs(t, err, diskscan.ErrNotAuthorized)
	_, err = NewAzureReader(azReadIn(t), AzureConfig{ClientID: "other", ClientSecret: "s", TenantID: "t", SubscriptionID: "sub"})
	require.ErrorIs(t, err, diskscan.ErrNotAuthorized)
	_, err = NewAzureReader(azReadIn(t), AzureConfig{ClientID: "scan-client"})
	require.Error(t, err)
}

// A reader built from a read opt-in alone cannot create or delete anything: the
// type has no such method, and its API slice has no such call.
func TestAzureReader_HoldsNoWriteCapability(t *testing.T) {
	var _ azureReadAPI = (*countingAzure)(nil)
	typ := reflect.TypeOf(&AzureReader{})
	for _, m := range []string{"CreateTagged", "DeleteTagged", "ListTagged"} {
		_, has := typ.MethodByName(m)
		assert.False(t, has, m)
	}
}

// A reader reaches an existing snapshot in any resource group of its own
// subscription, never another subscription.
func TestAzureReader_ReadsAcrossResourceGroupsOfItsSubscription(t *testing.T) {
	api := newCountingAzure()
	r := newTestReader(t, api)
	url, err := r.GrantRead(context.Background(), azReadIn(t), diskscan.Snapshot{ID: azSubPrefix + "rg-backups/providers/Microsoft.Compute/snapshots/b1"})
	require.NoError(t, err)
	assert.Equal(t, "https://x/sas", url)
	_, err = r.GrantRead(context.Background(), azReadIn(t), diskscan.Snapshot{ID: "/subscriptions/other/resourceGroups/rg/providers/Microsoft.Compute/snapshots/b1"})
	require.Error(t, err)
	assert.Equal(t, 1, api.count("grant_read"))
	assert.Zero(t, api.count("create")+api.count("delete"))
}

func TestAzure_CreateTagged(t *testing.T) {
	api := newCountingAzure()
	a := newTestAzure(t, api)
	vol := diskscan.VolumeRef{VolumeID: azDiskID, Region: "westeurope"}

	snap, err := a.CreateTagged(context.Background(), azOptIn(t), vol, "run-1")
	require.NoError(t, err)
	assert.True(t, snap.Ephemeral)
	assert.Equal(t, azDiskID, snap.VolumeID)
	assert.Equal(t, 1, api.count("create"))

	name := azureSnapshotName("run-1", azDiskID)
	created := api.live[name]
	require.NotNil(t, created.Tags[diskscan.TagKey])
	assert.Equal(t, "run-1", *created.Tags[diskscan.TagKey])
	assert.True(t, *created.Properties.Incremental)
	assert.Equal(t, azDiskID, *created.Properties.CreationData.SourceResourceID)
	assert.Equal(t, armcompute.DiskCreateOptionCopy, *created.Properties.CreationData.CreateOption)

	again, err := a.CreateTagged(context.Background(), azOptIn(t), vol, "run-1")
	require.NoError(t, err)
	assert.Equal(t, snap.ID, again.ID)
	assert.Equal(t, 1, api.created, "a retry must not create a second snapshot")

	api.live[name] = armcompute.Snapshot{Tags: map[string]*string{diskscan.TagKey: new("run-2")}}
	_, err = a.CreateTagged(context.Background(), azOptIn(t), vol, "run-1")
	require.Error(t, err)
}

func TestAzure_CreateTagged_Invalid(t *testing.T) {
	api := newCountingAzure()
	a := newTestAzure(t, api)
	for _, vol := range []diskscan.VolumeRef{{Region: "r"}, {VolumeID: azDiskID}} {
		_, err := a.CreateTagged(context.Background(), azOptIn(t), vol, "run")
		require.Error(t, err)
	}
	_, err := a.CreateTagged(context.Background(), azOptIn(t), diskscan.VolumeRef{VolumeID: azDiskID, Region: "r"}, "")
	require.Error(t, err)
	assert.Empty(t, api.calls)
}

func TestAzure_CreateFailureDeletesTheLeftover(t *testing.T) {
	api := newCountingAzure()
	api.failOn["create"] = errors.New("poll interrupted")
	// The service still made the snapshot even though polling failed.
	a := newTestAzure(t, &createLeavesBehind{countingAzure: api})

	_, err := a.CreateTagged(context.Background(), azOptIn(t), diskscan.VolumeRef{VolumeID: azDiskID, Region: "r"}, "run")
	require.Error(t, err)
	assert.Equal(t, 1, api.count("revoke_read"))
	assert.Equal(t, 1, api.count("delete"))
	assert.Empty(t, api.live)
}

type createLeavesBehind struct{ *countingAzure }

func (c *createLeavesBehind) create(_ context.Context, _, name string, s armcompute.Snapshot) (armcompute.Snapshot, error) {
	c.live[name] = s
	return armcompute.Snapshot{}, c.failOn["create"]
}

func TestAzure_GrantRead_RevokedOnEveryErrorPath(t *testing.T) {
	cases := []struct {
		name       string
		failGrant  error
		sas        string
		snapID     string
		wantErr    bool
		wantGrants int
		wantRevoke int
	}{
		{"success keeps the grant", nil, "https://x/sas", azSnapID, false, 1, 0},
		{"grant call fails after starting", errors.New("poll failed"), "", azSnapID, true, 1, 1},
		{"empty SAS", nil, "", azSnapID, true, 1, 1},
		{"snapshot in another subscription", nil, "https://x", "/subscriptions/other/resourceGroups/rg/providers/Microsoft.Compute/snapshots/s", true, 0, 0},
		{"unparseable id", nil, "https://x", "garbage", true, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := newCountingAzure()
			api.failOn["grant_read"] = tc.failGrant
			api.sas = tc.sas
			a := newTestAzure(t, api)
			url, err := a.GrantRead(context.Background(), azReadIn(t), diskscan.Snapshot{ID: tc.snapID})
			if tc.wantErr {
				require.Error(t, err)
				assert.Empty(t, url)
			} else {
				require.NoError(t, err)
				assert.Equal(t, "https://x/sas", url)
			}
			assert.Equal(t, tc.wantGrants, api.count("grant_read"))
			assert.Equal(t, tc.wantRevoke, api.count("revoke_read"))
		})
	}
}

func TestAzure_GrantRead_RevokesEvenWhenCallerCancelled(t *testing.T) {
	api := newCountingAzure()
	api.failOn["grant_read"] = context.Canceled
	a := newTestAzure(t, api)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := a.GrantRead(ctx, azReadIn(t), diskscan.Snapshot{ID: azSnapID})
	require.Error(t, err)
	assert.Equal(t, 1, api.count("revoke_read"))
}

func TestAzure_RevokeRead(t *testing.T) {
	api := newCountingAzure()
	a := newTestAzure(t, api)
	require.NoError(t, a.RevokeRead(context.Background(), azReadIn(t), diskscan.Snapshot{ID: azSnapID}))
	api.failOn["revoke_read"] = errAzureNotFound
	require.NoError(t, a.RevokeRead(context.Background(), azReadIn(t), diskscan.Snapshot{ID: azSnapID}), "a vanished snapshot has nothing to revoke")
	api.failOn["revoke_read"] = errors.New("boom")
	require.Error(t, a.RevokeRead(context.Background(), azReadIn(t), diskscan.Snapshot{ID: azSnapID}))
}

func TestAzure_DeleteTagged(t *testing.T) {
	tagged := armcompute.Snapshot{Tags: map[string]*string{diskscan.TagKey: new("run")}}
	cases := []struct {
		name       string
		live       map[string]armcompute.Snapshot
		failOn     map[string]error
		wantErr    error
		wantAnyErr bool
		wantRevoke int
		wantDelete int
	}{
		{"tagged snapshot is revoked then deleted", map[string]armcompute.Snapshot{"s1": tagged}, nil, nil, false, 1, 1},
		{"untagged snapshot is refused", map[string]armcompute.Snapshot{"s1": {}}, nil, ErrAzureUntagged, false, 0, 0},
		{"other tags only is refused", map[string]armcompute.Snapshot{"s1": {Tags: map[string]*string{"owner": new("x")}}}, nil, ErrAzureUntagged, false, 0, 0},
		{"already gone is success", map[string]armcompute.Snapshot{}, nil, nil, false, 0, 0},
		{"tag re-read fails", map[string]armcompute.Snapshot{"s1": tagged}, map[string]error{"get": errors.New("boom")}, nil, true, 0, 0},
		{"revoke fails but delete still runs", map[string]armcompute.Snapshot{"s1": tagged}, map[string]error{"revoke_read": errors.New("boom")}, nil, true, 1, 1},
		{"delete fails", map[string]armcompute.Snapshot{"s1": tagged}, map[string]error{"delete": errors.New("boom")}, nil, true, 1, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := newCountingAzure()
			api.live = tc.live
			for k, v := range tc.failOn {
				api.failOn[k] = v
			}
			a := newTestAzure(t, api)
			err := a.DeleteTagged(context.Background(), azOptIn(t), diskscan.Snapshot{ID: azSnapID})
			switch {
			case tc.wantErr != nil:
				require.ErrorIs(t, err, tc.wantErr)
			case tc.wantAnyErr:
				require.Error(t, err)
			default:
				require.NoError(t, err)
			}
			assert.Equal(t, tc.wantRevoke, api.count("revoke_read"))
			assert.Equal(t, tc.wantDelete, api.count("delete"))
		})
	}
}

func TestAzure_DeleteTagged_RefusesOtherResourceGroup(t *testing.T) {
	api := newCountingAzure()
	a := newTestAzure(t, api)
	err := a.DeleteTagged(context.Background(), azOptIn(t), diskscan.Snapshot{ID: azSubPrefix + "rg-disks/providers/Microsoft.Compute/snapshots/s1"})
	require.Error(t, err)
	assert.Empty(t, api.calls)
}

func TestAzure_ListTagged(t *testing.T) {
	api := newCountingAzure()
	api.live["a"] = armcompute.Snapshot{ID: new(azSnapID), Tags: map[string]*string{diskscan.TagKey: new("run")},
		Properties: &armcompute.SnapshotProperties{CreationData: &armcompute.CreationData{SourceResourceID: new(azDiskID)}}}
	api.live["b"] = armcompute.Snapshot{ID: new(azSnapID + "b")}
	got, err := newTestAzure(t, api).ListTagged(context.Background(), azOptIn(t))
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.True(t, got[0].Ephemeral)
	assert.Equal(t, azDiskID, got[0].VolumeID)
}
