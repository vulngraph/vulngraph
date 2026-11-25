package gcp

import (
	"context"
	"errors"
	"testing"
	"time"

	compute "google.golang.org/api/compute/v1"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/checks"
)

// fakeComputeImageAPI returns canned images/snapshots and treats a fixed set of
// names as public.
type fakeComputeImageAPI struct {
	images     []*compute.Image
	snapshots  []*compute.Snapshot
	publicName string // this image/snapshot name is public
	deniedName string // this image/snapshot's IAM policy read fails
}

func (f fakeComputeImageAPI) listImages(context.Context, string) ([]*compute.Image, error) {
	return f.images, nil
}
func (f fakeComputeImageAPI) listSnapshots(context.Context, string) ([]*compute.Snapshot, error) {
	return f.snapshots, nil
}
func (f fakeComputeImageAPI) imagePublic(_ context.Context, _, name string) (bool, error) {
	return f.public(name)
}
func (f fakeComputeImageAPI) snapshotPublic(_ context.Context, _, name string) (bool, error) {
	return f.public(name)
}
func (f fakeComputeImageAPI) public(name string) (bool, error) {
	if name == f.deniedName {
		return false, errors.New("403: getIamPolicy denied")
	}
	return name == f.publicName, nil
}

func TestCollectGCPImagesSnapshots_PublicFlag(t *testing.T) {
	api := fakeComputeImageAPI{
		images:     []*compute.Image{{Name: "base-public"}, {Name: "base-private"}},
		snapshots:  []*compute.Snapshot{{Name: "snap-private"}},
		publicName: "base-public",
	}
	got, err := collectGCPImagesSnapshots(context.Background(), api, "proj-1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 3)

	byID := map[string]struct {
		typ, public string
	}{}
	for _, a := range got {
		byID[a.ID] = struct{ typ, public string }{a.Type, a.Metadata["public"]}
	}
	require.Equal(t, "gcp_image", byID["proj-1/image/base-public"].typ)
	require.Equal(t, "true", byID["proj-1/image/base-public"].public)
	require.Equal(t, "false", byID["proj-1/image/base-private"].public)
	require.Equal(t, "gcp_disk_snapshot", byID["proj-1/snapshot/snap-private"].typ)
	require.Equal(t, "false", byID["proj-1/snapshot/snap-private"].public)
}

// A failed IAM read omits "public": "false" would grade a public image or
// snapshot private and close its finding as fixed.
func TestCollectGCPImagesSnapshots_UnreadPolicyIsUnknown(t *testing.T) {
	api := fakeComputeImageAPI{
		images:     []*compute.Image{{Name: "denied"}},
		snapshots:  []*compute.Snapshot{{Name: "denied"}},
		deniedName: "denied",
	}
	got, err := collectGCPImagesSnapshots(context.Background(), api, "proj-1", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 2)
	reg := checks.Default()
	for _, a := range got {
		require.NotContains(t, a.Metadata, "public", a.ID)
		require.Equal(t, publicAccessUnknown, a.Metadata["public_access"], a.ID)
		require.Equal(t, "denied", a.Name)
		id := map[string]string{"gcp_image": "gcp-image-public", "gcp_disk_snapshot": "gcp-snapshot-public"}[a.Type]
		c, ok := reg.ByID(id)
		require.True(t, ok, id)
		require.False(t, c.Evaluable(a), id)
	}
}

func TestPolicyHasPublicMember(t *testing.T) {
	binding := func(member string) *compute.Policy {
		return &compute.Policy{Bindings: []*compute.Binding{{Role: "roles/compute.imageUser", Members: []string{member}}}}
	}
	tests := []struct {
		name    string
		policy  *compute.Policy
		want    bool
		wantErr bool
	}{
		{"empty response is no observation", nil, false, true},
		{"no public member", binding("user:alice@example.com"), false, false},
		{"allUsers", binding("allUsers"), true, false},
		{"allAuthenticatedUsers", binding("allAuthenticatedUsers"), true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := policyHasPublicMember(tt.policy)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}
