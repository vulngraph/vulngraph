package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/workspaces"
	wstypes "github.com/aws/aws-sdk-go-v2/service/workspaces/types"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type fakeWorkSpaces struct {
	pages []*workspaces.DescribeWorkspacesOutput
	err   error
	calls int
}

func (f *fakeWorkSpaces) DescribeWorkspaces(_ context.Context, in *workspaces.DescribeWorkspacesInput, _ ...func(*workspaces.Options)) (*workspaces.DescribeWorkspacesOutput, error) {
	if f.err != nil && f.calls == len(f.pages) {
		return nil, f.err
	}
	p := f.pages[f.calls]
	f.calls++
	return p, nil
}

func indexAssetsByID(assets []asset.Asset) map[string]asset.Asset {
	out := map[string]asset.Asset{}
	for _, a := range assets {
		out[a.ID] = a
	}
	return out
}

func TestReadWorkSpaces(t *testing.T) {
	client := &fakeWorkSpaces{pages: []*workspaces.DescribeWorkspacesOutput{
		{Workspaces: []wstypes.Workspace{
			{WorkspaceId: awssdk.String("ws-1"), ComputerName: awssdk.String("WS1"), State: wstypes.WorkspaceStateAvailable,
				UserVolumeEncryptionEnabled: awssdk.Bool(false), RootVolumeEncryptionEnabled: awssdk.Bool(true)},
			{WorkspaceId: awssdk.String("ws-gone"), State: wstypes.WorkspaceStateTerminated},
		}, NextToken: awssdk.String("p2")},
		// Flags omitted: DescribeWorkspaces leaves out a false flag, so both volumes are unencrypted.
		{Workspaces: []wstypes.Workspace{{WorkspaceId: awssdk.String("ws-2"), State: wstypes.WorkspaceStateStopped}}},
	}}
	got, err := readWorkSpaces(context.Background(), client, "us-gov-west-1", "111", time.Now())
	require.NoError(t, err)
	require.Len(t, got, 2, "a terminated WorkSpace is not emitted; both pages are read")
	m := indexAssetsByID(got)
	ws1 := m["arn:aws-us-gov:workspaces:us-gov-west-1:111:workspace/ws-1"]
	require.Equal(t, "false", ws1.Metadata["user_volume_encrypted"])
	require.Equal(t, "true", ws1.Metadata["root_volume_encrypted"])
	require.Equal(t, "WS1", ws1.Name)
	ws2 := m["arn:aws-us-gov:workspaces:us-gov-west-1:111:workspace/ws-2"]
	require.Equal(t, "false", ws2.Metadata["user_volume_encrypted"], "an omitted flag is the API's false")
	require.Equal(t, "false", ws2.Metadata["root_volume_encrypted"])

	_, err = readWorkSpaces(context.Background(), &fakeWorkSpaces{
		pages: []*workspaces.DescribeWorkspacesOutput{{Workspaces: []wstypes.Workspace{{WorkspaceId: awssdk.String("ws-1")}}, NextToken: awssdk.String("p2")}},
		err:   errors.New("throttled"),
	}, "us-east-1", "111", time.Now())
	require.Error(t, err, "a failed later page fails the listing rather than returning a short one")
	// A failed listing emits no WorkSpace, so no flag is ever written from it.

	none, err := readWorkSpaces(context.Background(), &fakeWorkSpaces{pages: []*workspaces.DescribeWorkspacesOutput{{}}}, "us-east-1", "111", time.Now())
	require.NoError(t, err)
	require.Empty(t, none, "an unused service emits nothing")
}
