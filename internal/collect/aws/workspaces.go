package aws

import (
	"context"
	"fmt"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/workspaces"
	wstypes "github.com/aws/aws-sdk-go-v2/service/workspaces/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// workspacesType is one Amazon WorkSpaces virtual desktop (FSBP WorkSpaces.1/.2).
const workspacesType = "workspaces_workspace"

type workspacesAPI interface {
	DescribeWorkspaces(context.Context, *workspaces.DescribeWorkspacesInput, ...func(*workspaces.Options)) (*workspaces.DescribeWorkspacesOutput, error)
}

func collectWorkSpaces(ctx context.Context, cfg map[string]string, region, accountID string, now time.Time) ([]asset.Asset, error) {
	awsCfg, err := baseConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("collectWorkSpaces: %w", err)
	}
	return readWorkSpaces(ctx, workspaces.NewFromConfig(awsCfg), region, accountID, now)
}

// readWorkSpaces lists every WorkSpace in the region. DescribeWorkspaces
// returns both volume-encryption flags in the listing, so there is no
// per-resource read; a WorkSpace being terminated is skipped (it is going away
// and its volumes with it).
func readWorkSpaces(ctx context.Context, client workspacesAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	var (
		out  []asset.Asset
		next *string
	)
	for {
		page, err := client.DescribeWorkspaces(ctx, &workspaces.DescribeWorkspacesInput{NextToken: next})
		if err != nil {
			return nil, fmt.Errorf("readWorkSpaces: workspaces:DescribeWorkspaces: %w", err)
		}
		for _, w := range page.Workspaces {
			id := awssdk.ToString(w.WorkspaceId)
			if id == "" || w.State == wstypes.WorkspaceStateTerminating || w.State == wstypes.WorkspaceStateTerminated {
				continue
			}
			meta := map[string]string{
				"state":        string(w.State),
				"user_name":    awssdk.ToString(w.UserName),
				"directory_id": awssdk.ToString(w.DirectoryId),
			}
			// DescribeWorkspaces omits an encryption flag that is false (AWS's
			// example output relies on this), so a WorkSpace
			// listed without one has an unencrypted volume. A failed listing
			// emits no WorkSpace at all, so absent keys never arise here.
			meta["user_volume_encrypted"] = strconv.FormatBool(awssdk.ToBool(w.UserVolumeEncryptionEnabled))
			meta["root_volume_encrypted"] = strconv.FormatBool(awssdk.ToBool(w.RootVolumeEncryptionEnabled))
			name := awssdk.ToString(w.ComputerName)
			if name == "" {
				name = id
			}
			out = append(out, asset.Asset{
				ID:           fmt.Sprintf("arn:%s:workspaces:%s:%s:workspace/%s", partitionFor(region), region, accountID, id),
				Name:         name,
				Type:         workspacesType,
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if page.NextToken == nil {
			return out, nil
		}
		next = page.NextToken
	}
}
