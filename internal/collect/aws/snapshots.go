package aws

import (
	"context"
	"fmt"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// collectSnapshots emits the account's own EBS snapshots, flagging any that are
// shared publicly (restorable by the "all" group). A public snapshot is a
// direct data-exfiltration path: anyone can restore it into their own account
// and read the disk. Public detection is ONE extra filtered listing
// (RestorableByUserIds=["all"]), never a per-snapshot attribute call: a
// DescribeSnapshotAttribute call per snapshot issues thousands of serial API
// calls in snapshot-heavy accounts and exhausts the 30-minute sync budget,
// starving every collector after it.
func collectSnapshots(ctx context.Context, client ec2API, region, accountID string, now time.Time) ([]asset.Asset, error) {
	// A failed public listing leaves public nil, and every snapshot then OMITS
	// the "public" key: writing "false" would read as an observation and
	// auto-resolve every open public-snapshot finding on a single throttle.
	public, err := publicSnapshotIDs(ctx, client)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("region", region).
			Msg("public snapshot listing failed; snapshot public flag unknown this sweep")
	}

	var (
		assets []asset.Asset
		token  *string
	)
	for {
		// OwnerIds "self" — only the account's own snapshots, not the tens of
		// thousands of public/amazon ones.
		out, err := client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
			OwnerIds:  []string{"self"},
			NextToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("collectSnapshots: %w", err)
		}
		for _, s := range out.Snapshots {
			id := awssdk.ToString(s.SnapshotId)
			meta := map[string]string{
				"encrypted": fmt.Sprintf("%t", awssdk.ToBool(s.Encrypted)),
				"volume_id": awssdk.ToString(s.VolumeId),
				"volume_gb": fmt.Sprintf("%d", awssdk.ToInt32(s.VolumeSize)),
				"state":     string(s.State),
			}
			if public != nil {
				meta["public"] = fmt.Sprintf("%t", public[id])
			}
			assets = append(assets, asset.Asset{
				ID:           id,
				Name:         nameTag(s.Tags, id),
				Type:         "ebs_snapshot",
				Provider:     asset.ProviderAWS,
				Region:       region,
				AccountID:    accountID,
				Tags:         tagMap(s.Tags),
				Metadata:     meta,
				DiscoveredAt: now,
				LastSeen:     now,
			})
		}
		if out.NextToken == nil {
			return assets, nil
		}
		token = out.NextToken
	}
}

// publicSnapshotIDs lists the account's own snapshots that the "all" group can
// restore (i.e. public), in one paginated call.
func publicSnapshotIDs(ctx context.Context, client ec2API) (map[string]bool, error) {
	ids := map[string]bool{}
	var token *string
	for {
		out, err := client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
			OwnerIds:            []string{"self"},
			RestorableByUserIds: []string{"all"},
			NextToken:           token,
		})
		if err != nil {
			return nil, fmt.Errorf("publicSnapshotIDs: %w", err)
		}
		for _, s := range out.Snapshots {
			ids[awssdk.ToString(s.SnapshotId)] = true
		}
		if out.NextToken == nil {
			return ids, nil
		}
		token = out.NextToken
	}
}

// collectImages emits the account's own AMIs, flagging any that are public.
// A public AMI can leak baked-in secrets, credentials, and proprietary code to
// anyone who launches it.
func collectImages(ctx context.Context, client ec2API, region, accountID string, now time.Time) ([]asset.Asset, error) {
	out, err := client.DescribeImages(ctx, &ec2.DescribeImagesInput{Owners: []string{"self"}})
	if err != nil {
		return nil, fmt.Errorf("collectImages: %w", err)
	}
	assets := make([]asset.Asset, 0, len(out.Images))
	for _, img := range out.Images {
		id := awssdk.ToString(img.ImageId)
		assets = append(assets, asset.Asset{
			ID:        id,
			Name:      nameTag(img.Tags, awssdk.ToString(img.Name)),
			Type:      "ami",
			Provider:  asset.ProviderAWS,
			Region:    region,
			AccountID: accountID,
			Tags:      tagMap(img.Tags),
			Metadata: map[string]string{
				"public": fmt.Sprintf("%t", awssdk.ToBool(img.Public)),
				"state":  string(img.State),
			},
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	return assets, nil
}

// snapshotVolumeIDs returns the source volume IDs the snapshots were taken from.
func snapshotVolumeIDs(snaps []asset.Asset) map[string]bool {
	ids := make(map[string]bool, len(snaps))
	for _, s := range snaps {
		if v := s.Metadata["volume_id"]; v != "" {
			ids[v] = true
		}
	}
	return ids
}

// annotateVolumeSnapshots stamps has_snapshot (true/false) on every EBS volume
// in a region whose snapshot listing was read. A region missing from
// snapshotVolumes leaves its volumes without the key: a failed listing must
// never read as "no snapshots".
func annotateVolumeSnapshots(assets []asset.Asset, snapshotVolumes map[string]map[string]bool) {
	for i := range assets {
		a := &assets[i]
		if a.Type != "ebs_volume" || a.Provider != asset.ProviderAWS {
			continue
		}
		have, ok := snapshotVolumes[a.Region]
		if !ok {
			continue
		}
		a.Metadata["has_snapshot"] = strconv.FormatBool(have[a.ID])
	}
}
