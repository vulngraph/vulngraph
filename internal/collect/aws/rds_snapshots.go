package aws

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

const (
	// rdsSnapshotAttrConcurrency bounds the per-snapshot attribute reads in
	// flight at once. An account with hundreds of manual snapshots read them
	// one after another inside the region's collection deadline.
	rdsSnapshotAttrConcurrency = 8
	// rdsSnapshotAttrTimeout bounds one attribute read, so a hung call costs
	// one snapshot's public flag rather than the region's whole budget.
	rdsSnapshotAttrTimeout = 15 * time.Second
)

// rdsSnapshot is one manual snapshot, DB-instance or Aurora cluster, before
// its public flag is read. Both land as rds_snapshot assets: sharing a
// snapshot with "all" is the same exfiltration path for either kind, so the
// existing public-snapshot check and correlations cover both.
type rdsSnapshot struct {
	id, arn string
	cluster bool
	meta    map[string]string
}

// collectRDSSnapshots emits the account's own MANUAL DB and DB-cluster
// snapshots, flagging any shared publicly (restore attribute includes "all") —
// a direct data-exfiltration path: anyone can restore a public snapshot into
// their account and read the DB. Only manual snapshots can be shared, so
// automated ones are skipped; the per-snapshot attribute call is bounded to
// that small set (unlike EBS's thousands, which is why that collector uses a
// bulk filter instead) and fanned out rdsSnapshotAttrConcurrency at a time.
func collectRDSSnapshots(ctx context.Context, client rdsAPI, region, accountID string, now time.Time) ([]asset.Asset, error) {
	snaps, err := listDBSnapshots(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("collectRDSSnapshots: %w", err)
	}
	clusterSnaps, err := listDBClusterSnapshots(ctx, client)
	if err != nil {
		return nil, fmt.Errorf("collectRDSSnapshots: %w", err)
	}
	snaps = append(snaps, clusterSnaps...)

	flags := snapshotPublicFlags(ctx, client, snaps)
	assets := make([]asset.Asset, 0, len(snaps))
	unread := 0
	for i, s := range snaps {
		if flags[i].observed {
			s.meta["public"] = strconv.FormatBool(flags[i].public)
		} else {
			unread++
		}
		assets = append(assets, asset.Asset{
			ID:           s.arn,
			Name:         s.id,
			Type:         "rds_snapshot",
			Provider:     asset.ProviderAWS,
			Region:       region,
			AccountID:    accountID,
			Metadata:     s.meta,
			DiscoveredAt: now,
			LastSeen:     now,
		})
	}
	if unread > 0 {
		log.FromContext(ctx).Warn().Str("region", region).Int("snapshots", len(assets)).Int("unread", unread).
			Msg("rds snapshot attribute read failed for some snapshots; their public flag is unknown this sweep")
	}
	return assets, nil
}

func listDBSnapshots(ctx context.Context, client rdsAPI) ([]rdsSnapshot, error) {
	var (
		out    []rdsSnapshot
		marker *string
	)
	for {
		page, err := client.DescribeDBSnapshots(ctx, &rds.DescribeDBSnapshotsInput{
			SnapshotType: awssdk.String("manual"),
			Marker:       marker,
		})
		if err != nil {
			return nil, fmt.Errorf("listDBSnapshots: %w", err)
		}
		for _, s := range page.DBSnapshots {
			out = append(out, rdsSnapshot{
				id:  awssdk.ToString(s.DBSnapshotIdentifier),
				arn: awssdk.ToString(s.DBSnapshotArn),
				meta: map[string]string{
					"engine":      awssdk.ToString(s.Engine),
					"encrypted":   fmt.Sprintf("%t", awssdk.ToBool(s.Encrypted)),
					"db_instance": awssdk.ToString(s.DBInstanceIdentifier),
					"status":      awssdk.ToString(s.Status),
				},
			})
		}
		if page.Marker == nil {
			return out, nil
		}
		marker = page.Marker
	}
}

func listDBClusterSnapshots(ctx context.Context, client rdsAPI) ([]rdsSnapshot, error) {
	var (
		out    []rdsSnapshot
		marker *string
	)
	for {
		page, err := client.DescribeDBClusterSnapshots(ctx, &rds.DescribeDBClusterSnapshotsInput{
			SnapshotType: awssdk.String("manual"),
			Marker:       marker,
		})
		if err != nil {
			return nil, fmt.Errorf("listDBClusterSnapshots: %w", err)
		}
		for _, s := range page.DBClusterSnapshots {
			out = append(out, rdsSnapshot{
				id:      awssdk.ToString(s.DBClusterSnapshotIdentifier),
				arn:     awssdk.ToString(s.DBClusterSnapshotArn),
				cluster: true,
				meta: map[string]string{
					"engine":        awssdk.ToString(s.Engine),
					"encrypted":     fmt.Sprintf("%t", awssdk.ToBool(s.StorageEncrypted)),
					"db_cluster":    awssdk.ToString(s.DBClusterIdentifier),
					"status":        awssdk.ToString(s.Status),
					"snapshot_kind": "cluster",
				},
			})
		}
		if page.Marker == nil {
			return out, nil
		}
		marker = page.Marker
	}
}

type observedBool struct{ public, observed bool }

// snapshotPublicFlags reads every snapshot's restore attribute, at most
// rdsSnapshotAttrConcurrency at a time. Each goroutine writes only its own
// index, so the result needs no lock.
func snapshotPublicFlags(ctx context.Context, client rdsAPI, snaps []rdsSnapshot) []observedBool {
	out := make([]observedBool, len(snaps))
	sem := make(chan struct{}, rdsSnapshotAttrConcurrency)
	var wg sync.WaitGroup
	for i := range snaps {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if rec := recover(); rec != nil {
					log.FromContext(ctx).Error().Any("panic", rec).Str("snapshot", snaps[i].arn).
						Msg("rds snapshot attribute read panicked; public flag unknown")
				}
			}()
			actx, cancel := context.WithTimeout(ctx, rdsSnapshotAttrTimeout)
			defer cancel()
			if snaps[i].cluster {
				out[i].public, out[i].observed = rdsClusterSnapshotPublic(actx, client, snaps[i].id)
			} else {
				out[i].public, out[i].observed = rdsSnapshotPublic(actx, client, snaps[i].id)
			}
		}()
	}
	wg.Wait()
	return out
}

// rdsSnapshotPublic reports whether a manual DB snapshot is shared with "all"
// (public). observed is false when the attribute read failed: the caller then
// omits the key, because "false" would auto-resolve a real public-snapshot
// finding on a throttle or a missing permission.
func rdsSnapshotPublic(ctx context.Context, client rdsAPI, snapshotID string) (public, observed bool) {
	out, err := client.DescribeDBSnapshotAttributes(ctx, &rds.DescribeDBSnapshotAttributesInput{
		DBSnapshotIdentifier: awssdk.String(snapshotID),
	})
	if err != nil || out == nil || out.DBSnapshotAttributesResult == nil {
		return false, false
	}
	return restoreIsPublic(out.DBSnapshotAttributesResult.DBSnapshotAttributes, func(a rdstypes.DBSnapshotAttribute) (string, []string) {
		return awssdk.ToString(a.AttributeName), a.AttributeValues
	}), true
}

// rdsClusterSnapshotPublic is rdsSnapshotPublic for an Aurora cluster snapshot.
func rdsClusterSnapshotPublic(ctx context.Context, client rdsAPI, snapshotID string) (public, observed bool) {
	out, err := client.DescribeDBClusterSnapshotAttributes(ctx, &rds.DescribeDBClusterSnapshotAttributesInput{
		DBClusterSnapshotIdentifier: awssdk.String(snapshotID),
	})
	if err != nil || out == nil || out.DBClusterSnapshotAttributesResult == nil {
		return false, false
	}
	return restoreIsPublic(out.DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes, func(a rdstypes.DBClusterSnapshotAttribute) (string, []string) {
		return awssdk.ToString(a.AttributeName), a.AttributeValues
	}), true
}

// restoreIsPublic reports whether the "restore" attribute grants "all".
func restoreIsPublic[A any](attrs []A, field func(A) (string, []string)) bool {
	for _, a := range attrs {
		if name, values := field(a); name == "restore" && slices.Contains(values, "all") {
			return true
		}
	}
	return false
}
