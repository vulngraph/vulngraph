// Package snapshotter is the only package allowed to hold a client that can
// create or delete cloud snapshots. Every call needs a diskscan.OptIn, which
// only diskscan.Authorize produces, and deletion refuses anything the live
// tags do not show Vulngraph created.
package snapshotter

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan"
)

const gib = int64(1) << 30

var (
	// ErrPermissionDenied means the disk-scan role may not create the snapshot.
	// The service records not_enabled(snapshot_permission_denied) and does not retry.
	ErrPermissionDenied = errors.New("snapshotter: permission denied")
	// ErrNotTagged means a delete was refused because the snapshot does not
	// carry the Vulngraph tag.
	ErrNotTagged = errors.New("snapshotter: snapshot is not tagged as a Vulngraph disk-scan snapshot")
)

// EC2Writer is the mutating slice of the EC2 client. It is built from the
// disk-scan role's credentials.
type EC2Writer interface {
	CreateSnapshot(ctx context.Context, in *ec2.CreateSnapshotInput, opts ...func(*ec2.Options)) (*ec2.CreateSnapshotOutput, error)
	DeleteSnapshot(ctx context.Context, in *ec2.DeleteSnapshotInput, opts ...func(*ec2.Options)) (*ec2.DeleteSnapshotOutput, error)
}

// EC2Reader reads snapshots. The disk-scan role grants no read action, so it
// is built from the read-only role's credentials.
type EC2Reader interface {
	DescribeSnapshots(ctx context.Context, in *ec2.DescribeSnapshotsInput, opts ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
}

// AWSClients are the clients for one region.
type AWSClients struct {
	Write EC2Writer
	Read  EC2Reader
}

// AWS creates, lists and deletes tagged EBS snapshots.
type AWS struct {
	optIn   diskscan.OptIn
	regions []string
	clients func(region string) (AWSClients, error)
}

var _ diskscan.Snapshotter = (*AWS)(nil)

// NewAWS returns a snapshotter for the connector the OptIn authorizes.
// ListTagged sweeps the given regions.
func NewAWS(optIn diskscan.OptIn, regions []string, clients func(region string) (AWSClients, error)) (*AWS, error) {
	if !optIn.Valid() {
		return nil, fmt.Errorf("NewAWS: %w", diskscan.ErrNotAuthorized)
	}
	return &AWS{optIn: optIn, regions: regions, clients: clients}, nil
}

// NewAWSFromConfig builds clients from two credential sets: writeCfg for the
// disk-scan role (create and delete), readCfg for the read-only role (describe).
func NewAWSFromConfig(optIn diskscan.OptIn, regions []string, writeCfg, readCfg aws.Config) (*AWS, error) {
	return NewAWS(optIn, regions, func(region string) (AWSClients, error) {
		w, r := writeCfg.Copy(), readCfg.Copy()
		w.Region, r.Region = region, region
		return AWSClients{Write: ec2.NewFromConfig(w), Read: ec2.NewFromConfig(r)}, nil
	})
}

func (a *AWS) check(optIn diskscan.OptIn) error {
	if !optIn.Valid() || optIn.Role() != a.optIn.Role() {
		return fmt.Errorf("snapshotter: %w", diskscan.ErrNotAuthorized)
	}
	return nil
}

// CreateTagged snapshots the volume, tagging the snapshot with the run id at
// creation. A snapshot already carrying the run's tag is returned instead, so
// a retried job never creates a second one. The create call is probed with
// DryRun first; a denied probe returns ErrPermissionDenied and is not retried.
func (a *AWS) CreateTagged(ctx context.Context, optIn diskscan.OptIn, vol diskscan.VolumeRef, runID string) (diskscan.Snapshot, error) {
	if err := a.check(optIn); err != nil {
		return diskscan.Snapshot{}, fmt.Errorf("CreateTagged: %w", err)
	}
	if runID == "" || vol.VolumeID == "" {
		return diskscan.Snapshot{}, errors.New("CreateTagged: run id and volume id are required")
	}
	c, err := a.clients(vol.Region)
	if err != nil {
		return diskscan.Snapshot{}, fmt.Errorf("CreateTagged: clients for %s: %w", vol.Region, err)
	}
	existing, err := describe(ctx, c.Read, vol.Region, []ec2types.Filter{
		{Name: aws.String("tag:" + diskscan.TagKey), Values: []string{runID}},
		{Name: aws.String("volume-id"), Values: []string{vol.VolumeID}},
	}, nil)
	if err != nil {
		return diskscan.Snapshot{}, fmt.Errorf("CreateTagged: find run snapshot: %w", err)
	}
	if len(existing) > 0 {
		return existing[0], nil
	}

	in := &ec2.CreateSnapshotInput{
		VolumeId: aws.String(vol.VolumeID),
		TagSpecifications: []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeSnapshot,
			Tags:         []ec2types.Tag{{Key: aws.String(diskscan.TagKey), Value: aws.String(runID)}},
		}},
	}
	probe := *in
	probe.DryRun = aws.Bool(true)
	if _, err := c.Write.CreateSnapshot(ctx, &probe); !isDryRunOK(err) {
		if isDenied(err) {
			return diskscan.Snapshot{}, fmt.Errorf("CreateTagged: %s: %w: %w", vol.VolumeID, ErrPermissionDenied, err)
		}
		return diskscan.Snapshot{}, fmt.Errorf("CreateTagged: dry run %s: %w", vol.VolumeID, unexpectedProbe(err))
	}

	out, err := c.Write.CreateSnapshot(ctx, in)
	if err != nil {
		if isDenied(err) {
			return diskscan.Snapshot{}, fmt.Errorf("CreateTagged: %s: %w: %w", vol.VolumeID, ErrPermissionDenied, err)
		}
		return diskscan.Snapshot{}, fmt.Errorf("CreateTagged: %s: %w", vol.VolumeID, err)
	}
	snap := diskscan.Snapshot{
		ID:        aws.ToString(out.SnapshotId),
		Provider:  "aws",
		Region:    vol.Region,
		VolumeID:  vol.VolumeID,
		SizeBytes: int64(aws.ToInt32(out.VolumeSize)) * gib,
		Encrypted: aws.ToBool(out.Encrypted),
		Ephemeral: true,
	}
	if out.StartTime != nil {
		snap.CreatedAt = *out.StartTime
	}
	return snap, nil
}

// DeleteTagged deletes a snapshot only after re-reading its live tags and
// finding the Vulngraph tag. A snapshot that no longer exists is already deleted.
func (a *AWS) DeleteTagged(ctx context.Context, optIn diskscan.OptIn, snap diskscan.Snapshot) error {
	if err := a.check(optIn); err != nil {
		return fmt.Errorf("DeleteTagged: %w", err)
	}
	c, err := a.clients(snap.Region)
	if err != nil {
		return fmt.Errorf("DeleteTagged: clients for %s: %w", snap.Region, err)
	}
	live, err := describe(ctx, c.Read, snap.Region, nil, []string{snap.ID})
	if err != nil {
		if hasCode(err, "InvalidSnapshot.NotFound") {
			return nil
		}
		return fmt.Errorf("DeleteTagged: re-read tags of %s: %w", snap.ID, err)
	}
	if len(live) == 0 {
		return nil
	}
	if !live[0].Ephemeral {
		return fmt.Errorf("DeleteTagged: %s: %w", snap.ID, ErrNotTagged)
	}
	if _, err := c.Write.DeleteSnapshot(ctx, &ec2.DeleteSnapshotInput{SnapshotId: aws.String(snap.ID)}); err != nil {
		if hasCode(err, "InvalidSnapshot.NotFound") {
			return nil
		}
		if isDenied(err) {
			return fmt.Errorf("DeleteTagged: %s: %w: %w", snap.ID, ErrPermissionDenied, err)
		}
		return fmt.Errorf("DeleteTagged: %s: %w", snap.ID, err)
	}
	return nil
}

// ListTagged returns every snapshot carrying the Vulngraph tag in the
// configured regions, regardless of any database state.
func (a *AWS) ListTagged(ctx context.Context, optIn diskscan.OptIn) ([]diskscan.Snapshot, error) {
	if err := a.check(optIn); err != nil {
		return nil, fmt.Errorf("ListTagged: %w", err)
	}
	var out []diskscan.Snapshot
	for _, region := range a.regions {
		c, err := a.clients(region)
		if err != nil {
			return nil, fmt.Errorf("ListTagged: clients for %s: %w", region, err)
		}
		snaps, err := describe(ctx, c.Read, region, []ec2types.Filter{{Name: aws.String("tag-key"), Values: []string{diskscan.TagKey}}}, nil)
		if err != nil {
			return nil, fmt.Errorf("ListTagged: %s: %w", region, err)
		}
		out = append(out, snaps...)
	}
	return out, nil
}

// describe pages DescribeSnapshots over this account's snapshots.
func describe(ctx context.Context, r EC2Reader, region string, filters []ec2types.Filter, ids []string) ([]diskscan.Snapshot, error) {
	pager := ec2.NewDescribeSnapshotsPaginator(r, &ec2.DescribeSnapshotsInput{
		OwnerIds:    []string{"self"},
		Filters:     filters,
		SnapshotIds: ids,
	})
	var out []diskscan.Snapshot
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, s := range page.Snapshots {
			snap := diskscan.Snapshot{
				ID:        aws.ToString(s.SnapshotId),
				Provider:  "aws",
				Region:    region,
				VolumeID:  aws.ToString(s.VolumeId),
				SizeBytes: int64(aws.ToInt32(s.VolumeSize)) * gib,
				Encrypted: aws.ToBool(s.Encrypted),
				Ephemeral: hasTag(s.Tags, diskscan.TagKey),
			}
			if s.StartTime != nil {
				snap.CreatedAt = *s.StartTime
			}
			out = append(out, snap)
		}
	}
	return out, nil
}

func hasTag(tags []ec2types.Tag, key string) bool {
	for _, t := range tags {
		if aws.ToString(t.Key) == key && aws.ToString(t.Value) != "" {
			return true
		}
	}
	return false
}

func hasCode(err error, code string) bool {
	var api smithy.APIError
	return errors.As(err, &api) && api.ErrorCode() == code
}

// isDryRunOK: a DryRun call that would have succeeded fails with DryRunOperation.
func isDryRunOK(err error) bool { return hasCode(err, "DryRunOperation") }

func isDenied(err error) bool {
	return hasCode(err, "UnauthorizedOperation") || hasCode(err, "AccessDenied") || hasCode(err, "AccessDeniedException")
}

func unexpectedProbe(err error) error {
	if err == nil {
		return errors.New("dry run returned no DryRunOperation error")
	}
	return err
}
