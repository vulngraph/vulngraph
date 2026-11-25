// Package awsdisk reads existing EBS snapshots through the EC2 and EBS direct
// APIs. It holds read-only clients: the interfaces below carry no mutating
// method, and creating or deleting snapshots belongs to package snapshotter.
package awsdisk

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan"
)

const (
	providerName       = "aws"
	gib                = int64(1) << 30
	defaultConcurrency = 8
	defaultCacheBlocks = 64
	listPageSize       = 10000
)

// EC2API is the read-only slice of the EC2 client the provider uses.
type EC2API interface {
	DescribeSnapshots(ctx context.Context, in *ec2.DescribeSnapshotsInput, opts ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error)
}

// EBSAPI is the read-only slice of the EBS direct client the provider uses.
type EBSAPI interface {
	ListSnapshotBlocks(ctx context.Context, in *ebs.ListSnapshotBlocksInput, opts ...func(*ebs.Options)) (*ebs.ListSnapshotBlocksOutput, error)
	GetSnapshotBlock(ctx context.Context, in *ebs.GetSnapshotBlockInput, opts ...func(*ebs.Options)) (*ebs.GetSnapshotBlockOutput, error)
	ListChangedBlocks(ctx context.Context, in *ebs.ListChangedBlocksInput, opts ...func(*ebs.Options)) (*ebs.ListChangedBlocksOutput, error)
}

// Clients are the per-region clients for one provider call.
type Clients struct {
	EC2 EC2API
	EBS EBSAPI
}

// ClientFactory returns the clients for a region.
type ClientFactory func(region string) (Clients, error)

// Provider implements diskscan.Provider over EBS direct APIs.
type Provider struct {
	clients     ClientFactory
	concurrency int
	cacheBlocks int
}

var _ diskscan.Provider = (*Provider)(nil)

// Option tunes a Provider.
type Option func(*Provider)

// WithConcurrency bounds parallel GetSnapshotBlock calls per read.
func WithConcurrency(n int) Option {
	return func(p *Provider) {
		if n > 0 {
			p.concurrency = n
		}
	}
}

// WithCacheBlocks bounds the per-source block cache, in blocks.
func WithCacheBlocks(n int) Option {
	return func(p *Provider) {
		if n > 0 {
			p.cacheBlocks = n
		}
	}
}

// New returns a Provider that takes its clients from the factory.
func New(clients ClientFactory, opts ...Option) *Provider {
	p := &Provider{clients: clients, concurrency: defaultConcurrency, cacheBlocks: defaultCacheBlocks}
	for _, o := range opts {
		o(p)
	}
	return p
}

// NewFromConfig builds a Provider whose clients use the credentials in cfg.
func NewFromConfig(cfg aws.Config, opts ...Option) *Provider {
	return New(func(region string) (Clients, error) {
		rc := cfg.Copy()
		rc.Region = region
		return Clients{EC2: ec2.NewFromConfig(rc), EBS: ebs.NewFromConfig(rc)}, nil
	}, opts...)
}

// ListReusable returns the completed snapshots of the volume that Vulngraph
// did not create, newest first.
func (p *Provider) ListReusable(ctx context.Context, vol diskscan.VolumeRef) ([]diskscan.Snapshot, error) {
	c, err := p.clients(vol.Region)
	if err != nil {
		return nil, fmt.Errorf("ListReusable: clients for %s: %w", vol.Region, err)
	}
	pager := ec2.NewDescribeSnapshotsPaginator(c.EC2, &ec2.DescribeSnapshotsInput{
		OwnerIds: []string{"self"},
		Filters: []ec2types.Filter{
			{Name: aws.String("volume-id"), Values: []string{vol.VolumeID}},
			{Name: aws.String("status"), Values: []string{"completed"}},
		},
		MaxResults: aws.Int32(listPageSize),
	})
	var out []diskscan.Snapshot
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAccessDenied(err) {
				return nil, fmt.Errorf("ListReusable: DescribeSnapshots: %w: %w", ErrPermissionDenied, err)
			}
			return nil, fmt.Errorf("ListReusable: DescribeSnapshots: %w", err)
		}
		for _, s := range page.Snapshots {
			if hasTag(s.Tags, diskscan.TagKey) {
				continue
			}
			out = append(out, toSnapshot(s, vol.Region))
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// Open lists the snapshot's blocks and returns a source over them. For an
// encrypted snapshot it reads one block first, so a missing KMS grant surfaces
// here as ErrEncryptedNoKey rather than at the first filesystem read.
func (p *Provider) Open(ctx context.Context, snap diskscan.Snapshot) (diskscan.BlockSource, error) {
	c, err := p.clients(snap.Region)
	if err != nil {
		return nil, fmt.Errorf("Open: clients for %s: %w", snap.Region, err)
	}
	blockSize, volumeBytes, tokens, err := listBlocks(ctx, c.EBS, snap.ID)
	if err != nil {
		return nil, fmt.Errorf("Open: %w", err)
	}
	srcCtx, cancel := context.WithCancel(ctx)
	src := &blockSource{
		ctx:         srcCtx,
		cancel:      cancel,
		client:      c.EBS,
		snapshotID:  snap.ID,
		encrypted:   snap.Encrypted,
		blockSize:   blockSize,
		size:        volumeBytes,
		tokens:      tokens,
		cache:       newBlockCache(p.cacheBlocks),
		concurrency: p.concurrency,
	}
	if snap.Encrypted && len(tokens) > 0 {
		if _, err := src.block(ctx, lowestIndex(tokens)); err != nil {
			_ = src.Close()
			return nil, fmt.Errorf("Open: probe %s: %w", snap.ID, err)
		}
	}
	return src, nil
}

// Changed returns the byte ranges that differ between two snapshots of one
// volume. Snapshots the API cannot diff return diskscan.ErrNoDiff.
func (p *Provider) Changed(ctx context.Context, base, next diskscan.Snapshot) ([]diskscan.Extent, error) {
	c, err := p.clients(next.Region)
	if err != nil {
		return nil, fmt.Errorf("Changed: clients for %s: %w", next.Region, err)
	}
	pager := ebs.NewListChangedBlocksPaginator(c.EBS, &ebs.ListChangedBlocksInput{
		FirstSnapshotId:  aws.String(base.ID),
		SecondSnapshotId: aws.String(next.ID),
	})
	var extents []diskscan.Extent
	for pager.HasMorePages() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return nil, fmt.Errorf("Changed: %w", err)
			}
			if isAccessDenied(err) {
				return nil, fmt.Errorf("Changed: %w: %w", ErrPermissionDenied, err)
			}
			return nil, fmt.Errorf("Changed: %w: %w", diskscan.ErrNoDiff, err)
		}
		size := int64(aws.ToInt32(page.BlockSize))
		if size <= 0 {
			return nil, fmt.Errorf("Changed: API reported block size %d", size)
		}
		for _, b := range page.ChangedBlocks {
			extents = appendExtent(extents, int64(aws.ToInt32(b.BlockIndex))*size, size)
		}
	}
	return extents, nil
}

func appendExtent(extents []diskscan.Extent, offset, length int64) []diskscan.Extent {
	if n := len(extents); n > 0 && extents[n-1].Offset+extents[n-1].Length == offset {
		extents[n-1].Length += length
		return extents
	}
	return append(extents, diskscan.Extent{Offset: offset, Length: length})
}

// listBlocks pages ListSnapshotBlocks into a block-index to token map.
func listBlocks(ctx context.Context, client EBSAPI, snapshotID string) (blockSize, volumeBytes int64, tokens map[int32]string, err error) {
	tokens = make(map[int32]string)
	pager := ebs.NewListSnapshotBlocksPaginator(client, &ebs.ListSnapshotBlocksInput{SnapshotId: aws.String(snapshotID)})
	for pager.HasMorePages() {
		page, perr := pager.NextPage(ctx)
		if perr != nil {
			if isAccessDenied(perr) {
				return 0, 0, nil, fmt.Errorf("ListSnapshotBlocks %s: %w: %w", snapshotID, ErrPermissionDenied, perr)
			}
			return 0, 0, nil, fmt.Errorf("ListSnapshotBlocks %s: %w", snapshotID, perr)
		}
		if bs := int64(aws.ToInt32(page.BlockSize)); bs > 0 {
			blockSize = bs
		}
		if v := aws.ToInt64(page.VolumeSize); v > 0 {
			volumeBytes = v * gib
		}
		for _, b := range page.Blocks {
			tokens[aws.ToInt32(b.BlockIndex)] = aws.ToString(b.BlockToken)
		}
	}
	if blockSize <= 0 || volumeBytes <= 0 {
		return 0, 0, nil, fmt.Errorf("ListSnapshotBlocks %s: API reported block size %d, volume %d bytes", snapshotID, blockSize, volumeBytes)
	}
	return blockSize, volumeBytes, tokens, nil
}

func lowestIndex(tokens map[int32]string) int32 {
	first, set := int32(0), false
	for i := range tokens {
		if !set || i < first {
			first, set = i, true
		}
	}
	return first
}

func hasTag(tags []ec2types.Tag, key string) bool {
	for _, t := range tags {
		if aws.ToString(t.Key) == key {
			return true
		}
	}
	return false
}

func toSnapshot(s ec2types.Snapshot, region string) diskscan.Snapshot {
	var created time.Time
	if s.StartTime != nil {
		created = *s.StartTime
	}
	return diskscan.Snapshot{
		ID:        aws.ToString(s.SnapshotId),
		Provider:  providerName,
		Region:    region,
		VolumeID:  aws.ToString(s.VolumeId),
		SizeBytes: int64(aws.ToInt32(s.VolumeSize)) * gib,
		Encrypted: aws.ToBool(s.Encrypted),
		Ephemeral: hasTag(s.Tags, diskscan.TagKey),
		CreatedAt: created,
	}
}
