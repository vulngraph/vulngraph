package awsdisk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	ebstypes "github.com/aws/aws-sdk-go-v2/service/ebs/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan"
)

const testBlock = 8

type fakeEC2 struct {
	pages [][]ec2types.Snapshot
	err   error
	calls atomic.Int32
}

func (f *fakeEC2) DescribeSnapshots(_ context.Context, in *ec2.DescribeSnapshotsInput, _ ...func(*ec2.Options)) (*ec2.DescribeSnapshotsOutput, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	i := 0
	if in.NextToken != nil {
		i, _ = strconv.Atoi(*in.NextToken)
	}
	out := &ec2.DescribeSnapshotsOutput{Snapshots: f.pages[i]}
	if i+1 < len(f.pages) {
		out.NextToken = aws.String(strconv.Itoa(i + 1))
	}
	return out, nil
}

type fakeBlock struct {
	data      []byte
	checksum  *string
	algorithm ebstypes.ChecksumAlgorithm
	err       error
	length    *int32
}

type fakeEBS struct {
	blocks     map[int32]*fakeBlock
	listErr    error
	pageSize   int
	gets       atomic.Int32
	inflight   atomic.Int32
	maxFlight  atomic.Int32
	changed    [][]int32
	changedErr error
}

func sum(b []byte) *string {
	h := sha256.Sum256(b)
	return aws.String(base64.StdEncoding.EncodeToString(h[:]))
}

func goodBlock(data []byte) *fakeBlock {
	return &fakeBlock{data: data, checksum: sum(data), algorithm: ebstypes.ChecksumAlgorithmChecksumAlgorithmSha256}
}

func (f *fakeEBS) ListSnapshotBlocks(_ context.Context, in *ebs.ListSnapshotBlocksInput, _ ...func(*ebs.Options)) (*ebs.ListSnapshotBlocksOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	start := 0
	if in.NextToken != nil {
		start, _ = strconv.Atoi(*in.NextToken)
	}
	var idx []int32
	for i := int32(0); i < 64; i++ {
		if _, ok := f.blocks[i]; ok {
			idx = append(idx, i)
		}
	}
	size := f.pageSize
	if size == 0 {
		size = len(idx)
	}
	end := min(start+size, len(idx))
	out := &ebs.ListSnapshotBlocksOutput{BlockSize: aws.Int32(testBlock), VolumeSize: aws.Int64(1)}
	for _, i := range idx[start:end] {
		out.Blocks = append(out.Blocks, ebstypes.Block{BlockIndex: aws.Int32(i), BlockToken: aws.String(fmt.Sprintf("tok%d", i))})
	}
	if end < len(idx) {
		out.NextToken = aws.String(strconv.Itoa(end))
	}
	return out, nil
}

func (f *fakeEBS) GetSnapshotBlock(ctx context.Context, in *ebs.GetSnapshotBlockInput, _ ...func(*ebs.Options)) (*ebs.GetSnapshotBlockOutput, error) {
	f.gets.Add(1)
	n := f.inflight.Add(1)
	defer f.inflight.Add(-1)
	for {
		cur := f.maxFlight.Load()
		if n <= cur || f.maxFlight.CompareAndSwap(cur, n) {
			break
		}
	}
	time.Sleep(2 * time.Millisecond)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b, ok := f.blocks[*in.BlockIndex]
	if !ok || *in.BlockToken != fmt.Sprintf("tok%d", *in.BlockIndex) {
		return nil, errors.New("no such block")
	}
	if b.err != nil {
		return nil, b.err
	}
	length := b.length
	if length == nil {
		length = aws.Int32(int32(len(b.data)))
	}
	return &ebs.GetSnapshotBlockOutput{
		BlockData:         io.NopCloser(bytes.NewReader(b.data)),
		Checksum:          b.checksum,
		ChecksumAlgorithm: b.algorithm,
		DataLength:        length,
	}, nil
}

func (f *fakeEBS) ListChangedBlocks(_ context.Context, in *ebs.ListChangedBlocksInput, _ ...func(*ebs.Options)) (*ebs.ListChangedBlocksOutput, error) {
	if f.changedErr != nil {
		return nil, f.changedErr
	}
	page := 0
	if in.NextToken != nil {
		page, _ = strconv.Atoi(*in.NextToken)
	}
	out := &ebs.ListChangedBlocksOutput{BlockSize: aws.Int32(testBlock)}
	for _, i := range f.changed[page] {
		out.ChangedBlocks = append(out.ChangedBlocks, ebstypes.ChangedBlock{BlockIndex: aws.Int32(i)})
	}
	if page+1 < len(f.changed) {
		out.NextToken = aws.String(strconv.Itoa(page + 1))
	}
	return out, nil
}

func provider(e2 EC2API, eb EBSAPI, opts ...Option) *Provider {
	return New(func(string) (Clients, error) { return Clients{EC2: e2, EBS: eb}, nil }, opts...)
}

// openSized opens a source whose volume is shrunk to the blocks under test.
func openSized(t *testing.T, f *fakeEBS, snap diskscan.Snapshot, opts ...Option) *blockSource {
	t.Helper()
	src, err := provider(&fakeEC2{}, f, opts...).Open(context.Background(), snap)
	require.NoError(t, err)
	bs := src.(*blockSource)
	bs.size = 4 * testBlock
	t.Cleanup(func() { _ = bs.Close() })
	return bs
}

func TestReadAt(t *testing.T) {
	b0, b2 := []byte("AAAAAAAA"), []byte("CCCCCCCC")
	f := &fakeEBS{blocks: map[int32]*fakeBlock{0: goodBlock(b0), 2: goodBlock(b2)}, pageSize: 1}
	src := openSized(t, f, diskscan.Snapshot{ID: "snap-1"})

	tests := []struct {
		name string
		off  int64
		n    int
		want []byte
		eof  bool
	}{
		{"first block", 0, 8, b0, false},
		{"sparse block reads zeros", 8, 8, make([]byte, 8), false},
		{"spans data sparse data", 4, 16, append(append([]byte("AAAA"), make([]byte, 8)...), "CCCC"...), false},
		{"unaligned inside block", 18, 3, []byte("CCC"), false},
		{"trailing sparse block", 24, 8, make([]byte, 8), false},
		{"short read at end of volume", 28, 8, make([]byte, 4), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := make([]byte, tc.n)
			n, err := src.ReadAt(p, tc.off)
			assert.Equal(t, tc.want, p[:n])
			if tc.eof {
				assert.ErrorIs(t, err, io.EOF)
			} else {
				assert.NoError(t, err)
			}
		})
	}

	n, err := src.ReadAt(make([]byte, 1), src.Size())
	assert.Zero(t, n)
	assert.ErrorIs(t, err, io.EOF)
	_, err = src.ReadAt(make([]byte, 1), -1)
	assert.ErrorIs(t, err, diskscan.ErrBlockUnreadable)
}

func TestSparseBlocksCostNoCalls(t *testing.T) {
	f := &fakeEBS{blocks: map[int32]*fakeBlock{3: goodBlock([]byte("DDDDDDDD"))}}
	src := openSized(t, f, diskscan.Snapshot{ID: "snap-1"})
	p := make([]byte, 24)
	_, err := src.ReadAt(p, 0)
	require.NoError(t, err)
	assert.Equal(t, make([]byte, 24), p)
	assert.Zero(t, f.gets.Load())
}

func TestListSnapshotBlocksPagination(t *testing.T) {
	f := &fakeEBS{blocks: map[int32]*fakeBlock{
		0: goodBlock([]byte("AAAAAAAA")), 1: goodBlock([]byte("BBBBBBBB")),
		2: goodBlock([]byte("CCCCCCCC")), 3: goodBlock([]byte("DDDDDDDD")),
	}, pageSize: 1}
	src := openSized(t, f, diskscan.Snapshot{ID: "snap-1"})
	p := make([]byte, 32)
	_, err := src.ReadAt(p, 0)
	require.NoError(t, err)
	assert.Equal(t, "AAAAAAAABBBBBBBBCCCCCCCCDDDDDDDD", string(p))
}

func TestChecksumFailures(t *testing.T) {
	data := []byte("AAAAAAAA")
	bad := goodBlock(data)
	bad.checksum = sum([]byte("other"))
	missing := goodBlock(data)
	missing.checksum = nil
	notBase64 := goodBlock(data)
	notBase64.checksum = aws.String("%%%")
	wrongAlgo := goodBlock(data)
	wrongAlgo.algorithm = "MD5"
	shortLength := goodBlock(data)
	shortLength.length = aws.Int32(4)
	oversize := goodBlock([]byte("AAAAAAAAA"))

	for name, blk := range map[string]*fakeBlock{
		"mismatch": bad, "missing": missing, "not base64": notBase64,
		"unknown algorithm": wrongAlgo, "length mismatch": shortLength, "oversize": oversize,
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeEBS{blocks: map[int32]*fakeBlock{0: blk}}
			src := openSized(t, f, diskscan.Snapshot{ID: "snap-1"})
			p := make([]byte, 8)
			n, err := src.ReadAt(p, 0)
			assert.Zero(t, n)
			require.ErrorIs(t, err, diskscan.ErrBlockUnreadable)
			assert.NotErrorIs(t, err, ErrEncryptedNoKey)
			_, cached := src.cache.get(0)
			assert.False(t, cached, "a block that failed verification is never cached")
		})
	}
}

func TestCacheIsBoundedLRU(t *testing.T) {
	blocks := map[int32]*fakeBlock{}
	for i := int32(0); i < 4; i++ {
		blocks[i] = goodBlock(bytes.Repeat([]byte{'a' + byte(i)}, testBlock))
	}
	f := &fakeEBS{blocks: blocks}
	src := openSized(t, f, diskscan.Snapshot{ID: "snap-1"}, WithCacheBlocks(2), WithConcurrency(1))
	read := func(block int64) {
		_, err := src.ReadAt(make([]byte, testBlock), block*testBlock)
		require.NoError(t, err)
	}
	read(0)
	read(1)
	read(0) // hit; block 1 is now least recent
	assert.EqualValues(t, 2, f.gets.Load())
	read(2) // evicts 1
	assert.Equal(t, 2, src.cache.len())
	read(0) // still cached
	assert.EqualValues(t, 3, f.gets.Load())
	read(1) // refetched
	assert.EqualValues(t, 4, f.gets.Load())
}

func TestConcurrencyIsBounded(t *testing.T) {
	blocks := map[int32]*fakeBlock{}
	for i := int32(0); i < 4; i++ {
		blocks[i] = goodBlock(bytes.Repeat([]byte{'a' + byte(i)}, testBlock))
	}
	f := &fakeEBS{blocks: blocks}
	src := openSized(t, f, diskscan.Snapshot{ID: "snap-1"}, WithConcurrency(2))
	_, err := src.ReadAt(make([]byte, 4*testBlock), 0)
	require.NoError(t, err)
	assert.LessOrEqual(t, f.maxFlight.Load(), int32(2))
	assert.EqualValues(t, 4, f.gets.Load())
}

func TestReadAfterCloseAndCancelledContext(t *testing.T) {
	f := &fakeEBS{blocks: map[int32]*fakeBlock{0: goodBlock([]byte("AAAAAAAA"))}}
	ctx, cancel := context.WithCancel(context.Background())
	src, err := provider(&fakeEC2{}, f).Open(ctx, diskscan.Snapshot{ID: "snap-1"})
	require.NoError(t, err)
	cancel()
	_, err = src.ReadAt(make([]byte, 8), 0)
	require.ErrorIs(t, err, diskscan.ErrBlockUnreadable)
	require.ErrorIs(t, err, context.Canceled)

	require.NoError(t, src.Close())
	_, err = src.ReadAt(make([]byte, 8), 0)
	require.ErrorIs(t, err, diskscan.ErrBlockUnreadable)
}

func TestReadFailureClassification(t *testing.T) {
	kms := &ebstypes.AccessDeniedException{Reason: ebstypes.AccessDeniedExceptionReasonDependencyAccessDenied}
	plain := &ebstypes.AccessDeniedException{Reason: ebstypes.AccessDeniedExceptionReasonUnauthorizedAccount}
	badKey := &ebstypes.ValidationException{Reason: ebstypes.ValidationExceptionReasonInvalidCustomerKey}
	tests := []struct {
		name      string
		err       error
		encrypted bool
		want      error
	}{
		{"kms dependency denied", kms, false, ErrEncryptedNoKey},
		{"invalid customer key", badKey, true, ErrEncryptedNoKey},
		{"access denied on encrypted", plain, true, ErrEncryptedNoKey},
		{"access denied on plain", plain, false, ErrPermissionDenied},
		{"throttled", errors.New("slow down"), true, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &fakeEBS{blocks: map[int32]*fakeBlock{0: {err: tc.err}}}
			src := openSized(t, f, diskscan.Snapshot{ID: "snap-1", Encrypted: false})
			src.encrypted = tc.encrypted
			_, err := src.ReadAt(make([]byte, 8), 0)
			require.ErrorIs(t, err, diskscan.ErrBlockUnreadable)
			if tc.want == nil {
				assert.NotErrorIs(t, err, ErrEncryptedNoKey)
				assert.NotErrorIs(t, err, ErrPermissionDenied)
				return
			}
			assert.ErrorIs(t, err, tc.want)
		})
	}
}

func TestOpenEncryptedWithoutKeyFailsFast(t *testing.T) {
	f := &fakeEBS{blocks: map[int32]*fakeBlock{
		2: {err: &ebstypes.AccessDeniedException{Reason: ebstypes.AccessDeniedExceptionReasonDependencyAccessDenied}},
	}}
	_, err := provider(&fakeEC2{}, f).Open(context.Background(), diskscan.Snapshot{ID: "snap-1", Encrypted: true})
	require.ErrorIs(t, err, ErrEncryptedNoKey)

	f.blocks[2] = goodBlock([]byte("CCCCCCCC"))
	src, err := provider(&fakeEC2{}, f).Open(context.Background(), diskscan.Snapshot{ID: "snap-1", Encrypted: true})
	require.NoError(t, err)
	require.NoError(t, src.Close())
}

func TestOpenListErrors(t *testing.T) {
	denied := &ebstypes.AccessDeniedException{Reason: ebstypes.AccessDeniedExceptionReasonUnauthorizedAccount}
	_, err := provider(&fakeEC2{}, &fakeEBS{listErr: denied}).Open(context.Background(), diskscan.Snapshot{ID: "s"})
	require.ErrorIs(t, err, ErrPermissionDenied)

	_, err = provider(&fakeEC2{}, &fakeEBS{listErr: errors.New("boom")}).Open(context.Background(), diskscan.Snapshot{ID: "s"})
	require.Error(t, err)
	assert.NotErrorIs(t, err, ErrPermissionDenied)

	_, err = New(func(string) (Clients, error) { return Clients{}, errors.New("no creds") }).Open(context.Background(), diskscan.Snapshot{ID: "s"})
	require.Error(t, err)
}

func snap(id, vol string, start time.Time, tags ...ec2types.Tag) ec2types.Snapshot {
	return ec2types.Snapshot{
		SnapshotId: aws.String(id), VolumeId: aws.String(vol), VolumeSize: aws.Int32(8),
		Encrypted: aws.Bool(id == "snap-enc"), StartTime: aws.Time(start), Tags: tags,
	}
}

func TestListReusable(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ours := ec2types.Tag{Key: aws.String(diskscan.TagKey), Value: aws.String("run-1")}
	f := &fakeEC2{pages: [][]ec2types.Snapshot{
		{snap("snap-old", "vol-1", t0), snap("snap-ours", "vol-1", t0.Add(48*time.Hour), ours)},
		{snap("snap-new", "vol-1", t0.Add(24*time.Hour)), snap("snap-enc", "vol-1", t0.Add(12*time.Hour))},
	}}
	got, err := provider(f, &fakeEBS{}).ListReusable(context.Background(), diskscan.VolumeRef{Region: "eu-west-1", VolumeID: "vol-1"})
	require.NoError(t, err)
	var ids []string
	for _, s := range got {
		ids = append(ids, s.ID)
	}
	assert.Equal(t, []string{"snap-new", "snap-enc", "snap-old"}, ids, "newest first, Vulngraph's own snapshots excluded, every page read")
	assert.Equal(t, int32(2), f.calls.Load())
	assert.Equal(t, diskscan.Snapshot{
		ID: "snap-new", Provider: "aws", Region: "eu-west-1", VolumeID: "vol-1",
		SizeBytes: 8 << 30, CreatedAt: t0.Add(24 * time.Hour),
	}, got[0])
	assert.True(t, got[1].Encrypted)
}

func TestListReusableErrors(t *testing.T) {
	denied := &fakeEC2{err: errors.New("UnauthorizedOperation")}
	_, err := provider(denied, &fakeEBS{}).ListReusable(context.Background(), diskscan.VolumeRef{VolumeID: "vol-1"})
	require.Error(t, err)

	empty := &fakeEC2{pages: [][]ec2types.Snapshot{nil}}
	got, err := provider(empty, &fakeEBS{}).ListReusable(context.Background(), diskscan.VolumeRef{VolumeID: "vol-1"})
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestChanged(t *testing.T) {
	f := &fakeEBS{changed: [][]int32{{0, 1, 5}, {6, 9}}}
	got, err := provider(&fakeEC2{}, f).Changed(context.Background(), diskscan.Snapshot{ID: "a"}, diskscan.Snapshot{ID: "b"})
	require.NoError(t, err)
	assert.Equal(t, []diskscan.Extent{
		{Offset: 0, Length: 2 * testBlock},
		{Offset: 5 * testBlock, Length: 2 * testBlock},
		{Offset: 9 * testBlock, Length: testBlock},
	}, got, "adjacent blocks merge across pages")
}

func TestChangedUnsupported(t *testing.T) {
	_, err := provider(&fakeEC2{}, &fakeEBS{changedErr: &ebstypes.ValidationException{Reason: ebstypes.ValidationExceptionReasonUnrelatedSnapshots}}).
		Changed(context.Background(), diskscan.Snapshot{ID: "a"}, diskscan.Snapshot{ID: "b"})
	require.ErrorIs(t, err, diskscan.ErrNoDiff)

	_, err = provider(&fakeEC2{}, &fakeEBS{changedErr: &ebstypes.AccessDeniedException{}}).
		Changed(context.Background(), diskscan.Snapshot{ID: "a"}, diskscan.Snapshot{ID: "b"})
	require.ErrorIs(t, err, ErrPermissionDenied)
	assert.NotErrorIs(t, err, diskscan.ErrNoDiff)

	_, err = provider(&fakeEC2{}, &fakeEBS{changedErr: context.Canceled}).
		Changed(context.Background(), diskscan.Snapshot{ID: "a"}, diskscan.Snapshot{ID: "b"})
	require.ErrorIs(t, err, context.Canceled)
	assert.NotErrorIs(t, err, diskscan.ErrNoDiff)
}
