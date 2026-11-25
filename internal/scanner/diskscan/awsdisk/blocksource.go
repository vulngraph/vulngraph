package awsdisk

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/aws/aws-sdk-go-v2/service/ebs"
	ebstypes "github.com/aws/aws-sdk-go-v2/service/ebs/types"
	"golang.org/x/sync/errgroup"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan"
)

// blockSource serves a snapshot's bytes from the EBS direct APIs. Blocks the
// snapshot does not list are sparse and read as zeros.
type blockSource struct {
	ctx         context.Context
	cancel      context.CancelFunc
	client      EBSAPI
	snapshotID  string
	encrypted   bool
	blockSize   int64
	size        int64
	tokens      map[int32]string
	cache       *blockCache
	concurrency int
	closed      atomic.Bool
}

func (s *blockSource) Size() int64 { return s.size }

func (s *blockSource) Close() error {
	s.closed.Store(true)
	s.cancel()
	s.cache.clear()
	return nil
}

// ReadAt fills p from the snapshot. A range that cannot be fetched or verified
// returns an error matching diskscan.ErrBlockUnreadable.
func (s *blockSource) ReadAt(p []byte, off int64) (int, error) {
	if s.closed.Load() {
		return 0, fmt.Errorf("ReadAt: source closed: %w", diskscan.ErrBlockUnreadable)
	}
	if off < 0 {
		return 0, fmt.Errorf("ReadAt: negative offset %d: %w", off, diskscan.ErrBlockUnreadable)
	}
	if off >= s.size {
		return 0, io.EOF
	}
	n := int64(len(p))
	if off+n > s.size {
		n = s.size - off
	}
	if n == 0 {
		return 0, nil
	}
	first, last := off/s.blockSize, (off+n-1)/s.blockSize
	blocks := make([][]byte, last-first+1)

	g, gctx := errgroup.WithContext(s.ctx)
	g.SetLimit(s.concurrency)
	for i := range blocks {
		g.Go(func() error {
			data, err := s.block(gctx, int32(first)+int32(i))
			blocks[i] = data
			return err
		})
	}
	if err := g.Wait(); err != nil {
		return 0, err
	}

	var copied int64
	for i, data := range blocks {
		blockStart := (first + int64(i)) * s.blockSize
		from := max(off, blockStart) - blockStart
		to := min(off+n, blockStart+s.blockSize) - blockStart
		dst := p[copied : copied+to-from]
		if data == nil {
			clear(dst)
		} else {
			copy(dst, data[from:to])
		}
		copied += to - from
	}
	if n < int64(len(p)) {
		return int(n), io.EOF
	}
	return int(n), nil
}

// block returns one verified block, or nil for a sparse block.
func (s *blockSource) block(ctx context.Context, index int32) ([]byte, error) {
	token, ok := s.tokens[index]
	if !ok {
		return nil, nil
	}
	if data, ok := s.cache.get(index); ok {
		return data, nil
	}
	data, err := s.fetch(ctx, index, token)
	if err != nil {
		return nil, err
	}
	s.cache.put(index, data)
	return data, nil
}

func (s *blockSource) fetch(ctx context.Context, index int32, token string) ([]byte, error) {
	out, err := s.client.GetSnapshotBlock(ctx, &ebs.GetSnapshotBlockInput{
		SnapshotId: &s.snapshotID,
		BlockIndex: &index,
		BlockToken: &token,
	})
	if err != nil {
		return nil, s.readError(index, err)
	}
	defer func() { _ = out.BlockData.Close() }()
	data, err := io.ReadAll(io.LimitReader(out.BlockData, s.blockSize+1))
	if err != nil {
		return nil, s.readError(index, err)
	}
	if int64(len(data)) > s.blockSize {
		return nil, fmt.Errorf("block %d: %d bytes exceeds block size %d: %w", index, len(data), s.blockSize, diskscan.ErrBlockUnreadable)
	}
	if out.DataLength != nil && int64(*out.DataLength) != int64(len(data)) {
		return nil, fmt.Errorf("block %d: got %d bytes, API reported %d: %w", index, len(data), *out.DataLength, diskscan.ErrBlockUnreadable)
	}
	if err := verifyChecksum(data, out.ChecksumAlgorithm, out.Checksum); err != nil {
		return nil, fmt.Errorf("block %d: %w: %w", index, err, diskscan.ErrBlockUnreadable)
	}
	if int64(len(data)) < s.blockSize {
		padded := make([]byte, s.blockSize)
		copy(padded, data)
		data = padded
	}
	return data, nil
}

func (s *blockSource) readError(index int32, err error) error {
	if kind := classifyRead(err, s.encrypted); kind != nil {
		return fmt.Errorf("block %d: %w: %w (%s)", index, diskscan.ErrBlockUnreadable, kind, err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("block %d: %w: %w", index, diskscan.ErrBlockUnreadable, err)
	}
	return fmt.Errorf("block %d: %w (%s)", index, diskscan.ErrBlockUnreadable, err)
}

// verifyChecksum checks the block against the SHA-256 the API returned (base64).
// A missing checksum or an algorithm we do not know is a failure, not a pass.
func verifyChecksum(data []byte, algo ebstypes.ChecksumAlgorithm, checksum *string) error {
	if algo != ebstypes.ChecksumAlgorithmChecksumAlgorithmSha256 {
		return fmt.Errorf("unsupported checksum algorithm %q", algo)
	}
	if checksum == nil {
		return fmt.Errorf("no checksum returned")
	}
	want, err := base64.StdEncoding.DecodeString(*checksum)
	if err != nil {
		return fmt.Errorf("checksum is not base64: %w", err)
	}
	got := sha256.Sum256(data)
	if !bytes.Equal(got[:], want) {
		return fmt.Errorf("checksum mismatch")
	}
	return nil
}
