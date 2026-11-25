package diskscan

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/ext4"
	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/part"
	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/xfs"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
)

// Defaults for a zero Limits field.
const (
	defaultMaxVolumeBytes = 64 << 40
	defaultMaxBytesRead   = 1 << 30
	defaultMaxTotalBytes  = 512 << 20
	defaultMaxFileBytes   = pkginventory.MaxRPMDBBytes

	// packageDBUnreadReason is the value of asset.CVEGapPackageDBUnread;
	// TestPackageDBUnreadMatchesAsset pins it.
	packageDBUnreadReason = "package_db_unread"
)

func (l Limits) withDefaults() Limits {
	if l.MaxVolumeBytes <= 0 {
		l.MaxVolumeBytes = defaultMaxVolumeBytes
	}
	if l.MaxBytesRead <= 0 {
		l.MaxBytesRead = defaultMaxBytesRead
	}
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = defaultMaxFileBytes
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = defaultMaxTotalBytes
	}
	return l
}

// budgetReader counts every byte read from the disk and stops at the budget or
// when the context ends.
type budgetReader struct {
	ctx       context.Context
	r         io.ReaderAt
	remaining atomic.Int64
}

func (b *budgetReader) ReadAt(p []byte, off int64) (int, error) {
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	if b.remaining.Add(-int64(len(p))) < 0 {
		return 0, fmt.Errorf("read of %d bytes: %w", len(p), errOverCap)
	}
	return b.r.ReadAt(p, off)
}

// ScanDisk inventories the OS packages on a VM disk. It reads the partition
// table, finds the root filesystem (the readable partition that holds an OS
// package database) and runs the same parsers the image scanner uses over a
// LimitedFS of it.
//
// InventoryKnown is true only when a package database was positively read in
// full; a root that names an OS but yields no packages, or any disk part that
// could not be read, is InventoryKnown=false with Gap saying why. The error is
// non-nil only when ctx ends.
func ScanDisk(ctx context.Context, src BlockSource, lim Limits) (DiskResult, error) {
	lim = lim.withDefaults()
	size := src.Size()
	switch {
	case size <= 0:
		return DiskResult{Gap: GapReadError}, nil
	case size > lim.MaxVolumeBytes:
		return DiskResult{Gap: GapOverCap}, nil
	}
	br := &budgetReader{ctx: ctx, r: src}
	br.remaining.Store(lim.MaxBytesRead)

	var st scanState
	cands := st.candidates(br, size)
	for _, c := range cands {
		if res, ok := st.scan(ctx, br, c, lim); ok {
			return res, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return DiskResult{}, fmt.Errorf("ScanDisk: %w", err)
	}
	return DiskResult{Gap: st.gap()}, nil
}

type candidate struct{ offset, size int64 }

// scanState remembers why partitions could not be used, for the gap reported
// when none yields an inventory.
type scanState struct {
	overCap, readErr, encrypted, unsupportedFS, unsupportedPart, rootNoDB bool
}

func (s *scanState) note(err error) {
	switch {
	case errors.Is(err, errOverCap), errors.Is(err, ext4.ErrTooLarge), errors.Is(err, xfs.ErrTooLarge):
		s.overCap = true
	case errors.Is(err, ext4.ErrUnsupported), errors.Is(err, xfs.ErrUnsupported):
		s.unsupportedFS = true
	default:
		s.readErr = true
	}
}

func (s *scanState) gap() string {
	switch {
	case s.overCap:
		return GapOverCap
	case s.readErr, s.rootNoDB:
		return GapReadError
	case s.encrypted:
		return GapEncryptedNoKey
	case s.unsupportedPart:
		return GapUnsupportedPartition
	}
	return GapUnsupportedFS
}

func (s *scanState) candidates(r io.ReaderAt, size int64) []candidate {
	parts, err := part.Read(r, size)
	switch {
	case errors.Is(err, part.ErrNoTable):
		return []candidate{{0, size}}
	case errors.Is(err, part.ErrCorrupt):
		s.unsupportedPart = true
		return nil
	case err != nil:
		s.note(err)
		return nil
	}
	var out []candidate
	for _, p := range parts {
		if p.Unsupported != "" {
			s.unsupportedPart = true
			continue
		}
		out = append(out, candidate{p.Offset, p.Size})
	}
	return out
}

// scan tries one partition. ok is true when it is the root and its package
// database was read.
func (s *scanState) scan(ctx context.Context, r io.ReaderAt, c candidate, lim Limits) (DiskResult, bool) {
	sec := io.NewSectionReader(r, c.offset, c.size)
	var head [8]byte
	if _, err := sec.ReadAt(head[:], 0); err != nil && !errors.Is(err, io.EOF) {
		s.note(err)
		return DiskResult{}, false
	}
	if bytes.HasPrefix(head[:], []byte("LUKS\xba\xbe")) {
		s.encrypted = true
		return DiskResult{}, false
	}
	fsys, err := openFS(sec, c.size, head[:])
	if errors.Is(err, ext4.ErrNotExt4) || errors.Is(err, xfs.ErrNotXFS) {
		s.unsupportedFS = true
		return DiskResult{}, false
	}
	if err != nil {
		s.note(err)
		return DiskResult{}, false
	}
	lfs := NewLimitedFS(ctx, fsys, lim)
	inv := pkginventory.InventoryPackages(ctx, lfs)
	eco, gap, _ := pkginventory.OSCVEGap(lfs, inv.Packages, distro.Sources{}, time.Now())
	if err := lfs.Fault(); err != nil {
		s.note(err)
		return DiskResult{}, false
	}
	if !lfs.PackageDBRead() {
		s.rootNoDB = s.rootNoDB || lfs.OSReleaseRead()
		return DiskResult{}, false
	}
	if gap == packageDBUnreadReason && !hasOSPackages(inv.Packages) {
		s.readErr = true
		return DiskResult{}, false
	}
	return DiskResult{Packages: inv.Packages, Ecosystem: eco, InventoryKnown: true, LanguageGap: true}, true
}

// openFS picks the reader by superblock magic: XFS announces itself at the
// partition start, ext2/3/4 at offset 1024.
func openFS(r io.ReaderAt, size int64, head []byte) (RawFS, error) {
	if bytes.HasPrefix(head, []byte("XFSB")) {
		f, err := xfs.Open(r, size)
		if err != nil {
			return nil, err
		}
		return f, nil
	}
	f, err := ext4.Open(r, size)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func hasOSPackages(pkgs []pkginventory.InstalledPackage) bool {
	for _, p := range pkgs {
		if _, ok := distro.FamilyOf(p.Ecosystem); ok {
			return true
		}
	}
	return false
}
