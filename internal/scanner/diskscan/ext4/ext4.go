// Package ext4 is a bounded, read-only ext2/3/4 reader for untrusted disk
// images. It reads the superblock, group descriptors, inodes, extent trees and
// the legacy block map, directories (linear scan, which also covers htree
// directories) and symlinks. Anything else the filesystem uses (inline data,
// encryption, bigalloc, meta_bg, casefold, compression) is reported as
// ErrUnsupported, never read as if it were absent.
//
// Every length and block number comes from the image and is checked before use;
// loops are bounded by structure depth or by the image size, so a hostile image
// can cost reads but never an unbounded allocation or a hang.
package ext4

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
)

var (
	// ErrNotExt4 means the superblock magic is absent: the device is something else.
	ErrNotExt4 = errors.New("ext4: not an ext2/3/4 filesystem")
	// ErrUnsupported means the filesystem uses a feature this reader does not handle.
	ErrUnsupported = errors.New("ext4: unsupported feature")
	// ErrCorrupt means on-disk metadata contradicts itself or the device size.
	ErrCorrupt = errors.New("ext4: corrupt metadata")
	// ErrTooLarge means a directory or listing exceeds the reader's bound.
	ErrTooLarge = errors.New("ext4: structure exceeds the reader's bound")
)

const (
	superblockOffset = 1024
	superblockSize   = 1024
	magic            = 0xEF53
	rootIno          = 2
	maxLogBlockSize  = 6 // 64 KiB blocks
	maxSymlink       = 4095
	maxDirBytes      = 64 << 20
	maxDirNames      = 100_000
	maxExtentDepth   = 5

	incompatFiletype   = 0x2
	incompatRecover    = 0x4
	incompatExtents    = 0x40
	incompat64bit      = 0x80
	incompatMMP        = 0x100
	incompatFlexBG     = 0x200
	incompatEAInode    = 0x400
	incompatCsumSeed   = 0x2000
	incompatLargeDir   = 0x4000
	supportedIncompat  = incompatFiletype | incompatRecover | incompatExtents | incompat64bit | incompatMMP | incompatFlexBG | incompatEAInode | incompatCsumSeed | incompatLargeDir
	roCompatBigalloc   = 0x200
	inodeFlagEncrypt   = 0x800
	inodeFlagExtents   = 0x80000
	inodeFlagInlineDat = 0x10000000

	modeFmt     = 0xF000
	modeDir     = 0x4000
	modeSymlink = 0xA000
)

// FS is an opened filesystem. It is safe for concurrent reads when the
// underlying io.ReaderAt is.
type FS struct {
	r            io.ReaderAt
	blockSize    uint64
	blocksCount  uint64
	firstData    uint64
	blocksPerGrp uint64
	inodesPerGrp uint64
	inodesCount  uint64
	inodeSize    uint64
	descSize     uint64
	groups       uint64
	rev          uint32
}

// Open reads and validates the superblock of the filesystem at the start of r.
// size is the length of r in bytes.
func Open(r io.ReaderAt, size int64) (*FS, error) {
	var sb [superblockSize]byte
	if err := readFull(r, sb[:], superblockOffset); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrNotExt4
		}
		return nil, fmt.Errorf("ext4.Open: superblock: %w", err)
	}
	le := binary.LittleEndian
	if le.Uint16(sb[0x38:]) != magic {
		return nil, ErrNotExt4
	}
	logBS := le.Uint32(sb[0x18:])
	if logBS > maxLogBlockSize {
		return nil, fmt.Errorf("ext4.Open: block size shift %d: %w", logBS, ErrCorrupt)
	}
	incompat := le.Uint32(sb[0x60:])
	if bad := incompat &^ supportedIncompat; bad != 0 {
		return nil, fmt.Errorf("ext4.Open: incompat features %#x: %w", bad, ErrUnsupported)
	}
	if le.Uint32(sb[0x64:])&roCompatBigalloc != 0 {
		return nil, fmt.Errorf("ext4.Open: bigalloc: %w", ErrUnsupported)
	}
	f := &FS{
		r:            r,
		blockSize:    uint64(1024) << logBS,
		blocksCount:  uint64(le.Uint32(sb[0x4:])),
		firstData:    uint64(le.Uint32(sb[0x14:])),
		blocksPerGrp: uint64(le.Uint32(sb[0x20:])),
		inodesPerGrp: uint64(le.Uint32(sb[0x28:])),
		inodesCount:  uint64(le.Uint32(sb[0x0:])),
		inodeSize:    128,
		descSize:     32,
		rev:          le.Uint32(sb[0x4C:]),
	}
	if f.rev >= 1 {
		f.inodeSize = uint64(le.Uint16(sb[0x58:]))
	}
	if incompat&incompat64bit != 0 {
		f.blocksCount |= uint64(le.Uint32(sb[0x150:])) << 32
		f.descSize = uint64(le.Uint16(sb[0xFE:]))
		if f.descSize < 64 || f.descSize > 1024 || f.descSize&(f.descSize-1) != 0 {
			return nil, fmt.Errorf("ext4.Open: descriptor size %d: %w", f.descSize, ErrCorrupt)
		}
	}
	if err := f.validate(size); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *FS) validate(size int64) error {
	bs := f.blockSize
	switch {
	case f.blocksCount == 0 || f.blocksPerGrp == 0 || f.blocksPerGrp > bs*8:
		return fmt.Errorf("ext4.Open: block counts: %w", ErrCorrupt)
	case f.inodesPerGrp == 0 || f.inodesPerGrp > bs*8 || f.inodesCount == 0:
		return fmt.Errorf("ext4.Open: inode counts: %w", ErrCorrupt)
	case f.inodeSize < 128 || f.inodeSize > bs || f.inodeSize&(f.inodeSize-1) != 0:
		return fmt.Errorf("ext4.Open: inode size %d: %w", f.inodeSize, ErrCorrupt)
	case f.firstData >= f.blocksCount:
		return fmt.Errorf("ext4.Open: first data block: %w", ErrCorrupt)
	case f.blocksCount > uint64(size)/bs:
		return fmt.Errorf("ext4.Open: filesystem of %d blocks exceeds the %d byte device: %w", f.blocksCount, size, ErrCorrupt)
	}
	f.groups = (f.blocksCount - f.firstData + f.blocksPerGrp - 1) / f.blocksPerGrp
	if f.inodesCount > f.groups*f.inodesPerGrp {
		return fmt.Errorf("ext4.Open: inode count exceeds the groups: %w", ErrCorrupt)
	}
	return nil
}

// Root is the inode number of the root directory.
func (f *FS) Root() uint64 { return rootIno }

type inode struct {
	mode  uint16
	flags uint32
	size  uint64
	block [60]byte
}

func (in *inode) isDir() bool     { return in.mode&modeFmt == modeDir }
func (in *inode) isSymlink() bool { return in.mode&modeFmt == modeSymlink }

func (f *FS) readInode(ino uint64) (*inode, error) {
	if ino == 0 || ino > f.inodesCount {
		return nil, fmt.Errorf("ext4: inode %d out of range: %w", ino, ErrCorrupt)
	}
	group := (ino - 1) / f.inodesPerGrp
	idx := (ino - 1) % f.inodesPerGrp
	var gd [64]byte
	n := f.descSize
	if n > uint64(len(gd)) {
		n = uint64(len(gd))
	}
	if err := readFull(f.r, gd[:n], int64((f.firstData+1)*f.blockSize+group*f.descSize)); err != nil {
		return nil, fmt.Errorf("ext4: group descriptor %d: %w", group, mapEOF(err))
	}
	table := uint64(binary.LittleEndian.Uint32(gd[0x8:]))
	if f.descSize >= 64 {
		table |= uint64(binary.LittleEndian.Uint32(gd[0x28:])) << 32
	}
	tableBlocks := (f.inodesPerGrp*f.inodeSize + f.blockSize - 1) / f.blockSize
	if table == 0 || table+tableBlocks > f.blocksCount {
		return nil, fmt.Errorf("ext4: inode table of group %d: %w", group, ErrCorrupt)
	}
	var raw [256]byte
	buf := raw[:min(f.inodeSize, uint64(len(raw)))]
	if err := readFull(f.r, buf, int64(table*f.blockSize+idx*f.inodeSize)); err != nil {
		return nil, fmt.Errorf("ext4: inode %d: %w", ino, mapEOF(err))
	}
	le := binary.LittleEndian
	in := &inode{
		mode:  le.Uint16(buf[0x0:]),
		flags: le.Uint32(buf[0x20:]),
		size:  uint64(le.Uint32(buf[0x4:])),
	}
	if f.rev >= 1 {
		in.size |= uint64(le.Uint32(buf[0x6C:])) << 32
	}
	copy(in.block[:], buf[0x28:0x28+60])
	if in.size > 1<<62 {
		return nil, fmt.Errorf("ext4: inode %d size: %w", ino, ErrCorrupt)
	}
	return in, nil
}

// checkReadable rejects inode encodings this reader cannot interpret.
func (in *inode) checkReadable() error {
	switch {
	case in.flags&inodeFlagInlineDat != 0:
		return fmt.Errorf("ext4: inline data: %w", ErrUnsupported)
	case in.flags&inodeFlagEncrypt != 0:
		return fmt.Errorf("ext4: encrypted inode: %w", ErrUnsupported)
	}
	return nil
}

// Stat returns the raw Unix mode and size of an inode.
func (f *FS) Stat(ino uint64) (mode uint32, size int64, err error) {
	in, err := f.readInode(ino)
	if err != nil {
		return 0, 0, err
	}
	return uint32(in.mode), int64(in.size), nil
}

// ReadLink returns a symlink's target.
func (f *FS) ReadLink(ino uint64) (string, error) {
	in, err := f.readInode(ino)
	if err != nil {
		return "", err
	}
	if !in.isSymlink() {
		return "", fmt.Errorf("ext4: inode %d is not a symlink: %w", ino, ErrCorrupt)
	}
	if err := in.checkReadable(); err != nil {
		return "", err
	}
	if in.size > maxSymlink {
		return "", fmt.Errorf("ext4: symlink of %d bytes: %w", in.size, ErrCorrupt)
	}
	if in.size < uint64(len(in.block)) && in.flags&inodeFlagExtents == 0 {
		return string(in.block[:in.size]), nil
	}
	buf := make([]byte, in.size)
	if _, err := f.readData(in, buf, 0); err != nil {
		return "", err
	}
	return string(buf), nil
}

// ReadAt reads regular-file data. It follows io.ReaderAt: a short read at the
// end of the file returns io.EOF.
func (f *FS) ReadAt(ino uint64, p []byte, off int64) (int, error) {
	in, err := f.readInode(ino)
	if err != nil {
		return 0, err
	}
	if in.mode&modeFmt != 0x8000 {
		return 0, fmt.Errorf("ext4: inode %d is not a regular file: %w", ino, ErrCorrupt)
	}
	if err := in.checkReadable(); err != nil {
		return 0, err
	}
	return f.readData(in, p, off)
}

func (f *FS) readData(in *inode, p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("ext4: negative offset: %w", fs.ErrInvalid)
	}
	size := int64(in.size)
	if off >= size {
		return 0, io.EOF
	}
	want := p
	if int64(len(want)) > size-off {
		want = want[:size-off]
	}
	bs := int64(f.blockSize)
	done := 0
	for done < len(want) {
		pos := off + int64(done)
		m, err := f.mapBlock(in, uint64(pos/bs))
		if err != nil {
			return done, err
		}
		inBlock := pos % bs
		span := min(int64(m.run)*bs-inBlock, int64(len(want)-done))
		chunk := want[done : done+int(span)]
		if m.kind == mapData {
			if err := readFull(f.r, chunk, int64(m.phys)*bs+inBlock); err != nil {
				return done, fmt.Errorf("ext4: file data: %w", mapEOF(err))
			}
		} else {
			clear(chunk)
		}
		done += int(span)
	}
	if done < len(p) {
		return done, io.EOF
	}
	return done, nil
}

// readFull reads exactly len(p) bytes at off. A short read is
// io.ErrUnexpectedEOF; any other error is the source's own (for example
// ErrBlockUnreadable) and is passed through.
func readFull(r io.ReaderAt, p []byte, off int64) error {
	if len(p) == 0 {
		return nil
	}
	n, err := r.ReadAt(p, off)
	if n == len(p) {
		return nil
	}
	if err == nil || errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}

// mapEOF turns a short read inside a filesystem the superblock says fits the
// device into corruption; every other error keeps its identity.
func mapEOF(err error) error {
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("short read: %w", ErrCorrupt)
	}
	return err
}
