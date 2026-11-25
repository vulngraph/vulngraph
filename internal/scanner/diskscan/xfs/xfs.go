// Package xfs is a bounded, read-only XFS reader for untrusted disk images. It
// reads v4 and v5 superblocks, inodes addressed directly from their inode
// number (no inode btree), extent-list and btree data forks, short-form,
// block, leaf and node directories, and local and extent symlinks. Anything
// else the filesystem uses (realtime volumes, unknown incompat features,
// version 1 inodes or directories) is reported as ErrUnsupported, never read as
// if it were absent. The journal is not replayed.
//
// Every length and block number comes from the image and is checked before use;
// loops are bounded by structure depth or by the image size, so a hostile image
// can cost reads but never an unbounded allocation or a hang.
package xfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
)

var (
	// ErrNotXFS means the superblock magic is absent: the device is something else.
	ErrNotXFS = errors.New("xfs: not an XFS filesystem")
	// ErrUnsupported means the filesystem uses a feature this reader does not handle.
	ErrUnsupported = errors.New("xfs: unsupported feature")
	// ErrCorrupt means on-disk metadata contradicts itself or the device size.
	ErrCorrupt = errors.New("xfs: corrupt metadata")
	// ErrTooLarge means a directory or listing exceeds the reader's bound.
	ErrTooLarge = errors.New("xfs: structure exceeds the reader's bound")
)

const (
	sbMagic        = 0x58465342 // "XFSB"
	inodeMagic     = 0x494E     // "IN"
	maxSymlink     = 1024
	maxDirBytes    = 64 << 20
	maxDirNames    = 100_000
	maxBtreeLevels = 9
	maxSector      = 32768
	maxBlockLog    = 16

	v4CoreSize = 100
	v5CoreSize = 176

	versionMask       = 0xF
	v4DirV2Bit        = 0x2000
	v4MoreBits        = 0x8000
	features2Ftype    = 0x200
	features2Known    = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x80 | 0x100 | 0x200
	incompatFtype     = 0x1
	incompatSpinodes  = 0x2
	incompatMetaUUID  = 0x4
	incompatBigtime   = 0x8
	incompatNeedsFix  = 0x10
	incompatNrext64   = 0x20
	supportedIncompat = incompatFtype | incompatSpinodes | incompatMetaUUID | incompatBigtime | incompatNrext64

	flagRealtime   = 0x1
	flags2Nrext64  = 1 << 4
	formatLocal    = 1
	formatExtents  = 2
	formatBtree    = 3
	modeFmt        = 0xF000
	modeReg        = 0x8000
	modeDir        = 0x4000
	modeSymlink    = 0xA000
	maxInodeSize   = 2048
	maxLogicalBlks = uint64(1) << 54
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

// FS is an opened filesystem. It is safe for concurrent reads when the
// underlying io.ReaderAt is.
type FS struct {
	r         io.ReaderAt
	blockSize uint64
	dblocks   uint64
	agBlocks  uint64
	agCount   uint64
	inodeSize uint64
	dirBlkFsb uint64 // filesystem blocks per directory block
	agBlkLog  uint
	inoBlkLog uint
	rootIno   uint64
	v5        bool
	ftype     bool
	nrext64   bool
}

// Open reads and validates the superblock of the filesystem at the start of r.
// size is the length of r in bytes.
func Open(r io.ReaderAt, size int64) (*FS, error) {
	var sb [264]byte
	if err := readFull(r, sb[:4], 0); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrNotXFS
		}
		return nil, fmt.Errorf("xfs.Open: superblock: %w", err)
	}
	if binary.BigEndian.Uint32(sb[:]) != sbMagic {
		return nil, ErrNotXFS
	}
	if err := readFull(r, sb[4:], 4); err != nil {
		return nil, fmt.Errorf("xfs.Open: superblock: %w", mapEOF(err))
	}
	f, sectSize, err := parseSuperblock(sb[:], r, size)
	if err != nil {
		return nil, err
	}
	if f.v5 {
		if err := verifySuperblockCRC(r, sectSize); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func verifySuperblockCRC(r io.ReaderAt, sectSize uint64) error {
	buf := make([]byte, sectSize)
	if err := readFull(r, buf, 0); err != nil {
		return fmt.Errorf("xfs.Open: superblock sector: %w", mapEOF(err))
	}
	if !crcValid(buf, 0xE0) {
		return fmt.Errorf("xfs.Open: superblock checksum: %w", ErrCorrupt)
	}
	return nil
}

// crcValid checks the CRC32C stored little-endian at crcOff, computed with that
// field zeroed.
func crcValid(buf []byte, crcOff int) bool {
	want := binary.LittleEndian.Uint32(buf[crcOff:])
	var zero [4]byte
	crc := crc32.Update(0, castagnoli, buf[:crcOff])
	crc = crc32.Update(crc, castagnoli, zero[:])
	crc = crc32.Update(crc, castagnoli, buf[crcOff+4:])
	return crc == want
}

func parseSuperblock(sb []byte, r io.ReaderAt, size int64) (*FS, uint64, error) {
	be := binary.BigEndian
	f := &FS{
		r:         r,
		blockSize: uint64(be.Uint32(sb[0x4:])),
		dblocks:   be.Uint64(sb[0x8:]),
		rootIno:   be.Uint64(sb[0x38:]),
		agBlocks:  uint64(be.Uint32(sb[0x54:])),
		agCount:   uint64(be.Uint32(sb[0x58:])),
		inodeSize: uint64(be.Uint16(sb[0x68:])),
		agBlkLog:  uint(sb[0x7C]),
	}
	version := be.Uint16(sb[0x64:])
	sectSize := uint64(be.Uint16(sb[0x66:]))
	blockLog, sectLog, inodeLog, inoBlkLog := uint(sb[0x78]), uint(sb[0x79]), uint(sb[0x7A]), uint(sb[0x7B])
	dirBlkLog := uint(sb[0xC0])
	f.inoBlkLog = inoBlkLog

	if err := f.checkFeatures(sb, version); err != nil {
		return nil, 0, err
	}
	switch {
	case blockLog < 9 || blockLog > maxBlockLog || f.blockSize != 1<<blockLog:
		return nil, 0, fmt.Errorf("xfs.Open: block size %d: %w", f.blockSize, ErrCorrupt)
	case sectLog < 9 || sectLog > 15 || sectSize != 1<<sectLog || sectSize > f.blockSize || sectSize > maxSector:
		return nil, 0, fmt.Errorf("xfs.Open: sector size %d: %w", sectSize, ErrCorrupt)
	case inodeLog < 8 || inodeLog > 11 || f.inodeSize != 1<<inodeLog || f.inodeSize > f.blockSize:
		return nil, 0, fmt.Errorf("xfs.Open: inode size %d: %w", f.inodeSize, ErrCorrupt)
	case inoBlkLog != blockLog-inodeLog || uint64(be.Uint16(sb[0x6A:])) != f.blockSize/f.inodeSize:
		return nil, 0, fmt.Errorf("xfs.Open: inodes per block: %w", ErrCorrupt)
	case blockLog+dirBlkLog > maxBlockLog:
		return nil, 0, fmt.Errorf("xfs.Open: directory block shift %d: %w", dirBlkLog, ErrCorrupt)
	case sb[0x7E] != 0:
		return nil, 0, fmt.Errorf("xfs.Open: mkfs in progress: %w", ErrCorrupt)
	}
	f.dirBlkFsb = 1 << dirBlkLog
	if be.Uint64(sb[0x10:]) != 0 || be.Uint64(sb[0x18:]) != 0 {
		return nil, 0, fmt.Errorf("xfs.Open: realtime volume: %w", ErrUnsupported)
	}
	if err := f.validateGeometry(size); err != nil {
		return nil, 0, err
	}
	if _, err := f.inodeOffset(f.rootIno); err != nil {
		return nil, 0, fmt.Errorf("xfs.Open: root inode: %w", err)
	}
	return f, sectSize, nil
}

// checkFeatures sets the feature flags and rejects every version or feature bit
// this reader does not handle.
func (f *FS) checkFeatures(sb []byte, version uint16) error {
	be := binary.BigEndian
	switch version & versionMask {
	case 4:
		if version&v4DirV2Bit == 0 {
			return fmt.Errorf("xfs.Open: version 1 directories: %w", ErrUnsupported)
		}
		if version&v4MoreBits != 0 {
			f2 := be.Uint32(sb[0xC8:])
			if f2&^features2Known != 0 {
				return fmt.Errorf("xfs.Open: features2 %#x: %w", f2&^features2Known, ErrUnsupported)
			}
			f.ftype = f2&features2Ftype != 0
		}
	case 5:
		f.v5 = true
		incompat := be.Uint32(sb[0xD8:])
		if incompat&incompatNeedsFix != 0 {
			return fmt.Errorf("xfs.Open: filesystem needs repair: %w", ErrUnsupported)
		}
		if bad := incompat &^ supportedIncompat; bad != 0 {
			return fmt.Errorf("xfs.Open: incompat features %#x: %w", bad, ErrUnsupported)
		}
		f.ftype = incompat&incompatFtype != 0
		f.nrext64 = incompat&incompatNrext64 != 0
	case 1, 2, 3:
		return fmt.Errorf("xfs.Open: superblock version %d: %w", version&versionMask, ErrUnsupported)
	default:
		return fmt.Errorf("xfs.Open: superblock version %d: %w", version&versionMask, ErrCorrupt)
	}
	return nil
}

func (f *FS) validateGeometry(size int64) error {
	switch {
	case f.dblocks == 0 || f.dblocks > uint64(size)/f.blockSize:
		return fmt.Errorf("xfs.Open: filesystem of %d blocks exceeds the %d byte device: %w", f.dblocks, size, ErrCorrupt)
	case f.agBlocks == 0 || f.agCount == 0:
		return fmt.Errorf("xfs.Open: allocation group counts: %w", ErrCorrupt)
	case f.agBlkLog > 32 || f.agBlocks > 1<<f.agBlkLog || (f.agBlkLog > 0 && f.agBlocks <= 1<<(f.agBlkLog-1)):
		return fmt.Errorf("xfs.Open: allocation group of %d blocks with shift %d: %w", f.agBlocks, f.agBlkLog, ErrCorrupt)
	case (f.agCount-1)*f.agBlocks >= f.dblocks || f.agCount*f.agBlocks < f.dblocks:
		return fmt.Errorf("xfs.Open: %d groups of %d blocks do not cover %d blocks: %w", f.agCount, f.agBlocks, f.dblocks, ErrCorrupt)
	}
	return nil
}

// Root is the inode number of the root directory.
func (f *FS) Root() uint64 { return f.rootIno }

// agSize is the length in blocks of allocation group agno.
func (f *FS) agSize(agno uint64) uint64 {
	if agno == f.agCount-1 {
		return f.dblocks - agno*f.agBlocks
	}
	return f.agBlocks
}

// blockIndex converts a filesystem block number (the AG number above agBlkLog
// bits of AG block number) of a run of count blocks into a device block index.
func (f *FS) blockIndex(fsb, count uint64) (uint64, error) {
	agno := fsb >> f.agBlkLog
	agbno := fsb & (1<<f.agBlkLog - 1)
	if agno >= f.agCount || agbno+count > f.agSize(agno) {
		return 0, fmt.Errorf("xfs: block %d (+%d) outside the filesystem: %w", fsb, count, ErrCorrupt)
	}
	return agno*f.agBlocks + agbno, nil
}

// inodeOffset is the byte offset of an inode, from its number's AG, block and
// slot fields.
func (f *FS) inodeOffset(ino uint64) (int64, error) {
	agno := ino >> (f.agBlkLog + f.inoBlkLog)
	agbno := (ino >> f.inoBlkLog) & (1<<f.agBlkLog - 1)
	slot := ino & (1<<f.inoBlkLog - 1)
	if ino == 0 || agno >= f.agCount || agbno >= f.agSize(agno) {
		return 0, fmt.Errorf("xfs: inode %d out of range: %w", ino, ErrCorrupt)
	}
	return int64((agno*f.agBlocks+agbno)*f.blockSize + slot*f.inodeSize), nil
}

type inode struct {
	ino      uint64
	mode     uint16
	format   uint8
	flags    uint16
	size     uint64
	nextents uint64
	fork     []byte
}

func (in *inode) isDir() bool     { return in.mode&modeFmt == modeDir }
func (in *inode) isSymlink() bool { return in.mode&modeFmt == modeSymlink }

func (f *FS) readInode(ino uint64) (*inode, error) {
	off, err := f.inodeOffset(ino)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, f.inodeSize)
	if err := readFull(f.r, buf, off); err != nil {
		return nil, fmt.Errorf("xfs: inode %d: %w", ino, mapEOF(err))
	}
	be := binary.BigEndian
	if be.Uint16(buf) != inodeMagic {
		return nil, fmt.Errorf("xfs: inode %d magic: %w", ino, ErrCorrupt)
	}
	version := buf[4]
	core := uint64(v4CoreSize)
	switch {
	case version == 1:
		return nil, fmt.Errorf("xfs: inode %d version 1: %w", ino, ErrUnsupported)
	case version != 2 && version != 3, f.v5 != (version == 3):
		return nil, fmt.Errorf("xfs: inode %d version %d: %w", ino, version, ErrCorrupt)
	case version == 3:
		core = v5CoreSize
		if be.Uint64(buf[0x98:]) != ino || !crcValid(buf, 0x64) {
			return nil, fmt.Errorf("xfs: inode %d identity or checksum: %w", ino, ErrCorrupt)
		}
	}
	in := &inode{
		ino:      ino,
		mode:     be.Uint16(buf[0x2:]),
		format:   buf[0x5],
		flags:    be.Uint16(buf[0x5A:]),
		size:     be.Uint64(buf[0x38:]),
		nextents: uint64(be.Uint32(buf[0x4C:])),
	}
	if version == 3 && be.Uint64(buf[0x78:])&flags2Nrext64 != 0 {
		if !f.nrext64 {
			return nil, fmt.Errorf("xfs: inode %d large extent counts without the feature: %w", ino, ErrCorrupt)
		}
		in.nextents = be.Uint64(buf[0x18:])
	}
	forkSize := f.inodeSize - core
	if forkoff := uint64(buf[0x52]); forkoff != 0 {
		forkSize = forkoff << 3
	}
	if core+forkSize > f.inodeSize || in.size > 1<<62 {
		return nil, fmt.Errorf("xfs: inode %d fork or size: %w", ino, ErrCorrupt)
	}
	in.fork = buf[core : core+forkSize]
	return in, nil
}

// checkData rejects inodes whose data this reader cannot interpret.
func (in *inode) checkData() error {
	if in.flags&flagRealtime != 0 {
		return fmt.Errorf("xfs: inode %d on the realtime volume: %w", in.ino, ErrUnsupported)
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

// ReadAt reads regular-file data. It follows io.ReaderAt: a short read at the
// end of the file returns io.EOF.
func (f *FS) ReadAt(ino uint64, p []byte, off int64) (int, error) {
	in, err := f.readInode(ino)
	if err != nil {
		return 0, err
	}
	if in.mode&modeFmt != modeReg {
		return 0, fmt.Errorf("xfs: inode %d is not a regular file: %w", ino, ErrCorrupt)
	}
	if err := in.checkData(); err != nil {
		return 0, err
	}
	return f.readData(in, p, off)
}

func (f *FS) readData(in *inode, p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("xfs: negative offset: %w", fs.ErrInvalid)
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
		span := min(int64(min(m.run, 1<<40))*bs-inBlock, int64(len(want)-done))
		chunk := want[done : done+int(span)]
		if m.kind == mapData {
			if err := readFull(f.r, chunk, int64(m.phys)*bs+inBlock); err != nil {
				return done, fmt.Errorf("xfs: file data: %w", mapEOF(err))
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
