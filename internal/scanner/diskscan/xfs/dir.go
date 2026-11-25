package xfs

import (
	"encoding/binary"
	"fmt"
	"io/fs"
	"strings"
)

const (
	dirDataMagic    = 0x58443244 // "XD2D"
	dirBlockMagic   = 0x58443242 // "XD2B"
	dirDataMagicV5  = 0x58444433 // "XDD3"
	dirBlockMagicV5 = 0x58444233 // "XDB3"
	dirFreeMagic    = 0x58443246 // "XD2F"
	dirFreeMagicV5  = 0x58444633 // "XDF3"
	dirDataHdrV4    = 16
	dirDataHdrV5    = 64
	dirUnusedTag    = 0xFFFF
	// Leaf and da-node blocks carry their magic at byte 8.
	daLeaf1, daLeafN, daNode    = 0xD2F1, 0xD2FF, 0xFEBE
	da3Leaf1, da3LeafN, da3Node = 0x3DF1, 0x3DFF, 0x3EBE
	blockTailSize               = 8
	blockLeafEntrySize          = 8
	symlinkHdrSize              = 56
	symlinkMagic                = 0x58534C4D // "XSLM"
)

// walkDir calls visit for every live entry of directory ino, "." and ".."
// included, until it returns true. Short-form directories read from the inode;
// the others read the data blocks and ignore the leaf, node and free blocks,
// which only index what the data blocks already hold.
func (f *FS) walkDir(ino uint64, visit func(name string, child uint64) bool) error {
	in, err := f.readInode(ino)
	if err != nil {
		return err
	}
	if !in.isDir() {
		return fmt.Errorf("xfs: inode %d is not a directory: %w", ino, fs.ErrNotExist)
	}
	if err := in.checkData(); err != nil {
		return err
	}
	if in.size > maxDirBytes {
		return fmt.Errorf("xfs: directory of %d bytes: %w", in.size, ErrTooLarge)
	}
	switch in.format {
	case formatLocal:
		return f.walkShortForm(in, visit)
	case formatExtents, formatBtree:
		return f.walkBlocks(in, visit)
	}
	return fmt.Errorf("xfs: directory inode %d has data fork format %d: %w", ino, in.format, ErrCorrupt)
}

func (f *FS) walkShortForm(in *inode, visit func(string, uint64) bool) error {
	if in.size > uint64(len(in.fork)) || in.size < 6 {
		return fmt.Errorf("xfs: short-form directory of %d bytes in a %d byte fork: %w", in.size, len(in.fork), ErrCorrupt)
	}
	data := in.fork[:in.size]
	count, inoSize := int(data[0]), 4
	if data[1] != 0 {
		inoSize = 8
	}
	if len(data) < 2+inoSize {
		return fmt.Errorf("xfs: short-form directory header: %w", ErrCorrupt)
	}
	if visit(".", in.ino) || visit("..", beUint(data[2:2+inoSize])) {
		return nil
	}
	ftype := 0
	if f.ftype {
		ftype = 1
	}
	off := 2 + inoSize
	for i := 0; i < count; i++ {
		if off+3 > len(data) {
			return fmt.Errorf("xfs: short-form directory entry %d: %w", i, ErrCorrupt)
		}
		nameLen := int(data[off])
		end := off + 3 + nameLen + ftype + inoSize
		if nameLen == 0 || end > len(data) {
			return fmt.Errorf("xfs: short-form directory entry %d length: %w", i, ErrCorrupt)
		}
		child := beUint(data[end-inoSize : end])
		if err := f.checkChild(child); err != nil {
			return err
		}
		if visit(string(data[off+3:off+3+nameLen]), child) {
			return nil
		}
		off = end
	}
	return nil
}

func beUint(b []byte) uint64 {
	if len(b) == 4 {
		return uint64(binary.BigEndian.Uint32(b))
	}
	return binary.BigEndian.Uint64(b)
}

func (f *FS) checkChild(child uint64) error {
	if _, err := f.inodeOffset(child); err != nil {
		return fmt.Errorf("xfs: directory entry: %w", err)
	}
	return nil
}

// walkBlocks reads the directory's data blocks. The inode size covers the data
// space only (the leaf and free blocks are mapped far above it), and a data
// block missing from a node directory is a hole to skip.
func (f *FS) walkBlocks(in *inode, visit func(string, uint64) bool) error {
	dirBlkSize := f.dirBlkFsb * f.blockSize
	if in.size%dirBlkSize != 0 {
		return fmt.Errorf("xfs: directory size %d is not a multiple of the %d byte directory block: %w", in.size, dirBlkSize, ErrCorrupt)
	}
	buf := make([]byte, dirBlkSize)
	total := in.size / f.blockSize
	for lb := uint64(0); lb < total; {
		m, err := f.mapBlock(in, lb)
		if err != nil {
			return err
		}
		if m.kind != mapData {
			lb = (lb + m.run + f.dirBlkFsb - 1) / f.dirBlkFsb * f.dirBlkFsb
			continue
		}
		if n, err := f.readData(in, buf, int64(lb*f.blockSize)); err != nil || n != len(buf) {
			return fmt.Errorf("xfs: directory block %d: %w", lb, shortOrErr(err))
		}
		stop, err := f.scanDataBlock(buf, visit)
		if err != nil || stop {
			return err
		}
		lb += f.dirBlkFsb
	}
	return nil
}

func shortOrErr(err error) error {
	if err == nil {
		return ErrCorrupt
	}
	return err
}

// scanDataBlock visits the live entries of one data or block-form directory
// block. Entries tile the block exactly: live entries and unused gaps, each a
// multiple of 8 bytes.
func (f *FS) scanDataBlock(buf []byte, visit func(string, uint64) bool) (bool, error) {
	be := binary.BigEndian
	magic := be.Uint32(buf)
	dataMagic, blockMagic, freeMagic, hdr := uint32(dirDataMagic), uint32(dirBlockMagic), uint32(dirFreeMagic), dirDataHdrV4
	if f.v5 {
		dataMagic, blockMagic, freeMagic, hdr = dirDataMagicV5, dirBlockMagicV5, dirFreeMagicV5, dirDataHdrV5
	}
	end := len(buf)
	switch {
	case magic == dataMagic:
	case magic == blockMagic:
		leaves := uint64(be.Uint32(buf[len(buf)-blockTailSize:]))
		if leaves*blockLeafEntrySize > uint64(len(buf)-blockTailSize-hdr) {
			return false, fmt.Errorf("xfs: block directory with %d leaf entries: %w", leaves, ErrCorrupt)
		}
		end = len(buf) - blockTailSize - int(leaves)*blockLeafEntrySize
	case magic == freeMagic || f.isLeafBlock(buf):
		return false, nil
	default:
		return false, fmt.Errorf("xfs: directory block magic %#x: %w", magic, ErrCorrupt)
	}
	ftype := 0
	if f.ftype {
		ftype = 1
	}
	for off := hdr; off < end; {
		if end-off < 8 {
			return false, fmt.Errorf("xfs: directory entry tail: %w", ErrCorrupt)
		}
		if be.Uint16(buf[off:]) == dirUnusedTag {
			length := int(be.Uint16(buf[off+2:]))
			if length < 8 || length%8 != 0 || off+length > end {
				return false, fmt.Errorf("xfs: unused directory entry of %d bytes: %w", length, ErrCorrupt)
			}
			off += length
			continue
		}
		if end-off < 9 {
			return false, fmt.Errorf("xfs: directory entry tail: %w", ErrCorrupt)
		}
		nameLen := int(buf[off+8])
		size := (8 + 1 + nameLen + ftype + 2 + 7) &^ 7
		if nameLen == 0 || off+size > end {
			return false, fmt.Errorf("xfs: directory entry of %d bytes: %w", size, ErrCorrupt)
		}
		child := be.Uint64(buf[off:])
		if err := f.checkChild(child); err != nil {
			return false, err
		}
		if visit(string(buf[off+9:off+9+nameLen]), child) {
			return true, nil
		}
		off += size
	}
	return false, nil
}

func (f *FS) isLeafBlock(buf []byte) bool {
	magic := binary.BigEndian.Uint16(buf[8:])
	if f.v5 {
		return magic == da3Leaf1 || magic == da3LeafN || magic == da3Node
	}
	return magic == daLeaf1 || magic == daLeafN || magic == daNode
}

// Lookup finds name in directory dir. A missing name, or a dir that is not a
// directory, is fs.ErrNotExist.
func (f *FS) Lookup(dir uint64, name string) (uint64, error) {
	if name == "" || strings.Contains(name, "/") {
		return 0, fs.ErrNotExist
	}
	var found uint64
	err := f.walkDir(dir, func(n string, child uint64) bool {
		if n == name {
			found = child
			return true
		}
		return false
	})
	if err != nil {
		return 0, err
	}
	if found == 0 {
		return 0, fs.ErrNotExist
	}
	return found, nil
}

// DirNames lists a directory's entries except "." and "..", bounded.
func (f *FS) DirNames(dir uint64) ([]string, error) {
	var names []string
	tooMany := false
	err := f.walkDir(dir, func(n string, _ uint64) bool {
		if n == "." || n == ".." {
			return false
		}
		if len(names) >= maxDirNames {
			tooMany = true
			return true
		}
		names = append(names, n)
		return false
	})
	if err != nil {
		return nil, err
	}
	if tooMany {
		return nil, fmt.Errorf("xfs: more than %d entries: %w", maxDirNames, ErrTooLarge)
	}
	return names, nil
}

// ReadLink returns a symlink's target.
func (f *FS) ReadLink(ino uint64) (string, error) {
	in, err := f.readInode(ino)
	if err != nil {
		return "", err
	}
	if !in.isSymlink() {
		return "", fmt.Errorf("xfs: inode %d is not a symlink: %w", ino, ErrCorrupt)
	}
	if err := in.checkData(); err != nil {
		return "", err
	}
	if in.size > maxSymlink {
		return "", fmt.Errorf("xfs: symlink of %d bytes: %w", in.size, ErrCorrupt)
	}
	switch in.format {
	case formatLocal:
		if in.size > uint64(len(in.fork)) {
			return "", fmt.Errorf("xfs: symlink of %d bytes in a %d byte fork: %w", in.size, len(in.fork), ErrCorrupt)
		}
		return string(in.fork[:in.size]), nil
	case formatExtents, formatBtree:
		return f.readRemoteLink(in)
	}
	return "", fmt.Errorf("xfs: symlink inode %d has data fork format %d: %w", ino, in.format, ErrCorrupt)
}

// readRemoteLink reads a symlink stored in blocks. On v5 each block starts with
// a header saying which slice of the target it holds.
func (f *FS) readRemoteLink(in *inode) (string, error) {
	target := make([]byte, in.size)
	if !f.v5 {
		n, err := f.readData(in, target, 0)
		if err != nil || n != len(target) {
			return "", fmt.Errorf("xfs: symlink data: %w", shortOrErr(err))
		}
		return string(target), nil
	}
	be := binary.BigEndian
	blk := make([]byte, f.blockSize)
	got := uint64(0)
	for lb := uint64(0); got < in.size; lb++ {
		if lb >= maxSymlink {
			return "", fmt.Errorf("xfs: symlink spans too many blocks: %w", ErrCorrupt)
		}
		m, err := f.mapBlock(in, lb)
		if err != nil {
			return "", err
		}
		if m.kind != mapData {
			return "", fmt.Errorf("xfs: symlink block %d is not mapped: %w", lb, ErrCorrupt)
		}
		if err := readFull(f.r, blk, int64(m.phys*f.blockSize)); err != nil {
			return "", fmt.Errorf("xfs: symlink block %d: %w", lb, mapEOF(err))
		}
		off, length := uint64(be.Uint32(blk[4:])), uint64(be.Uint32(blk[8:]))
		if be.Uint32(blk) != symlinkMagic || off != got || length == 0 || length > f.blockSize-symlinkHdrSize || got+length > in.size {
			return "", fmt.Errorf("xfs: symlink block %d header: %w", lb, ErrCorrupt)
		}
		copy(target[got:], blk[symlinkHdrSize:symlinkHdrSize+length])
		got += length
	}
	return string(target), nil
}
