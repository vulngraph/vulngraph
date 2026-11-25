package xfs

import (
	"encoding/binary"
	"fmt"
)

type mapKind int

const (
	mapHole mapKind = iota
	mapData
	mapUninit
)

// mapping says where a run of logical blocks starting at the queried one lives.
// run is at least 1; hole and unwritten runs read as zeros.
type mapping struct {
	phys uint64
	run  uint64
	kind mapKind
}

const (
	recordSize     = 16
	btreeV4HdrSize = 24
	btreeV5HdrSize = 72
	bmapMagic      = 0x424D4150 // "BMAP"
	bmapMagicV5    = 0x424D4133 // "BMA3"
	rootHdrSize    = 4
)

func (f *FS) mapBlock(in *inode, lb uint64) (mapping, error) {
	if lb >= maxLogicalBlks {
		return mapping{}, fmt.Errorf("xfs: logical block %d beyond the extent range: %w", lb, ErrCorrupt)
	}
	switch in.format {
	case formatExtents:
		if in.nextents > uint64(len(in.fork)/recordSize) {
			return mapping{}, fmt.Errorf("xfs: inode %d claims %d extents in %d bytes: %w", in.ino, in.nextents, len(in.fork), ErrCorrupt)
		}
		return f.mapRecords(in.fork, int(in.nextents), lb, maxLogicalBlks)
	case formatBtree:
		return f.mapBtree(in, lb)
	}
	return mapping{}, fmt.Errorf("xfs: inode %d has data fork format %d: %w", in.ino, in.format, ErrCorrupt)
}

// mapRecords finds lb among n packed 128-bit extent records. Each record holds
// an unwritten flag (1 bit), start offset (54), start block (52) and count (21).
func (f *FS) mapRecords(recs []byte, n int, lb, limit uint64) (mapping, error) {
	be := binary.BigEndian
	for i := 0; i < n; i++ {
		l0, l1 := be.Uint64(recs[i*recordSize:]), be.Uint64(recs[i*recordSize+8:])
		start := (l0 &^ (1 << 63)) >> 9
		count := l1 & (1<<21 - 1)
		if count == 0 {
			return mapping{}, fmt.Errorf("xfs: extent of zero blocks at offset %d: %w", start, ErrCorrupt)
		}
		if start > lb {
			limit = min(limit, start)
			continue
		}
		if lb >= start+count {
			continue
		}
		block, err := f.blockIndex((l0&0x1FF)<<43|l1>>21, count)
		if err != nil {
			return mapping{}, err
		}
		kind := mapData
		if l0>>63 != 0 {
			kind = mapUninit
		}
		return mapping{phys: block + (lb - start), run: start + count - lb, kind: kind}, nil
	}
	return mapping{run: limit - lb, kind: mapHole}, nil
}

// mapBtree descends from the root in the inode fork to the leaf covering lb.
// Each level must be exactly one below its parent, so a cyclic or over-deep
// tree ends in ErrCorrupt rather than a loop.
func (f *FS) mapBtree(in *inode, lb uint64) (mapping, error) {
	be := binary.BigEndian
	fork := in.fork
	if len(fork) < rootHdrSize {
		return mapping{}, fmt.Errorf("xfs: inode %d btree root: %w", in.ino, ErrCorrupt)
	}
	level := int(be.Uint16(fork[0:]))
	numrecs := int(be.Uint16(fork[2:]))
	maxrecs := (len(fork) - rootHdrSize) / 16
	if level < 1 || level > maxBtreeLevels || numrecs == 0 || numrecs > maxrecs {
		return mapping{}, fmt.Errorf("xfs: inode %d btree root level %d with %d records: %w", in.ino, level, numrecs, ErrCorrupt)
	}
	keys, ptrs := fork[rootHdrSize:], fork[rootHdrSize+maxrecs*8:]
	hdr := btreeV4HdrSize
	wantMagic := uint32(bmapMagic)
	if f.v5 {
		hdr, wantMagic = btreeV5HdrSize, bmapMagicV5
	}
	limit := maxLogicalBlks
	for {
		child, found := pickChild(keys, ptrs, numrecs, lb, &limit)
		if !found {
			return mapping{run: limit - lb, kind: mapHole}, nil
		}
		block, err := f.blockIndex(child, 1)
		if err != nil {
			return mapping{}, err
		}
		buf := make([]byte, f.blockSize)
		if err := readFull(f.r, buf, int64(block*f.blockSize)); err != nil {
			return mapping{}, fmt.Errorf("xfs: btree block: %w", mapEOF(err))
		}
		level--
		numrecs = int(be.Uint16(buf[6:]))
		maxrecs = (int(f.blockSize) - hdr) / 16
		if be.Uint32(buf) != wantMagic || int(be.Uint16(buf[4:])) != level || numrecs > maxrecs {
			return mapping{}, fmt.Errorf("xfs: btree block %d (level %d, %d records): %w", block, level, numrecs, ErrCorrupt)
		}
		if level == 0 {
			return f.mapRecords(buf[hdr:], numrecs, lb, limit)
		}
		keys, ptrs = buf[hdr:], buf[hdr+maxrecs*8:]
	}
}

// pickChild returns the pointer of the last key at or below lb and lowers
// limit to the first key above it.
func pickChild(keys, ptrs []byte, n int, lb uint64, limit *uint64) (uint64, bool) {
	be := binary.BigEndian
	var child, best uint64
	found := false
	for i := 0; i < n; i++ {
		start := be.Uint64(keys[i*8:])
		switch {
		case start <= lb && (!found || start >= best):
			best, found = start, true
			child = be.Uint64(ptrs[i*8:])
		case start > lb:
			*limit = min(*limit, start)
		}
	}
	return child, found
}
