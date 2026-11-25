package ext4

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
// run is at least 1; hole and uninitialised runs read as zeros.
type mapping struct {
	phys uint64
	run  uint64
	kind mapKind
}

const (
	extentMagic     = 0xF30A
	maxLogicalBlock = uint64(1) << 32
)

func (f *FS) mapBlock(in *inode, lb uint64) (mapping, error) {
	if in.flags&inodeFlagExtents != 0 {
		return f.mapExtents(in, lb)
	}
	return f.mapBlockMap(in, lb)
}

func (f *FS) mapExtents(in *inode, lb uint64) (mapping, error) {
	if lb >= maxLogicalBlock {
		return mapping{}, fmt.Errorf("ext4: logical block %d beyond the extent range: %w", lb, ErrCorrupt)
	}
	le := binary.LittleEndian
	node := in.block[:]
	limit := maxLogicalBlock
	prevDepth := -1
	for {
		if len(node) < 12 || le.Uint16(node[0:]) != extentMagic {
			return mapping{}, fmt.Errorf("ext4: extent header: %w", ErrCorrupt)
		}
		entries := int(le.Uint16(node[2:]))
		depth := int(le.Uint16(node[6:]))
		switch {
		case entries > (len(node)-12)/12:
			return mapping{}, fmt.Errorf("ext4: %d extent entries in %d bytes: %w", entries, len(node), ErrCorrupt)
		case prevDepth < 0 && depth > maxExtentDepth:
			return mapping{}, fmt.Errorf("ext4: extent depth %d: %w", depth, ErrCorrupt)
		case prevDepth >= 0 && depth != prevDepth-1:
			return mapping{}, fmt.Errorf("ext4: extent depth %d under %d: %w", depth, prevDepth, ErrCorrupt)
		}
		if depth == 0 {
			return f.leafMapping(node, entries, lb, limit)
		}
		var child uint64
		found := false
		var best uint64
		for i := 0; i < entries; i++ {
			e := node[12+i*12:]
			start := uint64(le.Uint32(e[0:]))
			switch {
			case start <= lb && (!found || start >= best):
				best, found = start, true
				child = uint64(le.Uint32(e[4:])) | uint64(le.Uint16(e[8:]))<<32
			case start > lb:
				limit = min(limit, start)
			}
		}
		if !found {
			return mapping{run: limit - lb, kind: mapHole}, nil
		}
		if child == 0 || child >= f.blocksCount {
			return mapping{}, fmt.Errorf("ext4: extent index block %d: %w", child, ErrCorrupt)
		}
		buf := make([]byte, f.blockSize)
		if err := readFull(f.r, buf, int64(child*f.blockSize)); err != nil {
			return mapping{}, fmt.Errorf("ext4: extent node: %w", mapEOF(err))
		}
		node, prevDepth = buf, depth
	}
}

func (f *FS) leafMapping(node []byte, entries int, lb, limit uint64) (mapping, error) {
	le := binary.LittleEndian
	for i := 0; i < entries; i++ {
		e := node[12+i*12:]
		start := uint64(le.Uint32(e[0:]))
		length := uint64(le.Uint16(e[4:]))
		kind := mapData
		if length > 32768 {
			length -= 32768
			kind = mapUninit
		}
		if start > lb {
			limit = min(limit, start)
			continue
		}
		if length == 0 || lb >= start+length {
			continue
		}
		phys := uint64(le.Uint32(e[8:])) | uint64(le.Uint16(e[6:]))<<32
		if phys >= f.blocksCount || phys+length > f.blocksCount {
			return mapping{}, fmt.Errorf("ext4: extent at block %d: %w", phys, ErrCorrupt)
		}
		return mapping{phys: phys + (lb - start), run: start + length - lb, kind: kind}, nil
	}
	return mapping{run: limit - lb, kind: mapHole}, nil
}

func (f *FS) mapBlockMap(in *inode, lb uint64) (mapping, error) {
	ppb := f.blockSize / 4
	ptr := func(i uint64) uint64 { return uint64(binary.LittleEndian.Uint32(in.block[i*4:])) }
	var (
		blk    uint64
		levels int
		path   [3]uint64
	)
	switch {
	case lb < 12:
		blk = ptr(lb)
	case lb-12 < ppb:
		blk, levels, path[0] = ptr(12), 1, lb-12
	case lb-12-ppb < ppb*ppb:
		l := lb - 12 - ppb
		blk, levels, path[0], path[1] = ptr(13), 2, l/ppb, l%ppb
	case lb-12-ppb-ppb*ppb < ppb*ppb*ppb:
		l := lb - 12 - ppb - ppb*ppb
		blk, levels, path[0], path[1], path[2] = ptr(14), 3, l/(ppb*ppb), (l/ppb)%ppb, l%ppb
	default:
		return mapping{}, fmt.Errorf("ext4: logical block %d beyond the block map: %w", lb, ErrCorrupt)
	}
	for i := 0; i < levels && blk != 0; i++ {
		if blk >= f.blocksCount {
			return mapping{}, fmt.Errorf("ext4: indirect block %d: %w", blk, ErrCorrupt)
		}
		var b [4]byte
		if err := readFull(f.r, b[:], int64(blk*f.blockSize+path[i]*4)); err != nil {
			return mapping{}, fmt.Errorf("ext4: indirect block: %w", mapEOF(err))
		}
		blk = uint64(binary.LittleEndian.Uint32(b[:]))
	}
	if blk == 0 {
		return mapping{run: 1, kind: mapHole}, nil
	}
	if blk >= f.blocksCount {
		return mapping{}, fmt.Errorf("ext4: data block %d: %w", blk, ErrCorrupt)
	}
	return mapping{phys: blk, run: 1, kind: mapData}, nil
}
