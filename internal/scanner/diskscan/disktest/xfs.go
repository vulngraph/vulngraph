package disktest

import (
	"encoding/binary"
	"hash/crc32"
	"math/bits"
	"strings"
)

// DirForm selects how NewXFS lays out directories.
type DirForm int

const (
	// DirAuto uses short form when the entries fit the inode, a single block
	// when they fit one directory block, and leaf form otherwise.
	DirAuto DirForm = iota
	DirBlock
	DirLeaf
	// DirNode is leaf form plus node-form leaf and free blocks.
	DirNode
)

// XFSOpts shapes the image NewXFS builds. Zero values give a v4, 1 KiB-block
// filesystem with 256-byte inodes.
type XFSOpts struct {
	V5        bool
	Ftype     bool // directory entries carry a file type (always on for v5)
	BlockSize int  // 512 .. 65536, default 1024
	InodeSize int  // 256 .. 2048, default 256
	AGBlocks  int  // blocks per allocation group, default 2048; need not be a power of two
	DirBlkLog int  // directory block = BlockSize << DirBlkLog
	Dirs      DirForm
	DirGap    bool // leave a hole between the first two data blocks of a leaf directory
	MaxRecs   int  // cap on records per btree block (0 = as many as fit)
	Incompat  uint32
	NRExt64   bool // v5 only: large extent counts
	OSRelease string
}

// XFSFileOpts shapes how one file's data is mapped.
type XFSFileOpts struct {
	HoleBlocks int  // unmapped blocks before the data
	Fragmented bool // one extent per block, with gaps
	Btree      bool // use a btree even when the extents would fit the inode
	Unwritten  bool // mark extents unwritten (read as zeros)
}

type xnode struct {
	name     string
	path     string
	mode     uint16
	data     []byte
	target   string
	opts     XFSFileOpts
	children map[string]*xnode
	parent   *xnode
	ino      uint64
}

// XFS collects files and renders them as an XFS image.
type XFS struct {
	opts    XFSOpts
	root    *xnode
	nodes   []*xnode
	offsets map[string]int64
	inos    map[string]uint64
}

// NewXFS returns an empty filesystem.
func NewXFS(o XFSOpts) *XFS {
	if o.BlockSize == 0 {
		o.BlockSize = 1024
	}
	if o.InodeSize == 0 {
		o.InodeSize = 256
	}
	if o.AGBlocks == 0 {
		o.AGBlocks = 2048
	}
	x := &XFS{opts: o, root: &xnode{mode: 0x41ED, children: map[string]*xnode{}}}
	if o.OSRelease != "" {
		x.WriteFile("etc/os-release", []byte(o.OSRelease))
	}
	return x
}

func (x *XFS) dir(path string) *xnode {
	cur := x.root
	for _, c := range strings.Split(strings.Trim(path, "/"), "/") {
		if c == "" {
			continue
		}
		next, ok := cur.children[c]
		if !ok {
			next = &xnode{name: c, path: strings.TrimPrefix(cur.path+"/"+c, "/"), mode: 0x41ED, children: map[string]*xnode{}, parent: cur}
			cur.children[c] = next
			x.nodes = append(x.nodes, next)
		}
		cur = next
	}
	return cur
}

func (x *XFS) add(path string, n *xnode) {
	dir, name := "", path
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		dir, name = path[:i], path[i+1:]
	}
	parent := x.dir(dir)
	n.name, n.path, n.parent = name, strings.TrimPrefix(parent.path+"/"+name, "/"), parent
	parent.children[name] = n
	x.nodes = append(x.nodes, n)
}

// Mkdir creates a directory and its parents.
func (x *XFS) Mkdir(path string) { x.dir(path) }

// WriteFile adds a regular file, creating parent directories.
func (x *XFS) WriteFile(path string, data []byte) { x.WriteFileOpts(path, data, XFSFileOpts{}) }

// WriteFileOpts is WriteFile with control over the block mapping.
func (x *XFS) WriteFileOpts(path string, data []byte, o XFSFileOpts) {
	x.add(path, &xnode{mode: 0x81A4, data: data, opts: o})
}

// Symlink adds a symbolic link.
func (x *XFS) Symlink(path, target string) { x.add(path, &xnode{mode: 0xA1FF, target: target}) }

// InodeOffset is the byte offset of an inode in the last rendered image; ""
// names the root. Tests use it to corrupt a specific inode.
func (x *XFS) InodeOffset(path string) int64 { return x.offsets[path] }

// Ino is the inode number of a path in the last rendered image.
func (x *XFS) Ino(path string) uint64 { return x.inos[path] }

// Bytes renders the filesystem, growing the group count until it fits.
func (x *XFS) Bytes() []byte {
	for groups := 1; groups < 64; groups++ {
		if img, ok := x.build(groups); ok {
			return img
		}
	}
	panic("disktest: filesystem does not fit in 64 allocation groups")
}

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

type xextent struct {
	off, fsb, count uint64
	unwritten       bool
}

type xbuilder struct {
	x        *XFS
	img      []byte
	bs       uint64
	isz      uint64
	inoLog   uint
	agBlocks uint64
	agCount  uint64
	agLog    uint
	curAG    uint64
	curNext  uint64 // next free block in curAG
	inoFsb   uint64
	inoSlot  uint64
	inoReady bool
	failed   bool
	v5       bool
	ftype    bool
	dirBlk   uint64 // directory block size in bytes
	dirFsb   uint64 // fs blocks per directory block
}

const (
	xfsNull       = ^uint64(0)
	xfsLeafOffset = uint64(1) << 35
)

func (x *XFS) build(groups int) ([]byte, bool) {
	o := x.opts
	b := &xbuilder{x: x, bs: uint64(o.BlockSize), isz: uint64(o.InodeSize), agBlocks: uint64(o.AGBlocks), agCount: uint64(groups), v5: o.V5}
	b.ftype = o.V5 || o.Ftype
	b.inoLog = uint(bits.TrailingZeros64(b.bs / b.isz))
	b.agLog = uint(bits.Len64(b.agBlocks - 1))
	b.dirFsb = 1 << o.DirBlkLog
	b.dirBlk = b.bs * b.dirFsb
	b.img = make([]byte, b.agCount*b.agBlocks*b.bs)
	b.curNext = (2048 + b.bs - 1) / b.bs
	x.offsets, x.inos = map[string]int64{}, map[string]uint64{}

	x.root.path = ""
	all := append([]*xnode{x.root}, x.nodes...)
	for _, n := range all {
		n.ino = b.newInode()
		x.inos[n.path] = n.ino
	}
	for _, n := range all {
		b.writeNode(n)
	}
	if b.failed {
		return nil, false
	}
	b.writeSuperblock(all[0].ino)
	return b.img, true
}

func (b *xbuilder) mkfsb(ag, agbno uint64) uint64 { return ag<<b.agLog | agbno }

func (b *xbuilder) block(fsb uint64) []byte {
	idx := (fsb>>b.agLog)*b.agBlocks + fsb&(1<<b.agLog-1)
	return b.img[idx*b.bs : (idx+1)*b.bs]
}

// alloc returns n contiguous blocks inside one allocation group.
func (b *xbuilder) alloc(n uint64) uint64 {
	if n > b.agBlocks-(2048+b.bs-1)/b.bs {
		panic("disktest: allocation larger than an allocation group")
	}
	if b.curNext+n > b.agBlocks {
		b.curAG++
		b.curNext = (2048 + b.bs - 1) / b.bs
	}
	if b.curAG >= b.agCount {
		b.failed = true
		b.curAG, b.curNext = b.agCount-1, 0
		return b.mkfsb(b.curAG, 0)
	}
	first := b.mkfsb(b.curAG, b.curNext)
	b.curNext += n
	return first
}

func (b *xbuilder) newInode() uint64 {
	if !b.inoReady || b.inoSlot == b.bs/b.isz {
		b.inoFsb, b.inoSlot, b.inoReady = b.alloc(1), 0, true
	}
	ino := b.inoFsb<<b.inoLog | b.inoSlot
	b.inoSlot++
	return ino
}

func (b *xbuilder) inodeBytes(ino uint64) []byte {
	blk := b.block(ino >> b.inoLog)
	slot := ino & (1<<b.inoLog - 1)
	return blk[slot*b.isz : (slot+1)*b.isz]
}

func (b *xbuilder) coreSize() uint64 {
	if b.v5 {
		return 176
	}
	return 100
}

func (b *xbuilder) forkSize() uint64 { return b.isz - b.coreSize() }

func packExtent(e xextent) [16]byte {
	var l0 = e.off<<9 | e.fsb>>43&0x1FF
	if e.unwritten {
		l0 |= 1 << 63
	}
	l1 := (e.fsb&(1<<43-1))<<21 | e.count
	var out [16]byte
	binary.BigEndian.PutUint64(out[:], l0)
	binary.BigEndian.PutUint64(out[8:], l1)
	return out
}

func (b *xbuilder) writeNode(n *xnode) {
	var (
		fork   []byte
		format uint8
		size   uint64
		nblk   uint64
		nexts  uint64
	)
	switch {
	case n.mode == 0x41ED:
		fork, format, size, nblk, nexts = b.dirFork(n)
	case n.mode == 0xA1FF && uint64(len(n.target)) <= b.forkSize():
		fork, format, size = []byte(n.target), 1, uint64(len(n.target))
	case n.mode == 0xA1FF:
		fork, format, nblk, nexts = b.remoteLink(n)
		size = uint64(len(n.target))
	default:
		exts, count := b.place(n.data, n.opts)
		fork, format = b.fork(n.ino, exts, n.opts.Btree)
		size = uint64(n.opts.HoleBlocks)*b.bs + uint64(len(n.data))
		nblk, nexts = count, uint64(len(exts))
	}
	b.writeInode(n, format, size, nblk, nexts, fork)
}

// place writes content into data blocks and returns its extents.
func (b *xbuilder) place(content []byte, o XFSFileOpts) ([]xextent, uint64) {
	n := (uint64(len(content)) + b.bs - 1) / b.bs
	var exts []xextent
	write := func(fsb, i uint64) {
		end := min((i+1)*b.bs, uint64(len(content)))
		copy(b.block(fsb), content[i*b.bs:end])
	}
	if o.Fragmented {
		for i := uint64(0); i < n; i++ {
			fsb := b.alloc(2)
			write(fsb, i)
			exts = append(exts, xextent{off: uint64(o.HoleBlocks) + i, fsb: fsb, count: 1, unwritten: o.Unwritten})
		}
		return exts, n
	}
	maxRun := min(b.agBlocks-(2048+b.bs-1)/b.bs, 1<<21-1)
	for done := uint64(0); done < n; {
		run := min(n-done, maxRun)
		first := b.alloc(run)
		for i := uint64(0); i < run; i++ {
			write(first+i, done+i)
		}
		exts = append(exts, xextent{off: uint64(o.HoleBlocks) + done, fsb: first, count: run, unwritten: o.Unwritten})
		done += run
	}
	return exts, n
}

func (b *xbuilder) bmapHeader(blk []byte, level, numrecs uint64, ino, fsb uint64) int {
	be := binary.BigEndian
	magic, hdr := uint32(0x424D4150), 24
	if b.v5 {
		magic, hdr = 0x424D4133, 72
	}
	be.PutUint32(blk, magic)
	be.PutUint16(blk[4:], uint16(level))
	be.PutUint16(blk[6:], uint16(numrecs))
	be.PutUint64(blk[8:], xfsNull)
	be.PutUint64(blk[16:], xfsNull)
	if b.v5 {
		be.PutUint64(blk[24:], fsb*b.bs/512)
		be.PutUint64(blk[56:], ino)
	}
	return hdr
}

// fork encodes the data fork for exts: an inline extent list when it fits and
// a btree rooted in the inode otherwise.
func (b *xbuilder) fork(ino uint64, exts []xextent, btree bool) ([]byte, uint8) {
	be := binary.BigEndian
	size := b.forkSize()
	if !btree && uint64(len(exts))*16 <= size {
		fork := make([]byte, len(exts)*16)
		for i, e := range exts {
			p := packExtent(e)
			copy(fork[i*16:], p[:])
		}
		return fork, 2
	}
	hdr := 24
	if b.v5 {
		hdr = 72
	}
	perBlock := (int(b.bs) - hdr) / 16
	rootCap := int(size-4) / 16
	if b.x.opts.MaxRecs > 0 {
		perBlock, rootCap = min(perBlock, b.x.opts.MaxRecs), min(rootCap, b.x.opts.MaxRecs)
	}
	type entry struct{ key, fsb uint64 }
	var cur []entry
	for i := 0; i < len(exts); i += perBlock {
		chunk := exts[i:min(i+perBlock, len(exts))]
		fsb := b.alloc(1)
		blk := b.block(fsb)
		h := b.bmapHeader(blk, 0, uint64(len(chunk)), ino, fsb)
		for j, e := range chunk {
			p := packExtent(e)
			copy(blk[h+j*16:], p[:])
		}
		cur = append(cur, entry{chunk[0].off, fsb})
	}
	if len(cur) == 0 {
		cur = append(cur, entry{0, b.emptyLeaf(ino)})
	}
	level := uint64(0)
	for len(cur) > rootCap {
		level++
		var next []entry
		for i := 0; i < len(cur); i += perBlock {
			chunk := cur[i:min(i+perBlock, len(cur))]
			fsb := b.alloc(1)
			blk := b.block(fsb)
			h := b.bmapHeader(blk, level, uint64(len(chunk)), ino, fsb)
			maxrecs := (int(b.bs) - h) / 16
			for j, c := range chunk {
				be.PutUint64(blk[h+j*8:], c.key)
				be.PutUint64(blk[h+maxrecs*8+j*8:], c.fsb)
			}
			next = append(next, entry{chunk[0].key, fsb})
		}
		cur = next
	}
	root := make([]byte, size)
	be.PutUint16(root, uint16(level+1))
	be.PutUint16(root[2:], uint16(len(cur)))
	for j, c := range cur {
		be.PutUint64(root[4+j*8:], c.key)
		be.PutUint64(root[4+bmdrMaxRecs(size)*8+j*8:], c.fsb)
	}
	return root, 3
}

func bmdrMaxRecs(forkSize uint64) int { return int(forkSize-4) / 16 }

func (b *xbuilder) emptyLeaf(ino uint64) uint64 {
	fsb := b.alloc(1)
	b.bmapHeader(b.block(fsb), 0, 0, ino, fsb)
	return fsb
}

func (b *xbuilder) writeInode(n *xnode, format uint8, size, nblocks, nextents uint64, fork []byte) {
	be := binary.BigEndian
	buf := b.inodeBytes(n.ino)
	clear(buf)
	be.PutUint16(buf, 0x494E)
	be.PutUint16(buf[2:], n.mode)
	buf[4], buf[5] = 2, format
	be.PutUint32(buf[0x10:], 1)
	be.PutUint64(buf[0x38:], size)
	be.PutUint64(buf[0x40:], nblocks)
	be.PutUint32(buf[0x4C:], uint32(nextents))
	if b.v5 && b.x.opts.NRExt64 {
		be.PutUint64(buf[0x18:], nextents)
		be.PutUint64(buf[0x78:], 1<<4)
		be.PutUint32(buf[0x4C:], 0)
	}
	copy(buf[b.coreSize():], fork)
	if b.v5 {
		buf[4] = 3
		be.PutUint64(buf[0x98:], n.ino)
		binary.LittleEndian.PutUint32(buf[0x64:], crc32.Checksum(buf, castagnoli))
	}
	agno := n.ino >> (b.agLog + b.inoLog)
	agbno := n.ino >> b.inoLog & (1<<b.agLog - 1)
	b.x.offsets[n.path] = int64((agno*b.agBlocks+agbno)*b.bs + (n.ino&(1<<b.inoLog-1))*b.isz)
}

func (b *xbuilder) writeSuperblock(rootIno uint64) {
	be := binary.BigEndian
	o := b.x.opts
	sb := b.block(b.mkfsb(0, 0))[:512]
	be.PutUint32(sb[0x0:], 0x58465342)
	be.PutUint32(sb[0x4:], uint32(b.bs))
	be.PutUint64(sb[0x8:], b.agCount*b.agBlocks)
	be.PutUint64(sb[0x38:], rootIno)
	be.PutUint32(sb[0x54:], uint32(b.agBlocks))
	be.PutUint32(sb[0x58:], uint32(b.agCount))
	be.PutUint16(sb[0x66:], 512)
	be.PutUint16(sb[0x68:], uint16(b.isz))
	be.PutUint16(sb[0x6A:], uint16(b.bs/b.isz))
	sb[0x78] = byte(bits.TrailingZeros64(b.bs))
	sb[0x79] = 9
	sb[0x7A] = byte(bits.TrailingZeros64(b.isz))
	sb[0x7B] = byte(b.inoLog)
	sb[0x7C] = byte(b.agLog)
	sb[0xC0] = byte(o.DirBlkLog)
	if b.v5 {
		be.PutUint16(sb[0x64:], 5)
		be.PutUint32(sb[0xD8:], 1|o.Incompat)
		if o.NRExt64 {
			be.PutUint32(sb[0xD8:], 1|0x20|o.Incompat)
		}
		binary.LittleEndian.PutUint32(sb[0xE0:], crc32.Checksum(zeroed(sb, 0xE0), castagnoli))
		return
	}
	be.PutUint16(sb[0x64:], 4|0x2000|0x8000|0x10|0x20)
	f2 := uint32(0x2 | 0x8)
	if b.ftype {
		f2 |= 0x200
	}
	be.PutUint32(sb[0xC8:], f2)
}

// zeroed is buf with the 4 bytes at off cleared; the CRC is computed over it.
func zeroed(buf []byte, off int) []byte {
	out := append([]byte(nil), buf...)
	clear(out[off : off+4])
	return out
}

// sortedChildren returns the entries of a directory, name-ordered.
func sortedChildren(d *xnode) []*xnode {
	names := SortedKeys(d.children)
	out := make([]*xnode, len(names))
	for i, nm := range names {
		out[i] = d.children[nm]
	}
	return out
}
