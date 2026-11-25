package disktest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// Ext4Opts shapes the image NewExt4 builds. Zero values give a 1 KiB-block,
// extent-mapped filesystem.
type Ext4Opts struct {
	BlockSize      int  // 1024 (default), 2048, 4096
	Legacy         bool // block map instead of extents
	Bit64          bool // 64-bit feature with 64-byte group descriptors
	BlocksPerGroup int  // default 512
	InodesPerGroup int  // default 64
	HTreeDirs      bool // lay every directory out as an indexed directory
	Incompat       uint32
	RoCompat       uint32
	OSRelease      string // convenience: written to etc/os-release when set
}

// FileOpts shapes how one file's data is mapped.
type FileOpts struct {
	HoleBlocks int  // unmapped blocks before the data
	Fragmented bool // one extent per block, with gaps
	ForceIndex bool // put the extents in a leaf block under an index entry
	Uninit     bool // mark extents unwritten (read as zeros)
}

type node struct {
	name     string
	mode     uint16
	data     []byte
	target   string
	opts     FileOpts
	children map[string]*node
	parent   *node
	ino      uint64
}

// Ext4 collects files and renders them as an ext4 image.
type Ext4 struct {
	opts  Ext4Opts
	root  *node
	nodes []*node
}

// NewExt4 returns an empty filesystem.
func NewExt4(o Ext4Opts) *Ext4 {
	if o.BlockSize == 0 {
		o.BlockSize = 1024
	}
	if o.BlocksPerGroup == 0 {
		o.BlocksPerGroup = 512
	}
	if o.InodesPerGroup == 0 {
		o.InodesPerGroup = 64
	}
	e := &Ext4{opts: o, root: &node{mode: 0x41ED, children: map[string]*node{}}}
	e.root.ino = 2
	if o.OSRelease != "" {
		e.WriteFile("etc/os-release", []byte(o.OSRelease))
	}
	return e
}

func (e *Ext4) dir(path string) *node {
	cur := e.root
	for _, c := range strings.Split(strings.Trim(path, "/"), "/") {
		if c == "" {
			continue
		}
		next, ok := cur.children[c]
		if !ok {
			next = &node{name: c, mode: 0x41ED, children: map[string]*node{}, parent: cur}
			cur.children[c] = next
			e.nodes = append(e.nodes, next)
		}
		cur = next
	}
	return cur
}

func (e *Ext4) add(path string, n *node) {
	dir, name := "", path
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		dir, name = path[:i], path[i+1:]
	}
	parent := e.dir(dir)
	n.name, n.parent = name, parent
	parent.children[name] = n
	e.nodes = append(e.nodes, n)
}

// Mkdir creates a directory and its parents.
func (e *Ext4) Mkdir(path string) { e.dir(path) }

// WriteFile adds a regular file, creating parent directories.
func (e *Ext4) WriteFile(path string, data []byte) { e.WriteFileOpts(path, data, FileOpts{}) }

// WriteFileOpts is WriteFile with control over the block mapping.
func (e *Ext4) WriteFileOpts(path string, data []byte, o FileOpts) {
	e.add(path, &node{mode: 0x81A4, data: data, opts: o})
}

// Symlink adds a symbolic link.
func (e *Ext4) Symlink(path, target string) {
	e.add(path, &node{mode: 0xA1FF, target: target})
}

// Bytes renders the filesystem, growing the group count until it fits.
func (e *Ext4) Bytes() []byte {
	for groups := 1; groups < 64; groups++ {
		if img, ok := e.build(groups); ok {
			return img
		}
	}
	panic("disktest: filesystem does not fit in 64 groups")
}

type builder struct {
	e         *Ext4
	img       []byte
	bs        uint64
	fdb       uint64
	groups    uint64
	bpg       uint64
	ipg       uint64
	descSize  uint64
	tableBlks uint64
	gdtBlks   uint64
	curGroup  uint64
	curNext   uint64
	failed    bool
}

func (e *Ext4) build(groups int) ([]byte, bool) {
	o := e.opts
	b := &builder{e: e, bs: uint64(o.BlockSize), groups: uint64(groups), bpg: uint64(o.BlocksPerGroup), ipg: uint64(o.InodesPerGroup), descSize: 32}
	if o.Bit64 {
		b.descSize = 64
	}
	if b.bs == 1024 {
		b.fdb = 1
	}
	b.tableBlks = (b.ipg*256 + b.bs - 1) / b.bs
	b.gdtBlks = (b.groups*b.descSize + b.bs - 1) / b.bs
	total := b.fdb + b.groups*b.bpg
	b.img = make([]byte, total*b.bs)
	b.curNext = b.dataStart(0)

	if uint64(len(e.nodes))+11 > b.groups*b.ipg {
		return nil, false
	}
	for i, n := range e.nodes {
		n.ino = uint64(11 + i)
	}
	for _, n := range append([]*node{e.root}, e.nodes...) {
		b.writeNode(n)
	}
	if b.failed {
		return nil, false
	}
	b.writeSuperblock(total)
	return b.img, true
}

func (b *builder) groupStart(g uint64) uint64 { return b.fdb + g*b.bpg }
func (b *builder) inodeTable(g uint64) uint64 { return b.groupStart(g) + 1 + b.gdtBlks }
func (b *builder) dataStart(g uint64) uint64  { return b.inodeTable(g) + b.tableBlks }

// alloc returns n contiguous blocks, moving to the next group when needed.
func (b *builder) alloc(n uint64) uint64 {
	if n > b.bpg-(b.dataStart(0)-b.groupStart(0)) {
		panic("disktest: allocation larger than a block group")
	}
	end := b.groupStart(b.curGroup) + b.bpg
	if b.curNext+n > end {
		b.curGroup++
		b.curNext = b.dataStart(b.curGroup)
		if b.curGroup >= b.groups {
			b.failed = true
			b.curGroup = b.groups - 1
			b.curNext = b.dataStart(b.curGroup)
			return b.curNext
		}
	}
	first := b.curNext
	b.curNext += n
	return first
}

func (b *builder) block(n uint64) []byte { return b.img[n*b.bs : (n+1)*b.bs] }

func (b *builder) writeNode(n *node) {
	var content []byte
	size := uint64(0)
	opts := n.opts
	switch {
	case n.mode == 0x41ED:
		content = b.dirBlocks(n)
		size = uint64(len(content))
	case n.mode == 0xA1FF && len(n.target) < 60:
		size = uint64(len(n.target))
	case n.mode == 0xA1FF:
		content, size = []byte(n.target), uint64(len(n.target))
	default:
		content = n.data
		size = uint64(opts.HoleBlocks)*b.bs + uint64(len(n.data))
	}
	var iblock [60]byte
	var flags uint32
	var nblocks uint64
	switch {
	case n.mode == 0xA1FF && len(n.target) < 60:
		copy(iblock[:], n.target)
	default:
		phys, count := b.place(content, opts)
		nblocks = count
		if b.e.opts.Legacy {
			b.writeBlockMap(iblock[:], phys)
		} else {
			flags |= 0x80000
			b.writeExtents(iblock[:], phys, opts)
		}
	}
	if n.mode == 0x41ED && b.e.opts.HTreeDirs {
		flags |= 0x1000
	}
	b.writeInode(n.ino, n.mode, size, flags, nblocks, iblock)
}

// place writes content into data blocks and returns the physical block for
// each logical block (0 is a hole) and how many were allocated.
func (b *builder) place(content []byte, o FileOpts) ([]uint64, uint64) {
	n := (uint64(len(content)) + b.bs - 1) / b.bs
	phys := make([]uint64, uint64(o.HoleBlocks)+n)
	var used uint64
	var run uint64
	for i := uint64(0); i < n; i++ {
		var p uint64
		switch {
		case o.Fragmented:
			p = b.alloc(2)
		case i == 0:
			run = b.alloc(n)
			p = run
		default:
			p = run + i
		}
		phys[uint64(o.HoleBlocks)+i] = p
		used++
		end := min((i+1)*b.bs, uint64(len(content)))
		copy(b.block(p), content[i*b.bs:end])
	}
	return phys, used
}

type extent struct {
	lblk, pblk, n uint64
}

func (b *builder) writeExtents(iblock []byte, phys []uint64, o FileOpts) {
	var exts []extent
	for l, p := range phys {
		if p == 0 {
			continue
		}
		if k := len(exts) - 1; k >= 0 && exts[k].pblk+exts[k].n == p && exts[k].lblk+exts[k].n == uint64(l) {
			exts[k].n++
			continue
		}
		exts = append(exts, extent{uint64(l), p, 1})
	}
	le := binary.LittleEndian
	header := func(buf []byte, entries, max, depth int) {
		le.PutUint16(buf[0:], 0xF30A)
		le.PutUint16(buf[2:], uint16(entries))
		le.PutUint16(buf[4:], uint16(max))
		le.PutUint16(buf[6:], uint16(depth))
	}
	writeLeaf := func(buf []byte) {
		for i, x := range exts {
			e := buf[12+i*12:]
			l := uint16(x.n)
			if o.Uninit {
				l += 32768
			}
			le.PutUint32(e[0:], uint32(x.lblk))
			le.PutUint16(e[4:], l)
			le.PutUint16(e[6:], uint16(x.pblk>>32))
			le.PutUint32(e[8:], uint32(x.pblk))
		}
	}
	if len(exts) <= 4 && !o.ForceIndex {
		header(iblock, len(exts), 4, 0)
		writeLeaf(iblock)
		return
	}
	leaf := b.alloc(1)
	buf := b.block(leaf)
	header(buf, len(exts), int(b.bs-12)/12, 0)
	writeLeaf(buf)
	header(iblock, 1, 4, 1)
	first := uint64(0)
	if len(exts) > 0 {
		first = exts[0].lblk
	}
	le.PutUint32(iblock[12:], uint32(first))
	le.PutUint32(iblock[16:], uint32(leaf))
}

func (b *builder) writeBlockMap(iblock []byte, phys []uint64) {
	ppb := b.bs / 4
	le := binary.LittleEndian
	put := func(buf []byte, i, v uint64) { le.PutUint32(buf[i*4:], uint32(v)) }
	var single, double uint64
	for l, p := range phys {
		l := uint64(l)
		if p == 0 {
			continue
		}
		switch {
		case l < 12:
			put(iblock, l, p)
		case l-12 < ppb:
			if single == 0 {
				single = b.alloc(1)
				put(iblock, 12, single)
			}
			put(b.block(single), l-12, p)
		default:
			l -= 12 + ppb
			if double == 0 {
				double = b.alloc(1)
				put(iblock, 13, double)
			}
			slot := binary.LittleEndian.Uint32(b.block(double)[l/ppb*4:])
			if slot == 0 {
				slot = uint32(b.alloc(1))
				put(b.block(double), l/ppb, uint64(slot))
			}
			put(b.block(uint64(slot)), l%ppb, p)
		}
	}
}

func (b *builder) dirBlocks(d *node) []byte {
	parent := d.parent
	parentIno := uint64(2)
	if parent != nil {
		parentIno = parent.ino
	}
	selfIno := d.ino
	names := make([]string, 0, len(d.children))
	for n := range d.children {
		names = append(names, n)
	}
	sort.Strings(names)

	type ent struct {
		name string
		ino  uint64
		typ  byte
	}
	var ents []ent
	for _, n := range names {
		c := d.children[n]
		t := byte(1)
		switch c.mode {
		case 0x41ED:
			t = 2
		case 0xA1FF:
			t = 7
		}
		ents = append(ents, ent{n, c.ino, t})
	}
	bs := int(b.bs)
	var blocks [][]byte
	newBlock := func() []byte { blocks = append(blocks, make([]byte, bs)); return blocks[len(blocks)-1] }
	le := binary.LittleEndian
	put := func(blk []byte, off int, ino uint64, rec int, name string, typ byte) {
		le.PutUint32(blk[off:], uint32(ino))
		le.PutUint16(blk[off+4:], uint16(rec))
		blk[off+6], blk[off+7] = byte(len(name)), typ
		copy(blk[off+8:], name)
	}
	recLen := func(name string) int { return (8 + len(name) + 3) &^ 3 }

	blk := newBlock()
	off := 0
	last := -1
	if b.e.opts.HTreeDirs {
		put(blk, 0, selfIno, 12, ".", 2)
		put(blk, 12, parentIno, bs-12, "..", 2)
		blk = newBlock()
	} else {
		put(blk, 0, selfIno, 12, ".", 2)
		put(blk, 12, parentIno, 12, "..", 2)
		off, last = 24, 12
	}
	for _, en := range ents {
		rl := recLen(en.name)
		if off+rl > bs {
			le.PutUint16(blk[last+4:], uint16(bs-last))
			blk = newBlock()
			off = 0
		}
		put(blk, off, en.ino, rl, en.name, en.typ)
		last = off
		off += rl
	}
	if last >= 0 {
		le.PutUint16(blk[last+4:], uint16(bs-last))
	} else if off == 0 {
		le.PutUint16(blk[4:], uint16(bs))
	}
	return bytes.Join(blocks, nil)
}

func (b *builder) writeInode(ino uint64, mode uint16, size uint64, flags uint32, nblocks uint64, iblock [60]byte) {
	group := (ino - 1) / b.ipg
	idx := (ino - 1) % b.ipg
	off := b.inodeTable(group)*b.bs + idx*256
	in := b.img[off : off+256]
	le := binary.LittleEndian
	le.PutUint16(in[0:], mode)
	le.PutUint32(in[4:], uint32(size))
	le.PutUint16(in[0x1A:], 1)
	le.PutUint32(in[0x1C:], uint32(nblocks*b.bs/512))
	le.PutUint32(in[0x20:], flags)
	copy(in[0x28:], iblock[:])
	le.PutUint32(in[0x6C:], uint32(size>>32))
	le.PutUint16(in[0x80:], 32)
}

func (b *builder) writeSuperblock(total uint64) {
	sb := b.img[1024:2048]
	le := binary.LittleEndian
	le.PutUint32(sb[0x0:], uint32(b.groups*b.ipg))
	le.PutUint32(sb[0x4:], uint32(total))
	le.PutUint32(sb[0x14:], uint32(b.fdb))
	shift := uint32(0)
	for s := uint64(1024); s < b.bs; s <<= 1 {
		shift++
	}
	le.PutUint32(sb[0x18:], shift)
	le.PutUint32(sb[0x20:], uint32(b.bpg))
	le.PutUint32(sb[0x28:], uint32(b.ipg))
	le.PutUint16(sb[0x38:], 0xEF53)
	le.PutUint16(sb[0x3A:], 1)
	le.PutUint32(sb[0x4C:], 1)
	le.PutUint32(sb[0x54:], 11)
	le.PutUint16(sb[0x58:], 256)
	incompat := uint32(0x2) | b.e.opts.Incompat
	if !b.e.opts.Legacy {
		incompat |= 0x40
	}
	if b.e.opts.Bit64 {
		incompat |= 0x80
		le.PutUint32(sb[0x150:], uint32(total>>32))
		le.PutUint16(sb[0xFE:], uint16(b.descSize))
	}
	le.PutUint32(sb[0x60:], incompat)
	le.PutUint32(sb[0x64:], b.e.opts.RoCompat)
	for g := uint64(0); g < b.groups; g++ {
		gd := b.img[(b.fdb+1)*b.bs+g*b.descSize:]
		le.PutUint32(gd[0x8:], uint32(b.inodeTable(g)))
	}
}

// Describe names an image for failure messages.
func (e *Ext4) Describe() string {
	return fmt.Sprintf("ext4(bs=%d legacy=%v 64bit=%v)", e.opts.BlockSize, e.opts.Legacy, e.opts.Bit64)
}
