package disktest

import "encoding/binary"

type dirEnt struct {
	name  string
	ino   uint64
	ftype byte
}

func ftypeOf(n *xnode) byte {
	switch n.mode {
	case 0x41ED:
		return 2
	case 0xA1FF:
		return 7
	}
	return 1
}

func (b *xbuilder) entSize(name string) int {
	ft := 0
	if b.ftype {
		ft = 1
	}
	return (8 + 1 + len(name) + ft + 2 + 7) &^ 7
}

// dirFork lays a directory out in the form the options ask for and returns
// its data fork, format, size, block count and extent count.
func (b *xbuilder) dirFork(d *xnode) (fork []byte, format uint8, size, nblocks, nextents uint64) {
	parent := d.parent
	if parent == nil {
		parent = d
	}
	ents := []dirEnt{{".", d.ino, 2}, {"..", parent.ino, 2}}
	for _, c := range sortedChildren(d) {
		ents = append(ents, dirEnt{c.name, c.ino, ftypeOf(c)})
	}
	form := b.x.opts.Dirs
	if sf := b.shortForm(parent.ino, ents[2:]); form == DirAuto && uint64(len(sf)) <= b.forkSize() && len(ents)-2 <= 255 {
		return sf, 1, uint64(len(sf)), 0, 0
	}
	if form == DirAuto || form == DirBlock {
		if blk, ok := b.packBlockForm(ents); ok {
			fsb := b.alloc(b.dirFsb)
			copy(b.blockRun(fsb, b.dirFsb), blk)
			fork, format = b.fork(d.ino, []xextent{{off: 0, fsb: fsb, count: b.dirFsb}}, false)
			return fork, format, b.dirBlk, b.dirFsb, 1
		}
	}
	return b.leafForm(d, ents, form)
}

func (b *xbuilder) blockRun(fsb, n uint64) []byte {
	idx := (fsb>>b.agLog)*b.agBlocks + fsb&(1<<b.agLog-1)
	return b.img[idx*b.bs : (idx+n)*b.bs]
}

func (b *xbuilder) shortForm(parent uint64, ents []dirEnt) []byte {
	be := binary.BigEndian
	isz := 4
	for _, e := range ents {
		if e.ino > 0xFFFFFFFF {
			isz = 8
		}
	}
	if parent > 0xFFFFFFFF {
		isz = 8
	}
	put := func(buf []byte, v uint64) []byte {
		if isz == 4 {
			return be.AppendUint32(buf, uint32(v))
		}
		return be.AppendUint64(buf, v)
	}
	out := []byte{byte(len(ents)), 0}
	if isz == 8 {
		out[1] = byte(len(ents))
	}
	out = put(out, parent)
	off := uint16(b.dataHdr())
	for _, e := range ents {
		out = append(out, byte(len(e.name)))
		out = be.AppendUint16(out, off)
		out = append(out, e.name...)
		if b.ftype {
			out = append(out, e.ftype)
		}
		out = put(out, e.ino)
		off += uint16(b.entSize(e.name))
	}
	return out
}

func (b *xbuilder) dataHdr() int {
	if b.v5 {
		return 64
	}
	return 16
}

func (b *xbuilder) magics() (data, block, free uint32, leaf1, leafn uint16) {
	if b.v5 {
		return 0x58444433, 0x58444233, 0x58444633, 0x3DF1, 0x3DFF
	}
	return 0x58443244, 0x58443242, 0x58443246, 0xD2F1, 0xD2FF
}

// packDir fills directory blocks with ents; every block's entries end at
// capEnd (the rest of the block holds the leaf array in block form).
func (b *xbuilder) packDir(ents []dirEnt, capEnd int, magic uint32) [][]byte {
	be := binary.BigEndian
	var blocks [][]byte
	var cur []byte
	used := 0
	finish := func() {
		if cur == nil {
			return
		}
		if used < capEnd {
			be.PutUint16(cur[used:], 0xFFFF)
			be.PutUint16(cur[used+2:], uint16(capEnd-used))
			be.PutUint16(cur[capEnd-2:], uint16(used))
		}
		blocks = append(blocks, cur)
	}
	for _, e := range ents {
		sz := b.entSize(e.name)
		if cur == nil || used+sz > capEnd {
			finish()
			cur = make([]byte, b.dirBlk)
			be.PutUint32(cur, magic)
			used = b.dataHdr()
		}
		be.PutUint64(cur[used:], e.ino)
		cur[used+8] = byte(len(e.name))
		copy(cur[used+9:], e.name)
		if b.ftype {
			cur[used+9+len(e.name)] = e.ftype
		}
		be.PutUint16(cur[used+sz-2:], uint16(used))
		used += sz
	}
	finish()
	return blocks
}

// packBlockForm returns the single directory block holding ents with its leaf
// array and tail, or false when they do not fit one block.
func (b *xbuilder) packBlockForm(ents []dirEnt) ([]byte, bool) {
	_, blockMagic, _, _, _ := b.magics()
	capEnd := int(b.dirBlk) - 8 - 8*len(ents)
	if capEnd < b.dataHdr() {
		return nil, false
	}
	blocks := b.packDir(ents, capEnd, blockMagic)
	if len(blocks) != 1 {
		return nil, false
	}
	binary.BigEndian.PutUint32(blocks[0][b.dirBlk-8:], uint32(len(ents)))
	return blocks[0], true
}

// leafForm writes data blocks at the start of the directory's address space
// and the leaf (and, for node form, free) blocks far above them, where the
// inode size does not reach.
func (b *xbuilder) leafForm(d *xnode, ents []dirEnt, form DirForm) ([]byte, uint8, uint64, uint64, uint64) {
	dataMagic, _, freeMagic, leaf1, leafn := b.magics()
	blocks := b.packDir(ents, int(b.dirBlk), dataMagic)
	var exts []xextent
	gap := uint64(0)
	for i, blk := range blocks {
		if i == 1 && b.x.opts.DirGap {
			gap = b.dirFsb
		}
		fsb := b.alloc(b.dirFsb)
		copy(b.blockRun(fsb, b.dirFsb), blk)
		exts = append(exts, xextent{off: uint64(i)*b.dirFsb + gap, fsb: fsb, count: b.dirFsb})
	}
	size := (uint64(len(blocks)) + gap/b.dirFsb) * b.dirBlk
	nblocks := uint64(len(blocks)) * b.dirFsb
	leafAt := xfsLeafOffset / b.bs
	magic := leaf1
	if form == DirNode {
		magic = leafn
	}
	leaf := b.alloc(1)
	binary.BigEndian.PutUint16(b.block(leaf)[8:], magic)
	exts = append(exts, xextent{off: leafAt, fsb: leaf, count: 1})
	nblocks++
	if form == DirNode {
		free := b.alloc(1)
		binary.BigEndian.PutUint32(b.block(free), freeMagic)
		exts = append(exts, xextent{off: 2 * leafAt, fsb: free, count: 1})
		nblocks++
	}
	fork, format := b.fork(d.ino, exts, false)
	return fork, format, size, nblocks, uint64(len(exts))
}

// remoteLink stores a symlink target in blocks; v5 prefixes each block with a
// 56-byte header naming the slice of the target it holds.
func (b *xbuilder) remoteLink(n *xnode) ([]byte, uint8, uint64, uint64) {
	be := binary.BigEndian
	target := []byte(n.target)
	room := int(b.bs)
	hdr := 0
	if b.v5 {
		hdr = 56
		room -= hdr
	}
	nblk := uint64((len(target) + room - 1) / room)
	fsb := b.alloc(nblk)
	for i := 0; i < int(nblk); i++ {
		blk := b.block(fsb + uint64(i))
		part := target[i*room : min((i+1)*room, len(target))]
		if b.v5 {
			be.PutUint32(blk, 0x58534C4D)
			be.PutUint32(blk[4:], uint32(i*room))
			be.PutUint32(blk[8:], uint32(len(part)))
		}
		copy(blk[hdr:], part)
	}
	fork, format := b.fork(n.ino, []xextent{{fsb: fsb, count: nblk}}, false)
	return fork, format, nblk, 1
}
