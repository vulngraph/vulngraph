package xfs_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/disktest"
	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/xfs"
)

var errUnreadable = errors.New("unreadable")

func open(t *testing.T, img []byte) *xfs.FS {
	t.Helper()
	f, err := xfs.Open(bytes.NewReader(img), int64(len(img)))
	require.NoError(t, err)
	return f
}

func lookup(f *xfs.FS, path string) (uint64, error) {
	ino := f.Root()
	for _, c := range strings.Split(path, "/") {
		var err error
		if ino, err = f.Lookup(ino, c); err != nil {
			return 0, err
		}
	}
	return ino, nil
}

func readFile(f *xfs.FS, path string) ([]byte, error) {
	ino, err := lookup(f, path)
	if err != nil {
		return nil, err
	}
	_, size, err := f.Stat(ino)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, size)
	n, err := f.ReadAt(ino, buf, 0)
	if err != nil && (!errors.Is(err, io.EOF) || int64(n) != size) {
		return nil, err
	}
	return buf, nil
}

func pattern(n int, seed byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7) ^ seed
	}
	return b
}

var layouts = map[string]disktest.XFSOpts{
	"v4 1k":                   {},
	"v4 ftype":                {Ftype: true},
	"v5 1k":                   {V5: true},
	"v5 4k blocks 512 inodes": {V5: true, BlockSize: 4096, InodeSize: 512, AGBlocks: 1024},
	"v4 512-byte blocks":      {BlockSize: 512, AGBlocks: 4096},
	"v5 512-byte blocks":      {V5: true, BlockSize: 512, InodeSize: 512, AGBlocks: 4096},
	"non-power-of-two AGs":    {V5: true, AGBlocks: 3000},
	"tiny AGs":                {AGBlocks: 160},
	"multi-block dir blocks":  {V5: true, DirBlkLog: 2, AGBlocks: 4096},
	"v5 large extent counts":  {V5: true, NRExt64: true},
	"v5 sparse inodes":        {V5: true, Incompat: 0x2},
	"v5 big timestamps":       {V5: true, Incompat: 0x8 | 0x4},
	"2k inodes":               {V5: true, InodeSize: 2048, BlockSize: 4096, AGBlocks: 1024},
}

func TestReadsFilesAcrossLayouts(t *testing.T) {
	for name, o := range layouts {
		t.Run(name, func(t *testing.T) {
			e := disktest.NewXFS(o)
			small := []byte("Package: bash\nVersion: 5.2\n")
			big := pattern(300*1024+17, 3)
			e.WriteFile("var/lib/dpkg/status", small)
			e.WriteFile("data/big", big)
			e.WriteFile("data/empty", nil)
			f := open(t, e.Bytes())

			got, err := readFile(f, "var/lib/dpkg/status")
			require.NoError(t, err)
			assert.Equal(t, small, got)
			got, err = readFile(f, "data/big")
			require.NoError(t, err)
			assert.Equal(t, big, got)
			got, err = readFile(f, "data/empty")
			require.NoError(t, err)
			assert.Empty(t, got)
		})
	}
}

func TestDirectoryForms(t *testing.T) {
	forms := map[string]disktest.XFSOpts{
		"auto":            {},
		"auto v5":         {V5: true},
		"block":           {Dirs: disktest.DirBlock},
		"block v5":        {V5: true, Dirs: disktest.DirBlock},
		"leaf":            {Dirs: disktest.DirLeaf},
		"leaf v5":         {V5: true, Dirs: disktest.DirLeaf},
		"leaf with a gap": {Dirs: disktest.DirLeaf, DirGap: true},
		"node":            {V5: true, Dirs: disktest.DirNode, DirGap: true},
		"node v4":         {Dirs: disktest.DirNode},
		"multi-block":     {V5: true, DirBlkLog: 1, Dirs: disktest.DirLeaf},
	}
	for name, o := range forms {
		for _, n := range []int{1, 12, 300} {
			t.Run(name+"/"+strconv.Itoa(n)+" entries", func(t *testing.T) {
				e := disktest.NewXFS(o)
				want := map[string][]byte{}
				for i := 0; i < n; i++ {
					p := "etc/conf" + strings.Repeat("x", i%40) + string(rune('a'+i%26)) + "-" + strconv.Itoa(i)
					want[p] = pattern(30+i%50, byte(i))
					e.WriteFile(p, want[p])
				}
				f := open(t, e.Bytes())
				for p, data := range want {
					got, err := readFile(f, p)
					require.NoError(t, err, p)
					assert.Equal(t, data, got, p)
				}
				etc, err := lookup(f, "etc")
				require.NoError(t, err)
				names, err := f.DirNames(etc)
				require.NoError(t, err)
				assert.Len(t, names, n)
				_, err = f.Lookup(etc, "missing")
				assert.ErrorIs(t, err, fs.ErrNotExist)
				self, err := f.Lookup(etc, ".")
				require.NoError(t, err)
				assert.Equal(t, etc, self)
				up, err := f.Lookup(etc, "..")
				require.NoError(t, err)
				assert.Equal(t, f.Root(), up)
			})
		}
	}
}

func TestExtentShapes(t *testing.T) {
	data := pattern(9*1024+100, 9)
	shapes := map[string]disktest.XFSFileOpts{
		"fragmented":            {Fragmented: true},
		"btree, one leaf":       {Btree: true},
		"btree, fragmented":     {Btree: true, Fragmented: true},
		"hole before the data":  {HoleBlocks: 3},
		"hole and btree":        {HoleBlocks: 5, Btree: true, Fragmented: true},
		"fragmented past inode": {Fragmented: true, HoleBlocks: 1},
	}
	for _, v5 := range []bool{false, true} {
		for name, o := range shapes {
			t.Run(name+"/v5="+strconv.FormatBool(v5), func(t *testing.T) {
				e := disktest.NewXFS(disktest.XFSOpts{V5: v5})
				e.WriteFileOpts("f", data, o)
				got, err := readFile(open(t, e.Bytes()), "f")
				require.NoError(t, err)
				want := append(make([]byte, o.HoleBlocks*1024), data...)
				assert.Equal(t, want, got)
			})
		}
	}

	t.Run("btree two levels deep", func(t *testing.T) {
		for _, v5 := range []bool{false, true} {
			e := disktest.NewXFS(disktest.XFSOpts{V5: v5, MaxRecs: 2, AGBlocks: 4096})
			big := pattern(40*1024, 5)
			e.WriteFileOpts("f", big, disktest.XFSFileOpts{Fragmented: true})
			e.WriteFileOpts("sparse", big[:3000], disktest.XFSFileOpts{Fragmented: true, HoleBlocks: 7})
			f := open(t, e.Bytes())
			got, err := readFile(f, "f")
			require.NoError(t, err)
			assert.Equal(t, big, got)
			got, err = readFile(f, "sparse")
			require.NoError(t, err)
			assert.Equal(t, append(make([]byte, 7*1024), big[:3000]...), got)
		}
	})

	t.Run("unwritten extents read as zeros", func(t *testing.T) {
		e := disktest.NewXFS(disktest.XFSOpts{})
		e.WriteFileOpts("f", data, disktest.XFSFileOpts{Unwritten: true})
		e.WriteFileOpts("g", data, disktest.XFSFileOpts{Unwritten: true, Btree: true, Fragmented: true})
		f := open(t, e.Bytes())
		for _, p := range []string{"f", "g"} {
			got, err := readFile(f, p)
			require.NoError(t, err)
			assert.Equal(t, make([]byte, len(data)), got, p)
		}
	})

	t.Run("reads at offsets and past the end", func(t *testing.T) {
		e := disktest.NewXFS(disktest.XFSOpts{})
		e.WriteFileOpts("f", data, disktest.XFSFileOpts{Fragmented: true, Btree: true})
		f := open(t, e.Bytes())
		ino, err := lookup(f, "f")
		require.NoError(t, err)
		buf := make([]byte, 500)
		n, err := f.ReadAt(ino, buf, 1500)
		require.NoError(t, err)
		assert.Equal(t, 500, n)
		assert.Equal(t, data[1500:2000], buf)
		n, err = f.ReadAt(ino, buf, int64(len(data))-100)
		assert.ErrorIs(t, err, io.EOF)
		assert.Equal(t, 100, n)
		_, err = f.ReadAt(ino, buf, int64(len(data)))
		assert.ErrorIs(t, err, io.EOF)
		_, err = f.ReadAt(ino, buf, -1)
		assert.ErrorIs(t, err, fs.ErrInvalid)
	})
}

func TestSymlinks(t *testing.T) {
	long := "/" + strings.Repeat("a/", 300) + "end"
	for name, o := range map[string]disktest.XFSOpts{"v4": {}, "v5": {V5: true}, "v5 512-byte blocks": {V5: true, BlockSize: 512, InodeSize: 512, AGBlocks: 4096}} {
		t.Run(name, func(t *testing.T) {
			e := disktest.NewXFS(o)
			e.Symlink("lib", "usr/lib")
			e.Symlink("long", long)
			e.WriteFile("plain", []byte("x"))
			f := open(t, e.Bytes())
			for p, want := range map[string]string{"lib": "usr/lib", "long": long} {
				ino, err := lookup(f, p)
				require.NoError(t, err)
				mode, _, err := f.Stat(ino)
				require.NoError(t, err)
				assert.Equal(t, uint32(0xA000), mode&0xF000)
				got, err := f.ReadLink(ino)
				require.NoError(t, err)
				assert.Equal(t, want, got, p)
			}
			plain, err := lookup(f, "plain")
			require.NoError(t, err)
			_, err = f.ReadLink(plain)
			assert.ErrorIs(t, err, xfs.ErrCorrupt)
		})
	}
}

func TestKindMismatches(t *testing.T) {
	e := disktest.NewXFS(disktest.XFSOpts{})
	e.WriteFile("d/f", []byte("x"))
	f := open(t, e.Bytes())
	d, err := lookup(f, "d")
	require.NoError(t, err)
	file, err := lookup(f, "d/f")
	require.NoError(t, err)
	_, err = f.Lookup(file, "x")
	assert.ErrorIs(t, err, fs.ErrNotExist)
	_, err = f.DirNames(file)
	assert.ErrorIs(t, err, fs.ErrNotExist)
	_, err = f.ReadAt(d, make([]byte, 4), 0)
	assert.ErrorIs(t, err, xfs.ErrCorrupt)
	_, err = f.Lookup(d, "a/b")
	assert.ErrorIs(t, err, fs.ErrNotExist)
	_, err = f.Lookup(d, "")
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestSourceErrorsKeepTheirIdentity(t *testing.T) {
	e := disktest.NewXFS(disktest.XFSOpts{})
	e.WriteFile("f", pattern(4000, 1))
	img := e.Bytes()
	f := open(t, img)
	ino, err := lookup(f, "f")
	require.NoError(t, err)

	src := &disktest.Mem{Data: img, Err: errUnreadable, Unreadable: []disktest.Range{{Off: 0, Len: 0}}}
	g, err := xfs.Open(src, int64(len(img)))
	require.NoError(t, err)
	src.Unreadable = []disktest.Range{{Off: 3072, Len: int64(len(img))}}
	_, err = g.ReadAt(ino, make([]byte, 4000), 0)
	assert.ErrorIs(t, err, errUnreadable)

	src.Unreadable = []disktest.Range{{Off: 0, Len: 4}}
	_, err = xfs.Open(src, int64(len(img)))
	assert.ErrorIs(t, err, errUnreadable)
}

func put(img []byte, off int, v any) {
	switch x := v.(type) {
	case uint8:
		img[off] = x
	case uint16:
		binary.BigEndian.PutUint16(img[off:], x)
	case uint32:
		binary.BigEndian.PutUint32(img[off:], x)
	case uint64:
		binary.BigEndian.PutUint64(img[off:], x)
	}
}

// Superblock offsets patched by the hostile-input tables.
const (
	sbBlockSize = 0x4
	sbDBlocks   = 0x8
	sbRBlocks   = 0x10
	sbRootIno   = 0x38
	sbAGBlocks  = 0x54
	sbAGCount   = 0x58
	sbVersion   = 0x64
	sbSectSize  = 0x66
	sbInodeSize = 0x68
	sbBlockLog  = 0x78
	sbInodeLog  = 0x7A
	sbAGBlkLog  = 0x7C
	sbInProg    = 0x7E
	sbFeatures2 = 0xC8
	sbIncompat  = 0xD8
	sbDirBlkLog = 0xC0
)

func TestOpenRejects(t *testing.T) {
	base := func(v5 bool) []byte { return disktest.NewXFS(disktest.XFSOpts{V5: v5}).Bytes() }
	tests := []struct {
		name  string
		img   func() []byte
		patch func(img []byte)
		want  error
	}{
		{"wrong magic", func() []byte { return base(false) }, func(b []byte) { b[0] = 'Y' }, xfs.ErrNotXFS},
		{"shorter than the magic", func() []byte { return []byte("XF") }, nil, xfs.ErrNotXFS},
		{"magic only", func() []byte { return []byte("XFSB") }, nil, xfs.ErrCorrupt},
		{"truncated superblock", func() []byte { return base(false)[:100] }, nil, xfs.ErrCorrupt},
		{"device shorter than the filesystem", func() []byte { return base(false)[:1024*1024] }, nil, xfs.ErrCorrupt},
		{"block size not a power of two", func() []byte { return base(false) }, func(b []byte) { put(b, sbBlockSize, uint32(1000)) }, xfs.ErrCorrupt},
		{"block size disagrees with its log", func() []byte { return base(false) }, func(b []byte) { put(b, sbBlockLog, uint8(12)) }, xfs.ErrCorrupt},
		{"absurd block size", func() []byte { return base(false) }, func(b []byte) { put(b, sbBlockSize, uint32(1<<30)); put(b, sbBlockLog, uint8(30)) }, xfs.ErrCorrupt},
		{"sector size zero", func() []byte { return base(false) }, func(b []byte) { put(b, sbSectSize, uint16(0)) }, xfs.ErrCorrupt},
		{"sector larger than the block", func() []byte { return base(false) }, func(b []byte) { put(b, sbSectSize, uint16(4096)) }, xfs.ErrCorrupt},
		{"inode size too small", func() []byte { return base(false) }, func(b []byte) { put(b, sbInodeSize, uint16(128)); put(b, sbInodeLog, uint8(7)) }, xfs.ErrCorrupt},
		{"inode size above the block", func() []byte { return base(false) }, func(b []byte) { put(b, sbInodeSize, uint16(2048)); put(b, sbInodeLog, uint8(11)) }, xfs.ErrCorrupt},
		{"zero AG blocks", func() []byte { return base(false) }, func(b []byte) { put(b, sbAGBlocks, uint32(0)) }, xfs.ErrCorrupt},
		{"zero AGs", func() []byte { return base(false) }, func(b []byte) { put(b, sbAGCount, uint32(0)) }, xfs.ErrCorrupt},
		{"absurd AG count", func() []byte { return base(false) }, func(b []byte) { put(b, sbAGCount, uint32(1<<31)) }, xfs.ErrCorrupt},
		{"AG shift disagrees", func() []byte { return base(false) }, func(b []byte) { put(b, sbAGBlkLog, uint8(5)) }, xfs.ErrCorrupt},
		{"AG shift absurd", func() []byte { return base(false) }, func(b []byte) { put(b, sbAGBlkLog, uint8(60)) }, xfs.ErrCorrupt},
		{"absurd block count", func() []byte { return base(false) }, func(b []byte) { put(b, sbDBlocks, uint64(1<<62)) }, xfs.ErrCorrupt},
		{"zero block count", func() []byte { return base(false) }, func(b []byte) { put(b, sbDBlocks, uint64(0)) }, xfs.ErrCorrupt},
		{"root inode outside the filesystem", func() []byte { return base(false) }, func(b []byte) { put(b, sbRootIno, uint64(1<<40)) }, xfs.ErrCorrupt},
		{"root inode zero", func() []byte { return base(false) }, func(b []byte) { put(b, sbRootIno, uint64(0)) }, xfs.ErrCorrupt},
		{"directory block above 64 KiB", func() []byte { return base(false) }, func(b []byte) { put(b, sbDirBlkLog, uint8(9)) }, xfs.ErrCorrupt},
		{"mkfs unfinished", func() []byte { return base(false) }, func(b []byte) { put(b, sbInProg, uint8(1)) }, xfs.ErrCorrupt},
		{"realtime volume", func() []byte { return base(false) }, func(b []byte) { put(b, sbRBlocks, uint64(100)) }, xfs.ErrUnsupported},
		{"version 1 directories", func() []byte { return base(false) }, func(b []byte) { put(b, sbVersion, uint16(4)) }, xfs.ErrUnsupported},
		{"superblock version 3", func() []byte { return base(false) }, func(b []byte) { put(b, sbVersion, uint16(3)) }, xfs.ErrUnsupported},
		{"superblock version 0", func() []byte { return base(false) }, func(b []byte) { put(b, sbVersion, uint16(0)) }, xfs.ErrCorrupt},
		{"unknown features2 bit", func() []byte { return base(false) }, func(b []byte) { put(b, sbFeatures2, uint32(0x8000)) }, xfs.ErrUnsupported},
		{"v5 checksum", func() []byte { return base(true) }, func(b []byte) { b[0x70] ^= 1 }, xfs.ErrCorrupt},
		{"v5 truncated before the checksummed sector", func() []byte { return base(true)[:300] }, nil, xfs.ErrCorrupt},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			img := tc.img()
			if tc.patch != nil {
				tc.patch(img)
			}
			_, err := xfs.Open(bytes.NewReader(img), int64(len(img)))
			assert.ErrorIs(t, err, tc.want)
		})
	}

	// A v5 superblock with its checksum recomputed after the patch, so the
	// feature check rather than the checksum is what rejects it.
	v5 := map[string]uint32{
		"unknown incompat feature": 0x1000,
		"needs repair":             0x10,
		"parent pointers":          0x80,
		"metadata directory":       0x100,
	}
	for name, bits := range v5 {
		t.Run(name, func(t *testing.T) {
			img := disktest.NewXFS(disktest.XFSOpts{V5: true, Incompat: bits}).Bytes()
			_, err := xfs.Open(bytes.NewReader(img), int64(len(img)))
			assert.ErrorIs(t, err, xfs.ErrUnsupported)
		})
	}
}

// inodeFork patches the data fork of path's inode and, on v5, leaves the
// checksum stale: tests that need a valid one build with V5 false.
func patchInode(e *disktest.XFS, img []byte, path string, f func(inode []byte)) {
	off := e.InodeOffset(path)
	f(img[off : off+256])
}

func TestHostileInodes(t *testing.T) {
	data := pattern(5000, 4)
	build := func(o disktest.XFSFileOpts) (*disktest.XFS, []byte) {
		e := disktest.NewXFS(disktest.XFSOpts{})
		e.WriteFileOpts("f", data, o)
		e.Symlink("l", "target")
		e.WriteFile("d/x", []byte("x"))
		return e, e.Bytes()
	}
	extentRecord := func(off, fsb, count uint64) []byte {
		out := make([]byte, 16)
		binary.BigEndian.PutUint64(out, off<<9|fsb>>43&0x1FF)
		binary.BigEndian.PutUint64(out[8:], (fsb&(1<<43-1))<<21|count)
		return out
	}
	tests := []struct {
		name  string
		opts  disktest.XFSFileOpts
		path  string
		patch func(in []byte)
		op    string // stat, read, link, dir
		want  error
	}{
		{"inode magic", disktest.XFSFileOpts{}, "f", func(in []byte) { in[0] = 'X' }, "stat", xfs.ErrCorrupt},
		{"version 1 inode", disktest.XFSFileOpts{}, "f", func(in []byte) { in[4] = 1 }, "stat", xfs.ErrUnsupported},
		{"unknown inode version", disktest.XFSFileOpts{}, "f", func(in []byte) { in[4] = 9 }, "stat", xfs.ErrCorrupt},
		{"version 3 inode on a v4 filesystem", disktest.XFSFileOpts{}, "f", func(in []byte) { in[4] = 3 }, "stat", xfs.ErrCorrupt},
		{"absurd file size", disktest.XFSFileOpts{}, "f", func(in []byte) { binary.BigEndian.PutUint64(in[0x38:], 1<<63) }, "stat", xfs.ErrCorrupt},
		{"attribute fork larger than the inode", disktest.XFSFileOpts{}, "f", func(in []byte) { in[0x52] = 200 }, "stat", xfs.ErrCorrupt},
		{"realtime file", disktest.XFSFileOpts{}, "f", func(in []byte) { in[0x5B] = 1 }, "read", xfs.ErrUnsupported},
		{"data fork of unknown format", disktest.XFSFileOpts{}, "f", func(in []byte) { in[5] = 9 }, "read", xfs.ErrCorrupt},
		{"regular file in local format", disktest.XFSFileOpts{}, "f", func(in []byte) { in[5] = 1 }, "read", xfs.ErrCorrupt},
		{"more extents than the fork holds", disktest.XFSFileOpts{}, "f", func(in []byte) { binary.BigEndian.PutUint32(in[0x4C:], 1<<20) }, "read", xfs.ErrCorrupt},
		{"extent zero blocks long", disktest.XFSFileOpts{}, "f", func(in []byte) { copy(in[100:], extentRecord(0, 100, 0)) }, "read", xfs.ErrCorrupt},
		{"extent beyond the AG", disktest.XFSFileOpts{}, "f", func(in []byte) { copy(in[100:], extentRecord(0, 2040, 100)) }, "read", xfs.ErrCorrupt},
		{"extent in a nonexistent AG", disktest.XFSFileOpts{}, "f", func(in []byte) { copy(in[100:], extentRecord(0, 7<<11, 4)) }, "read", xfs.ErrCorrupt},
		{"btree root of level zero", disktest.XFSFileOpts{Btree: true}, "f", func(in []byte) { in[100], in[101] = 0, 0 }, "read", xfs.ErrCorrupt},
		{"btree root over-deep", disktest.XFSFileOpts{Btree: true}, "f", func(in []byte) { in[100], in[101] = 0, 12 }, "read", xfs.ErrCorrupt},
		{"btree root with no records", disktest.XFSFileOpts{Btree: true}, "f", func(in []byte) { in[102], in[103] = 0, 0 }, "read", xfs.ErrCorrupt},
		{"btree root with too many records", disktest.XFSFileOpts{Btree: true}, "f", func(in []byte) { in[102], in[103] = 0xFF, 0xFF }, "read", xfs.ErrCorrupt},
		{"btree pointer outside the filesystem", disktest.XFSFileOpts{Btree: true}, "f", func(in []byte) { binary.BigEndian.PutUint64(in[100+4+9*8:], 1<<50) }, "read", xfs.ErrCorrupt},
		{"symlink longer than allowed", disktest.XFSFileOpts{}, "l", func(in []byte) { binary.BigEndian.PutUint64(in[0x38:], 5000) }, "link", xfs.ErrCorrupt},
		{"local symlink longer than its fork", disktest.XFSFileOpts{}, "l", func(in []byte) { binary.BigEndian.PutUint64(in[0x38:], 900) }, "link", xfs.ErrCorrupt},
		{"short-form directory larger than its fork", disktest.XFSFileOpts{}, "d", func(in []byte) { binary.BigEndian.PutUint64(in[0x38:], 900) }, "dir", xfs.ErrCorrupt},
		{"short-form directory too small", disktest.XFSFileOpts{}, "d", func(in []byte) { binary.BigEndian.PutUint64(in[0x38:], 3) }, "dir", xfs.ErrCorrupt},
		{"short-form entry count too high", disktest.XFSFileOpts{}, "d", func(in []byte) { in[100] = 200 }, "dir", xfs.ErrCorrupt},
		{"short-form entry with an empty name", disktest.XFSFileOpts{}, "d", func(in []byte) { in[100+6] = 0 }, "dir", xfs.ErrCorrupt},
		{"short-form entry pointing outside the filesystem", disktest.XFSFileOpts{}, "d", func(in []byte) { in[100+6+3+1+0] = 0x7F }, "dir", xfs.ErrCorrupt},
		{"directory in an unknown format", disktest.XFSFileOpts{}, "d", func(in []byte) { in[5] = 0 }, "dir", xfs.ErrCorrupt},
		{"directory on the realtime volume", disktest.XFSFileOpts{}, "d", func(in []byte) { in[0x5B] = 1 }, "dir", xfs.ErrUnsupported},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, img := build(tc.opts)
			patchInode(e, img, tc.path, tc.patch)
			f := open(t, img)
			ino := e.Ino(tc.path)
			var err error
			switch tc.op {
			case "stat":
				_, _, err = f.Stat(ino)
			case "read":
				_, err = f.ReadAt(ino, make([]byte, 5000), 0)
			case "link":
				_, err = f.ReadLink(ino)
			case "dir":
				_, err = f.DirNames(ino)
			}
			assert.ErrorIs(t, err, tc.want)
		})
	}
}

func TestInodeAddressing(t *testing.T) {
	e := disktest.NewXFS(disktest.XFSOpts{})
	e.WriteFile("f", []byte("x"))
	img := e.Bytes()
	f := open(t, img)
	for _, ino := range []uint64{0, 1 << 60, f.Root() + 1<<40} {
		_, _, err := f.Stat(ino)
		assert.ErrorIs(t, err, xfs.ErrCorrupt, "inode %d", ino)
	}
	// An address inside the filesystem that holds no inode fails on the magic.
	_, _, err := f.Stat(f.Root() + 200)
	assert.ErrorIs(t, err, xfs.ErrCorrupt)
}

func TestV5InodeIntegrity(t *testing.T) {
	e := disktest.NewXFS(disktest.XFSOpts{V5: true})
	e.WriteFile("f", []byte("hello"))
	img := e.Bytes()
	f := open(t, img)
	ino, err := lookup(f, "f")
	require.NoError(t, err)

	t.Run("checksum", func(t *testing.T) {
		bad := bytes.Clone(img)
		bad[e.InodeOffset("f")+0x38+7] ^= 1
		_, _, err := open(t, bad).Stat(ino)
		assert.ErrorIs(t, err, xfs.ErrCorrupt)
	})
	t.Run("inode number stored in the inode", func(t *testing.T) {
		bad := bytes.Clone(img)
		binary.BigEndian.PutUint64(bad[e.InodeOffset("f")+0x98:], ino+1)
		_, _, err := open(t, bad).Stat(ino)
		assert.ErrorIs(t, err, xfs.ErrCorrupt)
	})
	t.Run("large extent count flag without the feature", func(t *testing.T) {
		bad := bytes.Clone(img)
		bad[e.InodeOffset("f")+0x78+7] = 1 << 4
		_, _, err := open(t, bad).Stat(ino)
		assert.ErrorIs(t, err, xfs.ErrCorrupt)
	})
}

// Every way a directory block can lie.
func TestHostileDirectoryBlocks(t *testing.T) {
	build := func(v5 bool) (*disktest.XFS, []byte) {
		e := disktest.NewXFS(disktest.XFSOpts{V5: v5, Dirs: disktest.DirBlock})
		e.WriteFile("d/aa", []byte("x"))
		e.WriteFile("d/bb", []byte("x"))
		return e, e.Bytes()
	}
	// The first extent record of d starts the single directory block.
	blockOf := func(e *disktest.XFS, img []byte, core int) int {
		in := img[e.InodeOffset("d"):]
		l0, l1 := binary.BigEndian.Uint64(in[core:]), binary.BigEndian.Uint64(in[core+8:])
		fsb := (l0&0x1FF)<<43 | l1>>21
		return int((fsb>>11)*2048+fsb&2047) * 1024
	}
	tests := []struct {
		name  string
		v5    bool
		patch func(blk []byte)
		want  error
	}{
		{"unknown magic", false, func(b []byte) { b[0] = 'Z' }, xfs.ErrCorrupt},
		{"v5 magic on a v4 filesystem", false, func(b []byte) { binary.BigEndian.PutUint32(b, 0x58444233) }, xfs.ErrCorrupt},
		{"v4 magic on a v5 filesystem", true, func(b []byte) { binary.BigEndian.PutUint32(b, 0x58443242) }, xfs.ErrCorrupt},
		{"leaf count larger than the block", false, func(b []byte) { binary.BigEndian.PutUint32(b[len(b)-8:], 1<<30) }, xfs.ErrCorrupt},
		{"entry with a zero-length name", false, func(b []byte) { b[16+8] = 0 }, xfs.ErrCorrupt},
		{"entry running past the block", false, func(b []byte) { b[16+8] = 255 }, xfs.ErrCorrupt},
		{"entry pointing outside the filesystem", false, func(b []byte) { b[16] = 0x7F }, xfs.ErrCorrupt},
		{"unused entry of length zero", false, func(b []byte) { binary.BigEndian.PutUint16(b[16:], 0xFFFF); binary.BigEndian.PutUint16(b[18:], 0) }, xfs.ErrCorrupt},
		{"unused entry not a multiple of 8", false, func(b []byte) { binary.BigEndian.PutUint16(b[16:], 0xFFFF); binary.BigEndian.PutUint16(b[18:], 12) }, xfs.ErrCorrupt},
		{"unused entry past the end", false, func(b []byte) { binary.BigEndian.PutUint16(b[16:], 0xFFFF); binary.BigEndian.PutUint16(b[18:], 0xFFF8) }, xfs.ErrCorrupt},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e, img := build(tc.v5)
			core := 100
			if tc.v5 {
				core = 176
			}
			off := blockOf(e, img, core)
			tc.patch(img[off : off+1024])
			f := open(t, img)
			_, err := f.DirNames(e.Ino("d"))
			assert.ErrorIs(t, err, tc.want)
		})
	}
}

// An entry that starts in the last 8 bytes of a block has no room for its name
// length; the reader once indexed past the block.
func TestDirectoryEntryAtTheBlockEnd(t *testing.T) {
	e := disktest.NewXFS(disktest.XFSOpts{Dirs: disktest.DirLeaf})
	e.WriteFile("d/aa", []byte("x"))
	e.WriteFile("d/bb", []byte("x"))
	img := e.Bytes()
	in := img[e.InodeOffset("d"):]
	l0, l1 := binary.BigEndian.Uint64(in[100:]), binary.BigEndian.Uint64(in[108:])
	fsb := (l0&0x1FF)<<43 | l1>>21
	blk := img[int((fsb>>11)*2048+fsb&2047)*1024:][:1024]
	const used = 16 + 4*16 // header, ".", "..", "aa", "bb"
	binary.BigEndian.PutUint16(blk[used:], 0xFFFF)
	binary.BigEndian.PutUint16(blk[used+2:], 1016-used)
	_, err := open(t, img).DirNames(e.Ino("d"))
	assert.ErrorIs(t, err, xfs.ErrCorrupt)
}

func TestDirectoryBounds(t *testing.T) {
	t.Run("directory larger than the cap", func(t *testing.T) {
		e := disktest.NewXFS(disktest.XFSOpts{Dirs: disktest.DirLeaf})
		e.WriteFile("d/x", []byte("x"))
		img := e.Bytes()
		patchInode(e, img, "d", func(in []byte) { binary.BigEndian.PutUint64(in[0x38:], 1<<40) })
		_, err := open(t, img).DirNames(e.Ino("d"))
		assert.ErrorIs(t, err, xfs.ErrTooLarge)
	})
	t.Run("size not a multiple of the directory block", func(t *testing.T) {
		e := disktest.NewXFS(disktest.XFSOpts{Dirs: disktest.DirLeaf})
		e.WriteFile("d/x", []byte("x"))
		img := e.Bytes()
		patchInode(e, img, "d", func(in []byte) { binary.BigEndian.PutUint64(in[0x38:], 1000) })
		_, err := open(t, img).DirNames(e.Ino("d"))
		assert.ErrorIs(t, err, xfs.ErrCorrupt)
	})
	t.Run("size claims blocks the extents do not map", func(t *testing.T) {
		e := disktest.NewXFS(disktest.XFSOpts{Dirs: disktest.DirLeaf})
		e.WriteFile("d/x", []byte("x"))
		img := e.Bytes()
		patchInode(e, img, "d", func(in []byte) { binary.BigEndian.PutUint64(in[0x38:], 1<<26) })
		names, err := open(t, img).DirNames(e.Ino("d"))
		require.NoError(t, err)
		assert.Equal(t, []string{"x"}, names)
	})
	t.Run("more entries than the listing bound", func(t *testing.T) {
		e := disktest.NewXFS(disktest.XFSOpts{V5: true, BlockSize: 4096, AGBlocks: 4096, Dirs: disktest.DirLeaf})
		for i := 0; i < 5000; i++ {
			e.WriteFile("d/"+strconv.Itoa(i), nil)
		}
		names, err := open(t, e.Bytes()).DirNames(e.Ino("d"))
		require.NoError(t, err)
		assert.Len(t, names, 5000)
	})
}

// A btree whose child points back at its own block must end in ErrCorrupt.
func TestBtreeCycleAndDepth(t *testing.T) {
	build := func(v5 bool) (*disktest.XFS, []byte) {
		e := disktest.NewXFS(disktest.XFSOpts{V5: v5, MaxRecs: 2, AGBlocks: 4096})
		e.WriteFileOpts("f", pattern(30*1024, 2), disktest.XFSFileOpts{Fragmented: true})
		return e, e.Bytes()
	}
	for _, v5 := range []bool{false, true} {
		core, hdr := 100, 24
		if v5 {
			core, hdr = 176, 72
		}
		rootChild := func(img []byte, e *disktest.XFS) (fsb uint64, blk int) {
			in := img[e.InodeOffset("f"):]
			maxrecs := (256 - core - 4) / 16
			fsb = binary.BigEndian.Uint64(in[core+4+maxrecs*8:])
			return fsb, int((fsb>>12)*4096+fsb&4095) * 1024
		}
		t.Run("child points at its own block, v5="+strconv.FormatBool(v5), func(t *testing.T) {
			e, img := build(v5)
			if v5 {
				t.Skip("v5 inodes carry a checksum the patch would break")
			}
			fsb, blk := rootChild(img, e)
			level := binary.BigEndian.Uint16(img[blk+4:])
			require.GreaterOrEqual(t, level, uint16(1), "needs an interior node")
			maxrecs := (1024 - hdr) / 16
			binary.BigEndian.PutUint64(img[blk+hdr+maxrecs*8:], fsb)
			f := open(t, img)
			_, err := readFile(f, "f")
			assert.ErrorIs(t, err, xfs.ErrCorrupt)
		})
		t.Run("child level does not decrease, v5="+strconv.FormatBool(v5), func(t *testing.T) {
			if v5 {
				t.Skip("v5 inodes carry a checksum the patch would break")
			}
			e, img := build(v5)
			_, blk := rootChild(img, e)
			binary.BigEndian.PutUint16(img[blk+4:], 7)
			_, err := readFile(open(t, img), "f")
			assert.ErrorIs(t, err, xfs.ErrCorrupt)
		})
		t.Run("child with the wrong magic, v5="+strconv.FormatBool(v5), func(t *testing.T) {
			if v5 {
				t.Skip("v5 inodes carry a checksum the patch would break")
			}
			e, img := build(v5)
			_, blk := rootChild(img, e)
			img[blk] = 'Q'
			_, err := readFile(open(t, img), "f")
			assert.ErrorIs(t, err, xfs.ErrCorrupt)
		})
		t.Run("child claims more records than fit, v5="+strconv.FormatBool(v5), func(t *testing.T) {
			if v5 {
				t.Skip("v5 inodes carry a checksum the patch would break")
			}
			e, img := build(v5)
			_, blk := rootChild(img, e)
			binary.BigEndian.PutUint16(img[blk+6:], 0xFFFF)
			_, err := readFile(open(t, img), "f")
			assert.ErrorIs(t, err, xfs.ErrCorrupt)
		})
	}
}

func TestHostileSymlinkBlocks(t *testing.T) {
	long := strings.Repeat("a", 700)
	build := func() (*disktest.XFS, []byte) {
		e := disktest.NewXFS(disktest.XFSOpts{})
		e.Symlink("l", long)
		return e, e.Bytes()
	}
	e, img := build()
	f := open(t, img)
	got, err := f.ReadLink(e.Ino("l"))
	require.NoError(t, err)
	assert.Equal(t, long, got)

	t.Run("v5 block header lying about its slice", func(t *testing.T) {
		e := disktest.NewXFS(disktest.XFSOpts{V5: true, BlockSize: 512, InodeSize: 512, AGBlocks: 4096})
		e.Symlink("l", long)
		img := e.Bytes()
		in := img[e.InodeOffset("l"):]
		l0, l1 := binary.BigEndian.Uint64(in[176:]), binary.BigEndian.Uint64(in[184:])
		fsb := (l0&0x1FF)<<43 | l1>>21
		blk := int((fsb>>12)*4096+fsb&4095) * 512
		binary.BigEndian.PutUint32(img[blk+4:], 99)
		_, err := open(t, img).ReadLink(e.Ino("l"))
		assert.ErrorIs(t, err, xfs.ErrCorrupt)
	})
}
