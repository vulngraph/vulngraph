package ext4_test

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
	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/ext4"
)

var errUnreadable = errors.New("unreadable")

func open(t *testing.T, img []byte) *ext4.FS {
	t.Helper()
	f, err := ext4.Open(bytes.NewReader(img), int64(len(img)))
	require.NoError(t, err)
	return f
}

func lookup(f *ext4.FS, path string) (uint64, error) {
	ino := f.Root()
	for _, c := range strings.Split(path, "/") {
		var err error
		if ino, err = f.Lookup(ino, c); err != nil {
			return 0, err
		}
	}
	return ino, nil
}

func readFile(f *ext4.FS, path string) ([]byte, error) {
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

func TestReadsFilesAcrossLayouts(t *testing.T) {
	layouts := map[string]disktest.Ext4Opts{
		"1k extents":        {},
		"4k extents":        {BlockSize: 4096, BlocksPerGroup: 128, InodesPerGroup: 16},
		"1k legacy map":     {Legacy: true},
		"4k legacy map":     {Legacy: true, BlockSize: 4096, BlocksPerGroup: 128, InodesPerGroup: 16},
		"64bit":             {Bit64: true},
		"htree directories": {HTreeDirs: true},
		"flex_bg and MMP":   {Incompat: 0x200 | 0x100 | 0x4},
	}
	for name, o := range layouts {
		t.Run(name, func(t *testing.T) {
			e := disktest.NewExt4(o)
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

func TestMultiGroupAndManyEntries(t *testing.T) {
	e := disktest.NewExt4(disktest.Ext4Opts{BlocksPerGroup: 256, InodesPerGroup: 32})
	want := map[string][]byte{}
	for i := 0; i < 150; i++ {
		name := "etc/conf" + strings.Repeat("x", i%40) + string(rune('a'+i%26)) + "-" + strconv.Itoa(i)
		want[name] = pattern(40+i, byte(i))
		e.WriteFile(name, want[name])
	}
	f := open(t, e.Bytes())
	for name, data := range want {
		got, err := readFile(f, name)
		require.NoError(t, err, name)
		assert.Equal(t, data, got, name)
	}
	etc, err := lookup(f, "etc")
	require.NoError(t, err)
	names, err := f.DirNames(etc)
	require.NoError(t, err)
	assert.Len(t, names, 150)
}

func TestExtentShapes(t *testing.T) {
	data := pattern(9*1024+100, 9)
	tests := []struct {
		name string
		opts disktest.FileOpts
		want func() []byte
	}{
		{"fragmented needs an index leaf", disktest.FileOpts{Fragmented: true}, func() []byte { return data }},
		{"forced index node", disktest.FileOpts{ForceIndex: true}, func() []byte { return data }},
		{"leading hole reads as zeros", disktest.FileOpts{HoleBlocks: 5}, func() []byte {
			return append(make([]byte, 5*1024), data...)
		}},
		{"uninitialised extents read as zeros", disktest.FileOpts{Uninit: true}, func() []byte { return make([]byte, len(data)) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := disktest.NewExt4(disktest.Ext4Opts{})
			e.WriteFileOpts("f", data, tc.opts)
			got, err := readFile(open(t, e.Bytes()), "f")
			require.NoError(t, err)
			assert.Equal(t, tc.want(), got)
		})
	}
}

func TestLegacyHoleReadsAsZeros(t *testing.T) {
	e := disktest.NewExt4(disktest.Ext4Opts{Legacy: true})
	data := pattern(2000, 1)
	e.WriteFileOpts("f", data, disktest.FileOpts{HoleBlocks: 20})
	got, err := readFile(open(t, e.Bytes()), "f")
	require.NoError(t, err)
	assert.Equal(t, append(make([]byte, 20*1024), data...), got)
}

func TestSymlinks(t *testing.T) {
	long := "/" + strings.Repeat("d/", 40) + "target"
	e := disktest.NewExt4(disktest.Ext4Opts{})
	e.Symlink("fast", "usr/lib/os-release")
	e.Symlink("slow", long)
	f := open(t, e.Bytes())

	ino, err := lookup(f, "fast")
	require.NoError(t, err)
	got, err := f.ReadLink(ino)
	require.NoError(t, err)
	assert.Equal(t, "usr/lib/os-release", got)

	ino, err = lookup(f, "slow")
	require.NoError(t, err)
	got, err = f.ReadLink(ino)
	require.NoError(t, err)
	assert.Equal(t, long, got)
}

func TestLookupMissingAndNotADirectory(t *testing.T) {
	e := disktest.NewExt4(disktest.Ext4Opts{})
	e.WriteFile("a/file", []byte("x"))
	f := open(t, e.Bytes())
	_, err := lookup(f, "a/missing")
	assert.ErrorIs(t, err, fs.ErrNotExist)
	_, err = lookup(f, "a/file/below")
	assert.ErrorIs(t, err, fs.ErrNotExist)
	_, err = f.Lookup(f.Root(), "a/b")
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestOpenRejects(t *testing.T) {
	base := func() []byte {
		e := disktest.NewExt4(disktest.Ext4Opts{})
		e.WriteFile("f", []byte("x"))
		return e.Bytes()
	}
	patch := func(off int, v uint32) []byte {
		img := base()
		binary.LittleEndian.PutUint32(img[1024+off:], v)
		return img
	}
	tests := []struct {
		name string
		img  []byte
		want error
	}{
		{"all zeros", make([]byte, 1<<16), ext4.ErrNotExt4},
		{"too short for a superblock", make([]byte, 1500), ext4.ErrNotExt4},
		{"inline data", disktest.NewExt4(disktest.Ext4Opts{Incompat: 0x8000}).Bytes(), ext4.ErrUnsupported},
		{"encryption", disktest.NewExt4(disktest.Ext4Opts{Incompat: 0x10000}).Bytes(), ext4.ErrUnsupported},
		{"casefold", disktest.NewExt4(disktest.Ext4Opts{Incompat: 0x20000}).Bytes(), ext4.ErrUnsupported},
		{"meta_bg", disktest.NewExt4(disktest.Ext4Opts{Incompat: 0x10}).Bytes(), ext4.ErrUnsupported},
		{"compression", disktest.NewExt4(disktest.Ext4Opts{Incompat: 0x1}).Bytes(), ext4.ErrUnsupported},
		{"bigalloc", disktest.NewExt4(disktest.Ext4Opts{RoCompat: 0x200}).Bytes(), ext4.ErrUnsupported},
		{"block size shift 31", patch(0x18, 31), ext4.ErrCorrupt},
		{"zero blocks per group", patch(0x20, 0), ext4.ErrCorrupt},
		{"huge blocks per group", patch(0x20, 1<<30), ext4.ErrCorrupt},
		{"zero inodes per group", patch(0x28, 0), ext4.ErrCorrupt},
		{"filesystem larger than the device", patch(0x4, 1<<30), ext4.ErrCorrupt},
		{"inode count beyond the groups", patch(0x0, 1<<30), ext4.ErrCorrupt},
		{"first data block past the end", patch(0x14, 1<<20), ext4.ErrCorrupt},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ext4.Open(bytes.NewReader(tc.img), int64(len(tc.img)))
			assert.ErrorIs(t, err, tc.want)
		})
	}
}

func TestOpenRejectsBadInodeSizeAndDescriptor(t *testing.T) {
	img := disktest.NewExt4(disktest.Ext4Opts{}).Bytes()
	binary.LittleEndian.PutUint16(img[1024+0x58:], 100)
	_, err := ext4.Open(bytes.NewReader(img), int64(len(img)))
	assert.ErrorIs(t, err, ext4.ErrCorrupt)

	img = disktest.NewExt4(disktest.Ext4Opts{Bit64: true}).Bytes()
	binary.LittleEndian.PutUint16(img[1024+0xFE:], 8)
	_, err = ext4.Open(bytes.NewReader(img), int64(len(img)))
	assert.ErrorIs(t, err, ext4.ErrCorrupt)
}

// inodeAt is the byte offset of an inode in a 1 KiB-block, single-group image
// built by disktest: the inode table follows the superblock and one
// descriptor block.
func inodeAt(ino int) int { return 3*1024 + (ino-1)*256 }

func TestHostileInodes(t *testing.T) {
	build := func() (*disktest.Ext4, []byte) {
		e := disktest.NewExt4(disktest.Ext4Opts{})
		e.WriteFile("file", pattern(3000, 5)) // inode 11
		e.Mkdir("dir")                        // inode 12
		e.Symlink("link", "x")                // inode 13
		return e, e.Bytes()
	}
	le := binary.LittleEndian
	tests := []struct {
		name   string
		mutate func(img []byte)
		do     func(f *ext4.FS) error
		want   error
	}{
		{"inline data inode", func(img []byte) { le.PutUint32(img[inodeAt(11)+0x20:], 0x10000000) },
			func(f *ext4.FS) error { _, err := readFile(f, "file"); return err }, ext4.ErrUnsupported},
		{"encrypted inode", func(img []byte) { le.PutUint32(img[inodeAt(11)+0x20:], 0x80800) },
			func(f *ext4.FS) error { _, err := readFile(f, "file"); return err }, ext4.ErrUnsupported},
		{"bad extent magic", func(img []byte) { img[inodeAt(11)+0x28] = 0 },
			func(f *ext4.FS) error { _, err := readFile(f, "file"); return err }, ext4.ErrCorrupt},
		{"extent depth beyond the limit", func(img []byte) { le.PutUint16(img[inodeAt(11)+0x28+6:], 9) },
			func(f *ext4.FS) error { _, err := readFile(f, "file"); return err }, ext4.ErrCorrupt},
		{"more entries than fit", func(img []byte) { le.PutUint16(img[inodeAt(11)+0x28+2:], 5) },
			func(f *ext4.FS) error { _, err := readFile(f, "file"); return err }, ext4.ErrCorrupt},
		{"extent past the filesystem", func(img []byte) { le.PutUint32(img[inodeAt(11)+0x28+12+8:], 1<<30) },
			func(f *ext4.FS) error { _, err := readFile(f, "file"); return err }, ext4.ErrCorrupt},
		{"index node pointing at itself", func(img []byte) {
			b := img[inodeAt(11)+0x28:]
			le.PutUint16(b[6:], 1)
			le.PutUint32(b[12:], 0)
			le.PutUint32(b[16:], 2) // block 2 holds the group descriptors, not an extent node
		}, func(f *ext4.FS) error { _, err := readFile(f, "file"); return err }, ext4.ErrCorrupt},
		{"logical block beyond the extent range", func(img []byte) { le.PutUint32(img[inodeAt(11)+0x6C:], 1<<13) },
			func(f *ext4.FS) error {
				ino, _ := lookup(f, "file")
				buf := make([]byte, 4096)
				_, err := f.ReadAt(ino, buf, 1<<44)
				return err
			}, ext4.ErrCorrupt},
		{"directory larger than the bound", func(img []byte) { le.PutUint32(img[inodeAt(12)+4:], 1<<30) },
			func(f *ext4.FS) error { _, err := f.DirNames(12); return err }, ext4.ErrTooLarge},
		{"symlink larger than a path", func(img []byte) {
			le.PutUint32(img[inodeAt(13)+4:], 1<<20)
			le.PutUint32(img[inodeAt(13)+0x20:], 0x80000)
		}, func(f *ext4.FS) error { _, err := f.ReadLink(13); return err }, ext4.ErrCorrupt},
		{"inode number out of range", func(img []byte) {}, func(f *ext4.FS) error { _, _, err := f.Stat(1 << 30); return err }, ext4.ErrCorrupt},
		{"inode zero", func(img []byte) {}, func(f *ext4.FS) error { _, _, err := f.Stat(0); return err }, ext4.ErrCorrupt},
		{"zero-length directory entry", func(img []byte) {
			// the root directory's first data block is the first allocated block
			root := int(le.Uint32(img[inodeAt(2)+0x28+20:])) * 1024
			le.PutUint16(img[root+4:], 0)
		}, func(f *ext4.FS) error { _, err := f.Lookup(f.Root(), "zzz"); return err }, ext4.ErrCorrupt},
		{"directory entry overrunning the block", func(img []byte) {
			root := int(le.Uint32(img[inodeAt(2)+0x28+20:])) * 1024
			le.PutUint16(img[root+4:], 4000)
		}, func(f *ext4.FS) error { _, err := f.Lookup(f.Root(), "zzz"); return err }, ext4.ErrCorrupt},
		{"directory entry naming an inode past the table", func(img []byte) {
			root := int(le.Uint32(img[inodeAt(2)+0x28+20:])) * 1024
			le.PutUint32(img[root+24:], 1<<30)
		}, func(f *ext4.FS) error { _, err := f.Lookup(f.Root(), "zzz"); return err }, ext4.ErrCorrupt},
		{"inode table outside the filesystem", func(img []byte) { le.PutUint32(img[2*1024+8:], 1<<30) },
			func(f *ext4.FS) error { _, _, err := f.Stat(11); return err }, ext4.ErrCorrupt},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, img := build()
			tc.mutate(img)
			err := tc.do(open(t, img))
			assert.ErrorIs(t, err, tc.want)
		})
	}
}

func TestLegacyBlockMapHostile(t *testing.T) {
	e := disktest.NewExt4(disktest.Ext4Opts{Legacy: true})
	e.WriteFile("file", pattern(20*1024, 2)) // direct and single-indirect
	img := e.Bytes()
	le := binary.LittleEndian
	le.PutUint32(img[inodeAt(11)+0x28+12*4:], 1<<30) // indirect pointer past the fs
	_, err := readFile(open(t, img), "file")
	assert.ErrorIs(t, err, ext4.ErrCorrupt)

	img = e.Bytes()
	le.PutUint32(img[inodeAt(11)+0x28:], 1<<30) // direct pointer past the fs
	_, err = readFile(open(t, img), "file")
	assert.ErrorIs(t, err, ext4.ErrCorrupt)
}

func TestUnreadableBlocksSurface(t *testing.T) {
	e := disktest.NewExt4(disktest.Ext4Opts{})
	e.WriteFile("file", pattern(3000, 5))
	img := e.Bytes()
	mem := &disktest.Mem{Data: img, Err: errUnreadable}
	f, err := ext4.Open(mem, mem.Size())
	require.NoError(t, err)
	ino, err := lookup(f, "file")
	require.NoError(t, err)

	// the file's data blocks sit after the inode table; make that range unreadable
	mem.Unreadable = []disktest.Range{{Off: 20 * 1024, Len: int64(len(img)) - 20*1024}}
	_, err = f.ReadAt(ino, make([]byte, 3000), 0)
	assert.ErrorIs(t, err, errUnreadable)
	assert.NotErrorIs(t, err, ext4.ErrCorrupt)
}

func TestTruncatedImageNeverPanics(t *testing.T) {
	e := disktest.NewExt4(disktest.Ext4Opts{})
	e.WriteFile("a/b/c", pattern(5000, 1))
	img := e.Bytes()
	for cut := 0; cut < len(img); cut += 997 {
		part := img[:cut]
		f, err := ext4.Open(bytes.NewReader(part), int64(len(img))) // device claims full size, reads come up short
		if err != nil {
			continue
		}
		_, _ = readFile(f, "a/b/c")
	}
}

func TestHugeSparseSizeReadsZeros(t *testing.T) {
	e := disktest.NewExt4(disktest.Ext4Opts{})
	e.WriteFile("file", pattern(3000, 5))
	img := e.Bytes()
	binary.LittleEndian.PutUint32(img[inodeAt(11)+0x6C:], 1) // size 2^32+3000
	f := open(t, img)
	ino, err := lookup(f, "file")
	require.NoError(t, err)
	buf := bytes.Repeat([]byte{0xFF}, 4096)
	n, err := f.ReadAt(ino, buf, 1<<32)
	assert.Equal(t, 3000, n)
	assert.ErrorIs(t, err, io.EOF)
	assert.Equal(t, make([]byte, 3000), buf[:3000])
}
