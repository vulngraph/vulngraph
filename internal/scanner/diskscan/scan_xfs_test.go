package diskscan

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/disktest"
)

func xfsOpts(v5 bool) disktest.XFSOpts {
	return disktest.XFSOpts{V5: v5, AGBlocks: 8192}
}

func TestScanDisk_XFSRoots(t *testing.T) {
	tests := []struct {
		name string
		opts disktest.XFSOpts
		file disktest.XFSFileOpts
	}{
		{"v4, extent list", xfsOpts(false), disktest.XFSFileOpts{}},
		{"v5, extent list", xfsOpts(true), disktest.XFSFileOpts{}},
		{"v5, 4k blocks", disktest.XFSOpts{V5: true, BlockSize: 4096, InodeSize: 512, AGBlocks: 2048}, disktest.XFSFileOpts{}},
		{"v4, fragmented btree-mapped database", xfsOpts(false), disktest.XFSFileOpts{Fragmented: true, Btree: true}},
		{"v5, fragmented btree-mapped database", xfsOpts(true), disktest.XFSFileOpts{Fragmented: true, Btree: true}},
	}
	for _, tc := range tests {
		t.Run("rpm sqlite, "+tc.name, func(t *testing.T) {
			e := disktest.NewXFS(tc.opts)
			e.WriteFile("etc/os-release", []byte(ubiRelease))
			e.WriteFileOpts("usr/lib/sysimage/rpm/rpmdb.sqlite", rpmFixture(t, "ubi9-minimal.rpmdb.sqlite.gz"), tc.file)
			e.Symlink("var/lib/rpm", "../../usr/lib/sysimage/rpm")
			e.Symlink("lib", "usr/lib")
			res := scan(t, disktest.GPTDisk(disktest.Part{Data: e.Bytes(), GPTType: disktest.GUIDLinux}), Limits{})
			require.True(t, res.InventoryKnown, res.Gap)
			assert.Equal(t, "Red Hat:9", res.Ecosystem)
			assert.NotEmpty(t, res.Packages)
		})
	}

	t.Run("rpm Berkeley DB on an Amazon Linux root, XFS beside an ext4 /boot", func(t *testing.T) {
		boot := disktest.NewExt4(disktest.Ext4Opts{})
		boot.WriteFile("vmlinuz", []byte("k"))
		e := disktest.NewXFS(xfsOpts(false))
		e.WriteFile("etc/os-release", []byte("ID=\"amzn\"\nVERSION_ID=\"2\"\n"))
		e.WriteFile("var/lib/rpm/Packages", rpmFixture(t, "amazonlinux2.Packages.gz"))
		res := scan(t, disktest.MBRDisk(
			disktest.Part{Data: boot.Bytes(), MBRType: 0x83},
			disktest.Part{Data: e.Bytes(), MBRType: 0x83}), Limits{})
		require.True(t, res.InventoryKnown, res.Gap)
		assert.Equal(t, "Amazon Linux:2", res.Ecosystem)
		assert.NotEmpty(t, res.Packages)
	})

	t.Run("dpkg on a bare XFS filesystem", func(t *testing.T) {
		e := disktest.NewXFS(xfsOpts(true))
		e.WriteFile("etc/os-release", []byte(debianRelease))
		e.WriteFile("var/lib/dpkg/status", pkginv(t, "testdata", "dpkg-status-debian12"))
		res := scan(t, e.Bytes(), Limits{})
		require.True(t, res.InventoryKnown, res.Gap)
		assert.ElementsMatch(t, debianNames, names(res))
	})
}

func TestScanDisk_XFSDegradedIsUnknown(t *testing.T) {
	rpmRoot := func(o disktest.XFSOpts) *disktest.XFS {
		e := disktest.NewXFS(o)
		e.WriteFile("etc/os-release", []byte(ubiRelease))
		e.WriteFile("var/lib/rpm/rpmdb.sqlite", rpmFixture(t, "ubi9-minimal.rpmdb.sqlite.gz"))
		return e
	}
	t.Run("blocks of the database are unreadable", func(t *testing.T) {
		img := rpmRoot(xfsOpts(false)).Bytes()
		src := &disktest.Mem{Data: img, Err: ErrBlockUnreadable, Unreadable: []disktest.Range{{Off: 16 * 1024, Len: int64(len(img)) - 16*1024}}}
		res, err := ScanDisk(context.Background(), src, Limits{})
		require.NoError(t, err)
		requireUnknown(t, res, GapReadError)
	})
	t.Run("superblock unreadable", func(t *testing.T) {
		img := rpmRoot(xfsOpts(true)).Bytes()
		src := &disktest.Mem{Data: img, Err: ErrBlockUnreadable, Unreadable: []disktest.Range{{Off: 0, Len: 512}}}
		res, err := ScanDisk(context.Background(), src, Limits{})
		require.NoError(t, err)
		requireUnknown(t, res, GapReadError)
	})
	t.Run("corrupt inode of the database", func(t *testing.T) {
		e := rpmRoot(xfsOpts(false))
		img := e.Bytes()
		img[e.InodeOffset("var/lib/rpm/rpmdb.sqlite")] = 0
		requireUnknown(t, scan(t, img, Limits{}), GapReadError)
	})
	t.Run("v5 superblock checksum", func(t *testing.T) {
		img := rpmRoot(xfsOpts(true)).Bytes()
		img[0x70] ^= 1
		requireUnknown(t, scan(t, img, Limits{}), GapReadError)
	})
	t.Run("unsupported features", func(t *testing.T) {
		for _, o := range []disktest.XFSOpts{{V5: true, Incompat: 0x1000}, {V5: true, Incompat: 0x10}} {
			o.AGBlocks = 8192
			requireUnknown(t, scan(t, rpmRoot(o).Bytes(), Limits{}), GapUnsupportedFS)
		}
	})
	t.Run("over the byte budget", func(t *testing.T) {
		requireUnknown(t, scan(t, rpmRoot(xfsOpts(false)).Bytes(), Limits{MaxBytesRead: 4000}), GapOverCap)
	})
	t.Run("os-release but no package database", func(t *testing.T) {
		e := disktest.NewXFS(xfsOpts(false))
		e.WriteFile("etc/os-release", []byte(ubiRelease))
		requireUnknown(t, scan(t, e.Bytes(), Limits{}), GapReadError)
	})
	t.Run("context cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := ScanDisk(ctx, &disktest.Mem{Data: rpmRoot(xfsOpts(false)).Bytes()}, Limits{})
		assert.ErrorIs(t, err, context.Canceled)
	})
}
