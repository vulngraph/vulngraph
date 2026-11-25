package diskscan

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/disktest"
)

var debianNames = []string{"base-files", "bash", "libc6", "mount"}

const (
	debianRelease = "PRETTY_NAME=\"Debian GNU/Linux 12\"\nID=debian\nVERSION_ID=\"12\"\n"
	alpineRelease = "ID=alpine\nVERSION_ID=3.18.4\n"
	ubiRelease    = "ID=\"rhel\"\nVERSION_ID=\"9.8\"\n"
)

func pkginv(t *testing.T, rel ...string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(append([]string{"..", "pkginventory"}, rel...)...))
	require.NoError(t, err)
	return b
}

func rpmFixture(t *testing.T, name string) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(pkginv(t, "rpmdb", "testdata", name)))
	require.NoError(t, err)
	data, err := io.ReadAll(zr)
	require.NoError(t, err)
	return data
}

func bigExt4() disktest.Ext4Opts {
	return disktest.Ext4Opts{BlocksPerGroup: 2048, InodesPerGroup: 64}
}

func debianRoot(t *testing.T) *disktest.Ext4 {
	e := disktest.NewExt4(bigExt4())
	e.WriteFile("etc/os-release", []byte(debianRelease))
	e.WriteFile("var/lib/dpkg/status", pkginv(t, "testdata", "dpkg-status-debian12"))
	return e
}

func scan(t *testing.T, img []byte, lim Limits) DiskResult {
	t.Helper()
	res, err := ScanDisk(context.Background(), &disktest.Mem{Data: img}, lim)
	require.NoError(t, err)
	return res
}

func names(res DiskResult) []string {
	var out []string
	for _, p := range res.Packages {
		out = append(out, p.Name)
	}
	return out
}

func requireUnknown(t *testing.T, res DiskResult, gap string) {
	t.Helper()
	assert.False(t, res.InventoryKnown, "an unreadable disk must not look like a clean one")
	assert.Nil(t, res.Packages)
	assert.Equal(t, gap, res.Gap)
}

func TestScanDisk_Layouts(t *testing.T) {
	root := debianRoot(t).Bytes()
	boot := disktest.NewExt4(disktest.Ext4Opts{})
	boot.WriteFile("vmlinuz", []byte("kernel"))
	tests := []struct {
		name string
		img  []byte
	}{
		{"bare filesystem, no partition table", root},
		{"MBR, root only", disktest.MBRDisk(disktest.Part{Data: root, MBRType: 0x83})},
		{"GPT, root only", disktest.GPTDisk(disktest.Part{Data: root, GPTType: disktest.GUIDLinux})},
		{"GPT, boot then root", disktest.GPTDisk(
			disktest.Part{Data: boot.Bytes(), GPTType: disktest.GUIDLinux},
			disktest.Part{Data: root, GPTType: disktest.GUIDLinux})},
		{"MBR, swap and vfat ahead of root", disktest.MBRDisk(
			disktest.Part{Data: make([]byte, 4096), MBRType: 0x82},
			disktest.Part{Data: append([]byte("\xEB\x3C\x90MSDOS5.0"), make([]byte, 4096)...), MBRType: 0x0C},
			disktest.Part{Data: root, MBRType: 0x83})},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			res := scan(t, tc.img, Limits{})
			require.True(t, res.InventoryKnown, "gap %q", res.Gap)
			assert.Empty(t, res.Gap)
			assert.ElementsMatch(t, debianNames, names(res))
			assert.Equal(t, "Debian:12", res.Ecosystem)
			assert.True(t, res.LanguageGap, "language manifests are never walked on a disk")
		})
	}
}

func TestScanDisk_PackageManagers(t *testing.T) {
	t.Run("apk through a usr-merge lib symlink", func(t *testing.T) {
		e := disktest.NewExt4(bigExt4())
		e.WriteFile("etc/os-release", []byte(alpineRelease))
		e.WriteFile("usr/lib/apk/db/installed", pkginv(t, "testdata", "apk-installed-alpine318"))
		e.Symlink("lib", "usr/lib")
		res := scan(t, e.Bytes(), Limits{})
		require.True(t, res.InventoryKnown, res.Gap)
		assert.Equal(t, "Alpine:v3.18", res.Ecosystem)
		assert.Contains(t, names(res), "busybox")
	})
	t.Run("os-release behind a symlink, as on Debian", func(t *testing.T) {
		e := disktest.NewExt4(bigExt4())
		e.WriteFile("usr/lib/os-release", []byte(debianRelease))
		e.Symlink("etc/os-release", "../usr/lib/os-release")
		e.WriteFile("var/lib/dpkg/status", pkginv(t, "testdata", "dpkg-status-debian12"))
		res := scan(t, e.Bytes(), Limits{})
		require.True(t, res.InventoryKnown, res.Gap)
		assert.Equal(t, "Debian:12", res.Ecosystem)
	})
	t.Run("distroless status.d", func(t *testing.T) {
		e := disktest.NewExt4(bigExt4())
		e.WriteFile("usr/lib/os-release", []byte(debianRelease))
		e.WriteFile("var/lib/dpkg/status.d/libc6", pkginv(t, "testdata", "distroless", "var", "lib", "dpkg", "status.d", "libc6"))
		e.WriteFile("var/lib/dpkg/status.d/libc6.md5sums", []byte("ignored"))
		res := scan(t, e.Bytes(), Limits{})
		require.True(t, res.InventoryKnown, res.Gap)
		assert.Equal(t, []string{"libc6"}, names(res))
	})
	rpmTests := []struct {
		name, release, fixture, dbPath, eco string
		legacy                              bool
	}{
		{"rpm sqlite at the classic path", ubiRelease, "ubi9-minimal.rpmdb.sqlite.gz", "var/lib/rpm/rpmdb.sqlite", "Red Hat:9", false},
		{"rpm sqlite, legacy block map", ubiRelease, "ubi9-minimal.rpmdb.sqlite.gz", "var/lib/rpm/rpmdb.sqlite", "Red Hat:9", true},
		{"rpm Berkeley DB", "ID=\"amzn\"\nVERSION_ID=\"2\"\n", "amazonlinux2.Packages.gz", "var/lib/rpm/Packages", "Amazon Linux:2", false},
		{"rpm ndb under sysimage", "ID=\"opensuse-leap\"\nVERSION_ID=\"15.6\"\n", "opensuse-leap15.6.Packages.db.gz", "usr/lib/sysimage/rpm/Packages.db", "openSUSE:Leap 15.6", false},
	}
	for _, tc := range rpmTests {
		t.Run(tc.name, func(t *testing.T) {
			o := bigExt4()
			o.Legacy = tc.legacy
			o.BlocksPerGroup = 4096
			e := disktest.NewExt4(o)
			e.WriteFile("etc/os-release", []byte(tc.release))
			e.WriteFile(tc.dbPath, rpmFixture(t, tc.fixture))
			res := scan(t, e.Bytes(), Limits{})
			require.True(t, res.InventoryKnown, res.Gap)
			assert.Equal(t, tc.eco, res.Ecosystem)
			assert.NotEmpty(t, res.Packages)
		})
	}
	t.Run("rpm database reached through a /var/lib/rpm symlink", func(t *testing.T) {
		o := bigExt4()
		o.BlocksPerGroup = 4096
		e := disktest.NewExt4(o)
		e.WriteFile("etc/os-release", []byte(ubiRelease))
		e.WriteFile("usr/lib/sysimage/rpm/rpmdb.sqlite", rpmFixture(t, "ubi9-minimal.rpmdb.sqlite.gz"))
		e.Symlink("var/lib/rpm", "../../usr/lib/sysimage/rpm")
		res := scan(t, e.Bytes(), Limits{})
		require.True(t, res.InventoryKnown, res.Gap)
		assert.NotEmpty(t, res.Packages)
	})
}

func TestScanDisk_LanguageManifestsAreNeverRead(t *testing.T) {
	e := debianRoot(t)
	e.WriteFile("srv/app/node_modules/left-pad/package.json", []byte(`{"name":"left-pad","version":"1.3.0"}`))
	e.WriteFile("srv/app/requirements.txt", []byte("flask==2.0.0\n"))
	res := scan(t, e.Bytes(), Limits{})
	require.True(t, res.InventoryKnown)
	for _, p := range res.Packages {
		assert.NotContains(t, []string{"npm", "PyPI"}, p.Ecosystem)
	}
	assert.True(t, res.LanguageGap)
}

// A zero-package result is known only when the package database was read.
func TestScanDisk_EmptyIsKnownOnlyWhenTheDatabaseWasRead(t *testing.T) {
	t.Run("database read and empty, no OS claimed", func(t *testing.T) {
		e := disktest.NewExt4(bigExt4())
		e.WriteFile("var/lib/dpkg/status", nil)
		res := scan(t, e.Bytes(), Limits{})
		assert.True(t, res.InventoryKnown)
		assert.Empty(t, res.Packages)
	})
	t.Run("os-release names a distribution but the database parses to nothing", func(t *testing.T) {
		e := disktest.NewExt4(bigExt4())
		e.WriteFile("etc/os-release", []byte(debianRelease))
		e.WriteFile("var/lib/dpkg/status", nil)
		requireUnknown(t, scan(t, e.Bytes(), Limits{}), GapReadError)
	})
}

func TestDegradedIsUnknown(t *testing.T) {
	root := func() *disktest.Ext4 { return debianRoot(t) }
	luks := append([]byte("LUKS\xba\xbe\x00\x01"), make([]byte, 8192)...)

	tests := []struct {
		name string
		img  func() []byte
		lim  Limits
		gap  string
	}{
		{"LUKS partition only", func() []byte {
			return disktest.GPTDisk(disktest.Part{Data: luks, GPTType: disktest.GUIDLinux})
		}, Limits{}, GapEncryptedNoKey},
		{"LUKS on the whole disk", func() []byte { return luks }, Limits{}, GapEncryptedNoKey},
		{"LVM physical volume only", func() []byte {
			return disktest.MBRDisk(disktest.Part{Data: make([]byte, 8192), MBRType: 0x8E})
		}, Limits{}, GapUnsupportedPartition},
		{"RAID member only", func() []byte {
			return disktest.GPTDisk(disktest.Part{Data: make([]byte, 8192), GPTType: disktest.GUIDRAID})
		}, Limits{}, GapUnsupportedPartition},
		{"readable /boot beside an LVM root", func() []byte {
			boot := disktest.NewExt4(disktest.Ext4Opts{})
			boot.WriteFile("vmlinuz", []byte("k"))
			return disktest.MBRDisk(
				disktest.Part{Data: boot.Bytes(), MBRType: 0x83},
				disktest.Part{Data: make([]byte, 8192), MBRType: 0x8E})
		}, Limits{}, GapUnsupportedPartition},
		{"corrupt GPT", func() []byte {
			img := disktest.GPTDisk(disktest.Part{Data: root().Bytes(), GPTType: disktest.GUIDLinux})
			img[512+20] ^= 0xFF
			img[len(img)-512+20] ^= 0xFF
			return img
		}, Limits{}, GapUnsupportedPartition},
		{"XFS superblock that is corrupt", func() []byte {
			x := make([]byte, 16384)
			copy(x, "XFSB")
			return disktest.GPTDisk(disktest.Part{Data: x, GPTType: disktest.GUIDLinux})
		}, Limits{}, GapReadError},
		{"XFS with a realtime volume", func() []byte {
			x := disktest.NewXFS(disktest.XFSOpts{}).Bytes()
			binary.BigEndian.PutUint64(x[0x10:], 100)
			return disktest.GPTDisk(disktest.Part{Data: x, GPTType: disktest.GUIDLinux})
		}, Limits{}, GapUnsupportedFS},
		{"blank disk", func() []byte { return make([]byte, 1<<16) }, Limits{}, GapUnsupportedFS},
		{"ext4 with inline data", func() []byte {
			return disktest.NewExt4(disktest.Ext4Opts{Incompat: 0x8000}).Bytes()
		}, Limits{}, GapUnsupportedFS},
		{"fscrypt ext4", func() []byte {
			return disktest.NewExt4(disktest.Ext4Opts{Incompat: 0x10000}).Bytes()
		}, Limits{}, GapUnsupportedFS},
		{"os-release but no package database", func() []byte {
			e := disktest.NewExt4(bigExt4())
			e.WriteFile("etc/os-release", []byte(debianRelease))
			return e.Bytes()
		}, Limits{}, GapReadError},
		{"rpm database that is not a database", func() []byte {
			e := disktest.NewExt4(bigExt4())
			e.WriteFile("etc/os-release", []byte(ubiRelease))
			e.WriteFile("var/lib/rpm/rpmdb.sqlite", bytes.Repeat([]byte("garbage"), 500))
			return e.Bytes()
		}, Limits{}, GapReadError},
		{"rpm write-ahead log with frames", func() []byte {
			e := disktest.NewExt4(bigExt4())
			e.WriteFile("etc/os-release", []byte(ubiRelease))
			e.WriteFile("var/lib/rpm/rpmdb.sqlite", rpmFixture(t, "ubi9-minimal.rpmdb.sqlite.gz"))
			e.WriteFile("var/lib/rpm/rpmdb.sqlite-wal", make([]byte, 4096))
			return e.Bytes()
		}, Limits{}, GapReadError},
		{"package database is a symlink loop", func() []byte {
			e := disktest.NewExt4(bigExt4())
			e.WriteFile("etc/os-release", []byte(debianRelease))
			e.Symlink("var/lib/dpkg/status", "status")
			return e.Bytes()
		}, Limits{}, GapReadError},
		{"package database is a directory", func() []byte {
			e := disktest.NewExt4(bigExt4())
			e.WriteFile("etc/os-release", []byte(debianRelease))
			e.Mkdir("var/lib/dpkg/status")
			return e.Bytes()
		}, Limits{}, GapReadError},
		{"package database over the per-file cap", func() []byte { return root().Bytes() }, Limits{MaxFileBytes: 100}, GapOverCap},
		{"package database over the total cap", func() []byte { return root().Bytes() }, Limits{MaxTotalBytes: 100}, GapOverCap},
		{"disk reads over the byte budget", func() []byte { return root().Bytes() }, Limits{MaxBytesRead: 2000}, GapOverCap},
		{"volume over the size cap", func() []byte { return root().Bytes() }, Limits{MaxVolumeBytes: 1024}, GapOverCap},
		{"empty volume", func() []byte { return nil }, Limits{}, GapReadError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requireUnknown(t, scan(t, tc.img(), tc.lim), tc.gap)
		})
	}
}

func TestDegradedIsUnknown_UnreadableBlocks(t *testing.T) {
	img := debianRoot(t).Bytes()
	tests := []struct {
		name string
		rng  disktest.Range
	}{
		{"superblock", disktest.Range{Off: 1024, Len: 1024}},
		{"inode table", disktest.Range{Off: 3 * 1024, Len: 8 * 1024}},
		{"file data", disktest.Range{Off: 16 * 1024, Len: int64(len(img)) - 16*1024}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			src := &disktest.Mem{Data: img, Err: ErrBlockUnreadable, Unreadable: []disktest.Range{tc.rng}}
			res, err := ScanDisk(context.Background(), src, Limits{})
			require.NoError(t, err)
			requireUnknown(t, res, GapReadError)
		})
	}
	t.Run("partition table", func(t *testing.T) {
		disk := disktest.GPTDisk(disktest.Part{Data: img, GPTType: disktest.GUIDLinux})
		src := &disktest.Mem{Data: disk, Err: ErrBlockUnreadable, Unreadable: []disktest.Range{{Off: 512, Len: 512}}}
		res, err := ScanDisk(context.Background(), src, Limits{})
		require.NoError(t, err)
		requireUnknown(t, res, GapReadError)
	})
}

func TestScanDisk_PartialGoodRootBeatsUnreadableNeighbour(t *testing.T) {
	root := debianRoot(t).Bytes()
	junk := make([]byte, 8192)
	disk := disktest.MBRDisk(
		disktest.Part{Data: junk, MBRType: 0x83},
		disktest.Part{Data: root, MBRType: 0x83})
	res := scan(t, disk, Limits{})
	assert.True(t, res.InventoryKnown)
}

func TestScanDisk_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ScanDisk(ctx, &disktest.Mem{Data: debianRoot(t).Bytes()}, Limits{})
	assert.ErrorIs(t, err, context.Canceled)
}

func TestScanDisk_HostileSizesStayBounded(t *testing.T) {
	e := debianRoot(t)
	img := e.Bytes()
	// Make /var/lib/dpkg/status claim 2^45 bytes: the file cap must stop it.
	tableBlock := 3 * 1024
	for ino := 11; ino < 20; ino++ {
		off := tableBlock + (ino-1)*256
		if binary.LittleEndian.Uint32(img[off+4:]) == uint32(len(pkginv(t, "testdata", "dpkg-status-debian12"))) {
			binary.LittleEndian.PutUint32(img[off+0x6C:], 1<<13)
		}
	}
	requireUnknown(t, scan(t, img, Limits{}), GapOverCap)
}

func TestPackageDBUnreadMatchesAsset(t *testing.T) {
	assert.Equal(t, asset.CVEGapPackageDBUnread, packageDBUnreadReason)
}

func TestDefaultsApplyToZeroLimits(t *testing.T) {
	l := Limits{}.withDefaults()
	assert.Positive(t, l.MaxVolumeBytes)
	assert.Positive(t, l.MaxBytesRead)
	assert.Positive(t, l.MaxFileBytes)
	assert.Positive(t, l.MaxTotalBytes)
	assert.Equal(t, Limits{MaxVolumeBytes: 1, MaxBytesRead: 2, MaxFileBytes: 3, MaxTotalBytes: 4},
		Limits{MaxVolumeBytes: 1, MaxBytesRead: 2, MaxFileBytes: 3, MaxTotalBytes: 4}.withDefaults())
}
