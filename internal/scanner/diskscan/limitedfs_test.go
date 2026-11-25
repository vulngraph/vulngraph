package diskscan

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/disktest"
	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/ext4"
)

func limited(t *testing.T, e *disktest.Ext4, lim Limits) *LimitedFS {
	t.Helper()
	img := e.Bytes()
	f, err := ext4.Open(bytes.NewReader(img), int64(len(img)))
	require.NoError(t, err)
	return NewLimitedFS(context.Background(), f, lim)
}

func TestLimitedFS_ExposesOnlyTheAllowlist(t *testing.T) {
	e := disktest.NewExt4(disktest.Ext4Opts{})
	for _, p := range []string{
		"etc/os-release", "usr/lib/os-release", "etc/alpine-release", "var/lib/dpkg/status",
		"lib/apk/db/installed", "var/lib/rpm/rpmdb.sqlite", "var/lib/rpm/rpmdb.sqlite-wal", "usr/lib/sysimage/rpm/Packages.db",
		"var/lib/dpkg/status.d/libc6", "package-lock.json",
		"etc/shadow", "root/.ssh/id_rsa", "var/lib/rpm/sub/Packages", "srv/package-lock.json",
		"srv/node_modules/x/package.json", "var/lib/dpkg/info/bash.list", "var/lib/dpkg/status.bak",
	} {
		e.WriteFile(p, []byte("content of "+p))
	}
	l := limited(t, e, Limits{})

	for _, p := range []string{
		"etc/os-release", "usr/lib/os-release", "etc/alpine-release", "var/lib/dpkg/status",
		"lib/apk/db/installed", "var/lib/rpm/rpmdb.sqlite", "var/lib/rpm/rpmdb.sqlite-wal",
		"usr/lib/sysimage/rpm/Packages.db", "var/lib/dpkg/status.d/libc6", "package-lock.json",
	} {
		b, err := fs.ReadFile(l, p)
		require.NoError(t, err, p)
		assert.Equal(t, "content of "+p, string(b))
	}
	for _, p := range []string{
		"etc/shadow", "root/.ssh/id_rsa", "var/lib/rpm/sub/Packages", "srv/package-lock.json",
		"srv/node_modules/x/package.json", "var/lib/dpkg/info/bash.list", "var/lib/dpkg/status.bak",
		"etc", "var/lib/rpm", "", "../etc/shadow", "/etc/shadow", "etc//os-release",
	} {
		_, err := l.Open(p)
		assert.Error(t, err, p)
	}
	assert.NoError(t, l.Fault(), "refusing a path outside the allowlist is not a read fault")
}

func TestLimitedFS_RootListsNothing(t *testing.T) {
	e := disktest.NewExt4(disktest.Ext4Opts{})
	e.WriteFile("srv/node_modules/x/package.json", []byte("{}"))
	e.WriteFile("etc/os-release", []byte("ID=debian"))
	l := limited(t, e, Limits{})
	var seen []string
	require.NoError(t, fs.WalkDir(l, ".", func(p string, _ fs.DirEntry, err error) error {
		seen = append(seen, p)
		return err
	}))
	assert.Equal(t, []string{"."}, seen)
}

func TestLimitedFS_StatusDirListsRegularFilesOnly(t *testing.T) {
	e := disktest.NewExt4(disktest.Ext4Opts{})
	e.WriteFile("var/lib/dpkg/status.d/libc6", []byte("a"))
	e.WriteFile("var/lib/dpkg/status.d/zlib", []byte("b"))
	e.Mkdir("var/lib/dpkg/status.d/subdir")
	e.Symlink("var/lib/dpkg/status.d/link", "libc6")
	l := limited(t, e, Limits{})
	entries, err := fs.ReadDir(l, "var/lib/dpkg/status.d")
	require.NoError(t, err)
	var got []string
	for _, en := range entries {
		got = append(got, en.Name())
	}
	assert.Equal(t, []string{"libc6", "zlib"}, got)
}

func TestLimitedFS_Symlinks(t *testing.T) {
	deep := disktest.NewExt4(disktest.Ext4Opts{})
	deep.WriteFile("usr/lib/os-release", []byte("ID=debian"))
	deep.Symlink("lib", "usr/lib")                          // usr-merge directory symlink
	deep.Symlink("etc/os-release", "../usr/lib/os-release") // relative file symlink
	deep.WriteFile("data/real", []byte("real"))
	deep.Symlink("data/abs", "/data/real")                     // absolute: resolved against the image
	deep.Symlink("data/escape", "../../../../../../data/real") // ".." cannot leave the image root
	deep.Symlink("var/lib/dpkg/status", "/data/abs")           // chain of two

	l := limited(t, deep, Limits{})
	for path, want := range map[string]string{
		"etc/os-release":      "ID=debian",
		"var/lib/dpkg/status": "real",
	} {
		b, err := fs.ReadFile(l, path)
		require.NoError(t, err, path)
		assert.Equal(t, want, string(b), path)
	}
	assert.NoError(t, l.Fault())
}

func TestLimitedFS_SymlinkEscapeStaysInTheImage(t *testing.T) {
	e := disktest.NewExt4(disktest.Ext4Opts{})
	e.Symlink("etc/os-release", "../../../../../../../../etc/passwd")
	e.WriteFile("etc/passwd", []byte("image-passwd"))
	l := limited(t, e, Limits{})
	b, err := fs.ReadFile(l, "etc/os-release")
	require.NoError(t, err)
	assert.Equal(t, "image-passwd", string(b))
}

func TestLimitedFS_SymlinkLoopsAreFaultsNotHangs(t *testing.T) {
	tests := map[string]func(e *disktest.Ext4){
		"self loop":         func(e *disktest.Ext4) { e.Symlink("etc/os-release", "os-release") },
		"two-cycle":         func(e *disktest.Ext4) { e.Symlink("etc/os-release", "/a"); e.Symlink("a", "/etc/os-release") },
		"exceeds hop limit": func(e *disktest.Ext4) { chain(e, 60) },
		"directory cycle": func(e *disktest.Ext4) {
			e.Symlink("a", "/b")
			e.Symlink("b", "/a")
			e.Symlink("etc/os-release", "/a/x")
		},
	}
	for name, build := range tests {
		t.Run(name, func(t *testing.T) {
			e := disktest.NewExt4(disktest.Ext4Opts{})
			build(e)
			l := limited(t, e, Limits{})
			_, err := l.Open("etc/os-release")
			assert.Error(t, err)
			assert.Error(t, l.Fault(), "an unresolvable allowlisted path is a fault, not an absent file")
		})
	}
}

// chain makes etc/os-release the head of an n-link symlink chain.
func chain(e *disktest.Ext4, n int) {
	e.WriteFile("end", []byte("ID=debian"))
	prev := "/end"
	for i := 0; i < n; i++ {
		name := "l" + strings.Repeat("x", i)
		e.Symlink(name, prev)
		prev = "/" + name
	}
	e.Symlink("etc/os-release", prev)
}

func TestLimitedFS_HopLimitAllowsRealisticChains(t *testing.T) {
	e := disktest.NewExt4(disktest.Ext4Opts{BlocksPerGroup: 256})
	chain(e, 5)
	l := limited(t, e, Limits{})
	b, err := fs.ReadFile(l, "etc/os-release")
	require.NoError(t, err)
	assert.Equal(t, "ID=debian", string(b))
}

func TestLimitedFS_AbsenceIsNotAFault(t *testing.T) {
	e := disktest.NewExt4(disktest.Ext4Opts{})
	e.WriteFile("etc/hosts", []byte("x"))
	l := limited(t, e, Limits{})
	for _, p := range []string{"etc/os-release", "var/lib/dpkg/status", "var/lib/rpm/Packages", "etc/hosts/os-release"} {
		_, err := l.Open(p)
		assert.ErrorIs(t, err, fs.ErrNotExist, p)
	}
	assert.NoError(t, l.Fault())
	assert.False(t, l.PackageDBRead())
}

func TestLimitedFS_NonRegularTargetsAreAbsent(t *testing.T) {
	e := disktest.NewExt4(disktest.Ext4Opts{})
	e.Mkdir("var/lib/dpkg/status")
	l := limited(t, e, Limits{})
	_, err := l.Open("var/lib/dpkg/status")
	assert.ErrorIs(t, err, fs.ErrNotExist)
}

func TestLimitedFS_Caps(t *testing.T) {
	e := disktest.NewExt4(disktest.Ext4Opts{})
	e.WriteFile("var/lib/dpkg/status", bytes.Repeat([]byte("p"), 1000))
	e.WriteFile("etc/os-release", bytes.Repeat([]byte("o"), 600))

	t.Run("per-file cap refuses the open", func(t *testing.T) {
		l := limited(t, e, Limits{MaxFileBytes: 999})
		_, err := l.Open("var/lib/dpkg/status")
		require.Error(t, err)
		assert.ErrorIs(t, l.Fault(), errOverCap)
		f, err := l.Open("etc/os-release")
		require.NoError(t, err)
		_ = f.Close()
	})
	t.Run("a file at the cap reads in full", func(t *testing.T) {
		l := limited(t, e, Limits{MaxFileBytes: 1000})
		b, err := fs.ReadFile(l, "var/lib/dpkg/status")
		require.NoError(t, err)
		assert.Len(t, b, 1000)
	})
	t.Run("total cap stops reading across files", func(t *testing.T) {
		l := limited(t, e, Limits{MaxTotalBytes: 1500})
		_, err := fs.ReadFile(l, "var/lib/dpkg/status")
		require.NoError(t, err)
		_, err = fs.ReadFile(l, "etc/os-release")
		assert.ErrorIs(t, err, errOverCap)
		assert.ErrorIs(t, l.Fault(), errOverCap)
	})
}

func TestLimitedFS_ContextCancel(t *testing.T) {
	e := disktest.NewExt4(disktest.Ext4Opts{})
	e.WriteFile("etc/os-release", []byte("ID=debian"))
	img := e.Bytes()
	f, err := ext4.Open(bytes.NewReader(img), int64(len(img)))
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	l := NewLimitedFS(ctx, f, Limits{})
	h, err := l.Open("etc/os-release")
	require.NoError(t, err)
	cancel()
	_, err = io.ReadAll(h)
	assert.ErrorIs(t, err, context.Canceled)
	_, err = l.Open("etc/os-release")
	assert.ErrorIs(t, err, context.Canceled)
}

func TestLimitedFS_UnreadableBlocksAreFaults(t *testing.T) {
	e := disktest.NewExt4(disktest.Ext4Opts{})
	e.WriteFile("var/lib/dpkg/status", bytes.Repeat([]byte("p"), 3000))
	img := e.Bytes()
	mem := &disktest.Mem{Data: img, Err: ErrBlockUnreadable}
	f, err := ext4.Open(mem, mem.Size())
	require.NoError(t, err)
	l := NewLimitedFS(context.Background(), f, Limits{})
	mem.Unreadable = []disktest.Range{{Off: 16 * 1024, Len: int64(len(img)) - 16*1024}}
	_, err = fs.ReadFile(l, "var/lib/dpkg/status")
	assert.ErrorIs(t, err, ErrBlockUnreadable)
	assert.ErrorIs(t, l.Fault(), ErrBlockUnreadable)
}
