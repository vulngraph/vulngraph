package pkginventory

import (
	"bytes"
	"context"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/rs/zerolog"
	zlog "github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
)

// recordingFS notes every path opened against it and serves nothing, so a parser's
// read attempt is observable without needing fixture content.
//
// It reports an empty root directory (rather than leaving fs.WalkDir to Open ".")
// so the recorded set stays exactly the FIXED paths the parsers ask for by name.
type recordingFS struct {
	mu     sync.Mutex
	opened []string
}

func (r *recordingFS) Open(name string) (fs.File, error) {
	r.mu.Lock()
	r.opened = append(r.opened, name)
	r.mu.Unlock()
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

func (r *recordingFS) ReadDir(string) ([]fs.DirEntry, error) { return nil, nil }
func (r *recordingFS) Stat(string) (fs.FileInfo, error)      { return emptyRootInfo{}, nil }

type emptyRootInfo struct{}

func (emptyRootInfo) Name() string       { return "." }
func (emptyRootInfo) Size() int64        { return 0 }
func (emptyRootInfo) Mode() fs.FileMode  { return fs.ModeDir | 0o555 }
func (emptyRootInfo) ModTime() time.Time { return time.Time{} }
func (emptyRootInfo) IsDir() bool        { return true }
func (emptyRootInfo) Sys() any           { return nil }

// TestPackageManifestPathsCoversEveryParser locks PackageManifestPaths to the
// FIXED paths InventoryPackages reads, mechanically rather than by review.
//
// Its companion is TestClassifyManifestCoversEveryParser: between them they cover
// the whole read set, which is what the image scanner classifies against. A parser
// added on either half without a matching entry would keep working for a parse of a
// whole assembled root and silently return nothing for every streamed container
// image — a capability that looks wired and covers nothing.
func TestPackageManifestPathsCoversEveryParser(t *testing.T) {
	rec := &recordingFS{}
	_ = InventoryPackages(context.Background(), rec)

	declared := PackageManifestPaths()
	require.ElementsMatch(t, declared, rec.opened,
		"PackageManifestPaths() must equal the paths InventoryPackages reads — "+
			"add the new parser's path to PackageManifestPaths (and remove any it no longer reads)")

	require.NotEmpty(t, declared)
	for _, p := range declared {
		require.False(t, strings.HasPrefix(p, "/"),
			"paths must be fs.FS-relative (no leading slash), got %q", p)
	}
}

// TestDistroEcosystems pins the OSV ecosystem string emitted for each distro.
//
// Every expectation here was checked against the LIVE OSV API — the qualifier is
// not cosmetic. For openssl 3.1.4-r5: ecosystem "Alpine" returns 0 advisories,
// "Alpine:v3.19" returns 9. For openssl 1.1.1n-0+deb11u5: "Debian" returns 89
// (the union of every release), "Debian:11" returns 32.
func TestDistroEcosystems(t *testing.T) {
	tests := []struct {
		name       string
		osRelease  string
		alpineFile string
		wantDebian string
		wantAlpine string
	}{
		{
			name:       "debian bookworm",
			osRelease:  "PRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\nID=debian\nVERSION_ID=\"12\"\n",
			wantDebian: "Debian:12",
			wantAlpine: "Alpine",
		},
		{
			name:       "ubuntu jammy is not debian",
			osRelease:  "ID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"22.04\"\n",
			wantDebian: "Ubuntu:22.04:LTS",
			wantAlpine: "Alpine",
		},
		{
			name:       "alpine via os-release",
			osRelease:  "ID=alpine\nVERSION_ID=3.19.1\n",
			wantDebian: "Debian",
			wantAlpine: "Alpine:v3.19",
		},
		{
			name:       "alpine via alpine-release fallback",
			alpineFile: "3.21.0\n",
			wantDebian: "Debian",
			wantAlpine: "Alpine:v3.21",
		},
		{
			// Three-component version: the patch component is dropped by the
			// second Cut, before any suffix trimming is needed.
			name:       "alpine patch version drops the third component",
			osRelease:  "ID=alpine\nVERSION_ID=3.22.0_alpha20250108\n",
			wantAlpine: "Alpine:v3.22",
			wantDebian: "Debian",
		},
		{
			// Suffix sitting ON the minor component, which only the TrimRight can
			// remove. Its cutset is letters/underscore/hyphen, so it normalises a
			// minor like "22_alpha"; a digit-tailed edge suffix
			// ("3.22.0_alpha20250108") is handled by the patch-component drop
			// above instead. "Alpine:v3.22_alpha" is not an OSV ecosystem and
			// returns zero advisories.
			name:       "alpine suffix on the minor component is trimmed",
			osRelease:  "ID=alpine\nVERSION_ID=3.22_alpha\n",
			wantAlpine: "Alpine:v3.22",
			wantDebian: "Debian",
		},
		{
			// Minimal images ship an os-release naming the distro but no
			// VERSION_ID; /etc/alpine-release supplies it. Without the backfill
			// the release is detected as alpine with no version and the ecosystem
			// degrades to the unqualified "Alpine", which matches no advisory.
			name:       "alpine os-release without VERSION_ID backfills from alpine-release",
			osRelease:  "ID=alpine\nPRETTY_NAME=\"Alpine Linux v3.19\"\n",
			alpineFile: "3.19.1\n",
			wantAlpine: "Alpine:v3.19",
			wantDebian: "Debian",
		},
		{
			// Point-release VERSION_ID: OSV keys Debian by major only, so
			// "Debian:12.5" would match nothing.
			name:       "debian point release keys on the major",
			osRelease:  "ID=debian\nVERSION_ID=\"12.5\"\n",
			wantDebian: "Debian:12",
			wantAlpine: "Alpine",
		},
		{
			name:       "raspbian routes by ID_LIKE",
			osRelease:  "ID=raspbian\nID_LIKE=debian\nVERSION_ID=\"11\"\n",
			wantDebian: "Debian:11",
			wantAlpine: "Alpine",
		},
		{
			name:       "no release files falls back to the unqualified ecosystem",
			wantDebian: "Debian",
			wantAlpine: "Alpine",
		},
		{
			name:       "debian sid has no VERSION_ID",
			osRelease:  "ID=debian\nPRETTY_NAME=\"Debian GNU/Linux trixie/sid\"\n",
			wantDebian: "Debian",
			wantAlpine: "Alpine",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := fstest.MapFS{}
			if tc.osRelease != "" {
				root[osReleasePath] = &fstest.MapFile{Data: []byte(tc.osRelease)}
			}
			if tc.alpineFile != "" {
				root[alpineReleasePath] = &fstest.MapFile{Data: []byte(tc.alpineFile)}
			}
			rel := detectRelease(root)
			require.Equal(t, tc.wantDebian, debianEcosystem(rel))
			require.Equal(t, tc.wantAlpine, alpineEcosystem(rel))
		})
	}
}

// The parsers must stamp the DETECTED ecosystem onto every package, not a constant.
func TestInventoryPackages_StampsDetectedEcosystem(t *testing.T) {
	root := fstest.MapFS{
		osReleasePath:    &fstest.MapFile{Data: []byte("ID=alpine\nVERSION_ID=3.19.1\n")},
		apkInstalledPath: &fstest.MapFile{Data: []byte("P:openssl\nV:3.1.4-r5\n\n")},
	}
	pkgs := InventoryPackages(context.Background(), root).Packages
	require.Len(t, pkgs, 1)
	require.Equal(t, "Alpine:v3.19", pkgs[0].Ecosystem)
	require.Equal(t, "3.1.4-r5", pkgs[0].Version)
}

// A fallback that silently yields zero coverage is worse than no scan at all:
// the packages are inventoried, the CVE query runs, and it returns nothing —
// indistinguishable from a clean image. OSV publishes Alpine advisories only
// under "Alpine:v<major>.<minor>"; bare "Alpine" returns 0 (vs 21 for openssl
// 3.1.4-r5 on Alpine:v3.19). Unlike "Debian", it is not an over-inclusive union
// — it is nothing. So the unresolved case has to be visible.
func TestInventoryPackages_WarnsWhenAlpineEcosystemIsUnresolved(t *testing.T) {
	logs := func(t *testing.T, root fstest.MapFS) (string, []InstalledPackage) {
		t.Helper()
		var buf bytes.Buffer
		orig := zlog.Logger
		zlog.Logger = zerolog.New(&buf)
		t.Cleanup(func() { zlog.Logger = orig })
		pkgs := InventoryPackages(context.Background(), root).Packages
		return buf.String(), pkgs
	}

	t.Run("apk packages with no resolvable release", func(t *testing.T) {
		// An Alpine rootfs with neither os-release nor alpine-release: the apk
		// database is read, so the packages exist and are stamped uncovered.
		out, pkgs := logs(t, fstest.MapFS{
			apkInstalledPath: &fstest.MapFile{Data: []byte("P:openssl\nV:3.1.4-r5\n\n")},
		})
		require.Len(t, pkgs, 1)
		require.Equal(t, alpineUnqualified, pkgs[0].Ecosystem)
		require.Contains(t, out, "zero advisories",
			"stamping apk packages with the unqualified ecosystem must be logged — it is a silent total loss of coverage")
	})

	t.Run("resolved alpine release is silent", func(t *testing.T) {
		out, pkgs := logs(t, fstest.MapFS{
			osReleasePath:    &fstest.MapFile{Data: []byte("ID=alpine\nVERSION_ID=3.19.1\n")},
			apkInstalledPath: &fstest.MapFile{Data: []byte("P:openssl\nV:3.1.4-r5\n\n")},
		})
		require.Equal(t, "Alpine:v3.19", pkgs[0].Ecosystem)
		require.Empty(t, out)
	})

	t.Run("a debian root has no apk packages to lose", func(t *testing.T) {
		// alpineEcosystem returns the unqualified string here too, but nothing is
		// stamped with it, so warning would be pure noise.
		out, pkgs := logs(t, fstest.MapFS{
			osReleasePath:  &fstest.MapFile{Data: []byte("ID=debian\nVERSION_ID=\"12\"\n")},
			dpkgStatusPath: &fstest.MapFile{Data: []byte("Package: openssl\nVersion: 3.0.11-1\n\n")},
		})
		require.Len(t, pkgs, 1)
		require.Equal(t, "Debian:12", pkgs[0].Ecosystem)
		require.Empty(t, out)
	})
}
