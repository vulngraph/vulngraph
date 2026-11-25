package pkginventory

import (
	"compress/gzip"
	"context"
	"io"
	"os"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/distro"
)

// rpmFixture is one of rpmdb's real, trimmed databases (see rpmdb_test.go for
// how they were made).
func rpmFixture(t *testing.T, name string) []byte {
	t.Helper()
	f, err := os.Open("rpmdb/testdata/" + name)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	require.NoError(t, err)
	data, err := io.ReadAll(zr)
	require.NoError(t, err)
	return data
}

func rpmRoot(osRelease, dbPath string, db []byte) fstest.MapFS {
	return fstest.MapFS{
		osReleasePath: {Data: []byte(osRelease)},
		dbPath:        {Data: db},
	}
}

// Each format, at the path its distribution keeps it, yields the packages on
// the release's ecosystem with the version, epoch and source package the SSM
// inventory reports for the same host — and no gpg-pubkey pseudo-packages.
func TestInventoryPackages_ReadsRPMDatabases(t *testing.T) {
	tests := []struct {
		name      string
		root      fstest.MapFS
		ecosystem string
		want      map[string][2]string // name → version, source package
	}{
		{"ubi9-minimal, SQLite", rpmRoot("ID=\"rhel\"\nVERSION_ID=\"9.8\"\n", "var/lib/rpm/rpmdb.sqlite",
			rpmFixture(t, "ubi9-minimal.rpmdb.sqlite.gz")), "Red Hat:9", map[string][2]string{
			"gmp":          {"1:6.2.0-13.el9", "gmp"},
			"libgcc":       {"11.5.0-14.el9", "gcc"},
			"openssl-libs": {"1:3.5.8-1.el9_8", "openssl"},
			"zlib":         {"1.2.11-40.el9", "zlib"},
		}},
		{"amazonlinux:2023, SQLite", rpmRoot("ID=\"amzn\"\nVERSION_ID=\"2023\"\n", "var/lib/rpm/rpmdb.sqlite",
			rpmFixture(t, "amazonlinux2023.rpmdb.sqlite.gz")), "Amazon Linux:2023", map[string][2]string{
			"gmp":          {"1:6.2.1-2.amzn2023.0.2", "gmp"},
			"libgcc":       {"14.2.1-7.amzn2023.0.2", "gcc14"},
			"openssl-libs": {"1:3.5.8-1.amzn2023.0.1", "openssl"},
			"zlib":         {"1.2.11-33.amzn2023.0.6", "zlib"},
		}},
		{"amazonlinux:2, Berkeley DB", rpmRoot("ID=\"amzn\"\nVERSION_ID=\"2\"\n", "var/lib/rpm/Packages",
			rpmFixture(t, "amazonlinux2.Packages.gz")), "Amazon Linux:2", map[string][2]string{
			"gmp":          {"1:6.0.0-15.amzn2.0.3", "gmp"},
			"libgcc":       {"7.3.1-18.amzn2", "gcc"},
			"openssl-libs": {"1:1.0.2k-24.amzn2.0.22", "openssl"},
			"zlib":         {"1.2.7-19.amzn2.0.3", "zlib"},
		}},
		{"opensuse/leap:15.6, ndb", rpmRoot("ID=\"opensuse-leap\"\nVERSION_ID=\"15.6\"\n", "usr/lib/sysimage/rpm/Packages.db",
			rpmFixture(t, "opensuse-leap15.6.Packages.db.gz")), "openSUSE:Leap 15.6", map[string][2]string{
			"libgmp10":    {"6.1.2-4.9.1", "gmp"},
			"libopenssl3": {"3.1.4-150600.5.50.1", "openssl-3"},
			"libz1":       {"1.2.13-150500.4.6.1", "zlib"},
			"openssl-3":   {"3.1.4-150600.5.50.1", "openssl-3"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgs := InventoryPackages(context.Background(), tt.root).Packages
			got := map[string][2]string{}
			for _, p := range pkgs {
				require.Equal(t, tt.ecosystem, p.Ecosystem)
				require.NotEqual(t, "gpg-pubkey", p.Name)
				got[p.Name] = [2]string{p.Version, p.SourceName}
			}
			require.Equal(t, tt.want, got)

			eco, gap, detail := OSCVEGap(tt.root, pkgs, distro.Sources{
				distro.SourceOSV: true, distro.SourceALAS: true}, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
			require.Equal(t, tt.ecosystem, eco)
			require.Empty(t, gap, "a readable database on a supported release is matchable")
			require.Empty(t, detail)
		})
	}
}

// The purl, ecosystem and source_package of a package read from an image's
// database are byte-identical to the same package reported by SSM Inventory, so
// the image and the VM share one graph node and one advisory match.
func TestRPMPackages_MatchSSMInventory(t *testing.T) {
	root := rpmRoot("ID=\"amzn\"\nVERSION_ID=\"2\"\n", "var/lib/rpm/Packages", rpmFixture(t, "amazonlinux2.Packages.gz"))
	var fromDB InstalledPackage
	for _, p := range InventoryPackages(context.Background(), root).Packages {
		if p.Name == "openssl-libs" {
			fromDB = p
		}
	}
	// AWS-ApplicationInventory's record for the same package.
	fromSSM, ok := InventoryPackage(InventoryEcosystem("amzn", "2"), "openssl-libs", "1.0.2k", "24.amzn2.0.22", "1", "ssm")
	require.True(t, ok)
	fromSSM.SourceName = SourceRPMName("openssl-1.0.2k-24.amzn2.0.22.src.rpm")

	require.Equal(t, PURL(fromSSM), PURL(fromDB))
	require.Equal(t, "pkg:rpm/amazon/openssl-libs@1:1.0.2k-24.amzn2.0.22", PURL(fromDB))
	require.Equal(t, fromSSM.Ecosystem, fromDB.Ecosystem)
	require.Equal(t, fromSSM.SourceName, fromDB.SourceName)
}

// TestEveryRPMDBPathIsRead iterates rpmDBPaths: a database at any of them is
// streamed out of an image (ClassifyManifest) and read (InventoryPackages). A
// path that is classified but not read leaves its images with no OS packages
// and no gap; one read but not classified is never fetched from a layer.
func TestEveryRPMDBPathIsRead(t *testing.T) {
	db := rpmFixture(t, "ubi9-minimal.rpmdb.sqlite.gz")
	for _, p := range rpmDBPaths {
		require.Equal(t, KindRpmDB, ClassifyManifest(p, fileMode, int64(len(db))), p)
		pkgs := InventoryPackages(context.Background(), rpmRoot("ID=\"rhel\"\nVERSION_ID=\"9.8\"\n", p, db)).Packages
		require.Len(t, pkgs, 4, "a database at %s is read", p)
	}
}

// A database that cannot be read in full yields no packages and a precise
// reason — never a partial list, never a root that looks like it has no OS.
func TestOSCVEGap_UnreadableRPMDatabase(t *testing.T) {
	rhel := "ID=\"rhel\"\nVERSION_ID=\"9.8\"\n"
	good := rpmFixture(t, "ubi9-minimal.rpmdb.sqlite.gz")
	walWithFrames := fstest.MapFS{
		osReleasePath:                  {Data: []byte(rhel)},
		"var/lib/rpm/rpmdb.sqlite":     {Data: good},
		"var/lib/rpm/rpmdb.sqlite-wal": {Data: make([]byte, walHeaderSize+24+4096)},
	}
	tests := []struct {
		name   string
		root   fstest.MapFS
		reason string
	}{
		{"truncated", rpmRoot(rhel, "var/lib/rpm/rpmdb.sqlite", good[:8192]), "rpmdb.sqlite"},
		{"empty: not retained by the image scan", rpmRoot(rhel, "var/lib/rpm/rpmdb.sqlite", nil), "is empty"},
		{"unknown format", rpmRoot(rhel, "var/lib/rpm/Packages", []byte("garbage")), "unsupported database format"},
		{"uncheckpointed write-ahead log", walWithFrames, "uncheckpointed write-ahead log"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkgs := InventoryPackages(context.Background(), tt.root).Packages
			require.Empty(t, pkgs)
			eco, gap, detail := OSCVEGap(tt.root, pkgs, distro.Sources{distro.SourceOSV: true}, time.Now())
			require.Equal(t, "Red Hat:9", eco)
			require.Equal(t, asset.CVEGapPackageDBUnread, gap)
			require.Contains(t, detail, tt.reason)
		})
	}
}

func TestOSCVEGap_RPMDistributionWithoutIdentity(t *testing.T) {
	db := rpmFixture(t, "ubi9-minimal.rpmdb.sqlite.gz")

	fedora := rpmRoot("ID=fedora\nVERSION_ID=40\n", "usr/lib/sysimage/rpm/rpmdb.sqlite", db)
	require.Empty(t, InventoryPackages(context.Background(), fedora).Packages, "no ecosystem, no package identity")
	eco, gap, detail := OSCVEGap(fedora, nil, distro.Sources{distro.SourceOSV: true}, time.Now())
	require.Empty(t, eco)
	require.Equal(t, asset.CVEGapNoAdvisorySource, gap)
	require.Contains(t, detail, "fedora")

	noRelease := fstest.MapFS{"var/lib/rpm/rpmdb.sqlite": {Data: db}}
	_, gap, _ = OSCVEGap(noRelease, nil, distro.Sources{distro.SourceOSV: true}, time.Now())
	require.Equal(t, asset.CVEGapUnknownRelease, gap)
}

func TestClassifyManifest_RPMWriteAheadLog(t *testing.T) {
	require.Equal(t, KindRpmDB, ClassifyManifest("var/lib/rpm/rpmdb.sqlite-wal", fileMode, 0))
	require.Equal(t, KindRpmDB, ClassifyManifest("usr/lib/sysimage/rpm/rpmdb.sqlite-wal", fileMode, 0))
	require.Equal(t, KindNone, ClassifyManifest("var/lib/rpm/Packages-wal", fileMode, 0))
	require.Equal(t, KindNone, ClassifyManifest("srv/app/data.sqlite-wal", fileMode, 0))
}

func TestReadRPMDB_EmptyWALIsClean(t *testing.T) {
	root := rpmRoot("ID=\"rhel\"\nVERSION_ID=\"9.8\"\n", "var/lib/rpm/rpmdb.sqlite", rpmFixture(t, "ubi9-minimal.rpmdb.sqlite.gz"))
	root["var/lib/rpm/rpmdb.sqlite-wal"] = &fstest.MapFile{Data: nil}
	pkgs, err := rpmPackages(root, "Red Hat:9")
	require.NoError(t, err)
	require.Len(t, pkgs, 4)
	require.True(t, strings.HasPrefix(pkgs[0].Source, "var/lib/rpm/"))
}
