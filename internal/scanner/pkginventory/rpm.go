package pkginventory

import (
	"fmt"
	"io"
	"io/fs"
	"slices"
	"strings"

	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory/rpmdb"
)

// rpmDBPaths are where an rpm-based root keeps its package database, in the
// order one is preferred when a root carries more than one: SQLite (RHEL/Rocky/
// Alma 9, Amazon Linux 2023, Fedora), ndb (SUSE 15), Berkeley DB (RHEL/CentOS 7
// and 8, Amazon Linux 2, SUSE 15 before SP3), each at the classic location and
// the sysimage one /var/lib/rpm symlinks to on Fedora and SUSE.
var rpmDBPaths = []string{
	"var/lib/rpm/rpmdb.sqlite",
	"usr/lib/sysimage/rpm/rpmdb.sqlite",
	"var/lib/rpm/Packages.db",
	"usr/lib/sysimage/rpm/Packages.db",
	"var/lib/rpm/Packages",
	"usr/lib/sysimage/rpm/Packages",
}

// rpmWALSuffix names SQLite's write-ahead log beside a database. rpm closes
// the database cleanly and the log is empty; one that still holds frames has
// writes the main file does not, so the database is not read as it stands.
const (
	rpmWALSuffix  = "-wal"
	walHeaderSize = 32
)

// isRPMWAL reports whether p is the write-ahead log of one of rpmDBPaths.
func isRPMWAL(p string) bool {
	db, ok := strings.CutSuffix(p, rpmWALSuffix)
	return ok && strings.HasSuffix(db, ".sqlite") && slices.Contains(rpmDBPaths, db)
}

// MaxRPMDBBytes caps one rpm database read into memory — the same ceiling as
// one Go binary (maxGoBinaryBytes). A full RHEL install's database is tens of
// MB; one larger than this is not read, and the root reports its OS packages
// unread rather than empty.
const MaxRPMDBBytes = 256 << 20

// rpmDBPath returns the first of rpmDBPaths present in root, "" for none.
func rpmDBPath(root fs.FS) string {
	for _, p := range rpmDBPaths {
		f, err := root.Open(p)
		if err == nil {
			_ = f.Close()
			return p
		}
	}
	return ""
}

// rpmPackages reads the root's rpm database into packages on ecosystem, the
// way the SSM inventory reports the same packages (InventoryPackage,
// SourceRPMName), so a package found in an image and on a VM is one node.
//
// No database, or a distribution with no ecosystem, is no packages and no
// error. A database that cannot be read in full is an error and no packages:
// part of a package list reads exactly like a smaller, cleaner image, so
// OSCVEGap reports the root unread instead.
func rpmPackages(root fs.FS, ecosystem string) ([]InstalledPackage, error) {
	p := rpmDBPath(root)
	if p == "" || ecosystem == "" {
		return nil, nil
	}
	data, err := readRPMDB(root, p)
	if err != nil {
		return nil, err
	}
	pkgs, err := rpmdb.Read(data)
	if err != nil {
		return nil, fmt.Errorf("rpmPackages: %s: %w", p, err)
	}
	out := make([]InstalledPackage, 0, len(pkgs))
	for _, rp := range pkgs {
		if rp.Name == "gpg-pubkey" {
			continue // an imported signing key, not software
		}
		ip, ok := InventoryPackage(ecosystem, rp.Name, rp.Version, rp.Release, rp.Epoch, p)
		if !ok {
			continue
		}
		ip.SourceName = SourceRPMName(rp.SourceRPM)
		out = append(out, ip)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("rpmPackages: %s lists no installed packages", p)
	}
	return out, nil
}

// readRPMDB reads the database at p, refusing one too large to hold, one whose
// write-ahead log still holds frames, and an empty file — which is what the
// image scanner leaves for a database over MaxRPMDBBytes.
func readRPMDB(root fs.FS, p string) ([]byte, error) {
	if wal, err := fs.Stat(root, p+rpmWALSuffix); err == nil && wal.Size() > walHeaderSize {
		return nil, fmt.Errorf("readRPMDB: %s has an uncheckpointed write-ahead log", p)
	}
	f, err := root.Open(p)
	if err != nil {
		return nil, fmt.Errorf("readRPMDB: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, MaxRPMDBBytes+1))
	if err != nil {
		return nil, fmt.Errorf("readRPMDB: %s: %w", p, err)
	}
	switch {
	case len(data) > MaxRPMDBBytes:
		return nil, fmt.Errorf("readRPMDB: %s exceeds %d MiB", p, MaxRPMDBBytes>>20)
	case len(data) == 0:
		return nil, fmt.Errorf("readRPMDB: %s is empty (an image scan keeps no database over %d MiB)", p, MaxRPMDBBytes>>20)
	}
	return data, nil
}
