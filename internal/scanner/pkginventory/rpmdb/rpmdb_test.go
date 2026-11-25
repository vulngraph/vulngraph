package rpmdb

import (
	"compress/gzip"
	"encoding/binary"
	"io"
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
)

// The fixtures are real rpm databases, one per on-disk format, trimmed by rpm
// itself: every package but a handful erased with `rpm -e --justdb`, then
// `rpm --rebuilddb`, so the file is still exactly what rpm writes. Source images:
// registry.access.redhat.com/ubi9/ubi-minimal (SQLite), amazonlinux:2023
// (SQLite), amazonlinux:2 (Berkeley DB), opensuse/leap:15.6 (ndb). Stored
// gzipped because a database is mostly empty pages. The SQLite fixtures' Packages
// table spans an interior page, leaf pages and overflow chains.
func fixture(t testing.TB, name string) []byte {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	zr, err := gzip.NewReader(f)
	require.NoError(t, err)
	data, err := io.ReadAll(zr)
	require.NoError(t, err)
	return data
}

// The expectations are `rpm -qa --qf '%{NAME} %{EPOCH} …'` on the trimmed
// database inside its image, with rpm's "(none)" written as "".
func TestRead_RealDatabases(t *testing.T) {
	tests := []struct {
		fixture string
		want    []Package
	}{
		{"ubi9-minimal.rpmdb.sqlite.gz", []Package{
			{Name: "gmp", Epoch: "1", Version: "6.2.0", Release: "13.el9", Arch: "x86_64", SourceRPM: "gmp-6.2.0-13.el9.src.rpm"},
			{Name: "gpg-pubkey", Version: "5a6340b3", Release: "6229229e"},
			{Name: "gpg-pubkey", Version: "fd431d51", Release: "4ae0493b"},
			{Name: "libgcc", Version: "11.5.0", Release: "14.el9", Arch: "x86_64", SourceRPM: "gcc-11.5.0-14.el9.src.rpm"},
			{Name: "openssl-libs", Epoch: "1", Version: "3.5.8", Release: "1.el9_8", Arch: "x86_64", SourceRPM: "openssl-3.5.8-1.el9_8.src.rpm"},
			{Name: "zlib", Version: "1.2.11", Release: "40.el9", Arch: "x86_64", SourceRPM: "zlib-1.2.11-40.el9.src.rpm"},
		}},
		{"amazonlinux2023.rpmdb.sqlite.gz", []Package{
			{Name: "gmp", Epoch: "1", Version: "6.2.1", Release: "2.amzn2023.0.2", Arch: "x86_64", SourceRPM: "gmp-6.2.1-2.amzn2023.0.2.src.rpm"},
			{Name: "gpg-pubkey", Version: "d832c631", Release: "6515c85e"},
			{Name: "libgcc", Version: "14.2.1", Release: "7.amzn2023.0.2", Arch: "x86_64", SourceRPM: "gcc14-14.2.1-7.amzn2023.0.2.src.rpm"},
			{Name: "openssl-libs", Epoch: "1", Version: "3.5.8", Release: "1.amzn2023.0.1", Arch: "x86_64", SourceRPM: "openssl-3.5.8-1.amzn2023.0.1.src.rpm"},
			{Name: "zlib", Version: "1.2.11", Release: "33.amzn2023.0.6", Arch: "x86_64", SourceRPM: "zlib-1.2.11-33.amzn2023.0.6.src.rpm"},
		}},
		{"amazonlinux2.Packages.gz", []Package{
			{Name: "gmp", Epoch: "1", Version: "6.0.0", Release: "15.amzn2.0.3", Arch: "x86_64", SourceRPM: "gmp-6.0.0-15.amzn2.0.3.src.rpm"},
			{Name: "gpg-pubkey", Version: "c87f5b1a", Release: "593863f8"},
			{Name: "libgcc", Version: "7.3.1", Release: "18.amzn2", Arch: "x86_64", SourceRPM: "gcc-7.3.1-18.amzn2.src.rpm"},
			{Name: "openssl-libs", Epoch: "1", Version: "1.0.2k", Release: "24.amzn2.0.22", Arch: "x86_64", SourceRPM: "openssl-1.0.2k-24.amzn2.0.22.src.rpm"},
			{Name: "zlib", Version: "1.2.7", Release: "19.amzn2.0.3", Arch: "x86_64", SourceRPM: "zlib-1.2.7-19.amzn2.0.3.src.rpm"},
		}},
		{"opensuse-leap15.6.Packages.db.gz", []Package{
			{Name: "gpg-pubkey", Version: "25db7ae0", Release: "645bae34"},
			{Name: "gpg-pubkey", Version: "29b700a4", Release: "62b07e22"},
			{Name: "gpg-pubkey", Version: "39db7c82", Release: "5f68629b"},
			{Name: "gpg-pubkey", Version: "3dbdc284", Release: "53674dd4"},
			{Name: "gpg-pubkey", Version: "3fa1d6ce", Release: "63c9481c"},
			{Name: "gpg-pubkey", Version: "65176565", Release: "61a0ee8f"},
			{Name: "libgmp10", Version: "6.1.2", Release: "4.9.1", Arch: "x86_64", SourceRPM: "gmp-6.1.2-4.9.1.src.rpm"},
			{Name: "libopenssl3", Version: "3.1.4", Release: "150600.5.50.1", Arch: "x86_64", SourceRPM: "openssl-3-3.1.4-150600.5.50.1.src.rpm"},
			{Name: "libz1", Version: "1.2.13", Release: "150500.4.6.1", Arch: "x86_64", SourceRPM: "zlib-1.2.13-150500.4.6.1.src.rpm"},
			{Name: "openssl-3", Version: "3.1.4", Release: "150600.5.50.1", Arch: "x86_64", SourceRPM: "openssl-3-3.1.4-150600.5.50.1.src.rpm"},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.fixture, func(t *testing.T) {
			got, err := Read(fixture(t, tt.fixture))
			require.NoError(t, err)
			sort.Slice(got, func(i, j int) bool {
				if got[i].Name != got[j].Name {
					return got[i].Name < got[j].Name
				}
				return got[i].Version < got[j].Version
			})
			require.Equal(t, tt.want, got)
		})
	}
}

// A database that is not fully readable is an error, never a shorter list: a
// partial package list reads exactly like a smaller, cleaner image.
func TestRead_CorruptDatabasesError(t *testing.T) {
	sqlite := fixture(t, "ubi9-minimal.rpmdb.sqlite.gz")
	bdb := fixture(t, "amazonlinux2.Packages.gz")
	ndb := fixture(t, "opensuse-leap15.6.Packages.db.gz")

	tests := []struct {
		name string
		data []byte
	}{
		{"sqlite truncated to its first pages", sqlite[:3*4096]},
		{"sqlite with an unknown page type", corruptAt(sqlite, 4096, 0x42)},
		{"sqlite interior page pointing at itself", withUint32(sqlite, 4096+8, 2)},
		{"bdb truncated", bdb[:len(bdb)/2]},
		{"bdb encrypted", corruptAt(bdb, 24, 1)},
		{"bdb first page not hash metadata", corruptAt(bdb, 25, 9)},
		{"ndb truncated", ndb[:len(ndb)/3]},
		{"ndb slot magic broken", corruptAt(ndb, 32, 'X')},
		{"empty file", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Read(tt.data)
			require.Error(t, err)
		})
	}
}

func TestRead_UnknownFormat(t *testing.T) {
	_, err := Read([]byte("this is not a package database at all"))
	require.ErrorIs(t, err, ErrUnsupportedFormat)
}

func TestRead_SQLiteWithoutPackagesTable(t *testing.T) {
	db := fixture(t, "amazonlinux2023.rpmdb.sqlite.gz")
	f, err := openSQLite(db)
	require.NoError(t, err)
	_, err = f.tableRoot("NoSuchTable")
	require.ErrorContains(t, err, "no NoSuchTable table")
}

func corruptAt(data []byte, off int, b byte) []byte {
	out := append([]byte(nil), data...)
	out[off] = b
	return out
}

func withUint32(data []byte, off int, v uint32) []byte {
	out := append([]byte(nil), data...)
	binary.BigEndian.PutUint32(out[off:], v)
	return out
}

// header builds an rpm header blob from (tag, type, value) entries.
func header(entries ...hdrEntry) []byte {
	var index, data []byte
	for _, e := range entries {
		var rec [16]byte
		binary.BigEndian.PutUint32(rec[0:], e.tag)
		binary.BigEndian.PutUint32(rec[4:], e.typ)
		binary.BigEndian.PutUint32(rec[8:], uint32(len(data)))
		binary.BigEndian.PutUint32(rec[12:], 1)
		index = append(index, rec[:]...)
		data = append(data, e.val...)
	}
	out := binary.BigEndian.AppendUint32(nil, uint32(len(entries)))
	out = binary.BigEndian.AppendUint32(out, uint32(len(data)))
	return append(append(out, index...), data...)
}

type hdrEntry struct {
	tag, typ uint32
	val      []byte
}

func str(tag uint32, s string) hdrEntry { return hdrEntry{tag, typeString, append([]byte(s), 0)} }

func TestParseHeader(t *testing.T) {
	epoch := hdrEntry{tagEpoch, typeInt32, binary.BigEndian.AppendUint32(nil, 2)}
	good := header(str(tagName, "vim-minimal"), epoch, str(tagVersion, "9.0"), str(tagRelease, "1.el9"),
		str(tagArch, "x86_64"), str(tagSourceRPM, "vim-9.0-1.el9.src.rpm"), str(1004, "ignored summary"))
	p, err := parseHeader(good)
	require.NoError(t, err)
	require.Equal(t, Package{Name: "vim-minimal", Epoch: "2", Version: "9.0", Release: "1.el9",
		Arch: "x86_64", SourceRPM: "vim-9.0-1.el9.src.rpm"}, p)

	bad := map[string][]byte{
		"shorter than its preamble": {0, 0, 0},
		"no entries":                {0, 0, 0, 0, 0, 0, 0, 0},
		"truncated data segment":    good[:len(good)-4],
		"no name":                   header(str(tagVersion, "1")),
		"unterminated string":       header(hdrEntry{tagName, typeString, []byte("bash")}),
		"truncated int32":           header(str(tagName, "a"), str(tagVersion, "1"), hdrEntry{tagEpoch, typeInt32, []byte{0, 1}}),
		"unexpected type":           header(hdrEntry{tagName, 7, []byte("bash\x00")}),
	}
	for name, blob := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := parseHeader(blob)
			require.Error(t, err)
		})
	}
}

// rpm keeps its next-instance counter under key 0 as a small on-page value; it
// is not a package. A header small enough to sit on the page (H_KEYDATA) is.
func TestBDB_OnPageItems(t *testing.T) {
	got, err := Read(onPageBDB())
	require.NoError(t, err)
	require.Equal(t, []Package{{Name: "tiny", Version: "1"}}, got)
}

// onPageBDB is a two-page hash database whose items all sit on the page.
func onPageBDB() []byte {
	const pageSize = 512
	hdr := header(str(tagName, "tiny"), str(tagVersion, "1"))
	db := make([]byte, 2*pageSize)
	binary.LittleEndian.PutUint32(db[12:], bdbHashMagic)
	binary.LittleEndian.PutUint32(db[20:], pageSize)
	db[25] = bdbPageHashMeta
	binary.LittleEndian.PutUint32(db[32:], 1) // last page

	pg := db[pageSize:]
	pg[25] = bdbPageHash
	// Items packed down from the end: counter key, counter value, package key, header.
	items := [][]byte{
		append([]byte{bdbItemKeyData}, 0, 0, 0, 0),
		append([]byte{bdbItemKeyData}, 7, 0, 0, 0),
		append([]byte{bdbItemKeyData}, 1, 0, 0, 0),
		append([]byte{bdbItemKeyData}, hdr...),
	}
	end := pageSize
	for i, it := range items {
		end -= len(it)
		copy(pg[end:], it)
		binary.LittleEndian.PutUint16(pg[bdbPageHeaderSize+2*i:], uint16(end))
	}
	binary.LittleEndian.PutUint16(pg[20:], uint16(len(items)))
	return db
}

// The input is image content: whatever a layer holds at an rpm path. Read must
// return an error for anything it cannot parse, never panic.
func FuzzRead(f *testing.F) {
	for _, name := range []string{"ubi9-minimal.rpmdb.sqlite.gz", "amazonlinux2.Packages.gz", "opensuse-leap15.6.Packages.db.gz"} {
		f.Add(fixture(f, name))
	}
	f.Add(onPageBDB())
	f.Add(header(str(tagName, "a"), str(tagVersion, "1")))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = Read(data)
	})
}

func TestVarint(t *testing.T) {
	tests := []struct {
		in   []byte
		want uint64
		n    int
	}{
		{[]byte{0x05}, 5, 1},
		{[]byte{0x81, 0x00}, 128, 2},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ^uint64(0), 9},
		{[]byte{0x81}, 0, 0},
	}
	for _, tt := range tests {
		v, n := varint(tt.in)
		require.Equal(t, tt.want, v)
		require.Equal(t, tt.n, n)
	}
}
