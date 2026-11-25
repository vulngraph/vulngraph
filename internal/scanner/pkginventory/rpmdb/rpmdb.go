// Package rpmdb reads the installed-package list out of an rpm database file,
// in pure Go and from bytes already in memory: the image scanner holds a
// layer's files in memory and never writes them to disk.
//
// rpm has used three on-disk formats, and a fleet still runs all of them:
//
//	SQLite         rpmdb.sqlite   RHEL/Rocky/Alma 9, Fedora 33+, Amazon Linux 2023
//	Berkeley DB    Packages       RHEL/CentOS 7 and 8, Amazon Linux 2
//	ndb            Packages.db    SUSE Linux Enterprise / openSUSE Leap 15
//
// Each stores one rpm header blob per installed package; this package finds
// those blobs and reads the few tags a package identity needs. Only the
// read paths rpm's own databases exercise are implemented, and anything
// outside them is an error rather than a guess: a database read in part would
// report an image as running fewer packages than it does.
package rpmdb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
)

// Package is one installed rpm's identity, read from its header.
type Package struct {
	Name    string
	Epoch   string // decimal; "" when the header carries no EPOCH tag
	Version string
	Release string
	Arch    string
	// SourceRPM is the source package file the binary was built from
	// ("openssl-3.0.7-24.el9.src.rpm"); "" for pseudo-packages (gpg-pubkey).
	SourceRPM string
}

// ErrUnsupportedFormat means the file is none of the three formats.
var ErrUnsupportedFormat = errors.New("rpmdb: unsupported database format")

// budget bounds the bytes a reader may assemble to the size of the file. A
// real database stores each header once, so its headers together never
// exceed it; a hostile one whose records all point at the same long chain
// would otherwise make a few hundred KB cost gigabytes of copying.
type budget struct{ left int }

func (b *budget) take(n int) error {
	if n > b.left {
		return errors.New("records claim more bytes than the file holds")
	}
	b.left -= n
	return nil
}

// Read returns every package header in an rpm database, whichever of the
// three formats it is in, recognised by content rather than by file name.
func Read(data []byte) ([]Package, error) {
	var (
		blobs [][]byte
		err   error
	)
	switch {
	case isSQLite(data):
		blobs, err = sqliteBlobs(data)
	case isNDB(data):
		blobs, err = ndbBlobs(data)
	case isBDB(data):
		blobs, err = bdbBlobs(data)
	default:
		return nil, ErrUnsupportedFormat
	}
	if err != nil {
		return nil, fmt.Errorf("Read: %w", err)
	}
	out := make([]Package, 0, len(blobs))
	for i, b := range blobs {
		p, err := parseHeader(b)
		if err != nil {
			return nil, fmt.Errorf("Read: header %d: %w", i, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// rpm header tags and data types (rpm's lib/rpmtag.h).
const (
	tagName      = 1000
	tagVersion   = 1001
	tagRelease   = 1002
	tagEpoch     = 1003
	tagArch      = 1022
	tagSourceRPM = 1044

	typeInt32  = 4
	typeString = 6
)

// Header bounds, as rpm enforces them (lib/header.c): a header with more
// entries or data than this is corrupt, not large.
const (
	maxHeaderEntries = 0xffff
	maxHeaderData    = 256 << 20
	headerEntrySize  = 16
)

// parseHeader reads the identity tags out of one header blob as rpm stores it
// in its database: a big-endian entry count and data length, the entry index
// (tag, type, offset, count), then the data segment the offsets point into.
// The other tags, and the signature/immutable-region bookkeeping, are not read.
func parseHeader(blob []byte) (Package, error) {
	if len(blob) < 8 {
		return Package{}, errors.New("header shorter than its preamble")
	}
	il := binary.BigEndian.Uint32(blob[0:4])
	dl := binary.BigEndian.Uint32(blob[4:8])
	if il == 0 || il > maxHeaderEntries || dl > maxHeaderData {
		return Package{}, fmt.Errorf("header claims %d entries and %d data bytes", il, dl)
	}
	dataStart := 8 + uint64(il)*headerEntrySize
	if dataStart+uint64(dl) > uint64(len(blob)) {
		return Package{}, fmt.Errorf("header of %d bytes is truncated (needs %d)", len(blob), dataStart+uint64(dl))
	}
	data := blob[dataStart : dataStart+uint64(dl)]

	var p Package
	for i := uint64(0); i < uint64(il); i++ {
		e := blob[8+i*headerEntrySize : 8+(i+1)*headerEntrySize]
		tag := binary.BigEndian.Uint32(e[0:4])
		typ := binary.BigEndian.Uint32(e[4:8])
		off := binary.BigEndian.Uint32(e[8:12])
		var dst *string
		switch tag {
		case tagName:
			dst = &p.Name
		case tagVersion:
			dst = &p.Version
		case tagRelease:
			dst = &p.Release
		case tagArch:
			dst = &p.Arch
		case tagSourceRPM:
			dst = &p.SourceRPM
		case tagEpoch:
			dst = &p.Epoch
		default:
			continue
		}
		v, err := tagValue(data, typ, off)
		if err != nil {
			return Package{}, fmt.Errorf("tag %d: %w", tag, err)
		}
		*dst = v
	}
	if p.Name == "" || p.Version == "" {
		return Package{}, errors.New("header has no NAME or VERSION")
	}
	if p.SourceRPM == "(none)" { // how gpg-pubkey headers spell "no source package"
		p.SourceRPM = ""
	}
	return p, nil
}

// tagValue reads one STRING (NUL-terminated) or INT32 (big-endian) value.
func tagValue(data []byte, typ, off uint32) (string, error) {
	if uint64(off) >= uint64(len(data)) {
		return "", fmt.Errorf("offset %d outside the %d-byte data segment", off, len(data))
	}
	switch typ {
	case typeString:
		end := bytes.IndexByte(data[off:], 0)
		if end < 0 {
			return "", errors.New("unterminated string")
		}
		return string(data[off : off+uint32(end)]), nil
	case typeInt32:
		if uint64(off)+4 > uint64(len(data)) {
			return "", errors.New("truncated int32")
		}
		return strconv.FormatUint(uint64(binary.BigEndian.Uint32(data[off:off+4])), 10), nil
	}
	return "", fmt.Errorf("unexpected type %d", typ)
}
