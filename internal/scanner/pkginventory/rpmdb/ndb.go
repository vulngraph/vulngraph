package rpmdb

import (
	"encoding/binary"
	"fmt"
)

// The ndb backend (rpm's lib/backend/ndb/rpmpkg.c) is a 32-byte header, then
// slot pages of 16-byte slots, each naming a package and where its blob
// starts, in 16-byte blocks from the start of the file. A blob is a 16-byte
// header (magic, package index, checksum, length) and the rpm header itself.

const (
	ndbHeaderMagic = 'R' | 'p'<<8 | 'm'<<16 | 'P'<<24
	ndbSlotMagic   = 'S' | 'l'<<8 | 'o'<<16 | 't'<<24
	ndbBlobMagic   = 'B' | 'l'<<8 | 'b'<<16 | 'S'<<24

	ndbSlotPageSize = 4096
	ndbSlotSize     = 16
	ndbBlockSize    = 16
	ndbHeaderSize   = 32
	ndbMaxSlotPages = 2048 // rpm's own sanity bound
)

func isNDB(data []byte) bool {
	return len(data) >= 4 && binary.LittleEndian.Uint32(data[0:4]) == ndbHeaderMagic
}

// ndbBlobs returns the header blob of every occupied slot.
func ndbBlobs(data []byte) ([][]byte, error) {
	if len(data) < ndbHeaderSize {
		return nil, fmt.Errorf("ndb: file shorter than its header")
	}
	if v := binary.LittleEndian.Uint32(data[4:8]); v != 0 {
		return nil, fmt.Errorf("ndb: unsupported version %d", v)
	}
	slotPages := int(binary.LittleEndian.Uint32(data[12:16]))
	if slotPages == 0 || slotPages > ndbMaxSlotPages || slotPages*ndbSlotPageSize > len(data) {
		return nil, fmt.Errorf("ndb: %d slot pages in a %d-byte file", slotPages, len(data))
	}
	var blobs [][]byte
	blobBytes := budget{left: len(data)}
	// The header occupies the first two slots of the first page.
	for off := ndbHeaderSize; off < slotPages*ndbSlotPageSize; off += ndbSlotSize {
		s := data[off : off+ndbSlotSize]
		if binary.LittleEndian.Uint32(s[0:4]) != ndbSlotMagic {
			return nil, fmt.Errorf("ndb: bad slot magic at offset %d", off)
		}
		pkg := binary.LittleEndian.Uint32(s[4:8])
		if pkg == 0 {
			continue // free slot
		}
		blk := uint64(binary.LittleEndian.Uint32(s[8:12])) * ndbBlockSize
		if blk+16 > uint64(len(data)) {
			return nil, fmt.Errorf("ndb: package %d blob outside the file", pkg)
		}
		b := data[blk : blk+16]
		if binary.LittleEndian.Uint32(b[0:4]) != ndbBlobMagic || binary.LittleEndian.Uint32(b[4:8]) != pkg {
			return nil, fmt.Errorf("ndb: package %d blob header does not match its slot", pkg)
		}
		n := uint64(binary.LittleEndian.Uint32(b[12:16]))
		if blk+16+n > uint64(len(data)) {
			return nil, fmt.Errorf("ndb: package %d blob of %d bytes overruns the file", pkg, n)
		}
		if err := blobBytes.take(int(n)); err != nil {
			return nil, fmt.Errorf("ndb: %w", err)
		}
		blobs = append(blobs, data[blk+16:blk+16+n])
	}
	return blobs, nil
}
