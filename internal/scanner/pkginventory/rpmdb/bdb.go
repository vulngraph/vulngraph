package rpmdb

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The Berkeley DB backend stores headers in a hash database keyed by package
// instance number. Only the hash access method's on-disk pages are read
// (Berkeley DB's dbinc/db_page.h): the metadata page, the hash pages listing
// key/data pairs, and the overflow pages a large item is chained across. The
// environment files beside it (__db.001…) are a cache of the same data and
// are not needed once rpm has closed the database.

const (
	bdbHashMagic = 0x00061561

	bdbPageHashMeta     = 8
	bdbPageHashUnsorted = 2 // hash pages written before Berkeley DB 4.6 (RHEL 5)
	bdbPageHash         = 13
	bdbPageOverflow     = 7

	bdbItemKeyData = 1 // H_KEYDATA: the item's bytes follow on the page
	bdbItemOffPage = 3 // H_OFFPAGE: the item lives on a chain of overflow pages

	bdbPageHeaderSize = 26
)

func isBDB(data []byte) bool {
	if len(data) < 16 {
		return false
	}
	return binary.LittleEndian.Uint32(data[12:16]) == bdbHashMagic ||
		binary.BigEndian.Uint32(data[12:16]) == bdbHashMagic
}

// bdbBlobs returns the data item of every key/data pair in the hash database.
func bdbBlobs(data []byte) ([][]byte, error) {
	var order binary.ByteOrder = binary.LittleEndian
	if binary.LittleEndian.Uint32(data[12:16]) != bdbHashMagic {
		order = binary.BigEndian
	}
	if len(data) < 512 {
		return nil, errors.New("bdb: file shorter than its metadata page")
	}
	pageSize := int(order.Uint32(data[20:24]))
	if pageSize < 512 || pageSize > 65536 || pageSize&(pageSize-1) != 0 {
		return nil, fmt.Errorf("bdb: invalid page size %d", pageSize)
	}
	if data[24] != 0 {
		return nil, errors.New("bdb: encrypted database")
	}
	if data[25] != bdbPageHashMeta {
		return nil, fmt.Errorf("bdb: first page has type %d, not hash metadata", data[25])
	}
	last := int(order.Uint32(data[32:36]))
	if (last+1)*pageSize > len(data) {
		return nil, fmt.Errorf("bdb: %d pages declared, file holds %d", last+1, len(data)/pageSize)
	}
	db := bdbFile{data: data, order: order, pageSize: pageSize, last: last, items: &budget{left: len(data)}}

	var blobs [][]byte
	for n := 1; n <= last; n++ {
		pg := db.page(n)
		if t := pg[25]; t != bdbPageHash && t != bdbPageHashUnsorted {
			continue
		}
		items, err := db.pageItems(pg)
		if err != nil {
			return nil, fmt.Errorf("bdb: page %d: %w", n, err)
		}
		blobs = append(blobs, items...)
	}
	return blobs, nil
}

type bdbFile struct {
	data     []byte
	order    binary.ByteOrder
	pageSize int
	last     int
	items    *budget
}

func (db bdbFile) page(n int) []byte {
	return db.data[n*db.pageSize : (n+1)*db.pageSize]
}

// pageItems returns the data item of each key/data pair on one hash page. The
// page's index lists item offsets, keys at even positions and their data at
// odd ones; items are packed down from the end of the page, so an on-page
// item ends where the previous one starts.
//
// rpm keeps one pair that is not a package: key 0 holds the next instance
// number to allocate, a four-byte on-page value. It is skipped by its key.
func (db bdbFile) pageItems(pg []byte) ([][]byte, error) {
	entries := int(db.order.Uint16(pg[20:22]))
	if entries%2 != 0 {
		return nil, fmt.Errorf("odd index count %d", entries)
	}
	if bdbPageHeaderSize+2*entries > len(pg) {
		return nil, errors.New("index overruns the page")
	}
	offset := func(i int) int { return int(db.order.Uint16(pg[bdbPageHeaderSize+2*i:])) }
	itemEnd := func(i int) int {
		if i == 0 {
			return len(pg)
		}
		return offset(i - 1)
	}

	var out [][]byte
	for k := 0; k < entries; k += 2 {
		// Each item holds at least its type byte and ends where the previous
		// one starts: data below its key, the key below the previous pair.
		kOff, dOff, kEnd := offset(k), offset(k+1), itemEnd(k)
		if dOff < bdbPageHeaderSize+2*entries || dOff >= kOff || kOff >= kEnd || kEnd > len(pg) {
			return nil, fmt.Errorf("pair %d outside the page", k/2)
		}
		if pg[kOff] == bdbItemKeyData && isZeroKey(pg[kOff+1:kEnd]) {
			continue
		}
		switch pg[dOff] {
		case bdbItemOffPage:
			v, err := db.overflow(pg[dOff:kOff])
			if err != nil {
				return nil, fmt.Errorf("pair %d: %w", k/2, err)
			}
			out = append(out, v)
		case bdbItemKeyData:
			v := pg[dOff+1 : kOff]
			if err := db.items.take(len(v)); err != nil {
				return nil, err
			}
			out = append(out, v)
		default:
			return nil, fmt.Errorf("pair %d: unsupported item type %d", k/2, pg[dOff])
		}
	}
	return out, nil
}

func isZeroKey(k []byte) bool {
	return len(k) == 4 && k[0]|k[1]|k[2]|k[3] == 0
}

// overflow follows an H_OFFPAGE item's chain: each overflow page holds its
// share of the item after the page header, its length in the header's
// free-offset field, and the next page's number.
func (db bdbFile) overflow(item []byte) ([]byte, error) {
	if len(item) < 12 {
		return nil, errors.New("truncated off-page item")
	}
	next := int(db.order.Uint32(item[4:8]))
	total := int(db.order.Uint32(item[8:12]))
	if total > len(db.data) {
		return nil, fmt.Errorf("off-page item of %d bytes exceeds the file", total)
	}
	if err := db.items.take(total); err != nil {
		return nil, err
	}
	out := make([]byte, 0, total)
	for hops := 0; next != 0; hops++ {
		if hops > db.last || next > db.last {
			return nil, fmt.Errorf("overflow chain broken at page %d", next)
		}
		pg := db.page(next)
		if pg[25] != bdbPageOverflow {
			return nil, fmt.Errorf("page %d in an overflow chain has type %d", next, pg[25])
		}
		n := int(db.order.Uint16(pg[22:24]))
		if bdbPageHeaderSize+n > len(pg) {
			return nil, fmt.Errorf("overflow page %d claims %d bytes", next, n)
		}
		if len(out)+n > total {
			return nil, fmt.Errorf("overflow chain holds more than the item's %d bytes", total)
		}
		out = append(out, pg[bdbPageHeaderSize:bdbPageHeaderSize+n]...)
		next = int(db.order.Uint32(pg[16:20]))
	}
	if len(out) != total {
		return nil, fmt.Errorf("off-page item is %d bytes, chain holds %d", total, len(out))
	}
	return out, nil
}
