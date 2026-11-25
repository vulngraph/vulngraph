package rpmdb

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// The SQLite backend keeps every header in one table,
//
//	CREATE TABLE Packages (hnum INTEGER PRIMARY KEY AUTOINCREMENT, blob BLOB NOT NULL)
//
// so reading it needs only SQLite's table B-tree, record and overflow-page
// formats (https://www.sqlite.org/fileformat2.html) — not a SQL engine, which
// in pure Go is several megabytes of transpiled C.
//
// The main database file is read as it stands. rpm runs SQLite in WAL mode and
// a clean close checkpoints the log into it; a log that still holds frames is
// the caller's to detect, since it is a separate file.

var sqliteMagic = []byte("SQLite format 3\x00")

func isSQLite(data []byte) bool { return bytes.HasPrefix(data, sqliteMagic) }

// sqliteFile is a database file split into pages.
type sqliteFile struct {
	data     []byte
	pageSize int
	usable   int // page size minus the per-page reserved bytes
	nPages   int
	payloads budget
}

const (
	pageLeafTable     = 0x0d
	pageInteriorTable = 0x05
	sqliteHeaderSize  = 100
	textUTF8          = 1
)

func openSQLite(data []byte) (*sqliteFile, error) {
	if len(data) < sqliteHeaderSize {
		return nil, errors.New("sqlite: file shorter than its header")
	}
	pageSize := int(binary.BigEndian.Uint16(data[16:18]))
	if pageSize == 1 {
		pageSize = 65536
	}
	if pageSize < 512 || pageSize&(pageSize-1) != 0 {
		return nil, fmt.Errorf("sqlite: invalid page size %d", pageSize)
	}
	usable := pageSize - int(data[20])
	if usable < 480 {
		return nil, fmt.Errorf("sqlite: usable page size %d below the format minimum", usable)
	}
	if enc := binary.BigEndian.Uint32(data[56:60]); enc != textUTF8 {
		return nil, fmt.Errorf("sqlite: text encoding %d is not UTF-8", enc)
	}
	return &sqliteFile{data: data, pageSize: pageSize, usable: usable, nPages: len(data) / pageSize,
		payloads: budget{left: len(data)}}, nil
}

func (f *sqliteFile) page(n uint32) ([]byte, error) {
	if n == 0 || int(n) > f.nPages {
		return nil, fmt.Errorf("sqlite: page %d outside the %d-page file", n, f.nPages)
	}
	start := (int(n) - 1) * f.pageSize
	return f.data[start : start+f.pageSize], nil
}

// sqliteBlobs returns the blob column of every row of the Packages table.
func sqliteBlobs(data []byte) ([][]byte, error) {
	f, err := openSQLite(data)
	if err != nil {
		return nil, err
	}
	root, err := f.tableRoot("Packages")
	if err != nil {
		return nil, err
	}
	var blobs [][]byte
	err = f.walkTable(root, func(payload []byte) error {
		cols, err := parseRecord(payload)
		if err != nil {
			return err
		}
		// hnum is the rowid alias and is stored as NULL; the blob is column 1.
		if len(cols) < 2 || !cols[1].isBlob() {
			return errors.New("sqlite: Packages row has no blob column")
		}
		blobs = append(blobs, cols[1].data)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return blobs, nil
}

// tableRoot finds a table's root page in the schema table (page 1), whose
// rows are (type, name, tbl_name, rootpage, sql).
func (f *sqliteFile) tableRoot(name string) (uint32, error) {
	var root uint32
	err := f.walkTable(1, func(payload []byte) error {
		cols, err := parseRecord(payload)
		if err != nil {
			return err
		}
		if len(cols) < 4 || string(cols[0].data) != "table" || string(cols[1].data) != name {
			return nil
		}
		n, ok := cols[3].int()
		if !ok || n <= 0 {
			return fmt.Errorf("sqlite: table %s has no valid root page", name)
		}
		root = uint32(n)
		return nil
	})
	if err != nil {
		return 0, err
	}
	if root == 0 {
		return 0, fmt.Errorf("sqlite: no %s table", name)
	}
	return root, nil
}

// walkTable visits every row payload of the table B-tree rooted at root. Each
// page is visited at most once, so a corrupt file whose child pointers form a
// cycle errors instead of looping.
func (f *sqliteFile) walkTable(root uint32, visit func(payload []byte) error) error {
	seen := map[uint32]bool{}
	stack := []uint32{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[n] {
			return fmt.Errorf("sqlite: page %d reached twice", n)
		}
		seen[n] = true
		pg, err := f.page(n)
		if err != nil {
			return err
		}
		hdr := 0
		if n == 1 {
			hdr = sqliteHeaderSize
		}
		if len(pg) < hdr+12 {
			return fmt.Errorf("sqlite: page %d too short", n)
		}
		kind := pg[hdr]
		cells := int(binary.BigEndian.Uint16(pg[hdr+3 : hdr+5]))
		ptrs := hdr + 8
		switch kind {
		case pageInteriorTable:
			ptrs = hdr + 12
			stack = append(stack, binary.BigEndian.Uint32(pg[hdr+8:hdr+12]))
		case pageLeafTable:
		default:
			return fmt.Errorf("sqlite: page %d has type %#x, not a table B-tree page", n, kind)
		}
		if ptrs+2*cells > len(pg) {
			return fmt.Errorf("sqlite: page %d cell pointers overrun the page", n)
		}
		for i := 0; i < cells; i++ {
			off := int(binary.BigEndian.Uint16(pg[ptrs+2*i:]))
			if off >= len(pg) {
				return fmt.Errorf("sqlite: page %d cell %d outside the page", n, i)
			}
			if kind == pageInteriorTable {
				if off+4 > len(pg) {
					return fmt.Errorf("sqlite: page %d cell %d truncated", n, i)
				}
				stack = append(stack, binary.BigEndian.Uint32(pg[off:off+4]))
				continue
			}
			payload, err := f.leafPayload(pg, off)
			if err != nil {
				return fmt.Errorf("sqlite: page %d cell %d: %w", n, i, err)
			}
			if err := visit(payload); err != nil {
				return err
			}
		}
	}
	return nil
}

// leafPayload assembles one table-leaf cell's payload: a size varint, the
// rowid varint, the bytes stored on the page, then — for a payload too large
// for the page — the rest from a chain of overflow pages.
func (f *sqliteFile) leafPayload(pg []byte, off int) ([]byte, error) {
	size, n := varint(pg[off:])
	if n == 0 {
		return nil, errors.New("bad payload size")
	}
	off += n
	if _, n = varint(pg[off:]); n == 0 {
		return nil, errors.New("bad rowid")
	}
	off += n
	if size > uint64(len(f.data)) {
		return nil, fmt.Errorf("payload of %d bytes exceeds the file", size)
	}
	total := int(size)
	if err := f.payloads.take(total); err != nil {
		return nil, err
	}
	local := f.localPayload(total)
	if off+local > len(pg) {
		return nil, errors.New("payload overruns the page")
	}
	if local == total {
		return pg[off : off+local], nil
	}
	if off+local+4 > len(pg) {
		return nil, errors.New("overflow pointer overruns the page")
	}
	out := make([]byte, 0, total)
	out = append(out, pg[off:off+local]...)
	next := binary.BigEndian.Uint32(pg[off+local:])
	for hops := 0; len(out) < total; hops++ {
		if hops > f.nPages {
			return nil, errors.New("overflow chain longer than the file")
		}
		ov, err := f.page(next)
		if err != nil {
			return nil, fmt.Errorf("overflow: %w", err)
		}
		chunk := min(total-len(out), f.usable-4)
		out = append(out, ov[4:4+chunk]...)
		next = binary.BigEndian.Uint32(ov[0:4])
	}
	return out, nil
}

// localPayload is how much of a table-leaf payload is stored on the page
// itself (the file format's X/M/K rule); the remainder overflows.
func (f *sqliteFile) localPayload(total int) int {
	x := f.usable - 35
	if total <= x {
		return total
	}
	m := (f.usable-12)*32/255 - 23
	k := m + (total-m)%(f.usable-4)
	if k <= x {
		return k
	}
	return m
}

// column is one value of a record: its serial type and its bytes.
type column struct {
	serial uint64
	data   []byte
}

func (c column) isBlob() bool { return c.serial >= 12 && c.serial%2 == 0 }

// int decodes an integer column (serial types 1–6 big-endian two's
// complement, 8 and 9 the constants 0 and 1).
func (c column) int() (int64, bool) {
	switch c.serial {
	case 8:
		return 0, true
	case 9:
		return 1, true
	case 1, 2, 3, 4, 5, 6:
		var v int64
		for i, b := range c.data {
			if i == 0 {
				v = int64(int8(b))
				continue
			}
			v = v<<8 | int64(b)
		}
		return v, true
	}
	return 0, false
}

// serialSize is the byte length of a value of the given serial type.
func serialSize(serial uint64) (int, bool) {
	switch {
	case serial == 0 || serial == 8 || serial == 9:
		return 0, true
	case serial >= 1 && serial <= 4:
		return int(serial), true
	case serial == 5:
		return 6, true
	case serial == 6 || serial == 7:
		return 8, true
	case serial >= 12:
		return int((serial - 12) / 2), true
	}
	return 0, false
}

// parseRecord splits a record into its columns: a header (its own length, then
// one serial type per column) followed by the column bodies in order.
func parseRecord(rec []byte) ([]column, error) {
	hdrLen, n := varint(rec)
	if n == 0 || hdrLen > uint64(len(rec)) || hdrLen < uint64(n) {
		return nil, errors.New("sqlite: bad record header")
	}
	var cols []column
	body := int(hdrLen)
	for pos := n; pos < int(hdrLen); {
		serial, m := varint(rec[pos:int(hdrLen)])
		if m == 0 {
			return nil, errors.New("sqlite: bad serial type")
		}
		pos += m
		size, ok := serialSize(serial)
		if !ok || body+size > len(rec) {
			return nil, fmt.Errorf("sqlite: column of serial type %d overruns the record", serial)
		}
		cols = append(cols, column{serial: serial, data: rec[body : body+size]})
		body += size
	}
	return cols, nil
}

// varint decodes SQLite's big-endian variable-length integer: up to eight
// bytes of seven bits each, then a ninth contributing all eight. n is 0 when
// the input ends mid-varint.
func varint(b []byte) (v uint64, n int) {
	for i := 0; i < 9 && i < len(b); i++ {
		if i == 8 {
			return v<<8 | uint64(b[i]), 9
		}
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return v, i + 1
		}
	}
	return 0, 0
}
