// Package disktest builds tiny in-memory disk images (MBR, GPT, ext4) for the
// disk-scan tests. It is test support only: no production package imports it.
package disktest

import (
	"encoding/binary"
	"hash/crc32"
	"io"
	"sort"
	"unicode/utf16"
)

// Mem is an in-memory BlockSource. Ranges listed in Unreadable fail with Err.
type Mem struct {
	Data       []byte
	Unreadable []Range
	Err        error
	Reads      int
}

// Range is a half-open byte range.
type Range struct{ Off, Len int64 }

func (m *Mem) ReadAt(p []byte, off int64) (int, error) {
	m.Reads++
	for _, u := range m.Unreadable {
		if off < u.Off+u.Len && off+int64(len(p)) > u.Off {
			return 0, m.Err
		}
	}
	if off < 0 || off >= int64(len(m.Data)) {
		return 0, io.EOF
	}
	n := copy(p, m.Data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (m *Mem) Size() int64  { return int64(len(m.Data)) }
func (m *Mem) Close() error { return nil }

// Part is one partition to place on a disk: its contents and type.
type Part struct {
	Data    []byte
	MBRType byte
	GPTType [16]byte // raw on-disk GUID bytes; see GUID
}

// GUID returns the on-disk (mixed-endian) bytes of a GUID given as its three
// leading little-endian fields and trailing eight bytes.
func GUID(a uint32, b, c uint16, tail [8]byte) [16]byte {
	var g [16]byte
	binary.LittleEndian.PutUint32(g[0:], a)
	binary.LittleEndian.PutUint16(g[4:], b)
	binary.LittleEndian.PutUint16(g[6:], c)
	copy(g[8:], tail[:])
	return g
}

// Linux filesystem data, LVM and RAID GPT type GUIDs.
var (
	GUIDLinux = GUID(0x0FC63DAF, 0x8483, 0x4772, [8]byte{0x8E, 0x79, 0x3D, 0x69, 0xD8, 0x47, 0x7D, 0xE4})
	GUIDLVM   = GUID(0xE6D6D379, 0xF507, 0x44C2, [8]byte{0xA2, 0x3C, 0x23, 0x8F, 0x2A, 0x3D, 0xF9, 0x28})
	GUIDRAID  = GUID(0xA19D880F, 0x05FC, 0x4D3B, [8]byte{0xA0, 0x06, 0x74, 0x3F, 0x0F, 0x84, 0x91, 0x1E})
)

const (
	sector     = 512
	firstLBA   = 2048
	gptEntries = 128
)

// MBRDisk lays the partitions out behind an MBR table, 1 MiB aligned.
func MBRDisk(parts ...Part) []byte {
	img := make([]byte, sector)
	var off int64 = firstLBA * sector
	for i, p := range parts {
		img = grow(img, off+int64(len(p.Data)))
		copy(img[off:], p.Data)
		e := img[446+i*16:]
		e[4] = p.MBRType
		binary.LittleEndian.PutUint32(e[8:], uint32(off/sector))
		binary.LittleEndian.PutUint32(e[12:], uint32(len(p.Data)/sector))
		off = align(off + int64(len(p.Data)))
	}
	img[510], img[511] = 0x55, 0xAA
	return img
}

// GPTDisk lays the partitions out behind a protective MBR and a GPT with a
// backup header at the end of the disk.
func GPTDisk(parts ...Part) []byte {
	img := make([]byte, firstLBA*sector)
	table := make([]byte, gptEntries*128)
	var off int64 = firstLBA * sector
	for i, p := range parts {
		img = grow(img, off+int64(len(p.Data)))
		copy(img[off:], p.Data)
		e := table[i*128:]
		copy(e[0:], p.GPTType[:])
		e[16] = byte(i + 1)
		binary.LittleEndian.PutUint64(e[32:], uint64(off/sector))
		binary.LittleEndian.PutUint64(e[40:], uint64((off+int64(len(p.Data)))/sector-1))
		for j, r := range utf16.Encode([]rune("part")) {
			binary.LittleEndian.PutUint16(e[56+j*2:], r)
		}
		off = align(off + int64(len(p.Data)))
	}
	img = grow(img, off+int64(len(table))+sector)
	total := int64(len(img)) / sector
	copy(img[1*sector:], gptHeader(1, uint64(total-1), 2, table, total))
	copy(img[2*sector:], table)
	backupTable := (total - 1 - int64(len(table))/sector) * sector
	copy(img[backupTable:], table)
	copy(img[(total-1)*sector:], gptHeader(uint64(total-1), 1, uint64(total-1)-uint64(len(table))/sector, table, total))

	e := img[446:]
	e[4] = 0xEE
	binary.LittleEndian.PutUint32(e[8:], 1)
	binary.LittleEndian.PutUint32(e[12:], uint32(total-1))
	img[510], img[511] = 0x55, 0xAA
	return img
}

func gptHeader(self, other, entries uint64, table []byte, total int64) []byte {
	h := make([]byte, 92)
	copy(h, "EFI PART")
	le := binary.LittleEndian
	le.PutUint32(h[8:], 0x00010000)
	le.PutUint32(h[12:], 92)
	le.PutUint64(h[24:], self)
	le.PutUint64(h[32:], other)
	le.PutUint64(h[40:], firstLBA)
	le.PutUint64(h[48:], uint64(total)-34)
	le.PutUint64(h[72:], entries)
	le.PutUint32(h[80:], gptEntries)
	le.PutUint32(h[84:], 128)
	le.PutUint32(h[88:], crc32.ChecksumIEEE(table))
	le.PutUint32(h[16:], crc32.ChecksumIEEE(h))
	return h
}

// SortedKeys returns the keys of m in order, for deterministic image layout.
func SortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func grow(b []byte, n int64) []byte {
	if int64(len(b)) >= n {
		return b
	}
	return append(b, make([]byte, n-int64(len(b)))...)
}

func align(n int64) int64 { return (n + 1<<20 - 1) &^ (1<<20 - 1) }
