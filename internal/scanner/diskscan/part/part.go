// Package part reads MBR and GPT partition tables from untrusted disk images.
// It lists partitions and says which ones it cannot interpret (LVM, RAID,
// extended and Windows dynamic volumes); it never guesses their contents.
package part

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
)

var (
	// ErrNoTable means the disk carries no MBR or GPT: it may be a bare filesystem.
	ErrNoTable = errors.New("part: no partition table")
	// ErrCorrupt means a table is present but unusable.
	ErrCorrupt = errors.New("part: corrupt partition table")
)

// Reasons a partition is listed but cannot be read.
const (
	ReasonLVM      = "lvm"
	ReasonRAID     = "raid"
	ReasonExtended = "extended"
	ReasonWindows  = "windows_dynamic"
	ReasonInvalid  = "invalid_range"
)

// Partition is one table entry. Offset and Size are bytes. Unsupported is empty
// for a partition worth probing for a filesystem.
type Partition struct {
	Number      int
	Offset      int64
	Size        int64
	Type        string
	Unsupported string
}

const (
	mbrSize         = 512
	gptMaxEntries   = 1024
	gptMaxEntryLen  = 4096
	gptMaxTableSize = 1 << 20
	gptHeaderMin    = 92
)

var (
	lvmGUID     = "e6d6d379-f507-44c2-a23c-238f2a3df928"
	raidGUID    = "a19d880f-05fc-4d3b-a006-743f0f84911e"
	windowsGUID = map[string]bool{
		"5808c8aa-7e8f-42e0-85d2-e1e90434cfb3": true, // LDM metadata
		"af9b60a0-1431-4f62-bc68-3311714a69ad": true, // LDM data
	}
)

// Read lists the partitions of the disk behind r, size bytes long. A GPT is
// preferred over its protective MBR. ErrNoTable means no table was found.
func Read(r io.ReaderAt, size int64) ([]Partition, error) {
	var mbr [mbrSize]byte
	if err := readFull(r, mbr[:], 0); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, ErrNoTable
		}
		return nil, fmt.Errorf("part.Read: mbr: %w", err)
	}
	for _, sector := range []int64{512, 4096} {
		var sig [8]byte
		if err := readFull(r, sig[:], sector); err == nil && string(sig[:]) == "EFI PART" {
			return readGPT(r, size, sector)
		} else if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("part.Read: gpt probe: %w", err)
		}
	}
	return readMBR(mbr[:], size)
}

func readMBR(mbr []byte, size int64) ([]Partition, error) {
	if mbr[510] != 0x55 || mbr[511] != 0xAA {
		return nil, ErrNoTable
	}
	var out []Partition
	for i := 0; i < 4; i++ {
		e := mbr[446+i*16 : 446+i*16+16]
		if e[0] != 0 && e[0] != 0x80 {
			return nil, ErrNoTable // a FAT boot sector, not a table
		}
		typ := e[4]
		first := int64(binary.LittleEndian.Uint32(e[8:]))
		count := int64(binary.LittleEndian.Uint32(e[12:]))
		if typ == 0 || count == 0 {
			continue
		}
		p := Partition{Number: i + 1, Offset: first * 512, Size: count * 512, Type: fmt.Sprintf("%02x", typ)}
		switch typ {
		case 0x8E:
			p.Unsupported = ReasonLVM
		case 0xFD:
			p.Unsupported = ReasonRAID
		case 0x05, 0x0F, 0x85:
			p.Unsupported = ReasonExtended
		case 0x42:
			p.Unsupported = ReasonWindows
		}
		if p.Unsupported == "" && p.Offset+p.Size > size {
			p.Unsupported = ReasonInvalid
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil, ErrNoTable
	}
	if len(out) == 1 && out[0].Type == "ee" {
		return nil, fmt.Errorf("part.Read: protective MBR without a GPT: %w", ErrCorrupt)
	}
	return out, nil
}

type gptHeader struct {
	entriesLBA, count, entryLen uint64
	entriesCRC                  uint32
}

func readGPT(r io.ReaderAt, size, sector int64) ([]Partition, error) {
	primary, err := gptHeaderAt(r, sector, sector)
	if err != nil && !errors.Is(err, ErrCorrupt) {
		return nil, err
	}
	if err != nil {
		backup, berr := gptHeaderAt(r, (size/sector-1)*sector, sector)
		if berr != nil {
			if errors.Is(berr, ErrCorrupt) {
				return nil, fmt.Errorf("part.Read: primary and backup GPT headers invalid: %w", ErrCorrupt)
			}
			return nil, berr
		}
		primary = backup
	}
	if primary.count == 0 || primary.count > gptMaxEntries || primary.entryLen < 128 ||
		primary.entryLen > gptMaxEntryLen || primary.entryLen%8 != 0 ||
		primary.count*primary.entryLen > gptMaxTableSize ||
		primary.entriesLBA > uint64(size/sector) {
		return nil, fmt.Errorf("part.Read: gpt entry array %dx%d: %w", primary.count, primary.entryLen, ErrCorrupt)
	}
	table := make([]byte, primary.count*primary.entryLen)
	if err := readFull(r, table, int64(primary.entriesLBA)*sector); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("part.Read: gpt entries beyond the disk: %w", ErrCorrupt)
		}
		return nil, fmt.Errorf("part.Read: gpt entries: %w", err)
	}
	if crc32.ChecksumIEEE(table) != primary.entriesCRC {
		return nil, fmt.Errorf("part.Read: gpt entry checksum: %w", ErrCorrupt)
	}
	var out []Partition
	zero := make([]byte, 16)
	for i := uint64(0); i < primary.count; i++ {
		e := table[i*primary.entryLen : (i+1)*primary.entryLen]
		if bytes.Equal(e[:16], zero) {
			continue
		}
		first := binary.LittleEndian.Uint64(e[32:])
		last := binary.LittleEndian.Uint64(e[40:])
		guid := guidString(e[:16])
		p := Partition{Number: int(i) + 1, Type: guid}
		switch {
		case guid == lvmGUID:
			p.Unsupported = ReasonLVM
		case guid == raidGUID:
			p.Unsupported = ReasonRAID
		case windowsGUID[guid]:
			p.Unsupported = ReasonWindows
		}
		if last < first || last >= uint64(size/sector) || first > uint64(size) {
			p.Unsupported = ReasonInvalid
		} else {
			p.Offset = int64(first) * sector
			p.Size = int64(last-first+1) * sector
		}
		out = append(out, p)
	}
	return out, nil
}

func gptHeaderAt(r io.ReaderAt, off, sector int64) (gptHeader, error) {
	var h [gptHeaderMin]byte
	if err := readFull(r, h[:], off); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return gptHeader{}, fmt.Errorf("part.Read: gpt header beyond the disk: %w", ErrCorrupt)
		}
		return gptHeader{}, fmt.Errorf("part.Read: gpt header: %w", err)
	}
	le := binary.LittleEndian
	hdrSize := int64(le.Uint32(h[12:]))
	if string(h[:8]) != "EFI PART" || hdrSize < gptHeaderMin || hdrSize > sector {
		return gptHeader{}, fmt.Errorf("part.Read: gpt header: %w", ErrCorrupt)
	}
	full := make([]byte, hdrSize)
	if err := readFull(r, full, off); err != nil {
		return gptHeader{}, fmt.Errorf("part.Read: gpt header: %w", ErrCorrupt)
	}
	want := le.Uint32(full[16:])
	clear(full[16:20])
	if crc32.ChecksumIEEE(full) != want {
		return gptHeader{}, fmt.Errorf("part.Read: gpt header checksum: %w", ErrCorrupt)
	}
	return gptHeader{
		entriesLBA: le.Uint64(full[72:]),
		count:      uint64(le.Uint32(full[80:])),
		entryLen:   uint64(le.Uint32(full[84:])),
		entriesCRC: le.Uint32(full[88:]),
	}, nil
}

// guidString renders a GPT mixed-endian GUID in canonical lowercase form.
func guidString(b []byte) string {
	le := binary.LittleEndian
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", le.Uint32(b[0:]), le.Uint16(b[4:]), le.Uint16(b[6:]), b[8:10], b[10:16])
}

func readFull(r io.ReaderAt, p []byte, off int64) error {
	if off < 0 {
		return io.ErrUnexpectedEOF
	}
	n, err := r.ReadAt(p, off)
	if n == len(p) {
		return nil
	}
	if err == nil || errors.Is(err, io.EOF) {
		return io.ErrUnexpectedEOF
	}
	return err
}
