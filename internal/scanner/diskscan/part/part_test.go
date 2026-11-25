package part_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/disktest"
	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/part"
)

func blob(n int, fill byte) []byte { return bytes.Repeat([]byte{fill}, n) }

func read(t *testing.T, img []byte) ([]part.Partition, error) {
	t.Helper()
	return part.Read(bytes.NewReader(img), int64(len(img)))
}

func TestMBR(t *testing.T) {
	img := disktest.MBRDisk(
		disktest.Part{Data: blob(4096, 1), MBRType: 0x83},
		disktest.Part{Data: blob(2048, 2), MBRType: 0x8E},
		disktest.Part{Data: blob(2048, 3), MBRType: 0xFD},
		disktest.Part{Data: blob(2048, 4), MBRType: 0x05},
	)
	parts, err := read(t, img)
	require.NoError(t, err)
	require.Len(t, parts, 4)
	assert.Equal(t, part.Partition{Number: 1, Offset: 1 << 20, Size: 4096, Type: "83"}, parts[0])
	assert.Equal(t, part.ReasonLVM, parts[1].Unsupported)
	assert.Equal(t, part.ReasonRAID, parts[2].Unsupported)
	assert.Equal(t, part.ReasonExtended, parts[3].Unsupported)
}

func TestMBRPartitionPastTheDisk(t *testing.T) {
	img := disktest.MBRDisk(disktest.Part{Data: blob(4096, 1), MBRType: 0x83})
	binary.LittleEndian.PutUint32(img[446+12:], 1<<30)
	parts, err := read(t, img)
	require.NoError(t, err)
	assert.Equal(t, part.ReasonInvalid, parts[0].Unsupported)
}

func TestGPT(t *testing.T) {
	img := disktest.GPTDisk(
		disktest.Part{Data: blob(4096, 1), GPTType: disktest.GUIDLinux},
		disktest.Part{Data: blob(2048, 2), GPTType: disktest.GUIDLVM},
		disktest.Part{Data: blob(2048, 3), GPTType: disktest.GUIDRAID},
	)
	parts, err := read(t, img)
	require.NoError(t, err)
	require.Len(t, parts, 3)
	assert.Equal(t, int64(1<<20), parts[0].Offset)
	assert.Equal(t, int64(4096), parts[0].Size)
	assert.Equal(t, "0fc63daf-8483-4772-8e79-3d69d8477de4", parts[0].Type)
	assert.Empty(t, parts[0].Unsupported)
	assert.Equal(t, part.ReasonLVM, parts[1].Unsupported)
	assert.Equal(t, part.ReasonRAID, parts[2].Unsupported)
}

func TestGPTFallsBackToBackupHeader(t *testing.T) {
	img := disktest.GPTDisk(disktest.Part{Data: blob(4096, 1), GPTType: disktest.GUIDLinux})
	img[512+20] ^= 0xFF // primary header checksum now wrong
	parts, err := read(t, img)
	require.NoError(t, err)
	require.Len(t, parts, 1)
	assert.Equal(t, int64(1<<20), parts[0].Offset)
}

func TestGPTCorruption(t *testing.T) {
	good := func() []byte {
		return disktest.GPTDisk(disktest.Part{Data: blob(4096, 1), GPTType: disktest.GUIDLinux})
	}
	tests := []struct {
		name   string
		mutate func(img []byte)
	}{
		{"primary and backup headers broken", func(img []byte) {
			img[512+20] ^= 0xFF
			img[len(img)-512+20] ^= 0xFF
		}},
		{"entry array checksum wrong", func(img []byte) { img[2*512+40] ^= 0xFF; copy(img[len(img)-512-128*128:], img[2*512:2*512+128*128]) }},
		{"protective MBR only", func(img []byte) { clear(img[512 : 512+92]); clear(img[len(img)-512:]) }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			img := good()
			tc.mutate(img)
			_, err := read(t, img)
			assert.ErrorIs(t, err, part.ErrCorrupt)
		})
	}
}

func TestNoTable(t *testing.T) {
	tests := map[string][]byte{
		"zeros":                     make([]byte, 1<<16),
		"too short":                 make([]byte, 100),
		"MBR signature, no entries": func() []byte { b := make([]byte, 4096); b[510], b[511] = 0x55, 0xAA; return b }(),
		"FAT boot sector": func() []byte {
			b := make([]byte, 4096)
			b[510], b[511] = 0x55, 0xAA
			b[446] = 0x6B // not a boot flag: not a partition entry
			b[450] = 0x83
			return b
		}(),
	}
	for name, img := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := read(t, img)
			assert.ErrorIs(t, err, part.ErrNoTable)
		})
	}
}

func TestUnreadableDiskIsNotAMissingTable(t *testing.T) {
	boom := errors.New("boom")
	mem := &disktest.Mem{Data: make([]byte, 4096), Err: boom, Unreadable: []disktest.Range{{Off: 0, Len: 512}}}
	_, err := part.Read(mem, mem.Size())
	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
	assert.NotErrorIs(t, err, part.ErrNoTable)
}

func TestGPTEntryArrayBounds(t *testing.T) {
	// A checksummed header declaring a huge entry array is refused before any read of it.
	img := disktest.GPTDisk(disktest.Part{Data: blob(4096, 1), GPTType: disktest.GUIDLinux})
	h := img[512 : 512+92]
	binary.LittleEndian.PutUint32(h[80:], 1<<30)
	binary.LittleEndian.PutUint32(h[16:], 0)
	binary.LittleEndian.PutUint32(h[16:], crc(h))
	img[len(img)-512+20] ^= 0xFF
	_, err := read(t, img)
	assert.ErrorIs(t, err, part.ErrCorrupt)
}
