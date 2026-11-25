package part_test

import (
	"bytes"
	"testing"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/disktest"
	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/part"
)

// FuzzPartition feeds arbitrary bytes as a disk; Read must return, not panic.
func FuzzPartition(f *testing.F) {
	f.Add(disktest.MBRDisk(disktest.Part{Data: make([]byte, 1024), MBRType: 0x83}))
	f.Add(disktest.GPTDisk(
		disktest.Part{Data: make([]byte, 1024), GPTType: disktest.GUIDLinux},
		disktest.Part{Data: make([]byte, 1024), GPTType: disktest.GUIDLVM},
	))
	f.Fuzz(func(t *testing.T, img []byte) {
		parts, err := part.Read(bytes.NewReader(img), int64(len(img)))
		if err != nil {
			return
		}
		for _, p := range parts {
			if p.Unsupported == "" && (p.Offset < 0 || p.Size <= 0 || p.Offset+p.Size > int64(len(img))) {
				t.Fatalf("usable partition outside the disk: %+v on %d bytes", p, len(img))
			}
		}
	})
}
