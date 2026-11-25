package diskscan

import (
	"context"
	"testing"
	"time"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/disktest"
)

// FuzzScanDisk runs the whole pipeline over a mutated disk. A result that
// claims a known inventory must carry no gap, and an unknown one no packages.
func FuzzScanDisk(f *testing.F) {
	e := disktest.NewExt4(disktest.Ext4Opts{BlocksPerGroup: 128, InodesPerGroup: 16})
	e.WriteFile("etc/os-release", []byte(debianRelease))
	e.WriteFile("var/lib/dpkg/status", []byte("Package: bash\nVersion: 5.2\nStatus: install ok installed\n\n"))
	e.Symlink("lib", "usr/lib")
	root := e.Bytes()
	f.Add(root)
	f.Add(disktest.GPTDisk(disktest.Part{Data: root, GPTType: disktest.GUIDLinux}))
	f.Add(disktest.MBRDisk(disktest.Part{Data: root, MBRType: 0x83}))

	x := disktest.NewXFS(disktest.XFSOpts{AGBlocks: 128})
	x.WriteFile("etc/os-release", []byte(debianRelease))
	x.WriteFile("var/lib/dpkg/status", []byte("Package: bash\nVersion: 5.2\nStatus: install ok installed\n\n"))
	x.Symlink("lib", "usr/lib")
	f.Add(disktest.GPTDisk(disktest.Part{Data: x.Bytes(), GPTType: disktest.GUIDLinux}))

	lim := Limits{MaxBytesRead: 1 << 22, MaxFileBytes: 1 << 20, MaxTotalBytes: 1 << 21}
	f.Fuzz(func(t *testing.T, img []byte) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		res, err := ScanDisk(ctx, &disktest.Mem{Data: img}, lim)
		if err != nil {
			return
		}
		if res.InventoryKnown && res.Gap != "" {
			t.Fatalf("known inventory with gap %q", res.Gap)
		}
		if !res.InventoryKnown && (res.Packages != nil || res.Gap == "") {
			t.Fatalf("unknown inventory must carry a gap and no packages: %+v", res)
		}
	})
}
