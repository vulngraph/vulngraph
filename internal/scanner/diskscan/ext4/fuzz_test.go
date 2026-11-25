package ext4_test

import (
	"bytes"
	"testing"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/disktest"
	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/ext4"
)

func fuzzSeeds() [][]byte {
	small := disktest.Ext4Opts{BlocksPerGroup: 128, InodesPerGroup: 16}
	var seeds [][]byte
	for _, o := range []disktest.Ext4Opts{small, {BlocksPerGroup: 128, InodesPerGroup: 16, Legacy: true}, {BlocksPerGroup: 128, InodesPerGroup: 16, HTreeDirs: true, Bit64: true}} {
		e := disktest.NewExt4(o)
		e.WriteFile("etc/os-release", []byte("ID=debian\nVERSION_ID=12\n"))
		e.WriteFile("var/lib/dpkg/status", pattern(5000, 1))
		e.WriteFileOpts("big", pattern(9000, 2), disktest.FileOpts{Fragmented: true})
		e.Symlink("lib", "usr/lib")
		e.Symlink("long", "/"+string(bytes.Repeat([]byte("a/"), 40)))
		seeds = append(seeds, e.Bytes())
	}
	return seeds
}

// FuzzExt4 walks whatever a mutated image describes. Reads may fail; they must
// not panic, hang or allocate without bound.
func FuzzExt4(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, img []byte) {
		fsys, err := ext4.Open(bytes.NewReader(img), int64(len(img)))
		if err != nil {
			return
		}
		queue := []uint64{fsys.Root()}
		seen := map[uint64]bool{}
		for len(queue) > 0 && len(seen) < 64 {
			ino := queue[0]
			queue = queue[1:]
			if seen[ino] {
				continue
			}
			seen[ino] = true
			mode, size, err := fsys.Stat(ino)
			if err != nil {
				continue
			}
			switch mode & 0xF000 {
			case 0x4000:
				names, err := fsys.DirNames(ino)
				if err != nil {
					continue
				}
				for _, n := range names[:min(len(names), 16)] {
					if child, err := fsys.Lookup(ino, n); err == nil {
						queue = append(queue, child)
					}
				}
			case 0xA000:
				_, _ = fsys.ReadLink(ino)
			case 0x8000:
				buf := make([]byte, min(size, 1<<16))
				_, _ = fsys.ReadAt(ino, buf, 0)
				_, _ = fsys.ReadAt(ino, buf[:min(len(buf), 512)], size/2)
			}
		}
	})
}
