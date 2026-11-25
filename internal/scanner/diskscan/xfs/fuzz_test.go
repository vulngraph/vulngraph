package xfs_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/disktest"
	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/xfs"
)

func fuzzSeeds() [][]byte {
	var seeds [][]byte
	for _, o := range []disktest.XFSOpts{
		{AGBlocks: 128},
		{V5: true, AGBlocks: 128, Dirs: disktest.DirBlock, MaxRecs: 2},
		{V5: true, AGBlocks: 128, Dirs: disktest.DirNode, DirGap: true, BlockSize: 512, InodeSize: 512},
		{AGBlocks: 128, Dirs: disktest.DirLeaf, Ftype: true, DirBlkLog: 1},
	} {
		e := disktest.NewXFS(o)
		e.WriteFile("etc/os-release", []byte("ID=debian\nVERSION_ID=12\n"))
		e.WriteFile("var/lib/dpkg/status", pattern(5000, 1))
		e.WriteFileOpts("big", pattern(9000, 2), disktest.XFSFileOpts{Fragmented: true, Btree: true})
		e.WriteFileOpts("hole", pattern(3000, 3), disktest.XFSFileOpts{HoleBlocks: 4, Unwritten: true})
		for i := 0; i < 40; i++ {
			e.WriteFile("many/file-"+strings.Repeat("n", i%20)+string(rune('a'+i%26)), nil)
		}
		e.Symlink("lib", "usr/lib")
		e.Symlink("long", "/"+strings.Repeat("a/", 300))
		seeds = append(seeds, e.Bytes())
	}
	return seeds
}

// FuzzXFS walks whatever a mutated image describes. Reads may fail; they must
// not panic, hang or allocate without bound.
func FuzzXFS(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, img []byte) {
		fsys, err := xfs.Open(bytes.NewReader(img), int64(len(img)))
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
