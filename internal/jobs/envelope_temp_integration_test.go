//go:build integration

package jobs

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

type envelopeTempBytes struct {
	Logical   int64 `json:"logical_bytes"`
	Allocated int64 `json:"allocated_bytes"`
	Files     int   `json:"files"`
}

// Anonymous correlation spools are absent from directory listings. Count them
// through open descriptors as well, deduplicating native files by device/inode.
func envelopeTempUsage(root string) (out envelopeTempBytes, err error) {
	seen := map[[2]uint64]bool{}
	add := func(path string) error {
		info, e := os.Stat(path)
		if os.IsNotExist(e) {
			return nil
		}
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("temporary file stat unavailable")
		}
		key := [2]uint64{uint64(stat.Dev), stat.Ino}
		if seen[key] {
			return nil
		}
		seen[key] = true
		out.Files++
		out.Logical += info.Size()
		out.Allocated += stat.Blocks * 512
		return nil
	}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, e error) error {
		if os.IsNotExist(e) {
			return nil
		}
		if e != nil {
			return e
		}
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil
		}
		return add(path)
	})
	if err != nil {
		return out, fmt.Errorf("sample temporary directory: %w", err)
	}
	descriptors, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return out, err
	}
	for _, descriptor := range descriptors {
		path := filepath.Join("/proc/self/fd", descriptor.Name())
		target, e := os.Readlink(path)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return out, e
		}
		if strings.HasPrefix(target, root+string(os.PathSeparator)) {
			if e := add(path); e != nil {
				return out, e
			}
		}
	}
	return out, nil
}

func TestEnvelopeTempUsageIncludesUnlinkedFilesWithoutDoubleCounting(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux process descriptor accounting")
	}
	dir := t.TempDir()
	f, err := os.CreateTemp(dir, "spool-")
	require.NoError(t, err)
	defer f.Close()
	_, err = f.Write(make([]byte, 8192))
	require.NoError(t, err)
	before, err := envelopeTempUsage(dir)
	require.NoError(t, err)
	require.Equal(t, int64(8192), before.Logical)
	require.Equal(t, 1, before.Files)
	require.NoError(t, os.Remove(f.Name()))
	after, err := envelopeTempUsage(dir)
	require.NoError(t, err)
	require.Equal(t, before, after)
}
