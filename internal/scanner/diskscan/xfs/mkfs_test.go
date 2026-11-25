package xfs_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/scanner/diskscan/xfs"
)

// TestReadsMkfsXFSImages reads images made by the real mkfs.xfs (populated from
// a protofile, so no mount or root is needed). It is the only test that checks
// the reader against a kernel-format image and skips when the tool is absent.
func TestReadsMkfsXFSImages(t *testing.T) {
	mkfs, err := exec.LookPath("mkfs.xfs")
	if err != nil {
		t.Skip("mkfs.xfs is not installed")
	}
	for _, crc := range []string{"0", "1"} {
		t.Run("crc="+crc, func(t *testing.T) {
			dir := t.TempDir()
			osRelease := filepath.Join(dir, "os-release")
			big := filepath.Join(dir, "big")
			bigData := pattern(2<<20, 7)
			require.NoError(t, os.WriteFile(osRelease, []byte("ID=rocky\nVERSION_ID=\"9.3\"\n"), 0o600))
			require.NoError(t, os.WriteFile(big, bigData, 0o600))
			proto := filepath.Join(dir, "proto")
			spec := fmt.Sprintf("ignored\n0 0\nd--755 0 0\netc d--755 0 0\nos-release ---644 0 0 %s\n$\nvar d--755 0 0\nbig ---644 0 0 %s\n$\n$\n", osRelease, big)
			require.NoError(t, os.WriteFile(proto, []byte(spec), 0o600))

			img := filepath.Join(dir, "img")
			out, err := exec.Command(mkfs, "-f", "-m", "crc="+crc, "-p", proto, "-d", "file,size=320m", img).CombinedOutput() //nolint:gosec // test-only invocation of a fixed tool
			require.NoError(t, err, string(out))
			fh, err := os.Open(img) //nolint:gosec // path built from t.TempDir
			require.NoError(t, err)
			defer fh.Close()
			st, err := fh.Stat()
			require.NoError(t, err)

			f, err := xfs.Open(fh, st.Size())
			require.NoError(t, err)
			got, err := readFile(f, "etc/os-release")
			require.NoError(t, err)
			assert.Contains(t, string(got), "rocky")
			got, err = readFile(f, "var/big")
			require.NoError(t, err)
			assert.Equal(t, bigData, got)
		})
	}
}
