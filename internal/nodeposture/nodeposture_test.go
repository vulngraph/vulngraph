package nodeposture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCollect(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(cfg, []byte("kind: KubeletConfiguration\nreadOnlyPort: 0\n"), 0o640))
	// Preserve the intended fixture mode under a restrictive process umask.
	require.NoError(t, os.Chmod(cfg, 0o640))
	pki := filepath.Join(dir, "pki")
	require.NoError(t, os.MkdirAll(filepath.Join(pki, "etcd"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(pki, "ca.crt"), []byte("c"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(pki, "etcd", "ca.key"), []byte("k"), 0o600))

	doc := Collect([]Spec{
		{Role: "kubelet_config", Kind: KindRead, Path: cfg},
		{Role: "kubelet_kubeconfig", Kind: KindStat, Path: filepath.Join(dir, "missing.conf")},
		{Role: "pki_dir", Kind: KindTree, Path: pki},
	})
	require.Equal(t, Marker, doc.Version)
	require.Len(t, doc.Files, 3)

	read := doc.Files[0]
	require.True(t, read.Exists)
	require.Equal(t, "0640", read.Mode)
	require.Contains(t, read.Content, "readOnlyPort")
	require.NotNil(t, read.UID)
	require.Equal(t, uint32(os.Getuid()), *read.UID)

	absent := doc.Files[1]
	require.False(t, absent.Exists)
	require.Empty(t, absent.Error, "absent is an observation, not an error")

	tree := doc.Files[2]
	require.True(t, tree.Dir)
	require.ElementsMatch(t, []string{"ca.crt", filepath.Join("etcd", "ca.key")},
		[]string{tree.Entries[0].Path, tree.Entries[1].Path})
	for _, e := range tree.Entries {
		if strings.HasSuffix(e.Path, ".key") {
			require.Equal(t, "0600", e.Mode)
		}
	}
}

// An unreadable file is reported as an error so the collector treats it as
// unknown, never as an empty (and therefore default) configuration.
func TestCollect_UnreadableIsAnError(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads mode-000 files")
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte("x"), 0o000))
	f := Collect([]Spec{{Role: "kubelet_config", Kind: KindRead, Path: p}}).Files[0]
	require.True(t, f.Exists)
	require.Equal(t, "0000", f.Mode, "the stat still succeeds")
	require.Equal(t, "permission denied", f.Error)
	require.Empty(t, f.Content)
}

func TestCollect_ContentIsCapped(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big")
	require.NoError(t, os.WriteFile(p, []byte(strings.Repeat("a", MaxContent+10)), 0o644))
	f := Collect([]Spec{{Role: "kubelet_config", Kind: KindRead, Path: p}}).Files[0]
	require.True(t, f.Truncated)
	require.Len(t, f.Content, MaxContent)
}

func TestParseSpec(t *testing.T) {
	s, err := ParseSpec(KindStat, "client_ca=/host/etc-kubernetes/pki/ca.crt")
	require.NoError(t, err)
	require.Equal(t, Spec{Role: "client_ca", Kind: KindStat, Path: "/host/etc-kubernetes/pki/ca.crt"}, s)
	_, err = ParseSpec(KindStat, "client_ca")
	require.Error(t, err)
}

func TestCollect_ReadDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "40-nodeadm.conf"), []byte(`{"seccompDefault":true}`), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "10-a.conf"), []byte(`{}`), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "sub"), 0o755))
	f := Collect([]Spec{{Role: "kubelet_config_dropins", Kind: KindReadDir, Path: dir}}).Files[0]
	require.Empty(t, f.Error)
	require.Len(t, f.Entries, 2, "directories are skipped")
	require.Equal(t, "10-a.conf", f.Entries[0].Path, "name order")
	require.Equal(t, `{"seccompDefault":true}`, f.Entries[1].Content)

	for i := 0; i <= maxDirFiles; i++ {
		require.NoError(t, os.WriteFile(filepath.Join(dir, "x"+strings.Repeat("y", i)+".conf"), nil, 0o644))
	}
	f = Collect([]Spec{{Role: "kubelet_config_dropins", Kind: KindReadDir, Path: dir}}).Files[0]
	require.Equal(t, "too many entries", f.Error, "a listing that does not fit is an error, never shortened")
}
