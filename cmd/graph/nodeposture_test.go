package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/nodeposture"
)

func TestParseNodePostureArgs(t *testing.T) {
	specs, interval, err := parseNodePostureArgs([]string{
		"--read=kubelet_config=/host/kubelet-config", "--stat", "client_ca=/host/etc-kubernetes/pki/ca.crt",
		"--tree=pki_dir=/host/etc-kubernetes/pki", "--interval=30m",
	})
	require.NoError(t, err)
	require.Equal(t, 30*time.Minute, interval)
	require.Equal(t, []nodeposture.Spec{
		{Role: "kubelet_config", Kind: nodeposture.KindRead, Path: "/host/kubelet-config"},
		{Role: "client_ca", Kind: nodeposture.KindStat, Path: "/host/etc-kubernetes/pki/ca.crt"},
		{Role: "pki_dir", Kind: nodeposture.KindTree, Path: "/host/etc-kubernetes/pki"},
	}, specs)

	for _, bad := range [][]string{
		nil,
		{"--stat=client_ca"},
		{"--stat=a=/x", "positional"},
		{"--stat=a=/x", "--interval=5s"},
		{"--write=a=/x"},
	} {
		_, _, err := parseNodePostureArgs(bad)
		require.Error(t, err, "%v", bad)
	}
}

// One document per pass, on stdout, until the context ends.
func TestNodePosture_EmitsDocument(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(p, []byte("readOnlyPort: 0\n"), 0o600))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out bytes.Buffer
	require.NoError(t, nodePosture(ctx, []string{"--read=kubelet_config=" + p}, &out))
	var doc nodeposture.Document
	require.NoError(t, json.Unmarshal(out.Bytes(), &doc))
	require.Equal(t, nodeposture.Marker, doc.Version)
	require.Equal(t, "readOnlyPort: 0\n", doc.Files[0].Content)
}
