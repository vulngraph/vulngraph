package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Offline is a first-class mode, not a failure: CI cannot reach production, and
// a generator that only works from a laptop rots.
func TestRunOfflineWritesTheDerivableDocument(t *testing.T) {
	out := filepath.Join(t.TempDir(), "nested", "COVERAGE.md")
	require.NoError(t, run(out, "../..", true))

	b, err := os.ReadFile(out)
	require.NoError(t, err)
	doc := string(b)
	assert.True(t, strings.HasPrefix(doc, "# Coverage\n"))
	assert.Contains(t, doc, "DO NOT EDIT")
	assert.Contains(t, doc, "Mode: **offline**")
	assert.Contains(t, doc, "## The four axes")
}

// A stale CLICKHOUSE_URL is the normal state of a laptop. It must degrade, not
// fail — otherwise the document stops being regenerated at all.
func TestRunFallsBackToOfflineWhenClickHouseIsUnreachable(t *testing.T) {
	t.Setenv("CLICKHOUSE_URL", "clickhouse://graph:graph@127.0.0.1:1/graph")
	out := filepath.Join(t.TempDir(), "COVERAGE.md")
	require.NoError(t, run(out, "../..", false))

	b, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Contains(t, string(b), "Mode: **offline**")
}

func TestRunReportsAnUnwritablePath(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("not a directory"), 0o644))

	err := run(filepath.Join(blocker, "COVERAGE.md"), "../..", true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "run:", "the error must be wrapped with context, never returned bare")
}
