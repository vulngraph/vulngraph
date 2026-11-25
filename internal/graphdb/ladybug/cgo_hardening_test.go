package ladybug

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// bareConn opens a fresh, unseeded database + connection: these tests exercise
// only the cgo binding paths, so they need no dataset.
func bareConn(t *testing.T) *Connection {
	t.Helper()
	dbPath := strings.ReplaceAll(filepath.Join(t.TempDir(), "testdb"), "\\", "/")
	cfg := DefaultSystemConfig()
	cfg.BufferPoolSize = 64 * 1024 * 1024
	cfg.MaxNumThreads = 2
	db, err := OpenDatabase(dbPath, cfg)
	require.NoError(t, err)
	conn, err := OpenConnection(db)
	require.NoError(t, err)
	return conn
}

// leakBinds and leakValueSize size the leak tests: a per-bind leak of one
// leakValueSize allocation adds leakBinds*leakValueSize (64 MiB) to the native
// heap, far above the engine's own churn over the same loop (well under 1 MiB
// measured on darwin), so leakCeiling separates the two with room on both sides.
const (
	leakBinds     = 1000
	leakValueSize = 64 * 1024
	leakCeiling   = 16 * 1024 * 1024
)

// bindLoop runs bind n times after a warm-up and returns how much the native
// heap grew across the measured loop.
func bindLoop(t *testing.T, n int, bind func()) int64 {
	t.Helper()
	for i := 0; i < 50; i++ {
		bind()
	}
	before := heapInUse()
	for i := 0; i < n; i++ {
		bind()
	}
	return int64(heapInUse()) - int64(before)
}

// Guards goValueToLadybugValue's string case: the CString handed to
// lbug_value_create_string must be freed after the call. Every string parameter
// (nearly every query) goes through here, so dropping that free leaks the
// string's bytes on each bind; this test measures the native heap across the
// loop and fails on that growth.
func TestStringParamDoesNotLeak(t *testing.T) {
	conn := bareConn(t)
	prepared, err := conn.Prepare("RETURN $1")
	require.NoError(t, err)
	value := strings.Repeat("a", leakValueSize)
	grew := bindLoop(t, leakBinds, func() {
		res, err := conn.Execute(prepared, map[string]any{"1": value})
		require.NoError(t, err)
		require.True(t, res.HasNext())
		next, err := res.Next()
		require.NoError(t, err)
		v, err := next.GetValue(0)
		require.NoError(t, err)
		require.Equal(t, value, v)
		res.Close()
	})
	require.Less(t, grew, int64(leakCeiling), "native heap grew %d bytes over %d string binds", grew, leakBinds)
}

// Guards goMapToLadybugStruct: each field-name CString must be freed exactly
// once, the same pointer passed to lbug_value_create_struct. Freeing a second,
// throwaway CString instead leaks every field name on each bind. The long field
// name makes that leak measurable; the struct must also round-trip unchanged.
func TestStructParamDoesNotLeak(t *testing.T) {
	conn := bareConn(t)
	prepared, err := conn.Prepare("RETURN $1")
	require.NoError(t, err)
	field := strings.Repeat("k", leakValueSize)
	param := map[string]any{field: "a-1", "score": int64(80)}
	grew := bindLoop(t, leakBinds, func() {
		res, err := conn.Execute(prepared, map[string]any{"1": param})
		require.NoError(t, err)
		require.True(t, res.HasNext())
		next, err := res.Next()
		require.NoError(t, err)
		v, err := next.GetValue(0)
		require.NoError(t, err)
		require.Equal(t, param, v)
		res.Close()
	})
	require.Less(t, grew, int64(leakCeiling), "native heap grew %d bytes over %d struct binds", grew, leakBinds)
}

// NULL handling: a query returning NULL must scan to a nil Go value without
// reading uninitialised memory or crashing (the value-helper NULL path).
func TestNullValueScansToNil(t *testing.T) {
	conn := bareConn(t)
	res, err := conn.Query("RETURN NULL")
	require.NoError(t, err)
	require.True(t, res.HasNext())
	next, _ := res.Next()
	v, _ := next.GetValue(0)
	require.Nil(t, v)
}

// Exception barrier: C++ exceptions thrown inside the engine (parser, binder,
// conversion, overflow) must surface as Go errors across the cgo boundary —
// never a crash — and the same connection must stay usable afterwards.
func TestCppExceptionsSurfaceAsGoErrors(t *testing.T) {
	conn := bareConn(t)
	for _, q := range []string{
		"MATCH (n:NoSuchTable) RETURN n",       // binder exception
		"RETURN CAST('not-a-number' AS INT64)", // conversion exception
		"RETURN 9223372036854775807 + 1",       // overflow exception
		"THIS IS NOT CYPHER",                   // parser exception
	} {
		_, err := conn.Query(q)
		require.Error(t, err, "query must fail with a Go error, not crash: %s", q)
	}
	res, err := conn.Query("RETURN 1")
	require.NoError(t, err, "connection must survive the exceptions above")
	require.True(t, res.HasNext())
	res.Close()
}

// Engine error messages are returned verbatim: one that quotes a '%' from the
// query must not be read as a format string ("%!d(MISSING)").
func TestEngineErrorMessageIsVerbatim(t *testing.T) {
	conn := bareConn(t)
	_, err := conn.Query("MATCH (n:`no%dtable`) RETURN n")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no%dtable")
	require.NotContains(t, err.Error(), "MISSING")
}
