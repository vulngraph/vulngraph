package graphstore

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"sort"
	"testing"
)

// computeSchemaChecksum hashes the structural Ladybug DDL: the CREATE/DROP table
// statements plus the per-label/per-rel UNWIND insert templates. Map keys are
// sorted so the hash is deterministic regardless of Go map iteration order.
func computeSchemaChecksum() string {
	h := sha256.New()
	io.WriteString(h, schemaDDL)
	io.WriteString(h, dropDDL)
	writeSorted := func(m map[string]string) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			io.WriteString(h, k)
			io.WriteString(h, "=")
			io.WriteString(h, m[k])
			io.WriteString(h, "\n")
		}
	}
	writeSorted(nodeUnwindQ)
	writeSorted(edgeUnwindQ)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// TestSchemaDDLChecksum is the deploy gate for the schema invariant: any change
// to the Ladybug DDL (a new node table, rel table, column, or UNWIND template)
// changes the checksum and fails this test until SchemaDDLChecksum is updated.
// The fix is to bump SchemaVersion AND update SchemaDDLChecksum together — the
// failure message prints the value to paste. This makes "forgot to bump the
// version" a red CI build instead of a silent stale-graph bug at runtime.
func TestSchemaDDLChecksum(t *testing.T) {
	got := computeSchemaChecksum()
	if got != SchemaDDLChecksum {
		t.Fatalf("Ladybug DDL changed but SchemaDDLChecksum is stale.\n"+
			"  If this was an intentional schema change:\n"+
			"    1. bump SchemaVersion in domain.go (forces a full rebuild on deploy)\n"+
			"    2. set SchemaDDLChecksum = %q\n"+
			"  got %q, pinned %q", got, got, SchemaDDLChecksum)
	}
}
