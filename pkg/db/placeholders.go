package db

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// CHIn builds a ClickHouse '?' placeholder list and matching args slice for
// use in IN clauses. Only literal '?' characters are interpolated into the
// query string — values are always passed as args. This is the ONLY safe
// pattern for variable-length IN clauses in ClickHouse.
//
//	ph, args := db.CHIn(findingTypes)
//	q := fmt.Sprintf(
//	    "ALTER TABLE findings DELETE WHERE resource_id = ? AND type IN (%s)",
//	    ph,
//	)
//	conn.Exec(ctx, q, append([]any{resourceID}, args...)...)
func CHIn[T any](values []T) (placeholders string, args []any) {
	ph := make([]string, len(values))
	args = make([]any, len(values))
	for i, v := range values {
		ph[i] = "?"
		args[i] = v
	}
	return strings.Join(ph, ", "), args
}

// DeterministicID creates a stable hex ID from the given parts joined with "|".
// Use for ClickHouse finding rows where the same logical event must produce the
// same ID across re-scans (idempotent upserts via ReplacingMergeTree).
func DeterministicID(parts ...string) string {
	h := sha256.New()
	for i, p := range parts {
		if i > 0 {
			h.Write([]byte("|"))
		}
		h.Write([]byte(p))
	}
	return fmt.Sprintf("%x", h.Sum(nil))[:32]
}

// PGIn builds Postgres '$N' placeholders for IN / = ANY clauses.
// startN is the $N index of the first element — use 1 for the first call, or
// the next index when chaining multiple parameterized clauses.
//
//	ph, args := db.PGIn(connectorIDs, 1)
//	q := fmt.Sprintf(
//	    "SELECT id FROM connectors WHERE id = ANY(ARRAY[%s]::text[])",
//	    ph,
//	)
//	pool.Query(ctx, q, args...)
func PGIn[T any](values []T, startN int) (placeholders string, args []any) {
	ph := make([]string, len(values))
	args = make([]any, len(values))
	for i, v := range values {
		ph[i] = fmt.Sprintf("$%d", startN+i)
		args[i] = v
	}
	return strings.Join(ph, ", "), args
}
