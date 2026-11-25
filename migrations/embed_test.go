package migrations

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// Guards the //go:embed patterns: a renamed directory or a stray pattern typo
// would otherwise only fail at runtime, inside a deploy.
func TestFS_ContainsBothDatabases(t *testing.T) {
	for _, dir := range []string{"postgres", "clickhouse"} {
		entries, err := FS.ReadDir(dir)
		require.NoError(t, err, "embedded dir %s must exist", dir)
		require.NotEmpty(t, entries, "embedded dir %s must contain migrations", dir)
	}
}

// goosePrefix matches the leading version number goose orders migrations by.
// Anything not matching this shape is not a migration goose will run.
var goosePrefix = regexp.MustCompile(`^(\d+)_`)

// TestMigrationVersionsAreUnique guards against two migrations landing on the
// same version number for one database: goose keys applied migrations by
// version, so if two files both claim the same number, the second is recorded
// as already-applied and never actually runs — a silent, unrecoverable-in-place
// schema drift that only surfaces later as a confusing failure. A duplicate
// version's only safe fix is renaming the loser to a fresh version; this test
// exists to catch the collision at `go test` time instead, as a red build.
//
// Uniqueness is checked PER DATABASE: postgres and clickhouse have independent
// goose version spaces, so the same number legitimately exists in both.
func TestMigrationVersionsAreUnique(t *testing.T) {
	for _, dir := range []string{"postgres", "clickhouse"} {
		entries, err := FS.ReadDir(dir)
		require.NoError(t, err)

		byVersion := map[int64]string{}
		for _, e := range entries {
			m := goosePrefix.FindStringSubmatch(e.Name())
			require.NotNilf(t, m,
				"%s/%s does not start with a goose version prefix (NNNNN_) — goose orders by that "+
					"number, so a file without one is silently never run", dir, e.Name())

			v, err := strconv.ParseInt(m[1], 10, 64)
			require.NoErrorf(t, err, "%s/%s: unparseable version %q", dir, e.Name(), m[1])

			if prev, dup := byVersion[v]; dup {
				t.Fatalf("DUPLICATE migration version %d in %s: %q and %q.\n"+
					"goose keys applied migrations by version, so only ONE of these will ever run while "+
					"goose_db_version claims both succeeded. Rename the newer file to the next free version.",
					v, dir, prev, e.Name())
			}
			byVersion[v] = e.Name()
		}
		require.NotEmpty(t, byVersion, "no migrations found in %s", dir)
	}
}

// TestMigrationVersionPrefixWidthIsConsistent keeps the directory sortable by
// name. goose itself parses the number, so a 4-digit file would still RUN in the
// right order — but every human and every `ls` in an incident reads the
// directory in lexicographic order, where 9999 sorts after 00010. Keeping one
// width means the filesystem order and the execution order can never disagree
// while someone is under pressure.
func TestMigrationVersionPrefixWidthIsConsistent(t *testing.T) {
	for _, dir := range []string{"postgres", "clickhouse"} {
		entries, err := FS.ReadDir(dir)
		require.NoError(t, err)

		widths := map[int][]string{}
		for _, e := range entries {
			m := goosePrefix.FindStringSubmatch(e.Name())
			require.NotNil(t, m, e.Name())
			widths[len(m[1])] = append(widths[len(m[1])], e.Name())
		}
		require.Lenf(t, widths, 1,
			"%s mixes version-prefix widths, so lexicographic order no longer matches execution order: %s",
			dir, fmt.Sprint(widths))
	}
}
