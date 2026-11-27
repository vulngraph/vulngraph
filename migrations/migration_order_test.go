package migrations

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// The branch gate must consider Go and SQL versions together, including
// immutable Go migrations already applied by deployed databases.
func TestMigrationOrderGateIncludesGoFiles(t *testing.T) {
	script, err := filepath.Abs("../scripts/check-migration-order.sh")
	require.NoError(t, err)
	for _, change := range []string{"lower_sql", "lower_go", "edit_go", "next_sql", "next_go"} {
		t.Run(change, func(t *testing.T) {
			dir := t.TempDir()
			run := func(args ...string) {
				ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "git", args...)
				cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
				cmd.Dir = dir
				out, err := cmd.CombinedOutput()
				require.NoError(t, err, string(out))
			}
			run("init", "-q")
			run("config", "user.name", "Migration test")
			run("config", "user.email", "migration@example.invalid")
			run("config", "commit.gpgsign", "false")
			run("config", "core.hooksPath", "/dev/null")
			path := filepath.Join(dir, "migrations/clickhouse")
			require.NoError(t, os.MkdirAll(path, 0700))
			require.NoError(t, os.WriteFile(filepath.Join(path, "00003_existing.go"), []byte("original"), 0600))
			run("add", ".")
			run("commit", "-qm", "base")
			run("branch", "base")
			file := map[string]string{"lower_sql": "00002_new.sql", "lower_go": "00002_new.go", "edit_go": "00003_existing.go", "next_sql": "00004_new.sql", "next_go": "00004_new.go"}[change]
			require.NoError(t, os.WriteFile(filepath.Join(path, file), []byte("changed"), 0600))
			run("add", ".")
			run("commit", "-qm", "change")
			cmd := exec.Command("bash", script, "base")
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if change == "next_sql" || change == "next_go" {
				require.NoError(t, err, string(out))
			} else {
				require.Error(t, err)
				require.Contains(t, string(out), "::error")
			}
		})
	}
}
