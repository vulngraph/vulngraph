package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func envFileFixture(t *testing.T, body string, existing map[string]string) (func(string) (string, bool), map[string]string) {
	t.Helper()
	got := map[string]string{}
	for k, v := range existing {
		got[k] = v
	}
	if body != "" {
		path := filepath.Join(t.TempDir(), "env")
		require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
		got[envFileVar] = path
	}
	lookup := func(k string) (string, bool) { v, ok := got[k]; return v, ok }
	return lookup, got
}

func TestLoadEnvFile(t *testing.T) {
	t.Run("sets what is missing and leaves what is set", func(t *testing.T) {
		lookup, got := envFileFixture(t, "# generated\n\nA=1\nDATABASE_URL=postgres://u:p@h:5432/d?sslmode=disable\nB=keep\n", map[string]string{"B": "env"})
		require.NoError(t, loadEnvFile(lookup, func(k, v string) error { got[k] = v; return nil }))
		require.Equal(t, "1", got["A"])
		require.Equal(t, "postgres://u:p@h:5432/d?sslmode=disable", got["DATABASE_URL"], "the first = splits, the rest is the value")
		require.Equal(t, "env", got["B"], "the environment outranks the file")
	})

	t.Run("no variable, no file", func(t *testing.T) {
		lookup, _ := envFileFixture(t, "", nil)
		require.NoError(t, loadEnvFile(lookup, func(string, string) error { t.Fatal("set called"); return nil }))
	})

	t.Run("a named file that cannot be read stops the process", func(t *testing.T) {
		lookup, _ := envFileFixture(t, "", map[string]string{envFileVar: filepath.Join(t.TempDir(), "missing")})
		require.ErrorContains(t, loadEnvFile(lookup, func(string, string) error { return nil }), envFileVar)
	})

	t.Run("a malformed line stops the process", func(t *testing.T) {
		for _, body := range []string{"NOEQUALS\n", "1BAD=x\n", "A B=x\n"} {
			lookup, _ := envFileFixture(t, body, nil)
			require.ErrorContains(t, loadEnvFile(lookup, func(string, string) error { return nil }), "not KEY=VALUE", body)
		}
	})
}
