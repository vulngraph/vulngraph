package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// envFileVar names a file of KEY=VALUE lines the process reads before anything
// else. The Compose stack generates its secrets into such a file on first start;
// reading it here, rather than in a shell entrypoint, means `docker compose exec
// serve /graph ...` sees them too.
const envFileVar = "GRAPH_ENV_FILE"

var envKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// loadEnvFile applies the file named by GRAPH_ENV_FILE, if set. A variable that
// is already set wins over the file. Values are taken verbatim: no quoting, no
// expansion.
func loadEnvFile(lookup func(string) (string, bool), set func(key, value string) error) error {
	path, ok := lookup(envFileVar)
	if !ok || path == "" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%s: %w", envFileVar, err)
	}
	defer func() { _ = f.Close() }()

	sc := bufio.NewScanner(f)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || !envKey.MatchString(key) {
			return fmt.Errorf("%s: %s:%d is not KEY=VALUE", envFileVar, path, n)
		}
		if _, present := lookup(key); present {
			continue
		}
		if err := set(key, value); err != nil {
			return fmt.Errorf("%s: %s: %w", envFileVar, key, err)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%s: %s: %w", envFileVar, path, err)
	}
	return nil
}
