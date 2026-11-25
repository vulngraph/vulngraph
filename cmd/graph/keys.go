package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/notify"
	"github.com/vulngraph/vulngraph/internal/db"
)

const keysUsage = "usage: graph keys rewrap"

// newCipher builds the credential cipher every process shares: GRAPH_SECRET_KEY
// seals all writes, and each comma-separated key in GRAPH_RETIRED_SECRET_KEYS is
// trusted for reads only — the state a key rotation passes through.
func newCipher(getenv func(string) string) (*connector.Cipher, error) {
	c, err := connector.NewCipher(getenv("GRAPH_SECRET_KEY"))
	if err != nil {
		return nil, fmt.Errorf("GRAPH_SECRET_KEY: %w", err)
	}
	for i, k := range strings.Split(getenv("GRAPH_RETIRED_SECRET_KEYS"), ",") {
		if k = strings.TrimSpace(k); k == "" {
			continue
		}
		if c, err = c.WithRetiredKey(k); err != nil {
			return nil, fmt.Errorf("GRAPH_RETIRED_SECRET_KEYS entry %d: %w", i+1, err)
		}
	}
	return c, nil
}

// rewrapPass re-seals one table's ciphertexts under the cipher's current key and
// reports how many rows it rewrote.
type rewrapPass struct {
	name string
	run  func(ctx context.Context) (int, error)
}

// keysCmd handles `graph keys rewrap`: re-seal connector configs, alert-channel
// secrets and TOTP seeds under the current GRAPH_SECRET_KEY. Safe to re-run; a
// second run rewrites nothing.
func keysCmd(ctx context.Context, args []string, getenv func(string) string) error {
	if len(args) != 1 || args[0] != "rewrap" {
		return fmt.Errorf("%s", keysUsage)
	}
	cipher, err := newCipher(getenv)
	if err != nil {
		return fmt.Errorf("keys rewrap: %w", err)
	}
	// Short-lived and sequential: a small pool fits beside the running pods.
	pool, err := db.NewPool(ctx, pgDSN(getenv), 2)
	if err != nil {
		return fmt.Errorf("keys rewrap: %w", err)
	}
	defer pool.Close()

	connectors := connector.NewService(connector.NewPGRepo(pool), cipher)
	channels := notify.NewService(notify.NewPGRepo(pool, cipher))
	return keysRewrap(ctx, os.Stdout, cipher.CurrentKeyID(), []rewrapPass{
		{name: "connectors", run: connectors.RewrapAll},
		{name: "alert channels", run: func(ctx context.Context) (int, error) { return channels.RewrapSecrets(ctx, cipher) }},
		{name: "totp secrets", run: auth.NewPGRepo(pool, cipher).RewrapTOTPSecrets},
	})
}

// keysRewrap runs the passes in order and stops at the first failure: a row
// that could not be opened is named in the error and left as it was, so fixing
// the key list and re-running picks up where it stopped.
func keysRewrap(ctx context.Context, w io.Writer, keyID string, passes []rewrapPass) error {
	for _, p := range passes {
		n, err := p.run(ctx)
		if err != nil {
			return fmt.Errorf("keys rewrap: %s: %w", p.name, err)
		}
		if _, err := fmt.Fprintf(w, "%s: re-sealed %d row(s) under key %s\n", p.name, n, keyID); err != nil {
			return fmt.Errorf("keys rewrap: %w", err)
		}
	}
	return nil
}
