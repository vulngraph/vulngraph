package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"time"

	"github.com/vulngraph/vulngraph/pkg/safenet"
)

// kubectlSecret reads one key from a Kubernetes secret via kubectl. Bootstrap
// runs as a one-shot Job with a service account that can read the migration
// namespace secrets; using kubectl keeps a full client-go dependency out of the
// command path.
func kubectlSecret(ctx context.Context, ns, secret, key string) (string, error) {
	out, err := exec.CommandContext(ctx,
		"kubectl", "get", "secret", secret,
		"-n", ns,
		"-o", fmt.Sprintf("jsonpath={.data.%s}", key),
	).Output()
	if err != nil {
		return "", fmt.Errorf("kubectlSecret %s/%s: %w", secret, key, err)
	}
	if len(out) == 0 {
		return "", fmt.Errorf("kubectlSecret %s/%s: key not present", secret, key)
	}
	decoded, err := base64Std(string(out))
	if err != nil {
		return "", fmt.Errorf("kubectlSecret %s/%s: base64: %w", secret, key, err)
	}
	return decoded, nil
}

// ── graph API client ─────────────────────────────────────────────────────────

type connectorPayload struct {
	Type   string            `json:"type"`
	Name   string            `json:"name"`
	Config map[string]string `json:"config"`
}

type graphAPI struct {
	base  string
	token string
	hc    *http.Client
}

func newGraphAPI(base, token string) *graphAPI {
	// safenet.NewInternal, not New: base is this app's own API, a trusted
	// internal endpoint, not a connector-supplied URL (CLAUDE.md).
	return &graphAPI{base: base, token: token, hc: safenet.NewInternal(15 * time.Second)}
}

// createConnector POSTs a connector. A 409 (already exists) is reported as an
// error the caller logs-and-continues, keeping bootstrap idempotent.
func (g *graphAPI) createConnector(ctx context.Context, p connectorPayload) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		g.base+"/api/connectors", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+g.token)

	resp, err := g.hc.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusConflict {
		return fmt.Errorf("already exists")
	}
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(b))
	}
	return nil
}
