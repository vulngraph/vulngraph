package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/vulngraph/vulngraph/pkg/safenet"
)

const healthcheckTimeout = 2 * time.Second

// healthcheck probes the local serve process's /healthz (`/graph healthcheck`)
// or the worker's Ladybug readiness (`/graph healthcheck worker`) and fails
// unless it answers 2xx. It exists so container probes need no wget/curl in
// the slim runtime image, and so kubelet probes need no network path: an exec
// probe lets the NetworkPolicy keep node addresses off the Ladybug RPC port.
func healthcheck(ctx context.Context, args []string, getenv func(string) string) error {
	var target string
	switch {
	case len(args) == 0:
		u, err := healthcheckURL(envOr(getenv, "ADDR", ":8080"))
		if err != nil {
			return fmt.Errorf("healthcheck: %w", err)
		}
		target = u
	case args[0] == "worker":
		port := envOr(getenv, "LADYBUG_INTERNAL_PORT", "8090")
		target = "http://" + net.JoinHostPort("127.0.0.1", port) + "/internal/graph/ready"
	default:
		return fmt.Errorf("healthcheck: unknown target %q (want: worker, or none for serve)", args[0])
	}
	ctx, cancel := context.WithTimeout(ctx, healthcheckTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	resp, err := safenet.NewInternal(healthcheckTimeout).Do(req)
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("healthcheck: %s returned %d", target, resp.StatusCode)
	}
	return nil
}

// healthcheckURL maps a listen address (":8080", "0.0.0.0:8080") to the
// loopback /healthz URL — the probe always runs inside the serve container.
func healthcheckURL(addr string) (string, error) {
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("parse ADDR %q: %w", addr, err)
	}
	return "http://" + net.JoinHostPort("127.0.0.1", port) + "/healthz", nil
}
