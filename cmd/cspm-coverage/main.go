// Command cspm-coverage regenerates docs/cspm-coverage.md — Vulngraph's CSPM
// coverage of each public benchmark and compliance framework — from the
// matrices in internal/checks/benchmarks, their upstream snapshots and the
// framework mappings in internal/checks/frameworks.
//
// Run from the repo root:
//
//	go run ./cmd/cspm-coverage
//
// Verified by internal/checks/coveragedoc.TestCoverageDocIsCurrent and the CI
// drift step, so a matrix edit cannot ship with a stale document.
package main

import (
	"fmt"
	"os"

	"github.com/vulngraph/vulngraph/internal/checks/coveragedoc"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "cspm-coverage:", err) //nolint:forbidigo // one-shot codegen CLI, not service code
		os.Exit(1)
	}
}

func run() error {
	doc, err := coveragedoc.Render(".")
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	if err := os.WriteFile(coveragedoc.Path, []byte(doc), 0o644); err != nil {
		return fmt.Errorf("run: write %s: %w", coveragedoc.Path, err)
	}
	_, _ = fmt.Fprintf(os.Stdout, "wrote %s\n", coveragedoc.Path) //nolint:forbidigo // one-shot codegen CLI, not service code
	return nil
}
