// Command checkkeys-gen derives, from the source of internal/checks, the asset
// metadata keys each check's Violates predicate reads, and writes them to
// internal/checks/required_keys_gen.go.
//
// The derived map feeds the lifecycle reconcile's evaluability gate: a check
// whose required keys are absent from a collected asset did not observe that
// asset, so its finding must not be closed as fixed. Generating it keeps the
// contract a consequence of the predicates rather than a hand-kept list beside
// them.
//
// Run: go run ./cmd/checkkeys-gen
// Verified by internal/checks.TestRequiredKeysGeneratedIsCurrent, which re-scans
// the live source and fails on any drift.
package main

import (
	"fmt"
	"go/format"
	"os"

	"github.com/vulngraph/vulngraph/internal/checks/keyscan"
)

const (
	srcDir  = "internal/checks"
	outPath = "internal/checks/required_keys_gen.go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "checkkeys-gen:", err)
		os.Exit(1)
	}
}

func run() error {
	scanned, err := keyscan.Scan(srcDir)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}
	src, err := format.Source(keyscan.Render(scanned))
	if err != nil {
		return fmt.Errorf("run: format: %w", err)
	}
	if err := os.WriteFile(outPath, src, 0o644); err != nil {
		return fmt.Errorf("run: write %s: %w", outPath, err)
	}
	_, _ = fmt.Fprintf(os.Stdout, "wrote %s (%d checks)\n", outPath, len(scanned)) //nolint:forbidigo // one-shot codegen CLI, not service code
	return nil
}
