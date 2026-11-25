// Command scoreband-gen regenerates frontend/src/generated/score-bands.json
// from the score thresholds in internal/app/enrich. Run from the repo root:
//
//	go run ./cmd/scoreband-gen
//
// TestExportBandsJSONIsFresh (internal/app/enrich) fails CI when the committed
// file is stale.
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
)

func main() {
	b, err := enrich.ExportBandsJSON()
	if err != nil {
		fmt.Fprintf(os.Stderr, "scoreband-gen: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(enrich.BandsJSONPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "scoreband-gen: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(enrich.BandsJSONPath, b, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "scoreband-gen: %v\n", err)
		os.Exit(1)
	}
	_, _ = fmt.Fprintln(os.Stdout, "wrote "+enrich.BandsJSONPath) //nolint:forbidigo // one-shot codegen CLI, not service code
}
