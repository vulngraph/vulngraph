// Command graphschema-gen regenerates frontend/src/generated/graph-schema.json
// from the internal/graphschema registry. Run from the repo root:
//
//	go run ./cmd/graphschema-gen
//
// TestExportJSONIsFresh (internal/graphschema) fails CI when the committed
// file is stale, and the frontend vitest pins preset Cypher rel labels to the
// loaded set in this file.
package main

import (
	"fmt"
	"os"

	"github.com/vulngraph/vulngraph/internal/graphschema"
)

const outPath = "frontend/src/generated/graph-schema.json"

func main() {
	b, err := graphschema.ExportJSON()
	if err != nil {
		fmt.Fprintf(os.Stderr, "graphschema-gen: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll("frontend/src/generated", 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "graphschema-gen: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outPath, b, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "graphschema-gen: %v\n", err)
		os.Exit(1)
	}
	_, _ = fmt.Fprintln(os.Stdout, "wrote "+outPath) //nolint:forbidigo // one-shot codegen CLI, not service code
}
