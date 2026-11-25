// Command coverage-gen regenerates docs/COVERAGE.md — the platform's detection
// posture across the four axes on which coverage fails.
//
// Its figures come from the checks registry, the graphschema edge registry, an
// AST scan of the tree and live ClickHouse counts; the headings and prose are
// fixed text in internal/app/coverage. The output reflects whichever estate it
// is pointed at, so it is gitignored and not compared in CI: run it against
// your own deployment. (docs/cspm-coverage.md, built by cmd/cspm-coverage, is
// the committed, CI-checked coverage doc.)
//
// Run from the repo root:
//
//	go run ./cmd/coverage-gen
//
// With CLICKHOUSE_URL reachable it emits the full document. Without one it
// emits the derivable half and notes, in each affected section, that a live
// connection is needed.
//
// Against a deployed cluster, port-forward first:
//
//	kubectl --context=<cluster> -n graph port-forward graph-clickhouse-0 9000:9000
//	CLICKHOUSE_URL=clickhouse://graph:graph@localhost:9000/graph go run ./cmd/coverage-gen
//
// Every query is a read.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/coverage"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/db"
)

const (
	defaultOut = "docs/COVERAGE.md"
	// connectTimeout bounds the ping. A generator that hangs for minutes on an
	// unreachable cluster is a generator nobody runs.
	connectTimeout = 15 * time.Second
	// buildTimeout bounds the whole measurement pass.
	buildTimeout = 20 * time.Minute
)

func main() {
	out := flag.String("out", defaultOut, "path to write")
	root := flag.String("root", ".", "repo root to scan for declared finding sources")
	offline := flag.Bool("offline", false, "skip ClickHouse entirely and emit the derivable half")
	flag.Parse()

	if err := run(*out, *root, *offline); err != nil {
		fmt.Fprintln(os.Stderr, "coverage-gen:", err) //nolint:forbidigo // one-shot codegen CLI, not service code
		os.Exit(1)
	}
}

func run(out, root string, offline bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), buildTimeout)
	defer cancel()

	var live *coverage.Repo
	if !offline {
		ch, err := connect(ctx)
		if err != nil {
			// Not fatal: offline is a first-class mode. The reason is printed and
			// recorded in the document so the reader knows what they are holding.
			fmt.Fprintln(os.Stderr, "coverage-gen: no live data:", err) //nolint:forbidigo // one-shot codegen CLI, not service code
		} else {
			defer func() { _ = ch.Close() }()
			live = coverage.NewRepo(ch)
		}
	}

	// Built through the branch rather than by passing a possibly-nil *Repo: a nil
	// pointer inside a non-nil interface would make the service believe it has a
	// connection and panic on the first query.
	svc := coverage.NewService(checks.Default(), nil, root)
	if live != nil {
		svc = coverage.NewService(checks.Default(), live, root)
	}
	report, err := svc.Build(ctx)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}

	if dir := filepath.Dir(out); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("run: mkdir %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(out, []byte(coverage.Render(report)), 0o644); err != nil {
		return fmt.Errorf("run: write %s: %w", out, err)
	}
	mode := "live"
	if !report.Live {
		mode = "offline"
	}
	//nolint:forbidigo // one-shot codegen CLI, not service code
	_, _ = fmt.Fprintf(os.Stdout, "wrote %s (%s; %d checks, %d edge types, %d categories, %d sources)\n",
		out, mode, len(report.Checks), len(report.Edges), len(report.Categories), len(report.Sources))
	return nil
}

func connect(ctx context.Context) (*db.CH, error) {
	dsn := os.Getenv("CLICKHOUSE_URL")
	if dsn == "" {
		return nil, fmt.Errorf("connect: CLICKHOUSE_URL is unset")
	}
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	ch, err := db.NewCH(ctx, dsn, 0)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	return ch, nil
}
