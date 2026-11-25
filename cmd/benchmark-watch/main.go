// Command benchmark-watch checks Vulngraph's benchmark matrices against the
// public lists they are pinned to: Prowler's compliance JSONs, kube-bench's
// cfg tree, the AWS Security Hub controls reference (or the Security Hub API
// when AWS credentials are available) and the Azure Policy regulatory
// initiatives. It reports a newer benchmark version, control IDs added or
// removed upstream for the pinned version, and new FSBP controls (ADR 092).
//
// Run from the repo root:
//
//	go run ./cmd/benchmark-watch                     # report
//	go run ./cmd/benchmark-watch -json -fail-on-drift
//	go run ./cmd/benchmark-watch -update             # re-record the snapshots
//	go run ./cmd/benchmark-watch -frameworks -update # also regenerate framework mappings
//	go run ./cmd/benchmark-watch -offline DIR        # read a recorded bundle, no network
//
// This is the only place the matrices' upstreams are fetched; the diff
// itself (internal/checks/upstream) reads a bundle and never the network.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/vulngraph/vulngraph/internal/checks/benchmarks"
	"github.com/vulngraph/vulngraph/internal/checks/frameworks"
	"github.com/vulngraph/vulngraph/internal/checks/upstream"
)

// exitDrift is the exit status for drift under -fail-on-drift, distinct from
// 1 (the tool itself failed) so CI can tell "open an issue" from "fix the job".
const exitDrift = 3

func main() {
	code, err := run(os.Args[1:], os.Stdout, os.Stderr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "benchmark-watch:", err) //nolint:forbidigo // dev CLI, not service code
		os.Exit(1)
	}
	os.Exit(code)
}

type options struct {
	json, failOnDrift, update, frameworks bool
	offline, record, snapshots, fwDir     string
	date                                  string
	securityHubAPI                        bool
}

func parseFlags(args []string, stderr io.Writer) (options, error) {
	var o options
	fl := flag.NewFlagSet("benchmark-watch", flag.ContinueOnError)
	fl.SetOutput(stderr)
	fl.BoolVar(&o.json, "json", false, "print the report as JSON")
	fl.BoolVar(&o.failOnDrift, "fail-on-drift", false, fmt.Sprintf("exit %d when drift is found", exitDrift))
	fl.BoolVar(&o.update, "update", false, "re-record the upstream snapshots (and, with -frameworks, the framework mappings)")
	fl.BoolVar(&o.frameworks, "frameworks", false, "also check the requirement-level framework mappings against their sources")
	fl.StringVar(&o.offline, "offline", "", "read a recorded bundle from this directory instead of fetching")
	fl.StringVar(&o.record, "record", "", "write the fetched bundle to this directory (for fixtures)")
	fl.StringVar(&o.snapshots, "snapshots", benchmarks.SnapshotDir, "snapshot directory")
	fl.StringVar(&o.fwDir, "frameworks-dir", frameworks.Dir, "framework mapping directory")
	fl.StringVar(&o.date, "date", time.Now().UTC().Format(time.DateOnly), "date recorded as 'checked'")
	fl.BoolVar(&o.securityHubAPI, "securityhub-api", true, "list FSBP controls with the AWS CLI when credentials are available")
	if err := fl.Parse(args); err != nil {
		return options{}, fmt.Errorf("parseFlags: %w", err)
	}
	return o, nil
}

func run(args []string, stdout, stderr io.Writer) (int, error) {
	o, err := parseFlags(args, stderr)
	if err != nil {
		return 1, err
	}
	bs, err := benchmarks.Load()
	if err != nil {
		return 1, fmt.Errorf("run: %w", err)
	}
	var bundle fs.FS
	if o.offline != "" {
		bundle = os.DirFS(o.offline)
	} else {
		f := newFetcher(stderr, o.securityHubAPI)
		mem, err := f.fill(bs, o.frameworks)
		if err != nil {
			return 1, fmt.Errorf("run: %w", err)
		}
		if o.record != "" {
			if err := writeBundle(o.record, mem); err != nil {
				return 1, fmt.Errorf("run: %w", err)
			}
		}
		bundle = mem
	}

	obs, err := upstream.Observe(bundle, bs)
	if err != nil {
		return 1, fmt.Errorf("run: %w", err)
	}
	snaps, err := benchmarks.ReadSnapshots(o.snapshots)
	if err != nil {
		return 1, fmt.Errorf("run: %w", err)
	}
	acks, err := benchmarks.ReadAcknowledged(o.snapshots)
	if err != nil {
		return 1, fmt.Errorf("run: %w", err)
	}
	rep := upstream.Diff(bs, obs, snaps, acks, o.date)
	if o.frameworks {
		stale, err := checkFrameworks(bundle, bs, o)
		if err != nil {
			return 1, fmt.Errorf("run: %w", err)
		}
		rep.Frameworks = stale
		rep.Drift = rep.Drift || len(stale) > 0
	}
	if o.update {
		if err := writeSnapshots(o.snapshots, obs, o.date); err != nil {
			return 1, fmt.Errorf("run: %w", err)
		}
	}

	if o.json {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return 1, fmt.Errorf("run: %w", err)
		}
	} else if _, err := io.WriteString(stdout, rep.Text()); err != nil {
		return 1, fmt.Errorf("run: %w", err)
	}
	if rep.Drift && o.failOnDrift {
		return exitDrift, nil
	}
	return 0, nil
}

// writeSnapshots re-records each observation, stamped with the run's date:
// the coverage document reports when each matrix was last checked.
func writeSnapshots(dir string, obs []upstream.Observation, date string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("writeSnapshots: %w", err)
	}
	for _, ob := range obs {
		raw, err := benchmarks.EncodeSnapshot(upstream.Snapshot(ob, date))
		if err != nil {
			return fmt.Errorf("writeSnapshots: %w", err)
		}
		if err := os.WriteFile(filepath.Join(dir, ob.Benchmark+".json"), raw, 0o644); err != nil {
			return fmt.Errorf("writeSnapshots: %w", err)
		}
	}
	return nil
}

func writeBundle(dir string, b fs.FS) error {
	err := fs.WalkDir(b, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		raw, err := fs.ReadFile(b, p)
		if err != nil {
			return err
		}
		out := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		return os.WriteFile(out, raw, 0o644)
	})
	if err != nil {
		return fmt.Errorf("writeBundle: %w", err)
	}
	return nil
}

// checkFrameworks regenerates the framework mappings from the bundle and
// reports which committed files differ; with -update it rewrites them.
func checkFrameworks(bundle fs.FS, bs []benchmarks.Benchmark, o options) ([]string, error) {
	current, err := frameworks.LoadDir(o.fwDir)
	if err != nil {
		return nil, fmt.Errorf("checkFrameworks: %w", err)
	}
	generated, err := upstream.GenerateFrameworks(bundle, bs, current)
	if err != nil {
		return nil, fmt.Errorf("checkFrameworks: %w", err)
	}
	var stale []string
	for _, fw := range generated {
		raw := frameworks.Encode(fw)
		path := filepath.Join(o.fwDir, frameworks.FileName(fw.ID))
		prev, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("checkFrameworks: %w", err)
		}
		if string(prev) == string(raw) {
			continue
		}
		stale = append(stale, fw.ID)
		if o.update {
			if err := os.WriteFile(path, raw, 0o644); err != nil {
				return nil, fmt.Errorf("checkFrameworks: %w", err)
			}
		}
	}
	return stale, nil
}
