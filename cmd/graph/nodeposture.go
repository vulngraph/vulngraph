package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/vulngraph/vulngraph/internal/nodeposture"
)

// nodePosture runs the opt-in node posture reader (`graph node-posture`, ADR
// 094): it prints one nodeposture.Document per interval to out until ctx ends.
// It takes no environment, no credentials and opens no connection — the chart
// runs it with read-only host mounts and no service account token, and the
// Kubernetes collector reads the documents back from the pod log.
func nodePosture(ctx context.Context, args []string, out io.Writer) error {
	specs, interval, err := parseNodePostureArgs(args)
	if err != nil {
		return fmt.Errorf("node-posture: %w", err)
	}
	enc := json.NewEncoder(out)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := enc.Encode(nodeposture.Collect(specs)); err != nil {
			return fmt.Errorf("node-posture: write: %w", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// specFlag collects repeated --stat/--read/--tree role=path arguments.
type specFlag struct {
	kind  nodeposture.Kind
	specs *[]nodeposture.Spec
}

func (f specFlag) String() string { return "" }

func (f specFlag) Set(v string) error {
	s, err := nodeposture.ParseSpec(f.kind, v)
	if err != nil {
		return fmt.Errorf("--%s: %w", f.kind, err)
	}
	*f.specs = append(*f.specs, s)
	return nil
}

func parseNodePostureArgs(args []string) ([]nodeposture.Spec, time.Duration, error) {
	fs := flag.NewFlagSet("node-posture", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var specs []nodeposture.Spec
	for _, k := range []nodeposture.Kind{nodeposture.KindStat, nodeposture.KindRead, nodeposture.KindTree, nodeposture.KindReadDir} {
		fs.Var(specFlag{kind: k, specs: &specs}, string(k), "<role>=<path> (repeatable)")
	}
	interval := fs.Duration("interval", time.Hour, "time between reports")
	if err := fs.Parse(args); err != nil {
		return nil, 0, fmt.Errorf("parseNodePostureArgs: %w", err)
	}
	if fs.NArg() > 0 {
		return nil, 0, fmt.Errorf("parseNodePostureArgs: unexpected argument %q", fs.Arg(0))
	}
	if len(specs) == 0 {
		return nil, 0, fmt.Errorf("parseNodePostureArgs: no --stat, --read, --tree or --readdir paths")
	}
	if *interval < time.Minute {
		return nil, 0, fmt.Errorf("parseNodePostureArgs: --interval %s is under a minute", *interval)
	}
	return specs, *interval, nil
}
