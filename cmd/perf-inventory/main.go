// Command perf-inventory reports discovered performance scope without assigning credit.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"os"

	"github.com/vulngraph/vulngraph/internal/perfassurance"
	"github.com/vulngraph/vulngraph/pkg/log"
)

func main() {
	root := flag.String("root", ".", "repository root")
	check := flag.Bool("check", false, "reconcile reviewed inventory and profiles")
	flag.Parse()
	entries, err := perfassurance.Discover(*root)
	if err != nil {
		log.FromContext(context.Background()).Error().Err(err).Msg("discover workloads")
		os.Exit(1)
	}
	if *check {
		inv, profiles, err := perfassurance.Load(*root)
		if err != nil {
			log.FromContext(context.Background()).Error().Err(err).Msg("load inventory")
			os.Exit(1)
		}
		problems := perfassurance.Validate(inv, profiles, entries)
		if len(problems) > 0 {
			for _, problem := range problems {
				log.FromContext(context.Background()).Error().Msg(problem)
			}
			os.Exit(1)
		}
		weight := 0
		critical := 0
		for _, f := range inv.Families {
			weight += f.Weight
			if f.Weight == 5 {
				critical++
			}
		}
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"revision": inv.Revision, "entries": len(entries), "families": len(inv.Families), "weight": weight, "critical_families": critical, "coverage": "not assessed by reconciliation; see evidence report"}); err != nil {
			log.FromContext(context.Background()).Error().Err(err).Msg("encode reconciliation")
			os.Exit(1)
		}
		return
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(entries); err != nil {
		log.FromContext(context.Background()).Error().Err(err).Msg("encode workloads")
		os.Exit(1)
	}
}
