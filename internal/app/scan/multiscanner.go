package scan

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// multiScanner drives every enabled scanner over the same targets and merges
// their results, deduping on (scanner, template, host, port, url). A single
// scanner's failure fails the whole run: partial results would silently
// undercount findings, which is worse than a visible failure.
type multiScanner struct {
	scanners []Scanner
}

// NewMultiScanner builds a Scanner that fans out to every enabled connector.
// enabled selects connectors by name; an empty map enables all of them (the
// OSS default — ship everything bundled, let operators narrow it). A name that
// matches no bundled connector is an error listing the valid names: a typo
// would otherwise disable scanning while every run still reported success.
func NewMultiScanner(enabled map[string]bool, all ...Scanner) (Scanner, error) {
	known := make(map[string]bool, len(all))
	valid := make([]string, 0, len(all))
	for _, s := range all {
		known[s.Name()] = true
		valid = append(valid, s.Name())
	}
	var unknown []string
	for name := range enabled {
		if !known[name] {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		return nil, fmt.Errorf("NewMultiScanner: %w: %s (valid: %s)", ErrUnknownScanner,
			strings.Join(unknown, ", "), strings.Join(valid, ", "))
	}
	sel := make([]Scanner, 0, len(all))
	for _, s := range all {
		if len(enabled) == 0 || enabled[s.Name()] {
			sel = append(sel, s)
		}
	}
	return &multiScanner{scanners: sel}, nil
}

func (m *multiScanner) Name() string { return "multi" }

// Capabilities is the union of the enabled connectors' capabilities.
func (m *multiScanner) Capabilities() Capability {
	var caps Capability
	for _, s := range m.scanners {
		caps |= s.Capabilities()
	}
	return caps
}

// Scan refuses the whole run when a target fits no enabled scanner, before any
// scanner runs: an empty result for that target would be indistinguishable
// from a clean scan of it.
func (m *multiScanner) Scan(ctx context.Context, targets []Target, templateTags []string) (ScanOutput, error) {
	if uncovered := m.uncoveredTargets(targets); len(uncovered) > 0 {
		return ScanOutput{}, fmt.Errorf("Scan: %w: %s", ErrNoScannerForTarget, strings.Join(uncovered, " "))
	}
	seen := make(map[string]struct{})
	var out ScanOutput
	for _, s := range m.scanners {
		relevant := relevantTargets(targets, s.Capabilities())
		if len(relevant) == 0 {
			continue
		}
		scanOut, err := s.Scan(ctx, relevant, templateTags)
		if err != nil {
			return ScanOutput{}, fmt.Errorf("Scan: %s: %w", s.Name(), err)
		}
		out.TemplateTags = append(out.TemplateTags, scanOut.TemplateTags...)
		out.TemplateCount += scanOut.TemplateCount
		for _, r := range scanOut.Results {
			if r.Scanner == "" {
				r.Scanner = s.Name()
			}
			key := r.dedupKey()
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			out.Results = append(out.Results, r)
		}
	}
	return out, nil
}

// uncoveredTargets names the targets no enabled scanner is relevant to.
func (m *multiScanner) uncoveredTargets(targets []Target) []string {
	caps := m.Capabilities()
	var out []string
	for _, t := range targets {
		if t.relevantTo(caps) {
			continue
		}
		name := t.URL
		if name == "" {
			name = t.Host
		}
		out = append(out, strconv.Quote(name))
	}
	return out
}

// relevantTargets selects the targets a connector with the given capabilities
// can act on, so a web scanner isn't handed bare hosts nor a network scanner
// handed URL-only targets.
func relevantTargets(targets []Target, caps Capability) []Target {
	out := make([]Target, 0, len(targets))
	for _, t := range targets {
		if t.relevantTo(caps) {
			out = append(out, t)
		}
	}
	return out
}

// dedupKey identifies a result across scanners so the same vulnerability on the
// same endpoint, found by the same connector, is recorded once.
func (r Result) dedupKey() string {
	return fmt.Sprintf("%s|%s|%s|%d|%s", r.Scanner, r.TemplateID, r.Host, r.Port, r.MatchedURL)
}
