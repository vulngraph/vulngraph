// Package benchmarks is graph's CSPM coverage matrix: for every control of a
// public cloud benchmark (CIS Foundations, AWS FSBP, CIS Kubernetes/EKS/GKE/AKS),
// whether graph evaluates it and which registry checks do. Coverage is
// measured against public benchmarks, one YAML file per benchmark version.
//
// The files hold control IDs and short paraphrased titles only — CIS benchmark
// prose is CC BY-NC-SA and is never reproduced.
package benchmarks

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed *.yaml
var files embed.FS

// Status is how far graph evaluates one control.
type Status string

const (
	// StatusCovered: a check evaluates the control's exact condition.
	StatusCovered Status = "covered"
	// StatusPartial: a check evaluates part of the condition; Reason says
	// what is missing.
	StatusPartial Status = "partial"
	// StatusMissing: evaluable from cloud APIs but no check exists; Reason
	// names the data a collector must gather.
	StatusMissing Status = "missing"
	// StatusNotApplicable: outside what an API-driven CSPM can evaluate (e.g.
	// node-level files needing host access); Reason says why.
	StatusNotApplicable Status = "not_applicable"
	// StatusManual: needs human judgement or out-of-band evidence.
	StatusManual Status = "manual"
)

// Statuses lists every status in report order.
var Statuses = []Status{StatusCovered, StatusPartial, StatusMissing, StatusNotApplicable, StatusManual}

// Family groups benchmarks by publisher; the compliance consistency test
// reads it to find which matrices back a CIS claim.
type Family string

const (
	FamilyCIS  Family = "cis"
	FamilyFSBP Family = "fsbp"
)

// Severity hints, matching finding.Severity's strings.
var severities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "info": true}

// maxTitleWords bounds a title so it stays a paraphrase, not benchmark text.
const maxTitleWords = 10

// Control is one benchmark control and graph's coverage of it.
type Control struct {
	ID       string   `yaml:"id"`
	Title    string   `yaml:"title"`
	Service  string   `yaml:"service"`
	Status   Status   `yaml:"status"`
	CheckIDs []string `yaml:"check_ids,omitempty"`
	Reason   string   `yaml:"reason,omitempty"`
	Severity string   `yaml:"severity"`
}

// Benchmark is one benchmark version's full control list.
type Benchmark struct {
	ID      string `yaml:"benchmark"`
	Name    string `yaml:"name"`
	Version string `yaml:"version"`
	Family  Family `yaml:"family"`
	// Providers are the asset.Provider values whose checks may evidence this
	// benchmark: managed-Kubernetes benchmarks span the cloud and the cluster.
	Providers []string  `yaml:"providers"`
	Source    string    `yaml:"source"`
	Controls  []Control `yaml:"controls"`
}

// Counts tallies controls by status.
func (b Benchmark) Counts() map[Status]int {
	out := make(map[Status]int, len(Statuses))
	for _, c := range b.Controls {
		out[c.Status]++
	}
	return out
}

// Load parses every embedded benchmark file, sorted by benchmark ID. Unknown
// keys are an error: a misspelt `check_id:` would otherwise parse as a control
// with no checks and read as a gap rather than a typo.
func Load() ([]Benchmark, error) {
	names, err := fs.Glob(files, "*.yaml")
	if err != nil {
		return nil, fmt.Errorf("Load: %w", err)
	}
	out := make([]Benchmark, 0, len(names))
	for _, name := range names {
		raw, err := files.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("Load: %s: %w", name, err)
		}
		b, err := Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("Load: %s: %w", name, err)
		}
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Parse decodes one benchmark file strictly.
func Parse(raw []byte) (Benchmark, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	var b Benchmark
	if err := dec.Decode(&b); err != nil {
		return Benchmark{}, fmt.Errorf("Parse: %w", err)
	}
	return b, nil
}

// Validate reports every structural problem in b: missing header fields,
// duplicate IDs, unknown status or severity, a title that is not a short
// paraphrase, a covered/partial control with no check, a missing/n/a/manual
// control claiming one, and a status that needs a reason but has none.
// Whether the check IDs exist is the caller's question (the registry lives in
// internal/checks, which imports this package).
func Validate(b Benchmark) error {
	var errs []error
	for field, v := range map[string]string{
		"benchmark": b.ID, "name": b.Name, "version": b.Version,
		"source": b.Source,
	} {
		if strings.TrimSpace(v) == "" {
			errs = append(errs, fmt.Errorf("%s: header %q is empty", b.ID, field))
		}
	}
	if b.Family != FamilyCIS && b.Family != FamilyFSBP {
		errs = append(errs, fmt.Errorf("%s: unknown family %q", b.ID, b.Family))
	}
	if len(b.Providers) == 0 {
		errs = append(errs, fmt.Errorf("%s: no providers", b.ID))
	}
	if len(b.Controls) == 0 {
		errs = append(errs, fmt.Errorf("%s: no controls", b.ID))
	}
	seen := map[string]bool{}
	for _, c := range b.Controls {
		where := fmt.Sprintf("%s %s", b.ID, c.ID)
		if c.ID == "" {
			errs = append(errs, fmt.Errorf("%s: control with empty id (title %q)", b.ID, c.Title))
		}
		if seen[c.ID] {
			errs = append(errs, fmt.Errorf("%s: duplicate control id", where))
		}
		seen[c.ID] = true
		if n := len(strings.Fields(c.Title)); n == 0 || n > maxTitleWords {
			errs = append(errs, fmt.Errorf("%s: title must be 1-%d words, got %d", where, maxTitleWords, n))
		}
		if strings.TrimSpace(c.Service) == "" {
			errs = append(errs, fmt.Errorf("%s: service is empty", where))
		}
		if !severities[c.Severity] {
			errs = append(errs, fmt.Errorf("%s: unknown severity %q", where, c.Severity))
		}
		errs = append(errs, validateStatus(where, c)...)
	}
	return errors.Join(errs...)
}

func validateStatus(where string, c Control) []error {
	var errs []error
	hasReason := strings.TrimSpace(c.Reason) != ""
	switch c.Status {
	case StatusCovered:
		if len(c.CheckIDs) == 0 {
			errs = append(errs, fmt.Errorf("%s: covered needs check_ids", where))
		}
	case StatusPartial:
		if len(c.CheckIDs) == 0 {
			errs = append(errs, fmt.Errorf("%s: partial needs check_ids", where))
		}
		if !hasReason {
			errs = append(errs, fmt.Errorf("%s: partial needs a reason saying what is missing", where))
		}
	case StatusMissing, StatusNotApplicable, StatusManual:
		if len(c.CheckIDs) != 0 {
			errs = append(errs, fmt.Errorf("%s: %s cannot list check_ids (use partial)", where, c.Status))
		}
		if !hasReason {
			errs = append(errs, fmt.Errorf("%s: %s needs a reason", where, c.Status))
		}
	default:
		errs = append(errs, fmt.Errorf("%s: unknown status %q", where, c.Status))
	}
	dup := map[string]bool{}
	for _, id := range c.CheckIDs {
		if dup[id] {
			errs = append(errs, fmt.Errorf("%s: check %q listed twice", where, id))
		}
		dup[id] = true
	}
	return errs
}
