package benchmarks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// SnapshotDir is where cmd/benchmark-watch records each matrix's upstream
// control list, relative to the repository root.
const SnapshotDir = "internal/checks/benchmarks/testdata/sources"

// AcknowledgedFile lists the known differences between a matrix and its
// recorded upstream, each with the reason it is not yet reconciled.
const AcknowledgedFile = "acknowledged.yaml"

// SourceSnapshot is one matrix's upstream control list as benchmark-watch
// last read it. Exact is false when the upstream does not publish the pinned
// version and SourceVersion is the nearest one below it.
type SourceSnapshot struct {
	Benchmark     string   `json:"benchmark"`
	Source        string   `json:"source"`
	Pinned        string   `json:"pinned"`
	SourceVersion string   `json:"source_version"`
	Exact         bool     `json:"exact"`
	Latest        string   `json:"latest"`
	Checked       string   `json:"checked"`
	ControlIDs    []string `json:"control_ids"`
}

// Acknowledgement records why a matrix and its upstream disagree on some
// IDs. Every entry carries a reason; an unexplained difference fails
// TestMatricesMatchUpstreamSnapshot.
type Acknowledgement struct {
	// MissingFromMatrix: upstream controls the matrix has no row for yet.
	MissingFromMatrix map[string]string `yaml:"missing_from_matrix,omitempty"`
	// NotInSource: matrix rows the upstream no longer lists.
	NotInSource map[string]string `yaml:"not_in_source,omitempty"`
}

// EncodeSnapshot renders a snapshot deterministically (IDs sorted).
func EncodeSnapshot(s SourceSnapshot) ([]byte, error) {
	s.ControlIDs = append([]string(nil), s.ControlIDs...)
	sort.Strings(s.ControlIDs)
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("EncodeSnapshot: %w", err)
	}
	return append(raw, '\n'), nil
}

// ReadSnapshots loads every <benchmark>.json snapshot in dir, keyed by
// benchmark ID.
func ReadSnapshots(dir string) (map[string]SourceSnapshot, error) {
	names, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return nil, fmt.Errorf("ReadSnapshots: %w", err)
	}
	out := make(map[string]SourceSnapshot, len(names))
	for _, name := range names {
		raw, err := os.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("ReadSnapshots: %w", err)
		}
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		var s SourceSnapshot
		if err := dec.Decode(&s); err != nil {
			return nil, fmt.Errorf("ReadSnapshots: %s: %w", name, err)
		}
		if want := strings.TrimSuffix(filepath.Base(name), ".json"); s.Benchmark != want {
			return nil, fmt.Errorf("ReadSnapshots: %s holds benchmark %q", name, s.Benchmark)
		}
		out[s.Benchmark] = s
	}
	return out, nil
}

// ReadAcknowledged loads the acknowledgement file, keyed by benchmark ID. A
// missing file means nothing is acknowledged.
func ReadAcknowledged(dir string) (map[string]Acknowledgement, error) {
	raw, err := os.ReadFile(filepath.Join(dir, AcknowledgedFile))
	if os.IsNotExist(err) {
		return map[string]Acknowledgement{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("ReadAcknowledged: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	out := map[string]Acknowledgement{}
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("ReadAcknowledged: %w", err)
	}
	return out, nil
}

// IDDiff is the set difference between a matrix and an upstream list.
type IDDiff struct {
	// MissingFromMatrix: upstream IDs with no matrix row.
	MissingFromMatrix []string
	// NotInSource: matrix IDs the upstream does not list.
	NotInSource []string
}

// DiffIDs compares a matrix's control IDs with an upstream list.
func DiffIDs(b Benchmark, upstream []string) IDDiff {
	have := make(map[string]bool, len(b.Controls))
	for _, c := range b.Controls {
		have[c.ID] = true
	}
	src := make(map[string]bool, len(upstream))
	var d IDDiff
	for _, id := range upstream {
		src[id] = true
		if !have[id] {
			d.MissingFromMatrix = append(d.MissingFromMatrix, id)
		}
	}
	for _, c := range b.Controls {
		if !src[c.ID] {
			d.NotInSource = append(d.NotInSource, c.ID)
		}
	}
	sort.Strings(d.MissingFromMatrix)
	sort.Strings(d.NotInSource)
	return d
}
