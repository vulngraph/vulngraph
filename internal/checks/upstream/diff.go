package upstream

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/vulngraph/vulngraph/internal/checks/benchmarks"
)

// BenchmarkReport is one matrix against its upstream.
type BenchmarkReport struct {
	Benchmark     string `json:"benchmark"`
	Name          string `json:"name"`
	Pinned        string `json:"pinned"`
	Source        string `json:"source"`
	SourceVersion string `json:"source_version"`
	// Exact: the upstream publishes the pinned version. When false, the ID
	// lists below are the delta to the nearest older version and are
	// informational only.
	Exact  bool   `json:"exact"`
	Latest string `json:"latest"`
	// NewerVersion: an upstream publishes a version above the pinned one.
	NewerVersion bool `json:"newer_version"`
	// Added: upstream control IDs with no matrix row (for FSBP, new controls,
	// with AWS's titles).
	Added []Control `json:"added"`
	// Removed: matrix rows the upstream no longer lists.
	Removed []string `json:"removed"`
	// Acknowledged: the subset of Added/Removed recorded in acknowledged.yaml,
	// ID → reason. Still drift: the weekly issue stays open until reconciled.
	Acknowledged map[string]string `json:"acknowledged,omitempty"`
	// SnapshotStale: the upstream list differs from the committed snapshot, so
	// the completeness test is checking against an old list.
	SnapshotStale bool `json:"snapshot_stale"`
	Drift         bool `json:"drift"`
}

// Report is benchmark-watch's output.
type Report struct {
	Checked    string            `json:"checked"`
	Benchmarks []BenchmarkReport `json:"benchmarks"`
	// Frameworks lists requirement-mapping files that would change if
	// regenerated (only when frameworks were checked).
	Frameworks []string `json:"stale_frameworks,omitempty"`
	Drift      bool     `json:"drift"`
}

// Diff compares each matrix with its observation and the committed
// snapshot. A matrix with no observation is reported as drift rather than
// skipped: an upstream that could not be read is not one that matched.
func Diff(bs []benchmarks.Benchmark, obs []Observation, snaps map[string]benchmarks.SourceSnapshot,
	acks map[string]benchmarks.Acknowledgement, checked string) Report {
	rep := Report{Checked: checked}
	for _, bm := range bs {
		r := BenchmarkReport{Benchmark: bm.ID, Name: bm.Name, Pinned: bm.Version}
		i := slices.IndexFunc(obs, func(o Observation) bool { return o.Benchmark == bm.ID })
		if i < 0 {
			r.Source = "unread"
			r.Drift = true
			rep.Benchmarks = append(rep.Benchmarks, r)
			rep.Drift = true
			continue
		}
		o := obs[i]
		r.Source, r.SourceVersion, r.Exact, r.Latest = o.Source, o.SourceVersion, o.Exact, o.Latest
		if lv, err := parseVersion(o.Latest); err == nil {
			if pv, err := parseVersion(bm.Version); err == nil && lv.compare(pv) > 0 {
				r.NewerVersion = true
			}
		}
		d := benchmarks.DiffIDs(bm, o.IDs())
		titles := map[string]string{}
		for _, c := range o.Controls {
			titles[c.ID] = c.Title
		}
		for _, id := range d.MissingFromMatrix {
			r.Added = append(r.Added, Control{ID: id, Title: titles[id]})
		}
		r.Removed = d.NotInSource
		ack := acks[bm.ID]
		for _, id := range d.MissingFromMatrix {
			if why, ok := ack.MissingFromMatrix[id]; ok {
				r.addAck(id, why)
			}
		}
		for _, id := range d.NotInSource {
			if why, ok := ack.NotInSource[id]; ok {
				r.addAck(id, why)
			}
		}
		snap, ok := snaps[bm.ID]
		r.SnapshotStale = !ok || !sameSet(snap.ControlIDs, o.IDs()) || snap.SourceVersion != o.SourceVersion
		r.Drift = r.NewerVersion || r.SnapshotStale || (r.Exact && (len(r.Added) > 0 || len(r.Removed) > 0))
		rep.Drift = rep.Drift || r.Drift
		rep.Benchmarks = append(rep.Benchmarks, r)
	}
	return rep
}

func (r *BenchmarkReport) addAck(id, why string) {
	if r.Acknowledged == nil {
		r.Acknowledged = map[string]string{}
	}
	r.Acknowledged[id] = why
}

func sameSet(a, b []string) bool {
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(x, y)
}

// Snapshot turns an observation into the record the completeness test reads.
func Snapshot(o Observation, checked string) benchmarks.SourceSnapshot {
	return benchmarks.SourceSnapshot{
		Benchmark: o.Benchmark, Source: o.Source, Pinned: o.Pinned, SourceVersion: o.SourceVersion,
		Exact: o.Exact, Latest: o.Latest, Checked: checked, ControlIDs: o.IDs(),
	}
}

// Text renders the report for a person.
func (rep Report) Text() string {
	var w strings.Builder
	fmt.Fprintf(&w, "benchmark-watch %s\n\n", rep.Checked)
	for _, r := range rep.Benchmarks {
		mark := "ok   "
		if r.Drift {
			mark = "DRIFT"
		}
		fmt.Fprintf(&w, "[%s] %s %s — %s", mark, r.Benchmark, r.Pinned, r.Source)
		if r.SourceVersion != "" && !r.Exact {
			fmt.Fprintf(&w, " (pinned version not published; nearest is %s)", r.SourceVersion)
		}
		w.WriteString("\n")
		if r.NewerVersion {
			fmt.Fprintf(&w, "    newer version available: %s\n", r.Latest)
		}
		if r.SnapshotStale {
			w.WriteString("    upstream list differs from the committed snapshot: run benchmark-watch -update\n")
		}
		label := "added upstream"
		if r.Benchmark == "aws-fsbp" {
			label = "new FSBP controls"
		}
		if !r.Exact {
			label = "only in nearest version (informational)"
		}
		for _, c := range r.Added {
			fmt.Fprintf(&w, "    %s: %s %s%s\n", label, c.ID, c.Title, ackNote(r, c.ID))
		}
		for _, id := range r.Removed {
			fmt.Fprintf(&w, "    no longer upstream: %s%s\n", id, ackNote(r, id))
		}
	}
	for _, f := range rep.Frameworks {
		fmt.Fprintf(&w, "[DRIFT] framework mapping %s is stale: run benchmark-watch -frameworks -update\n", f)
	}
	if rep.Drift {
		w.WriteString("\ndrift detected\n")
	} else {
		w.WriteString("\nno drift\n")
	}
	return w.String()
}

func ackNote(r BenchmarkReport, id string) string {
	if why, ok := r.Acknowledged[id]; ok {
		return " [acknowledged: " + why + "]"
	}
	return ""
}
