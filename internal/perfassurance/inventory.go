package perfassurance

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

// Inventory fixes the denominator before performance evidence is accepted.
type Inventory struct {
	Version       int      `json:"version"`
	Revision      string   `json:"revision"`
	Profiles      []string `json:"profiles"`
	Architectures []string `json:"architectures"`
	Families      []Family `json:"families"`
}

// Family groups entries with a common cost model. Entries may feed multiple
// distinct models, such as inventory filters and finding-rollup risk ordering.
type Family struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Owner      string   `json:"owner"`
	Weight     int      `json:"weight"`
	Rationale  string   `json:"rationale"`
	Budget     string   `json:"budget"`
	Scenarios  []string `json:"scenarios"`
	Status     string   `json:"status"`
	Entries    []string `json:"entries"`
	NextAction string   `json:"next_action"`
}

// Profiles contains predeclared resource profiles and reusable scenario classes.
type Profiles struct {
	Version  int                        `json:"version"`
	Revision string                     `json:"revision"`
	Profiles map[string]json.RawMessage `json:"profiles"`
	Classes  map[string]struct {
		Scenarios []string `json:"required_scenarios"`
		Repeats   int      `json:"repeats"`
	} `json:"budget_classes"`
}

// Load reads the reviewed inventory and budgets.
func Load(root string) (Inventory, Profiles, error) {
	var inv Inventory
	var profiles Profiles
	for name, target := range map[string]any{"workloads.json": &inv, "profiles.json": &profiles} {
		data, err := os.ReadFile(filepath.Join(root, "docs/performance", name))
		if err != nil {
			return inv, profiles, fmt.Errorf("read %s: %w", name, err)
		}
		if err := json.Unmarshal(data, target); err != nil {
			return inv, profiles, fmt.Errorf("decode %s: %w", name, err)
		}
	}
	return inv, profiles, nil
}

// Validate fails closed on scope drift. This validates the denominator, not the
// truth of measurements: covered claims belong to a separately reviewed report.
func Validate(inv Inventory, profiles Profiles, entries []Entry) []string {
	var errors []string
	if inv.Version != 1 || profiles.Version != 1 || inv.Revision == "" || profiles.Revision == "" {
		errors = append(errors, "missing/unsupported inventory or profile revision")
	}
	for _, name := range []string{"small", "target", "stress"} {
		if !slices.Contains(inv.Profiles, name) || len(profiles.Profiles[name]) == 0 {
			errors = append(errors, "missing profile: "+name)
		} else {
			errors = append(errors, validateProfile(name, profiles.Profiles[name])...)
		}
	}
	for _, arch := range []string{"linux/amd64", "linux/arm64"} {
		if !slices.Contains(inv.Architectures, arch) {
			errors = append(errors, "missing native architecture: "+arch)
		}
	}
	discovered := map[string]bool{}
	mapped := map[string]bool{}
	ids := map[string]bool{}
	for _, entry := range entries {
		discovered[entry.ID] = true
	}
	for _, f := range inv.Families {
		if ids[f.ID] || f.ID == "" {
			errors = append(errors, "duplicate/empty family ID: "+f.ID)
		}
		ids[f.ID] = true
		if f.Owner == "" || f.Title == "" || f.Rationale == "" || f.NextAction == "" {
			errors = append(errors, "missing ownership/risk/next action: "+f.ID)
		}
		if f.Weight != 1 && f.Weight != 3 && f.Weight != 5 {
			errors = append(errors, "invalid weight: "+f.ID)
		}
		if len(f.Entries) == 0 || len(f.Scenarios) == 0 {
			errors = append(errors, "empty scope/scenarios: "+f.ID)
		}
		if _, ok := profiles.Classes[f.Budget]; !ok {
			errors = append(errors, "unknown budget: "+f.ID)
		}
		for _, name := range f.Scenarios {
			c, ok := profiles.Classes[name]
			if !ok || len(c.Scenarios) < 9 || c.Repeats < 3 {
				errors = append(errors, "incomplete scenario class: "+f.ID+"/"+name)
			}
		}
		if !slices.Contains([]string{"unmeasured", "partial", "failing", "stale"}, f.Status) {
			errors = append(errors, "coverage requires a separately reviewed evidence report, not a manifest status: "+f.ID)
		}
		seen := map[string]bool{}
		for _, id := range f.Entries {
			if !discovered[id] {
				errors = append(errors, "removed/unknown entry: "+f.ID+" -> "+id)
			}
			if seen[id] {
				errors = append(errors, "duplicate membership: "+f.ID+" -> "+id)
			}
			seen[id] = true
			mapped[id] = true
		}
	}
	for id := range discovered {
		if !mapped[id] {
			errors = append(errors, "unmapped entry: "+id)
		}
	}
	slices.Sort(errors)
	return errors
}
