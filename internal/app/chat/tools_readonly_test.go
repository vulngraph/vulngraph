package chat

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/compliance"
	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// fakeDeps satisfies every chat dependency interface at once, so a test can
// enable all conditional tool blocks (connectors, live, cypher) with one value.
type fakeDeps struct{}

func (fakeDeps) Get(context.Context, string) (asset.Asset, error) { return asset.Asset{}, nil }
func (fakeDeps) BlastRadius(context.Context, string, int) (asset.BlastRadius, error) {
	return asset.BlastRadius{}, nil
}
func (fakeDeps) List(context.Context, finding.Filter) ([]finding.Finding, error) { return nil, nil }
func (fakeDeps) Coverage(context.Context) (compliance.Coverage, error) {
	return compliance.Coverage{}, nil
}
func (fakeDeps) RunCypher(context.Context, string) (explore.Result, error) {
	return explore.Result{}, nil
}
func (fakeDeps) DescribeEC2Instance(context.Context, string, string) (map[string]any, error) {
	return nil, nil
}
func (fakeDeps) DescribeSecurityGroup(context.Context, string, string) (map[string]any, error) {
	return nil, nil
}
func (fakeDeps) ListRolePolicies(context.Context, string, string) (map[string]any, error) {
	return nil, nil
}
func (fakeDeps) DescribeBucket(context.Context, string, string) (map[string]any, error) {
	return nil, nil
}
func (fakeDeps) LookupCloudTrailEvents(context.Context, string, string, int, int) ([]map[string]any, error) {
	return nil, nil
}
func (fakeDeps) ListForChat(context.Context) ([]ConnInfo, error) { return nil, nil }

// TestToolsAreReadOnly is the guardrail: every tool the chat agent can be handed
// must be on the readOnlyTools allowlist. The agent runs against real cloud
// credentials, so a mutating tool slipping in would let the model change
// infrastructure. If this fails, you added a tool — confirm it is read-only and
// add it to readOnlyTools, or (if it writes) move it off the chat path entirely.
func TestToolsAreReadOnly(t *testing.T) {
	deps := fakeDeps{}
	// Enable every conditional tool block so toolDefs emits the full surface.
	svc := NewService(nil, deps, deps, deps).
		WithConnectors(deps).
		WithLiveCaller(deps).
		WithCypher(deps)

	tools := svc.toolDefs()
	if len(tools) < 7 {
		t.Fatalf("expected the full tool surface (>=7 tools), got %d — did a With* block stop wiring?", len(tools))
	}
	for _, tool := range tools {
		name := tool.Name
		if !readOnlyTools[name] {
			t.Errorf("tool %q is exposed to the chat agent but not on the readOnlyTools allowlist — "+
				"if it mutates cloud state it must NOT be here; route writes through the executor + governance gate", name)
		}
	}
}

// TestCallToolRefusesNonAllowlisted proves the runtime guard: a tool name not on
// the allowlist is refused before dispatch, never executed.
func TestCallToolRefusesNonAllowlisted(t *testing.T) {
	svc := NewService(nil, fakeDeps{}, fakeDeps{}, fakeDeps{})
	out, isErr := svc.callTool(context.Background(), "terminate_instance", `{}`)
	if !isErr {
		t.Fatalf("expected refusal of a non-allowlisted tool, got success: %s", out)
	}
}

// scalarCypher returns a scalar/tabular result — the shape an aggregate query
// produces (Rows/Columns populated, Nodes empty).
type scalarCypher struct{ fakeDeps }

func (scalarCypher) RunCypher(context.Context, string) (explore.Result, error) {
	return explore.Result{
		Columns: []string{"c"},
		Rows:    []map[string]any{{"c": 93454}},
	}, nil
}

// TestRunCypherToolReportsScalarRows guards the bug that made the assistant tell
// users their security graph was empty: toolRunCypher marshalled only Nodes, so
// every aggregate ("how many assets?") came back as count 0 with no rows, and the
// model concluded there was no graph at all. The scalar shape must survive to the
// model — explore.Result populates Rows/Columns OR Nodes/Edges, never both.
func TestRunCypherToolReportsScalarRows(t *testing.T) {
	svc := NewService(nil, fakeDeps{}, fakeDeps{}, fakeDeps{}).WithCypher(scalarCypher{})

	out, isErr := svc.callTool(context.Background(), "run_cypher", `{"query":"MATCH (n:Asset) RETURN count(n) AS c"}`)
	if isErr {
		t.Fatalf("run_cypher failed: %s", out)
	}

	var got struct {
		Rows    []map[string]any `json:"rows"`
		Columns []string         `json:"columns"`
		Count   int              `json:"count"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("tool output is not JSON: %v (%s)", err, out)
	}
	if len(got.Rows) != 1 {
		t.Fatalf("scalar rows dropped from tool output: %s", out)
	}
	if got.Columns == nil {
		t.Errorf("scalar columns dropped from tool output: %s", out)
	}
	// count must reflect the shape the query produced, not len(Nodes).
	if got.Count != 1 {
		t.Errorf("count = %d, want 1 (the scalar row) — a 0 here is what read as 'empty graph'", got.Count)
	}
}

type oversizedCypher struct{ fakeDeps }

func (oversizedCypher) RunCypher(context.Context, string) (explore.Result, error) {
	return explore.Result{Columns: []string{"c"}, Rows: []map[string]any{{"c": 1}}, MultiHopMayBeIncomplete: true}, nil
}

// A result the graph engine flagged reaches the model with the flag and a
// warning, so a possibly short attack-path answer is never read as complete.
func TestRunCypherToolCarriesMultiHopFlag(t *testing.T) {
	for _, tc := range []struct {
		name   string
		runner CypherRunner
		want   bool
	}{
		{"flagged", oversizedCypher{}, true},
		{"unflagged", scalarCypher{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := NewService(nil, fakeDeps{}, fakeDeps{}, fakeDeps{}).WithCypher(tc.runner)
			out, isErr := svc.callTool(context.Background(), "run_cypher", `{"query":"MATCH p=(a)-[*1..3]->(b) RETURN count(p) AS c"}`)
			if isErr {
				t.Fatalf("run_cypher failed: %s", out)
			}
			var got struct {
				MultiHop *bool  `json:"multi_hop_may_be_incomplete"`
				Warning  string `json:"warning"`
			}
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("tool output is not JSON: %v (%s)", err, out)
			}
			if got.MultiHop == nil || *got.MultiHop != tc.want {
				t.Fatalf("multi_hop_may_be_incomplete = %v, want %v (%s)", got.MultiHop, tc.want, out)
			}
			if (got.Warning != "") != tc.want {
				t.Fatalf("warning present = %v, want %v (%s)", got.Warning != "", tc.want, out)
			}
		})
	}
}
