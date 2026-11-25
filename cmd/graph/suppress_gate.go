package main

import (
	"context"
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// findingsByID is the finding read suppressAgentGate needs (*finding.Service).
type findingsByID interface {
	ByIDs(ctx context.Context, ids []string) ([]finding.Finding, error)
}

// suppressAgentGate is suppress.FindingGate over the finding store: the
// MCP suppress_finding rule (enrich.AgentRefusal), applied to an API-key
// suppression on REST.
type suppressAgentGate struct{ findings findingsByID }

// agentGateBatch bounds one ByIDs read, like finding.Service's own batches.
const agentGateBatch = 500

func (g suppressAgentGate) AgentRefusals(ctx context.Context, ids []string) (map[string]string, error) {
	out := make(map[string]string, len(ids))
	for start := 0; start < len(ids); start += agentGateBatch {
		found, err := g.findings.ByIDs(ctx, ids[start:min(start+agentGateBatch, len(ids))])
		if err != nil {
			return nil, fmt.Errorf("suppress agent gate: %w", err)
		}
		for _, f := range found {
			out[f.ID] = enrich.AgentRefusal(f)
		}
	}
	return out, nil
}
