package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/app/graphstore"
	"github.com/vulngraph/vulngraph/internal/app/mcp"
)

// When neither Ladybug tier exists, graphStatsSource must return an interface
// that is nil to `== nil` — not an interface holding a nil pointer. MCP registers
// get_graph_stats on `stats != nil` and then calls NodeCounts on it, so a typed
// nil turns a disabled serve-Ladybug deployment into a panicking tool.
func TestGraphStatsSource_NilWhenNoTierAvailable(t *testing.T) {
	var serveLadybug *graphstore.Service
	var ladybugRepo *explore.LadybugRPCRepo

	// Converted to mcp.GraphStats exactly as serve.go passes it to mcp.NewHandler.
	var stats mcp.GraphStats = graphStatsSource(serveLadybug, ladybugRepo)

	// Deliberately `== nil` and not require.Nil: require.Nil reflects into the
	// interface and reports a nil *graphstore.Service as nil, so it passes for
	// exactly the typed-nil value this test exists to reject. MCP's guard is a
	// plain `stats != nil`, so that is what must be asserted.
	require.True(t, stats == nil,
		"a typed-nil interface passes MCP's registration guard and then panics on call")
}

func TestGraphStatsSource_FollowsTheCypherTiering(t *testing.T) {
	serveLadybug := &graphstore.Service{}
	ladybugRepo := &explore.LadybugRPCRepo{}

	require.IsType(t, &explore.TieredStats{}, graphStatsSource(serveLadybug, ladybugRepo),
		"with both tiers, report whichever one is serving Cypher")
	require.Same(t, serveLadybug, graphStatsSource(serveLadybug, nil),
		"serve replica alone")
	require.Same(t, ladybugRepo, graphStatsSource(nil, ladybugRepo),
		"falls back to the worker RPC when serve Ladybug is disabled")
}
