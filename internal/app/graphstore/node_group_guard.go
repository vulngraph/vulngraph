package graphstore

// node_group_guard.go — the runtime signal for an upstream engine limit.
//
// The pinned LadybugDB release (v0.21.2) can miss relationships in multi-hop
// and variable-length matches once a node table holds more rows than one node
// group and its last groups have no outgoing edges of the queried type
// (ladybug#1341; fixed by #1342, not in a release yet). An attack-path query
// then returns fewer paths than exist, with no engine error, which reads as
// less risk. The engine cannot report it, so every load counts its node
// tables and the served graph carries the answer: GraphHealth for
// /api/graph/{status,stats} and MCP get_graph_stats, a metric, and a flag on
// every Cypher result it answers. Single-hop reads (explore neighbours, the
// hop-by-hop blast-radius walk) and the Go BFS risk propagation are not
// affected, so they carry no flag.
//
// The guard goes with the pin bump to the first release that has the fix.

import (
	"context"
	"fmt"
	"sort"

	ladybug "github.com/vulngraph/vulngraph/internal/graphdb/ladybug"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// LadybugNodeGroupRows is the row count of one engine node group: a node
// table above it is exposed to ladybug#1341.
const LadybugNodeGroupRows = 131072

// countNodeTables reads the row count of every node table the loader writes,
// from the engine itself, so sentinel rows and dedup are counted as stored.
func countNodeTables(conn *ladybug.Connection) (map[string]int64, error) {
	labels := make([]string, 0, len(nodeUnwindQ))
	for label := range nodeUnwindQ {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	rows := make(map[string]int64, len(labels))
	for _, label := range labels {
		res, err := conn.Query(fmt.Sprintf("MATCH (n:`%s`) RETURN count(n) AS c", label))
		if err != nil {
			return nil, fmt.Errorf("countNodeTables %s: %w", label, err)
		}
		n, err := scanCount(res)
		res.Close()
		if err != nil {
			return nil, fmt.Errorf("countNodeTables %s: %w", label, err)
		}
		rows[label] = n
	}
	return rows, nil
}

// oversizedNodeTables keeps the tables holding more rows than one node group.
func oversizedNodeTables(rows map[string]int64) map[string]int64 {
	out := map[string]int64{}
	for label, n := range rows {
		if n > LadybugNodeGroupRows {
			out[label] = n
		}
	}
	return out
}

// publishNodeTableRows records the per-table row counts of the graph being
// swapped in. The caller holds s.mu for writing, so a reader holding the read
// lock always sees the counts of the graph it is querying.
func (s *Service) publishNodeTableRows(ctx context.Context, rows map[string]int64) {
	cp := make(map[string]int64, len(rows))
	for label, n := range rows {
		cp[label] = n
	}
	s.nodeTableRows.Store(&cp)
	if over := oversizedNodeTables(cp); len(over) > 0 {
		log.FromContext(ctx).Warn().Interface("oversized_node_tables", over).Int("node_group_rows", LadybugNodeGroupRows).
			Msg("graphstore: a node table is above one Ladybug node group — multi-hop and variable-length Cypher may miss relationships (ladybug#1341); results are flagged multi_hop_may_be_incomplete")
	}
}

// NodeTableRows returns the per-table row counts of the served graph, and
// false when no build has been published (unknown, not empty).
func (s *Service) NodeTableRows() (map[string]int64, bool) {
	p := s.nodeTableRows.Load()
	if p == nil {
		return nil, false
	}
	return *p, true
}

// multiHopMayBeIncomplete reports whether the served graph has a table above
// one node group. Read it under s.mu (inside withRead/withCypher) to get the
// answer for the graph the query ran on.
func (s *Service) multiHopMayBeIncomplete() bool {
	p := s.nodeTableRows.Load()
	return p != nil && len(oversizedNodeTables(*p)) > 0
}
