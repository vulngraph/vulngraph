package graphstore

// Per-table counts are read from each loaded graph for telemetry. The old
// LadybugDB node-group bug (ladybug#1341) was fixed in v0.22.0; crossing a
// node group is no longer a query-correctness warning.

import (
	"fmt"
	"sort"

	ladybug "github.com/vulngraph/vulngraph/internal/graphdb/ladybug"
)

// LadybugNodeGroupRows is a storage layout detail, not a graph size limit.
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

// publishNodeTableRows records the per-table row counts of the graph being
// swapped in. The caller holds s.mu for writing, so a reader holding the read
// lock always sees the counts of the graph it is querying.
func (s *Service) publishNodeTableRows(rows map[string]int64) {
	cp := make(map[string]int64, len(rows))
	for label, n := range rows {
		cp[label] = n
	}
	s.nodeTableRows.Store(&cp)
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
