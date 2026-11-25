package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	ladybug "github.com/vulngraph/vulngraph/internal/graphdb/ladybug"

	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/app/notify"
	"github.com/vulngraph/vulngraph/internal/app/savedquery"
)

// savedQueryCypherAdapter adapts any explore.CypherRunner (the worker's Ladybug
// primary or the serve pod's tiered runner) to savedquery.CypherRunner. It runs
// the saved query's read-only Cypher and projects the result down to node IDs,
// edge keys and scalar rows the service needs for counting and change detection.
type savedQueryCypherAdapter struct {
	runner explore.CypherRunner
}

func (a savedQueryCypherAdapter) RunForSavedQuery(ctx context.Context, cypher string) (savedquery.QueryResult, error) {
	// Generous budget — saved detections may legitimately match large result sets.
	out, err := a.runner.RunCypher(ctx, cypher, 2000, 5000)
	if err != nil {
		return savedquery.QueryResult{}, fmt.Errorf("RunForSavedQuery: %w", err)
	}
	res := savedquery.QueryResult{
		NodeIDs:                 make([]string, 0, len(out.Nodes)),
		EdgeKeys:                make([]string, 0, len(out.Edges)),
		Rows:                    make([]string, 0, len(out.Rows)),
		Truncated:               out.Truncated,
		MultiHopMayBeIncomplete: out.MultiHopMayBeIncomplete,
	}
	for _, n := range out.Nodes {
		res.NodeIDs = append(res.NodeIDs, n.ID)
	}
	for _, e := range out.Edges {
		res.EdgeKeys = append(res.EdgeKeys, e.SrcID+"|"+e.EdgeType+"|"+e.DstID)
	}
	// One id map for the whole result: RETURN a, collect(r) or a bare
	// collect(r) can carry a relationship whose endpoint node sits in another
	// column or another row.
	ids := map[ladybug.InternalID]string{}
	for _, row := range out.Rows {
		for _, v := range row {
			collectNodeIDs(v, ids)
		}
	}
	for _, row := range out.Rows {
		// encoding/json sorts map keys, so equal rows encode identically.
		b, err := json.Marshal(stableRow(row, ids))
		if err != nil {
			return savedquery.QueryResult{}, fmt.Errorf("RunForSavedQuery: encode row: %w", err)
		}
		res.Rows = append(res.Rows, string(b))
	}
	return res, nil
}

// stableRow rewrites the graph entities nested in a scalar row (collect(n),
// collect(r), paths) to their logical identity, so the row hash survives a
// graph rebuild: a node becomes "Label:id", a relationship (src id, type, dst
// id), and a list of entities is sorted. Internal TableID/Offset values and
// per-sweep properties (score, signal rollups) are dropped — they change on
// every rebuild without the result changing. ids maps internal node IDs to
// stable ids across the whole result (collectNodeIDs).
func stableRow(row map[string]any, ids map[ladybug.InternalID]string) map[string]any {
	out := make(map[string]any, len(row))
	for k, v := range row {
		out[k] = stableValue(v, ids)
	}
	return out
}

// collectNodeIDs maps every nested node's internal ID to its stable id, so a
// relationship anywhere in the result can name its endpoints.
func collectNodeIDs(v any, ids map[ladybug.InternalID]string) {
	switch t := v.(type) {
	case ladybug.Node:
		ids[t.ID] = nodeKey(t)
	case ladybug.RecursiveRelationship:
		for _, n := range t.Nodes {
			ids[n.ID] = nodeKey(n)
		}
	case []any:
		for _, e := range t {
			collectNodeIDs(e, ids)
		}
	case map[string]any:
		for _, e := range t {
			collectNodeIDs(e, ids)
		}
	}
}

func stableValue(v any, ids map[ladybug.InternalID]string) any {
	switch t := v.(type) {
	case ladybug.Node:
		return nodeKey(t)
	case ladybug.Relationship:
		return relKey(t, ids)
	case ladybug.RecursiveRelationship:
		nodes := make([]any, len(t.Nodes))
		for i, n := range t.Nodes {
			nodes[i] = nodeKey(n)
		}
		rels := make([]any, len(t.Relationships))
		for i, r := range t.Relationships {
			rels[i] = relKey(r, ids)
		}
		return map[string]any{"nodes": nodes, "rels": rels}
	case []any:
		out := make([]any, len(t))
		entities := len(t) > 0
		for i, e := range t {
			out[i] = stableValue(e, ids)
			entities = entities && isEntity(e)
		}
		if entities {
			sortByEncoding(out)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = stableValue(e, ids)
		}
		return out
	default:
		return v
	}
}

// isEntity reports a graph entity: collect() lists of these come back in
// engine scan order, which a rebuild reshuffles, so they hash as a set.
func isEntity(v any) bool {
	switch v.(type) {
	case ladybug.Node, ladybug.Relationship, ladybug.RecursiveRelationship:
		return true
	}
	return false
}

// sortByEncoding orders normalised entities by their printed form (fmt sorts
// map keys, so equal values print identically).
func sortByEncoding(vals []any) {
	type keyed struct {
		key string
		val any
	}
	ks := make([]keyed, len(vals))
	for i, v := range vals {
		ks[i] = keyed{key: fmt.Sprint(v), val: v}
	}
	sort.Slice(ks, func(i, j int) bool { return ks[i].key < ks[j].key })
	for i := range ks {
		vals[i] = ks[i].val
	}
}

func nodeKey(n ladybug.Node) string {
	id, _ := n.Properties["id"].(string)
	return n.Label + ":" + id
}

// relKey names a relationship by its endpoints' stable ids and its semantic
// type (the generic Edge table carries it in edge_type). An endpoint whose
// node is nowhere in the result falls back to its internal ID: a rebuild
// renumbers it (one spurious alert), which beats hashing every endpoint
// change of the same type and count identically (a missed one).
func relKey(r ladybug.Relationship, ids map[ladybug.InternalID]string) map[string]any {
	typ := r.Label
	if et, ok := r.Properties["edge_type"].(string); ok && et != "" {
		typ = et
	}
	endpoint := func(id ladybug.InternalID) string {
		if s, ok := ids[id]; ok {
			return s
		}
		return fmt.Sprintf("internal:%d:%d", id.TableID, id.Offset)
	}
	return map[string]any{"src": endpoint(r.SourceID), "type": typ, "dst": endpoint(r.DestinationID)}
}

// queryAlertNotifier is the part of *notify.Service the saved-query alerter uses.
type queryAlertNotifier interface {
	DeliverCounted(ctx context.Context, n notify.Notification) (notify.DeliveryResult, error)
}

// savedQueryAlerter adapts notify.Service to savedquery.Alerter: it builds a
// query-match notification when a scheduled query's result set changes and
// delivers it to the query's chosen channels (every channel routing
// query_match when none are chosen). Each channel's own severity and
// min_score rules still apply.
type savedQueryAlerter struct {
	notify queryAlertNotifier
}

func (a savedQueryAlerter) AlertQueryChange(ctx context.Context, q savedquery.SavedQuery, nodeCount, prevCount int) error {
	sev := q.AlertSeverity
	if !savedquery.ValidSeverity(sev) {
		sev = savedquery.DefaultAlertSeverity
	}
	res, err := a.notify.DeliverCounted(ctx, notify.Notification{
		EventType: notify.EventQueryMatch,
		Severity:  sev,
		Score:     savedQueryAlertScore(sev),
		Title:     "Saved query changed: " + q.Name,
		Message:   q.Description,
		Fields: []notify.Field{
			{Label: "Result count", Value: fmt.Sprintf("%d (was %d)", nodeCount, prevCount), Short: true},
			{Label: "Query", Value: q.Name, Short: true},
		},
		ChannelIDs: q.AlertChannelIDs,
	})
	if err != nil {
		return fmt.Errorf("AlertQueryChange: %w", err)
	}
	switch {
	case res.Delivered > 0:
		return nil
	case res.Eligible == 0:
		// Routing chose nobody (no channel, none routing query_match, a chosen
		// channel deleted or disabled, min_score above this severity's score).
		// A retry cannot change that, so the baseline advances.
		return fmt.Errorf("AlertQueryChange: %w", savedquery.ErrAlertNoRecipients)
	default:
		return fmt.Errorf("AlertQueryChange: %w", savedquery.ErrAlertUndelivered)
	}
}

// savedQueryAlertScore gives a saved-query alert a score that follows its
// severity, so a channel's min_score gate weighs it like any other alert of
// that severity instead of every saved query passing it at 100. The values sit
// inside the enrich score bands (page ≥81, high ≥61, pipeline ≥50).
func savedQueryAlertScore(sev string) int {
	switch sev {
	case savedquery.SeverityCritical:
		return 90
	case savedquery.SeverityHigh:
		return 70
	case savedquery.SeverityMedium:
		return 50
	case savedquery.SeverityLow:
		return 30
	default:
		return 10
	}
}
