package main

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ladybug "github.com/vulngraph/vulngraph/internal/graphdb/ladybug"

	"github.com/vulngraph/vulngraph/internal/app/explore"
	"github.com/vulngraph/vulngraph/internal/app/notify"
	"github.com/vulngraph/vulngraph/internal/app/savedquery"
)

type fakeCypher struct{ out explore.Result }

func (f fakeCypher) RunCypher(context.Context, string, int, int) (explore.Result, error) {
	return f.out, nil
}

// Truncation and scalar rows survive the projection: a truncated result must
// not be hashed as complete, and a count must be part of the hash.
func TestSavedQueryCypherAdapter_CarriesTruncationAndRows(t *testing.T) {
	a := savedQueryCypherAdapter{runner: fakeCypher{out: explore.Result{
		Truncated: true,
		Rows:      []map[string]any{{"b": 2, "a": 1}},
	}}}
	res, err := a.RunForSavedQuery(context.Background(), "MATCH (n) RETURN count(n)")
	require.NoError(t, err)
	assert.True(t, res.Truncated)
	assert.Equal(t, []string{`{"a":1,"b":2}`}, res.Rows)
}

// A graph rebuild renumbers internal IDs and rewrites per-sweep properties;
// the same logical result must hash identically across it, while a real
// membership change must not.
func TestSavedQueryCypherAdapter_RowHashSurvivesRebuild(t *testing.T) {
	node := func(id string, tableOff uint64, score int) ladybug.Node {
		return ladybug.Node{
			ID:         ladybug.InternalID{TableID: tableOff, Offset: tableOff * 7},
			Label:      "Asset",
			Properties: map[string]any{"id": id, "score": score, "max_score": score, "exposed": score % 2},
		}
	}
	rel := func(src, dst ladybug.Node, off uint64) ladybug.Relationship {
		return ladybug.Relationship{
			ID: ladybug.InternalID{TableID: 9, Offset: off}, SourceID: src.ID, DestinationID: dst.ID,
			Label: "Edge", Properties: map[string]any{"edge_type": "CAN_REACH"},
		}
	}
	rows := func(a, b ladybug.Node, relOff uint64) []map[string]any {
		return []map[string]any{{
			"nodes": []any{a, b},
			"rels":  []any{rel(a, b, relOff)},
			"path":  ladybug.RecursiveRelationship{Nodes: []ladybug.Node{a, b}, Relationships: []ladybug.Relationship{rel(a, b, relOff)}},
			"n":     int64(2),
		}}
	}
	hash := func(r []map[string]any) []string {
		res, err := savedQueryCypherAdapter{runner: fakeCypher{out: explore.Result{Rows: r}}}.
			RunForSavedQuery(context.Background(), "MATCH ...")
		require.NoError(t, err)
		return res.Rows
	}

	before := hash(rows(node("a", 1, 40), node("b", 2, 60), 3))
	// Rebuild: new internal IDs, rescored, and collect() returns the other order.
	afterA, afterB := node("a", 5, 81), node("b", 4, 13)
	after := hash([]map[string]any{{
		"nodes": []any{afterB, afterA},
		"rels":  []any{rel(afterA, afterB, 11)},
		"path":  ladybug.RecursiveRelationship{Nodes: []ladybug.Node{afterA, afterB}, Relationships: []ladybug.Relationship{rel(afterA, afterB, 11)}},
		"n":     int64(2),
	}})
	assert.Equal(t, before, after)
	assert.NotContains(t, before[0], "score")
	assert.NotContains(t, before[0], "Offset")

	changed := hash(rows(node("a", 1, 40), node("c", 2, 60), 3))
	assert.NotEqual(t, before, changed, "a different member must change the hash")
}

// RETURN collect(r) carries no endpoint nodes. Retargeting an edge to another
// node keeps its type and the count, so the hash has to change anyway.
func TestSavedQueryCypherAdapter_CollectRelsEndpointChangeAlerts(t *testing.T) {
	rel := func(dstOff uint64) ladybug.Relationship {
		return ladybug.Relationship{
			ID:       ladybug.InternalID{TableID: 9, Offset: 1},
			SourceID: ladybug.InternalID{TableID: 1, Offset: 1}, DestinationID: ladybug.InternalID{TableID: 1, Offset: dstOff},
			Label: "Edge", Properties: map[string]any{"edge_type": "CAN_REACH"},
		}
	}
	hash := func(r ladybug.Relationship) []string {
		res, err := savedQueryCypherAdapter{runner: fakeCypher{out: explore.Result{
			Rows: []map[string]any{{"rels": []any{r}}},
		}}}.RunForSavedQuery(context.Background(), "MATCH ()-[r]->() RETURN collect(r) AS rels")
		require.NoError(t, err)
		return res.Rows
	}
	assert.NotEqual(t, hash(rel(2)), hash(rel(3)), "an unresolved endpoint change must not hash as unchanged")
	assert.NotContains(t, hash(rel(2))[0], "unresolved")
}

// An endpoint node in another row (RETURN a, collect(r) grouped by a) still
// resolves to its stable id, so a rebuild that renumbers it hashes the same.
func TestSavedQueryCypherAdapter_EndpointResolvedAcrossRows(t *testing.T) {
	node := func(id string, off uint64) ladybug.Node {
		return ladybug.Node{ID: ladybug.InternalID{TableID: 1, Offset: off}, Label: "Asset", Properties: map[string]any{"id": id}}
	}
	rel := func(src, dst ladybug.Node) ladybug.Relationship {
		return ladybug.Relationship{SourceID: src.ID, DestinationID: dst.ID, Label: "Edge",
			Properties: map[string]any{"edge_type": "CAN_REACH"}}
	}
	hash := func(a, b ladybug.Node) []string {
		res, err := savedQueryCypherAdapter{runner: fakeCypher{out: explore.Result{Rows: []map[string]any{
			{"a": a, "rels": []any{}},
			{"a": b, "rels": []any{rel(b, a)}},
		}}}}.RunForSavedQuery(context.Background(), "MATCH ...")
		require.NoError(t, err)
		return res.Rows
	}
	before := hash(node("x", 1), node("y", 2))
	assert.Equal(t, before, hash(node("x", 7), node("y", 8)), "a rebuild renumbering both nodes is the same result")
	assert.Contains(t, before[1], `"dst":"Asset:x"`)
	assert.NotEqual(t, before, hash(node("z", 1), node("y", 2)), "a different endpoint changes the hash")
}

type fakeQueryNotifier struct {
	res notify.DeliveryResult
	err error
	got notify.Notification
}

func (f *fakeQueryNotifier) DeliverCounted(_ context.Context, n notify.Notification) (notify.DeliveryResult, error) {
	f.got = n
	return f.res, f.err
}

func TestSavedQueryAlerter(t *testing.T) {
	q := savedquery.SavedQuery{Name: "q", AlertSeverity: savedquery.SeverityMedium, AlertChannelIDs: []string{"c1"}}
	tests := []struct {
		name    string
		n       *fakeQueryNotifier
		wantErr error
		anyErr  bool
	}{
		{name: "delivered", n: &fakeQueryNotifier{res: notify.DeliveryResult{Eligible: 1, Delivered: 1}}},
		{name: "partly delivered", n: &fakeQueryNotifier{res: notify.DeliveryResult{Eligible: 2, Delivered: 1}}},
		{name: "routing chose nobody advances the baseline", n: &fakeQueryNotifier{}, wantErr: savedquery.ErrAlertNoRecipients},
		{name: "eligible channels but every send failed", n: &fakeQueryNotifier{res: notify.DeliveryResult{Eligible: 2}}, wantErr: savedquery.ErrAlertUndelivered},
		{name: "channel list unreadable", n: &fakeQueryNotifier{err: errors.New("pg")}, anyErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := savedQueryAlerter{notify: tc.n}.AlertQueryChange(context.Background(), q, 3, 2)
			switch {
			case tc.wantErr != nil:
				require.ErrorIs(t, err, tc.wantErr)
			case tc.anyErr:
				require.Error(t, err)
			default:
				require.NoError(t, err)
			}
			assert.Equal(t, []string{"c1"}, tc.n.got.ChannelIDs, "selected channels are honoured")
			assert.Equal(t, savedquery.SeverityMedium, tc.n.got.Severity)
			assert.Equal(t, 50, tc.n.got.Score, "score follows severity instead of bypassing min_score")
		})
	}
}

func TestSavedQueryAlertScore_GatesLikeSeverity(t *testing.T) {
	assert.Greater(t, savedQueryAlertScore(savedquery.SeverityCritical), savedQueryAlertScore(savedquery.SeverityHigh))
	assert.Greater(t, savedQueryAlertScore(savedquery.SeverityHigh), savedQueryAlertScore(savedquery.SeverityMedium))
	assert.Greater(t, savedQueryAlertScore(savedquery.SeverityMedium), savedQueryAlertScore(savedquery.SeverityLow))
	assert.Greater(t, savedQueryAlertScore(savedquery.SeverityLow), savedQueryAlertScore(savedquery.SeverityInfo))
	assert.Less(t, savedQueryAlertScore(savedquery.SeverityCritical), 100)
}
