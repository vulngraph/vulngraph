package respond

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

type fakeDecisionLister struct {
	events  []AuditEvent
	summary DecisionsSummary
	err     error
	// lastFilter records the filter the handler passed through on the most
	// recent ListDecisions call, so tests can assert the query params were
	// parsed and threaded down rather than silently dropped.
	lastFilter *DecisionFilter
}

func (f *fakeDecisionLister) ListDecisions(_ context.Context, _ time.Time, _ string, _ int, filter DecisionFilter) ([]AuditEvent, error) {
	f.lastFilter = &filter
	return f.events, f.err
}

func (f fakeDecisionLister) DecisionsSummary(context.Context) (DecisionsSummary, error) {
	return f.summary, f.err
}

type fakeFindings struct{ byID map[string]finding.Finding }

func (f fakeFindings) ByIDs(_ context.Context, ids []string) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, id := range ids {
		if fnd, ok := f.byID[id]; ok {
			out = append(out, fnd)
		}
	}
	return out, nil
}

func TestListDecisions_ResolvesTargetNames(t *testing.T) {
	h := NewHandler(
		&fakeDecisionLister{events: []AuditEvent{
			{ID: "1", TS: time.Unix(0, 0).UTC(), Actor: "agent", Action: "decision", TargetID: "f1", Details: `{"outcome":"escalated"}`},
		}},
		fakeFindings{byID: map[string]finding.Finding{
			"f1": {ID: "f1", Title: "IAM privilege escalation", ResourceID: "arn:aws:iam::1:user/x"},
		}},
	)

	rec := httptest.NewRecorder()
	h.ListDecisions(rec, httptest.NewRequest(http.MethodGet, "/api/decisions", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	var page struct {
		Items []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	require.Len(t, page.Items, 1)
	require.Equal(t, "agent", page.Items[0]["actor"])
	// The opaque target id is resolved to a human-readable finding title + resource.
	require.Equal(t, "IAM privilege escalation", page.Items[0]["target_title"])
	require.Equal(t, "arn:aws:iam::1:user/x", page.Items[0]["target_resource"])
}

func TestDecisionsSummary_ResolvesHotspots(t *testing.T) {
	h := NewHandler(
		&fakeDecisionLister{summary: DecisionsSummary{
			Total: 942, Observed: 7, Escalated: 900, Parked: 35,
			SuppressedByVerdict: 6,
			QuickWins:           12, UniqueResources: 311,
			ActionClasses:     map[string]int{"remediate": 500},
			ConfidenceBands:   map[string]int{"insufficient": 800},
			EscalationReasons: map[string]int{"insufficient_confidence": 850, "policy_blocked": 50, "pattern_denied": 6},
			Hotspots: []EscalationHotspot{
				{TargetID: "f1", Count: 33, Latest: time.Unix(0, 0).UTC()},
			},
		}},
		fakeFindings{byID: map[string]finding.Finding{
			"f1": {ID: "f1", Title: "OsPackageVulnerability", ResourceID: "example-org/notify-server"},
		}},
	)

	rec := httptest.NewRecorder()
	h.DecisionsSummary(rec, httptest.NewRequest(http.MethodGet, "/api/decisions/summary", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	var got map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &got))
	// Whole-trail aggregates come through, not page-local tallies.
	require.EqualValues(t, 942, got["total"])
	require.EqualValues(t, 900, got["escalated"])
	require.EqualValues(t, 311, got["unique_resources"])
	require.EqualValues(t, 6, got["suppressed_by_verdict"], "questions a human already answered")
	reasons, ok := got["escalation_reasons"].(map[string]any)
	require.True(t, ok)
	require.EqualValues(t, 850, reasons["insufficient_confidence"])
	require.EqualValues(t, 50, reasons["policy_blocked"])
	require.EqualValues(t, 6, reasons["pattern_denied"])
	hotspots, ok := got["hotspots"].([]any)
	require.True(t, ok)
	require.Len(t, hotspots, 1)
	hs := hotspots[0].(map[string]any)
	// Hotspot targets are resolved to finding title + resource like the list path.
	require.Equal(t, "OsPackageVulnerability", hs["target_title"])
	require.Equal(t, "example-org/notify-server", hs["target_resource"])
	require.EqualValues(t, 33, hs["count"])
}

func TestDecisionsSummary_Error500(t *testing.T) {
	h := NewHandler(&fakeDecisionLister{err: errors.New("ch down")}, fakeFindings{})

	rec := httptest.NewRecorder()
	h.DecisionsSummary(rec, httptest.NewRequest(http.MethodGet, "/api/decisions/summary", nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestListDecisions_Error500(t *testing.T) {
	h := NewHandler(&fakeDecisionLister{err: errors.New("ch down")}, fakeFindings{})

	rec := httptest.NewRecorder()
	h.ListDecisions(rec, httptest.NewRequest(http.MethodGet, "/api/decisions", nil))
	require.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestListDecisions_FiltersThreadThroughToTheRepo(t *testing.T) {
	tests := []struct {
		name   string
		query  string
		filter DecisionFilter
	}{
		{"by outcome", "?outcome=escalated", DecisionFilter{Outcome: "escalated"}},
		{"by action_class", "?action_class=remediate", DecisionFilter{ActionClass: "remediate"}},
		{"needs_action", "?outcome=needs_action", DecisionFilter{Outcome: "needs_action"}},
		{"safe_to_fix", "?outcome=safe_to_fix", DecisionFilter{Outcome: "safe_to_fix"}},
		{
			"outcome and action_class AND together",
			"?outcome=escalated&action_class=isolate",
			DecisionFilter{Outcome: "escalated", ActionClass: "isolate"},
		},
		{"no filter", "", DecisionFilter{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lister := &fakeDecisionLister{}
			h := NewHandler(lister, fakeFindings{})

			rec := httptest.NewRecorder()
			h.ListDecisions(rec, httptest.NewRequest(http.MethodGet, "/api/decisions"+tc.query, nil))

			require.Equal(t, http.StatusOK, rec.Code)
			require.NotNil(t, lister.lastFilter)
			require.Equal(t, tc.filter, *lister.lastFilter)
		})
	}
}

// clampingDecisionLister mimics CHRepo.ListDecisions' own clamp to
// decisionsPageLimit (repo.go), independent of whatever limit the handler
// asks for — the real repo does this too. Used to prove the handler clamps
// BEFORE comparing len(events) == limit, not just before calling the repo.
type clampingDecisionLister struct{ requestedLimit int }

func (f *clampingDecisionLister) ListDecisions(_ context.Context, _ time.Time, _ string, limit int, _ DecisionFilter) ([]AuditEvent, error) {
	f.requestedLimit = limit
	if limit > decisionsPageLimit {
		limit = decisionsPageLimit
	}
	out := make([]AuditEvent, limit)
	for i := range out {
		out[i] = AuditEvent{ID: "d" + string(rune('a'+i)), TS: time.Unix(int64(i), 0).UTC()}
	}
	return out, nil
}

func (f clampingDecisionLister) DecisionsSummary(context.Context) (DecisionsSummary, error) {
	return DecisionsSummary{}, nil
}

// A ?limit over decisionsPageLimit must not silently look "exhausted": the
// repo clamps the row count to decisionsPageLimit, and comparing that against
// the UNCLAMPED requested limit (500 != 100) meant next_cursor was never
// emitted — a truncated page presented as the complete answer.
func TestListDecisions_LimitOverPageLimitStillEmitsNextCursor(t *testing.T) {
	lister := &clampingDecisionLister{}
	h := NewHandler(lister, fakeFindings{})

	rec := httptest.NewRecorder()
	h.ListDecisions(rec, httptest.NewRequest(http.MethodGet, "/api/decisions?limit=500", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, decisionsPageLimit, lister.requestedLimit, "the repo must be asked for the clamped limit")
	var page decisionsPage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	require.Len(t, page.Items, decisionsPageLimit)
	require.NotEmpty(t, page.NextCursor, "a full clamped page must still say more may exist")
}

func TestListDecisions_InvalidOutcome400s(t *testing.T) {
	lister := &fakeDecisionLister{}
	h := NewHandler(lister, fakeFindings{})

	rec := httptest.NewRecorder()
	h.ListDecisions(rec, httptest.NewRequest(http.MethodGet, "/api/decisions?outcome=bogus", nil))

	require.Equal(t, http.StatusBadRequest, rec.Code)
	// The unrecognized value must reject the request, not silently match zero
	// rows (the classic degraded-input bug shape: a degraded input indistinguishable
	// from a genuine empty result).
	require.Nil(t, lister.lastFilter)
}

func TestListDecisions_InvalidActionClass400s(t *testing.T) {
	lister := &fakeDecisionLister{}
	h := NewHandler(lister, fakeFindings{})

	rec := httptest.NewRecorder()
	h.ListDecisions(rec, httptest.NewRequest(http.MethodGet, "/api/decisions?action_class=nuke", nil))

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.Nil(t, lister.lastFilter)
}

// Every proposed fix reaches the approver with what it changes, why it
// matters, whether it can be undone and how to run it by hand. An observe
// plan changes nothing, so it carries no remediation block.
func TestListDecisions_CarriesFixGuidance(t *testing.T) {
	var guidedClass string
	h := NewHandler(
		&fakeDecisionLister{events: []AuditEvent{
			{ID: "1", TS: time.Unix(1, 0).UTC(), Actor: "agent", Action: "decision", TargetType: "finding", TargetID: "f1",
				Details: `{"outcome":"parked_for_approval","action_class":"remediate"}`},
			{ID: "2", TS: time.Unix(0, 0).UTC(), Actor: "agent", Action: "decision", TargetType: "finding", TargetID: "f1",
				Details: `{"outcome":"observed","action_class":"observe"}`},
		}},
		fakeFindings{byID: map[string]finding.Finding{
			"f1": {ID: "f1", Title: "Public bucket", ResourceID: "arn:aws:s3:::b", ResourceType: "s3_bucket",
				MustFixReason: "internet-reachable · blast 4", Remediation: "Enable S3 Block Public Access."},
		}},
	).WithRemediationGuide(RemediationGuideFunc(func(f finding.Finding, actionClass string) (Remediation, bool) {
		guidedClass = actionClass
		return Remediation{
			Action: "s3_block_public", Change: "block all public access on S3 bucket b", Reversible: true,
			Rollback: "aws s3api delete-public-access-block --bucket b", CLI: "aws s3api put-public-access-block --bucket b",
		}, f.ResourceType == "s3_bucket"
	}))

	rec := httptest.NewRecorder()
	h.ListDecisions(rec, httptest.NewRequest(http.MethodGet, "/api/decisions", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	var page struct {
		Items []map[string]any `json:"items"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &page))
	require.Len(t, page.Items, 2)

	parked := page.Items[0]
	require.Equal(t, "remediate", guidedClass, "the guide is asked about the plan's own action class")
	require.Equal(t, "internet-reachable · blast 4", parked["target_must_fix_reason"])
	require.Equal(t, "Enable S3 Block Public Access.", parked["target_remediation"])
	rem, ok := parked["remediation"].(map[string]any)
	require.True(t, ok, "a remediate plan on an executable resource carries guidance")
	require.Equal(t, "s3_block_public", rem["action"])
	require.Equal(t, true, rem["reversible"])
	require.Equal(t, false, rem["destructive"])
	require.Contains(t, rem["cli"], "put-public-access-block")

	require.NotContains(t, page.Items[1], "remediation", "an observe plan changes nothing")
}
