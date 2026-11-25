package govern

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/reasoncache"
)

// A guidance-only ("disabled") class drops routine items from the queue, but
// never an urgent one: an observe plan CoVe escalated for a page-band finding
// must stay in front of a person.
func TestApplyPolicyRules_DisabledKeepsUrgentItems(t *testing.T) {
	pol := PolicySnapshot{SuggestThreshold: 60, ActionRules: map[string]string{"observe": "disabled"}}
	entries := []reasoncache.Entry{
		makeEntry("f-urgent", "observe", "high", 0.90),
		makeEntry("f-routine", "observe", "high", 0.90),
	}
	finds := map[string]finding.Finding{
		"f-urgent":  {ID: "f-urgent", CheckID: "kev", Score: 95, ScoreBand: string(enrich.BandPage), ResourceID: "h1"},
		"f-routine": {ID: "f-routine", CheckID: "tag", Score: 40, ScoreBand: string(enrich.BandPipeline), ResourceID: "h2"},
	}
	items, err := makeQueueSvc(pol, entries, finds).Queue(context.Background(), "")
	require.NoError(t, err)
	require.Len(t, items, 1)
	require.Equal(t, []string{"f-urgent"}, items[0].FindingIDs)
	require.True(t, items[0].Urgent)
	require.Equal(t, "escalated", items[0].Outcome)
}
