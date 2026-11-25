package finding

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// obsScrapeBudget mirrors internal/obs's unexported scrapeBudget. It is repeated
// rather than imported because obs deliberately reaches this package through a
// func field instead of an import, and a domain must not import the
// observability layer to satisfy a test.
//
// A hand-copy like this can drift silently: if obs.scrapeBudget shrinks and
// this mirror (and CheckQualityTimeout itself) does not, this test keeps
// passing against its own stale copy while CheckQuality's real queries are
// capped at the smaller budget. There is no compiler check that can catch this copy
// going stale again; whoever changes obs.scrapeBudget must grep for
// "obsScrapeBudget" (here) and "sourceActivityTimeout" (source_activity.go)
// and update both by hand.
const obsScrapeBudget = 8 * time.Second

// A CheckQualityTimeout larger than the scrape budget is not a longer budget, it
// is a dead number: context.WithTimeout keeps the earlier deadline, so the outer
// budget always wins. This ratchet fails the moment someone raises it back —
// but only as long as obsScrapeBudget itself still matches the real
// obs.scrapeBudget; see that constant's comment.
func TestCheckQualityTimeoutFitsTheScrapeBudget(t *testing.T) {
	require.LessOrEqual(t, CheckQualityTimeout, obsScrapeBudget,
		"CheckQualityTimeout can never exceed the /metrics scrape budget that wraps it")
	require.Positive(t, CheckQualityTimeout, "a full-table aggregate needs its own deadline")
}

// The scoreboard is queried with LIMIT CheckQualityLimit+1 so the caller can
// detect truncation; the limit itself must stay above the check registry.
func TestCheckQualityLimitCoversTheRegistry(t *testing.T) {
	require.Greater(t, CheckQualityLimit, 124, "must exceed the ~124-check registry")
}
