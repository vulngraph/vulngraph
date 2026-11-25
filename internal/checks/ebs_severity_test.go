package checks

import (
	"testing"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// aws-ebs-unencrypted is pinned at Medium deliberately. At High a single
// compliance control can dominate the entire open cspm High band, and these
// findings typically resolve as resource_gone rather than fixed.
//
// The threat model needs a precondition this check cannot see: the
// snapshot-exfil path is covered separately by aws-ebs-snapshot-public, a
// Critical check.
//
// Raising this back to High re-inflates every crit/high count in the product, so
// it must be a deliberate act with this comment read, not a drive-by.
func TestAWSEBSUnencrypted_IsMediumNotHigh(t *testing.T) {
	c, ok := checkByID(Default(), "aws-ebs-unencrypted")
	if !ok {
		t.Fatal("aws-ebs-unencrypted is not registered")
	}
	if c.Severity != finding.SeverityMedium {
		t.Fatalf("severity = %q, want %q — see the comment on this test before changing it",
			c.Severity, finding.SeverityMedium)
	}
	if c.SeverityFor != nil {
		t.Fatal("a SeverityFor override would bypass the flat-Medium decision")
	}
}

// checkByID reads the registered Check directly. Registry has no exported
// accessor for its slice, and this test asserts on the registered value rather
// than the package var so a future re-registration cannot silently bypass it.
func checkByID(r *Registry, id string) (Check, bool) {
	for _, c := range r.checks {
		if c.ID == id {
			return c, true
		}
	}
	return Check{}, false
}
