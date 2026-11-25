package enrich

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func TestFindingAge(t *testing.T) {
	now := time.Date(2026, 7, 7, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	src := FindingAge{Now: clock}
	ctx := context.Background()

	base := func(days int) finding.Finding {
		return finding.Finding{
			CheckID: "iam-privesc-01", Type: "ciem_privesc",
			FirstDetectedAt: now.Add(-time.Duration(days) * 24 * time.Hour),
			DetectedAt:      now, // re-observed this instant, as every producer does
		}
	}

	tests := []struct {
		name        string
		f           finding.Finding
		wantApplied bool
	}{
		{"over a year demotes -10", base(400), true},
		{"over 90d demotes -5", base(120), true},
		{"fresh no-op", base(10), false},
		{"KEV never demoted", func() finding.Finding { f := base(400); f.KnownExploited = true; return f }(), false},
		{"exposure age is not a mitigant", func() finding.Finding {
			f := base(400)
			f.Type, f.CheckID = "exposure", "s3-public"
			return f
		}(), false},
		{"no first_detected_at no-op", finding.Finding{CheckID: "iam-privesc-01"}, false},
		// Regression: age must not be read from DetectedAt, which every producer
		// re-stamps on every re-observation, or a year-old finding seen five
		// minutes ago scores as brand new.
		{"old first observation demotes even though detected_at is fresh", finding.Finding{
			CheckID: "iam-privesc-01", Type: "ciem_privesc",
			FirstDetectedAt: now.Add(-400 * 24 * time.Hour),
			DetectedAt:      now.Add(-time.Minute),
		}, true},
		// The mirror: a genuinely new finding whose producer reported an ancient
		// upstream detected_at must NOT be demoted on that basis alone.
		{"stale detected_at alone never demotes", finding.Finding{
			CheckID: "iam-privesc-01", Type: "ciem_privesc",
			DetectedAt: now.Add(-400 * 24 * time.Hour),
		}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			factor, applied, _ := src.Evaluate(ctx, tc.f)
			if applied != tc.wantApplied {
				t.Fatalf("applied = %v, want %v", applied, tc.wantApplied)
			}
			if applied && factor.Points >= 0 {
				t.Errorf("age must be demotion-only, got %d", factor.Points)
			}
		})
	}
}

// TestFindingAgeReadsFirstDetectedAtOnly is a source-reading guard, not a
// behaviour test, because the behaviour tests above cannot see the whole
// hazard: any NEW branch added to this source that reaches for f.DetectedAt
// reintroduces the bug for whatever case that branch covers, and would sail
// past a table that only exercises the branches that exist today.
//
// finding.DetectedAt is "when we last emitted this", not "when it started" —
// producers stamp `now` on every re-observation. There is no correct use of it
// in an age computation, so the guard is a flat ban on the identifier rather
// than a judgement about a particular call site.
func TestFindingAgeReadsFirstDetectedAtOnly(t *testing.T) {
	src, err := os.ReadFile("sources_age.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	for i, line := range strings.Split(string(src), "\n") {
		code, _, _ := strings.Cut(line, "//")
		if strings.Contains(code, "f.DetectedAt") {
			t.Errorf("sources_age.go:%d reads f.DetectedAt: %s\n"+
				"detected_at is re-stamped by every producer on every re-observation, so it "+
				"measures time-since-last-seen, not age. Read f.FirstDetectedAt.", i+1, strings.TrimSpace(line))
		}
	}
}
