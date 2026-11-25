package belief

import "testing"

func TestNeedsAdjudication(t *testing.T) {
	tests := []struct {
		name string
		in   SeverityInputs
		want bool
	}{
		{"high band, no must-fix signal → adjudicate", SeverityInputs{Band: "page"}, true},
		{"high band, elevated (partial) → adjudicate", SeverityInputs{Band: "high", MustFixClass: "elevated"}, true},
		// routine is the classifier saying "weighed, no urgency evidence". A page/high
		// score is the opposite claim from the same enrichment pass, which is the
		// disagreement this gate exists for — and it is the MAJORITY class, so
		// excluding it would empty the sweep.
		{"high band, routine (no urgency evidence) → adjudicate", SeverityInputs{Band: "page", MustFixClass: "routine"}, true},
		{"high band but controlled → resolved, skip", SeverityInputs{Band: "page", MustFixClass: "controlled"}, false},
		{"high band but contained → resolved, skip", SeverityInputs{Band: "page", MustFixClass: "contained"}, false},
		{"high band but must_fix → resolved, skip", SeverityInputs{Band: "high", MustFixClass: "must_fix"}, false},
		{"low band → never adjudicate", SeverityInputs{Band: "pipeline"}, false},
		{"monitor band → never adjudicate", SeverityInputs{Band: "monitor", MustFixClass: "elevated"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NeedsAdjudication(tt.in); got != tt.want {
				t.Fatalf("NeedsAdjudication(%+v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
