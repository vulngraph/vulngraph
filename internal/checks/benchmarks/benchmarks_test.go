package benchmarks

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateRejectsBrokenControls(t *testing.T) {
	base := Benchmark{ID: "b", Name: "B", Version: "1", Family: FamilyCIS, Providers: []string{"aws"}, Source: "s"}
	cases := []struct {
		name string
		c    Control
		ok   bool
	}{
		{"covered with check", Control{ID: "1", Title: "t", Service: "s", Severity: "low", Status: StatusCovered, CheckIDs: []string{"x"}}, true},
		{"covered without check", Control{ID: "1", Title: "t", Service: "s", Severity: "low", Status: StatusCovered}, false},
		{"partial without reason", Control{ID: "1", Title: "t", Service: "s", Severity: "low", Status: StatusPartial, CheckIDs: []string{"x"}}, false},
		{"missing without reason", Control{ID: "1", Title: "t", Service: "s", Severity: "low", Status: StatusMissing}, false},
		{"missing with check", Control{ID: "1", Title: "t", Service: "s", Severity: "low", Status: StatusMissing, Reason: "r", CheckIDs: []string{"x"}}, false},
		{"manual with reason", Control{ID: "1", Title: "t", Service: "s", Severity: "low", Status: StatusManual, Reason: "r"}, true},
		{"no status", Control{ID: "1", Title: "t", Service: "s", Severity: "low", Reason: "r"}, false},
		{"bad severity", Control{ID: "1", Title: "t", Service: "s", Severity: "urgent", Status: StatusManual, Reason: "r"}, false},
		{"title too long", Control{ID: "1", Title: "one two three four five six seven eight nine ten eleven", Service: "s", Severity: "low", Status: StatusManual, Reason: "r"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := base
			b.Controls = []Control{tc.c}
			if tc.ok {
				require.NoError(t, Validate(b))
			} else {
				require.Error(t, Validate(b))
			}
		})
	}
}

func TestParseRejectsUnknownKeys(t *testing.T) {
	_, err := Parse([]byte("benchmark: b\ncontrols:\n  - id: \"1\"\n    check_id: [x]\n"))
	require.Error(t, err, "a misspelt key must not parse as a control with no checks")
}
