package respond

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOutcome_AwaitingHuman(t *testing.T) {
	for o, want := range map[Outcome]bool{
		OutcomeParked:              true,
		OutcomeEscalated:           true,
		OutcomeObserved:            false,
		OutcomeSuppressedByVerdict: false,
		"":                         false,
	} {
		require.Equal(t, want, o.AwaitingHuman(), string(o))
	}
}

func TestParseDecisionDetails(t *testing.T) {
	d, err := ParseDecisionDetails(`{"action_class":"isolate","outcome":"escalated","summary":"x"}`)
	require.NoError(t, err)
	require.Equal(t, DecisionDetails{ActionClass: "isolate", Outcome: OutcomeEscalated}, d)

	_, err = ParseDecisionDetails("not json")
	require.Error(t, err)
}
