package chat

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoopLimitsEnableParallelReadsAndWrapUp(t *testing.T) {
	l := DefaultLimits.loopLimits(time.Now())
	require.Greater(t, l.MaxParallelTools, 1, "independent read tools run together")
	require.Greater(t, l.WrapUp, 0.0)
	require.Less(t, l.WrapUp, 1.0, "the wrap-up starts before the hard caps")
}

func TestLiveToolsAreSerial(t *testing.T) {
	c := chatTools{}
	for name := range liveTools {
		require.True(t, c.Serial(name), "%s passes the live gate and audits in order", name)
	}
	require.False(t, c.Serial("get_asset"), "read tools may run in parallel")
}

func TestToolQueryBudgetIsBounded(t *testing.T) {
	require.Positive(t, toolQueryBudget.Timeout)
	require.Positive(t, toolQueryBudget.MaxExecutionTime)
	require.Less(t, time.Duration(toolQueryBudget.MaxExecutionTime)*time.Second, toolQueryBudget.Timeout,
		"the server stops the query first, so the model reads a timeout error rather than a cancelled stream")
}
