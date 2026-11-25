package querybudget

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWithKeepsTheTighterBound(t *testing.T) {
	tests := []struct {
		name        string
		outer, next Budget
		want        Budget
	}{
		{"first budget is taken as is", Budget{}, Budget{Timeout: time.Second, MaxExecutionTime: 5}, Budget{Timeout: time.Second, MaxExecutionTime: 5}},
		{"a looser inner budget never widens", Budget{Timeout: time.Second, MaxExecutionTime: 5}, Budget{Timeout: time.Minute, MaxExecutionTime: 60}, Budget{Timeout: time.Second, MaxExecutionTime: 5}},
		{"a tighter inner budget narrows", Budget{Timeout: time.Minute, MaxExecutionTime: 60}, Budget{Timeout: time.Second, MaxExecutionTime: 5}, Budget{Timeout: time.Second, MaxExecutionTime: 5}},
		{"zero is unbounded, not tightest", Budget{Timeout: time.Second}, Budget{MaxExecutionTime: 5}, Budget{Timeout: time.Second, MaxExecutionTime: 5}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.outer != (Budget{}) {
				ctx = With(ctx, tt.outer)
			}
			got, ok := From(With(ctx, tt.next))
			require.True(t, ok)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestFromWithoutBudget(t *testing.T) {
	_, ok := From(context.Background())
	require.False(t, ok)
}
