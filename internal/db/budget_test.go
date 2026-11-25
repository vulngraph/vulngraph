package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/pkg/querybudget"
)

func TestApplyBudget_Deadline(t *testing.T) {
	t.Run("no budget leaves the context alone", func(t *testing.T) {
		ctx := context.Background()
		got, cancel := applyBudget(ctx)
		defer cancel()
		require.Equal(t, ctx, got)
	})
	t.Run("budget sets the deadline", func(t *testing.T) {
		got, cancel := applyBudget(querybudget.With(context.Background(), querybudget.Budget{Timeout: 2 * time.Second}))
		defer cancel()
		d, ok := got.Deadline()
		require.True(t, ok)
		require.WithinDuration(t, time.Now().Add(2*time.Second), d, time.Second)
	})
	t.Run("a caller's shorter deadline stands", func(t *testing.T) {
		ctx, cancelCaller := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancelCaller()
		want, _ := ctx.Deadline()
		got, cancel := applyBudget(querybudget.With(ctx, querybudget.Budget{Timeout: time.Minute}))
		defer cancel()
		d, _ := got.Deadline()
		require.Equal(t, want, d)
	})
}

func TestBudgetedSettings(t *testing.T) {
	ch := &CH{}
	tests := []struct {
		name   string
		caller map[string]any
		budget int
		want   map[string]any
	}{
		{"no caller settings", nil, 25, map[string]any{"max_execution_time": 25}},
		{"looser caller value is lowered", map[string]any{"max_execution_time": 600}, 25, map[string]any{"max_execution_time": 25}},
		{"tighter caller value stands", map[string]any{"max_execution_time": 8}, 25, map[string]any{"max_execution_time": 8}},
		{"other caller settings survive", map[string]any{"join_use_nulls": 1}, 25, map[string]any{"join_use_nulls": 1, "max_execution_time": 25}},
		{"no budget keeps the caller's", map[string]any{"max_execution_time": 600}, 0, map[string]any{"max_execution_time": 600}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.caller != nil {
				ctx = ch.WithQuerySettings(ctx, tt.caller)
			}
			require.Equal(t, tt.want, budgetedSettings(ctx, querybudget.Budget{MaxExecutionTime: tt.budget}))
		})
	}
}
