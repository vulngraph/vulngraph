package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/costdata"
)

func TestCostCollectEnabled(t *testing.T) {
	cases := []struct {
		env     map[string]string
		want    bool
		wantErr bool
	}{
		{env: nil, want: true},
		{env: map[string]string{"COST_COLLECT_DISABLED": "true"}, want: false},
		{env: map[string]string{"COST_COLLECT_DISABLED": "1"}, want: false},
		{env: map[string]string{"COST_COLLECT_DISABLED": "false"}, want: true},
		{env: map[string]string{"OFFLINE_MODE": "true"}, want: false},
		{env: map[string]string{"COST_COLLECT_DISABLED": "ture"}, wantErr: true},
		{env: map[string]string{"OFFLINE_MODE": "maybe"}, wantErr: true},
	}
	for _, tc := range cases {
		got, err := costCollectEnabled(func(k string) string { return tc.env[k] })
		if tc.wantErr {
			require.Errorf(t, err, "env %v", tc.env)
			require.Falsef(t, got, "env %v: an unreadable switch must not collect", tc.env)
			continue
		}
		require.NoErrorf(t, err, "env %v", tc.env)
		require.Equalf(t, tc.want, got, "env %v", tc.env)
	}
}

type fakeCostRepo struct {
	counts map[string]costdata.SnapshotCount
	err    error
}

func (f fakeCostRepo) SaveSnapshots(context.Context, []costdata.CostSnapshot) error { return nil }
func (f fakeCostRepo) ListRecent(context.Context, string, int) ([]costdata.CostSnapshot, error) {
	return nil, nil
}
func (f fakeCostRepo) DetectAnomalies(context.Context, string) ([]costdata.CostAnomaly, error) {
	return nil, nil
}
func (f fakeCostRepo) SnapshotCounts(context.Context) (map[string]costdata.SnapshotCount, error) {
	return f.counts, f.err
}

// A connector another replica collected inside the freshness window is
// skipped; an older one, or an unreadable status, is collected.
func TestRecentlyCollected(t *testing.T) {
	now := time.Now()
	svc := costdata.NewService(fakeCostRepo{counts: map[string]costdata.SnapshotCount{
		"fresh": {Rows: 3, LastCollectedAt: now.Add(-time.Hour)},
		"stale": {Rows: 3, LastCollectedAt: now.Add(-costCollectFreshness - time.Minute)},
	}})
	got := recentlyCollected(context.Background(), svc, now)
	require.True(t, got["fresh"])
	require.False(t, got["stale"])
	require.False(t, got["never"])

	failing := costdata.NewService(fakeCostRepo{err: errors.New("pg down")})
	require.Empty(t, recentlyCollected(context.Background(), failing, now), "unknown freshness collects")
}
