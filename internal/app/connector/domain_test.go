package connector

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestConnectorStale(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }

	tests := []struct {
		name string
		c    Connector
		want bool
	}{
		{"recently succeeded", Connector{Enabled: true, LastSuccessAt: ago(1 * time.Hour)}, false},
		{"succeeded just under window", Connector{Enabled: true, LastSuccessAt: ago(23 * time.Hour)}, false},
		{"succeeded past window", Connector{Enabled: true, LastSuccessAt: ago(30 * time.Hour)}, true},
		// Attempts keep moving LastSyncedAt but staleness tracks LastSuccessAt,
		// so a connector that runs on schedule yet errors every time is still stale.
		{"attempting recently but never succeeded (old)", Connector{Enabled: true, LastSyncedAt: ago(1 * time.Hour), CreatedAt: now.Add(-48 * time.Hour)}, true},
		{"attempting recently, succeeded recently", Connector{Enabled: true, LastSyncedAt: ago(1 * time.Hour), LastSuccessAt: ago(2 * time.Hour)}, false},
		{"never succeeded but young", Connector{Enabled: true, CreatedAt: now.Add(-2 * time.Hour)}, false},
		{"never succeeded and old", Connector{Enabled: true, CreatedAt: now.Add(-48 * time.Hour)}, true},
		{"disabled never stale", Connector{Enabled: false, CreatedAt: now.Add(-500 * time.Hour)}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, tt.c.Stale(now, DefaultStaleAfter))
		})
	}
}
