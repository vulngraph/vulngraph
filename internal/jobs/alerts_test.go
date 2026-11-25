package jobs

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/notify"
)

// The finding alert carries the routing context enrich persisted, and an owner
// that is unresolved routes exactly like an unowned one.
func TestNewFindingNotification_RoutingContext(t *testing.T) {
	f := finding.Finding{ID: "f", Severity: finding.SeverityHigh, Title: "t", ResourceID: "r"}
	tests := []struct {
		name        string
		owner       asset.Ownership
		env         string
		wantOwner   string
		wantUnowned bool
	}{
		{"owned", asset.Ownership{Team: "payments", Source: asset.OwnerSourceTag}, "prod", "payments", false},
		{"resolved unowned", asset.Ownership{Source: asset.OwnerSourceNone}, "unknown", "", true},
		{"unresolved routes as unowned", asset.Ownership{}, "", "", true},
		{"unclassified env routes as unknown", asset.Ownership{Source: asset.OwnerSourceNone}, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := newFindingNotification(f, enrich.Score{Value: 70, Owner: tt.owner, Environment: tt.env}, false)
			assert.Equal(t, notify.EventFinding, n.EventType)
			assert.Equal(t, 70, n.Score)
			assert.Equal(t, tt.wantOwner, n.Owner)
			assert.Equal(t, tt.wantUnowned, n.Unowned)
			wantEnv := tt.env
			if wantEnv == "" {
				wantEnv = "unknown"
			}
			assert.Equal(t, wantEnv, n.Environment, "an unclassified environment must route as unknown, never as \"\"")
		})
	}
}
