//go:build integration

package notify

import (
	"cmp"
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/db"
)

// pgDSN is the compose Postgres; GRAPH_TEST_PG_DSN points the test at another database.
var pgDSN = cmp.Or(os.Getenv("GRAPH_TEST_PG_DSN"), "postgres://graph:graph@localhost:5432/graph?sslmode=disable")

// identityCipher stands in for connector.Cipher: the routing columns under test
// are plaintext, so encryption is beside the point here.
type identityCipher struct{}

func (identityCipher) EncryptWithAAD(b, _ []byte) ([]byte, error) { return b, nil }
func (identityCipher) DecryptWithAAD(b, _ []byte) ([]byte, error) { return b, nil }

// Requires `docker compose up` and applied migrations.
// The owner/environment scope round-trips through create, update, the list and
// the dispatch read.
func TestPGRepo_RoutingScope(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := NewPGRepo(pool, identityCipher{})

	name := "it-routing-" + time.Now().Format("150405.000000")
	created, err := repo.Create(ctx, Channel{
		Type: TypeWebhook, Name: name, WebhookURL: "https://example.com/h", Enabled: true,
		EventTypes: []EventType{EventFinding}, Severities: []string{},
		OwnerTeams: []string{"payments"}, Environments: []string{"prod", "unknown"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.Delete(ctx, created.ID) })
	require.Equal(t, []string{"payments"}, created.OwnerTeams)
	require.Equal(t, []string{"prod", "unknown"}, created.Environments)
	require.False(t, created.RouteUnowned)

	// Update without a secret: scope fields change, secret is kept.
	updated, err := repo.Update(ctx, Channel{
		ID: created.ID, Name: name, Enabled: true, EventTypes: []EventType{EventFinding}, Severities: []string{},
		RouteUnowned: true,
	})
	require.NoError(t, err)
	require.Empty(t, updated.OwnerTeams, "a nil scope is stored as the empty array, not NULL")
	require.Empty(t, updated.Environments)
	require.True(t, updated.RouteUnowned)

	enabled, _, err := repo.EnabledWithSecret(ctx)
	require.NoError(t, err)
	var got *Channel
	for i := range enabled {
		if enabled[i].ID == created.ID {
			got = &enabled[i]
		}
	}
	require.NotNil(t, got)
	require.True(t, got.RouteUnowned)
	require.Equal(t, "https://example.com/h", got.WebhookURL, "the secret survived the secretless update")
	require.True(t, got.accepts(Notification{EventType: EventFinding, Unowned: true}))
	require.False(t, got.accepts(Notification{EventType: EventFinding, Owner: "payments"}))
}
