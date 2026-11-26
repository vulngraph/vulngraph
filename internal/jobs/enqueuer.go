package jobs

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
)

// InsertClient builds a River client that can only insert jobs (no queues, no
// workers) — used by the HTTP server to trigger an on-demand sync.
func InsertClient(pool *pgxpool.Pool) (*river.Client[pgx.Tx], error) {
	client, err := river.NewClient(riverpgxv5.New(pool), &river.Config{})
	if err != nil {
		return nil, fmt.Errorf("InsertClient: %w", err)
	}
	return client, nil
}

// Enqueuer inserts connector synchronization jobs from the HTTP service.
type Enqueuer struct{ client *river.Client[pgx.Tx] }

func NewEnqueuer(client *river.Client[pgx.Tx]) *Enqueuer { return &Enqueuer{client: client} }

// EnqueueSync inserts an immediate sync for one connector.
func (e *Enqueuer) EnqueueSync(ctx context.Context, connectorID string) error {
	if _, err := e.client.Insert(ctx, SyncConnectorArgs{ConnectorID: connectorID}, nil); err != nil {
		return fmt.Errorf("EnqueueSync: %w", err)
	}
	return nil
}

// EnqueueOrgDiscovery inserts an immediate aws_org discovery. The job is a
// singleton, so a request while one is queued or running is a no-op.
func (e *Enqueuer) EnqueueOrgDiscovery(ctx context.Context) error {
	if _, err := e.client.Insert(ctx, DiscoverAWSOrgsArgs{}, nil); err != nil {
		return fmt.Errorf("EnqueueOrgDiscovery: %w", err)
	}
	return nil
}
