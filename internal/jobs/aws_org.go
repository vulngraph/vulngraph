package jobs

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// awsOrgDiscoveryInterval is how often every aws_org connector re-lists its
// organization. An hour keeps a new account's first sync within about an hour
// of the StackSet putting its role there, at a handful of Organizations calls
// per org per run.
const awsOrgDiscoveryInterval = time.Hour

// DiscoverAWSOrgsArgs reconciles every enabled aws_org connector's child
// connectors against its organization's account list (ADR 091).
type DiscoverAWSOrgsArgs struct{}

func (DiscoverAWSOrgsArgs) Kind() string { return "discover_aws_orgs" }

// InsertOpts: a singleton on the sync queue — discovery creates the
// connectors that queue then syncs, and a manual "sync now" on an org
// connector is a no-op while one is already queued or running.
func (DiscoverAWSOrgsArgs) InsertOpts() river.InsertOpts {
	return periodicSingletonOpts(queueSync, 2)
}

// orgReconciler is the connector-service capability the worker needs.
type orgReconciler interface {
	ReconcileAllOrgs(ctx context.Context) ([]string, error)
}

// DiscoverAWSOrgsWorker runs discovery and syncs the children it created at
// once, rather than leaving them for the next EnqueueSyncs tick.
type DiscoverAWSOrgsWorker struct {
	river.WorkerDefaults[DiscoverAWSOrgsArgs]
	orgs orgReconciler
}

// Timeout bounds one pass over every org: listing is a few paged calls per
// org (plus one per OU with OU filters), and child writes are local.
func (DiscoverAWSOrgsWorker) Timeout(_ *river.Job[DiscoverAWSOrgsArgs]) time.Duration {
	return 10 * time.Minute
}

func (w *DiscoverAWSOrgsWorker) Work(ctx context.Context, _ *river.Job[DiscoverAWSOrgsArgs]) error {
	created, err := w.orgs.ReconcileAllOrgs(ctx)
	// Children created before an error in another org still get their sync.
	if len(created) > 0 {
		client := river.ClientFromContext[pgx.Tx](ctx)
		for _, id := range created {
			if _, insErr := client.Insert(ctx, SyncConnectorArgs{ConnectorID: id}, nil); insErr != nil {
				log.FromContext(ctx).Warn().Err(insErr).Str("connector_id", id).
					Msg("aws_org: first sync of a new child not enqueued; the next sync sweep picks it up")
			}
		}
	}
	if err != nil {
		return fmt.Errorf("DiscoverAWSOrgsWorker: %w", err)
	}
	return nil
}
