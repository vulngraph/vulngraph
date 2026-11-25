package gcp

import (
	"context"
	"time"

	compute "google.golang.org/api/compute/v1"

	"github.com/vulngraph/vulngraph/internal/collect"
)

// collectManaged runs the managed-service collectors (Cloud SQL, Secret Manager,
// Cloud Run, Cloud Functions) best-effort: each builds its own ADC client and a
// failure in one is logged, skipped, and flags the result partial (bestEffort),
// never failing the whole sync. Keeping the orchestration here keeps gcp.go's
// Collect readable as the four lines grow.
func collectManaged(ctx context.Context, projectID string, now time.Time, result *collect.Result) {
	bestEffort(ctx, result, "gcp cloudsql", func() error {
		c, err := newCloudSQLClient(ctx)
		if err != nil {
			return err
		}
		assets, err := collectCloudSQL(ctx, c, projectID, now)
		if err != nil {
			return err
		}
		result.Assets = append(result.Assets, assets...)
		return nil
	})
	bestEffort(ctx, result, "gcp secretmanager", func() error {
		c, err := newSecretsClient(ctx)
		if err != nil {
			return err
		}
		secretAssets, secretEdges, err := collectSecrets(ctx, c, projectID, now)
		if err != nil {
			return err
		}
		result.Assets = append(result.Assets, secretAssets...)
		result.Edges = append(result.Edges, secretEdges...)
		return nil
	})
	bestEffort(ctx, result, "gcp cloudrun", func() error {
		c, err := newCloudRunClient(ctx)
		if err != nil {
			return err
		}
		// A partial listing (an unreachable location, a failed revision list)
		// returns what it did see alongside the error: keep it, and let the
		// error flag the sweep partial.
		assets, edges, err := collectCloudRun(ctx, c, projectID, now)
		result.Assets = append(result.Assets, assets...)
		result.Edges = append(result.Edges, edges...)
		return err
	})
	bestEffort(ctx, result, "gcp cloudfunctions", func() error {
		c, err := newFunctionsClient(ctx)
		if err != nil {
			return err
		}
		assets, err := collectFunctions(ctx, c, projectID, now)
		if err != nil {
			return err
		}
		result.Assets = append(result.Assets, assets...)
		return nil
	})
	// External Forwarding Rules are GCP cloud load balancer VIPs — each is a
	// direct internet entry point.
	bestEffort(ctx, result, "gcp forwardingrules", func() error {
		svc, err := compute.NewService(ctx)
		if err != nil {
			return err
		}
		assets, err := collectForwardingRules(ctx, svc, projectID, now)
		if err != nil {
			return err
		}
		result.Assets = append(result.Assets, assets...)
		return nil
	})
}
