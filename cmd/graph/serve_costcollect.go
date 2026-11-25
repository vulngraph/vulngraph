package main

// This file holds the serve pod's background AWS cost-collection loop, split
// out of serve.go to keep that file under the repo's file-length ceiling. The
// loop is a self-contained periodic job (list AWS connectors, pull Cost
// Explorer data, record outcomes) with no other reader in serve.go besides
// the one goroutine that starts it.

import (
	"context"
	"fmt"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/app/costdata"
	awscollect "github.com/vulngraph/vulngraph/internal/collect/aws"
	"github.com/vulngraph/vulngraph/internal/obs"
	"github.com/vulngraph/vulngraph/pkg/egress"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// costCollectDisabledEnv switches the cost-collection loop off. Every Cost
// Explorer request is billed by AWS ($0.01 each), so an operator must be able to
// stop it without removing the connector. OFFLINE_MODE turns it off too.
const costCollectDisabledEnv = "COST_COLLECT_DISABLED"

// costCollectInterval is the loop cadence. costCollectFreshness is how recent a
// stored collection must be for a run to skip that connector: every serve
// replica runs this loop, and runs it again on every restart, so without the
// check N replicas pay for N identical Cost Explorer pulls per cycle. It is
// shorter than the interval so a replica's own previous run never suppresses
// its next one. Replicas starting at the same instant can still both collect —
// the check reads stored data, it is not a lock.
const (
	costCollectInterval  = 6 * time.Hour
	costCollectFreshness = 5 * time.Hour
)

// costCollectEnabled reports whether the loop should run at all. An
// unrecognised switch value is an error (and reads as disabled).
func costCollectEnabled(getenv func(string) string) (bool, error) {
	off, err := egress.Disabled(getenv, costCollectDisabledEnv)
	if err != nil {
		return false, fmt.Errorf("costCollectEnabled: %w", err)
	}
	return !off, nil
}

// recentlyCollected returns, per connector, whether cost data was stored within
// costCollectFreshness of now. A status read failure returns nil — collecting
// twice costs cents, skipping on a guess costs the data.
func recentlyCollected(ctx context.Context, costdataSvc *costdata.Service, now time.Time) map[string]bool {
	statuses, err := costdataSvc.Statuses(ctx)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("cost collect: stored collection times unreadable; collecting every connector this cycle")
		return nil
	}
	fresh := map[string]bool{}
	for _, st := range statuses {
		if !st.LastCollectedAt.IsZero() && now.Sub(st.LastCollectedAt) < costCollectFreshness {
			fresh[st.ConnectorID] = true
		}
	}
	return fresh
}

// startCostCollectLoop runs the serve pod's background cost-collection loop:
// pull cost data for every AWS connector every 6h, skipping connectors another
// replica collected recently. The caller's `go func(){ defer recover();
// startCostCollectLoop(...) }()` wrapper (in serve.go) owns the panic recovery,
// per the repo's goroutine convention.
func startCostCollectLoop(ctx context.Context, enabled bool, connectorSvc *connector.Service, costdataSvc *costdata.Service, metrics *obs.Metrics) {
	if !enabled {
		log.FromContext(ctx).Warn().Msg("cost collect: disabled by COST_COLLECT_DISABLED or OFFLINE_MODE; no Cost Explorer calls will be made and cost panels stay empty")
		return
	}
	ticker := time.NewTicker(costCollectInterval)
	defer ticker.Stop()
	// Every exit path logs AND increments graph_cost_collect_total{outcome}.
	// SaveSnapshots returns nil for an empty batch, so without this a
	// permission denial, a config skip and a genuine zero would all reach the
	// UI as the same "No cost anomalies" string: cost data is silently empty
	// when the role lacks ce:GetCostAndUsage.
	runCostCollect := func() {
		connectors, err := connectorSvc.List(ctx, true)
		if err != nil {
			metrics.ObserveCostCollect("connector_list_error")
			log.FromContext(ctx).Error().Err(err).Msg("cost collect: connector list failed; no cost data will be collected this cycle")
			return
		}
		attempted := 0
		fresh := recentlyCollected(ctx, costdataSvc, time.Now())
		for _, c := range connectors {
			if c.Type != "aws" {
				continue
			}
			attempted++
			if fresh[c.ID] {
				metrics.ObserveCostCollect("recently_collected")
				log.FromContext(ctx).Debug().Str("connector_id", c.ID).
					Msg("cost collect: collected within the freshness window (another replica or a recent restart); skipped")
				continue
			}
			// connectorSvc.List returns connectors with Config == nil by design
			// (list callers only need metadata) — every field read off c.Config
			// here, including region, would be empty and fail baseConfig's
			// "region is required" check for every connector. Get decrypts the
			// real config.
			full, getErr := connectorSvc.Get(ctx, c.ID)
			if getErr != nil {
				metrics.ObserveCostCollect(costdata.OutcomeConfigError)
				costdataSvc.RecordStatus(costdata.CollectStatus{
					ConnectorID: c.ID, Outcome: costdata.OutcomeConfigError, Detail: getErr.Error(),
				})
				log.FromContext(ctx).Warn().Err(getErr).Str("connector_id", c.ID).
					Msg("cost collect: connector config unusable; skipped")
				continue
			}
			accountID := full.Config["account_id"]
			if accountID == "" {
				accountID = c.ID
			}
			awsCfg, cfgErr := awscollect.BaseConfig(ctx, full.Config)
			if cfgErr != nil {
				metrics.ObserveCostCollect(costdata.OutcomeConfigError)
				costdataSvc.RecordStatus(costdata.CollectStatus{
					ConnectorID: c.ID, AccountID: accountID,
					Outcome: costdata.OutcomeConfigError, Detail: cfgErr.Error(),
				})
				log.FromContext(ctx).Warn().Err(cfgErr).Str("connector_id", c.ID).
					Msg("cost collect: connector config unusable; skipped")
				continue
			}
			st, err := costdataSvc.Collect(ctx, c.ID, accountID, awsCfg)
			metrics.ObserveCostCollect(st.Outcome)
			switch {
			case costdata.IsPermissionDenied(err):
				// The single most likely cause, called out by name so the fix is
				// actionable from the log line alone.
				log.FromContext(ctx).Error().Err(err).
					Str("connector_id", c.ID).Str("account_id", accountID).
					Str("required_permission", costdata.RequiredIAMPermission).
					Msg("cost collect: AWS denied Cost Explorer; grant the permission to the connector role or cost panels stay empty")
			case err != nil:
				log.FromContext(ctx).Error().Err(err).
					Str("connector_id", c.ID).Str("outcome", st.Outcome).
					Msg("cost collect failed")
			case st.Outcome == costdata.OutcomeEmpty:
				log.FromContext(ctx).Warn().
					Str("connector_id", c.ID).Str("account_id", accountID).
					Msg("cost collect: Cost Explorer returned zero cost entries; nothing stored")
			default:
				metrics.ObserveCostCollectSuccess(c.ID, float64(time.Now().Unix()), st.Fetched)
				log.FromContext(ctx).Info().
					Str("connector_id", c.ID).Int("snapshots", st.Fetched).
					Msg("cost collect ok")
			}
		}
		if attempted == 0 {
			metrics.ObserveCostCollect("no_aws_connectors")
			log.FromContext(ctx).Info().Msg("cost collect: no enabled AWS connectors; nothing to collect")
		}
	}
	runCostCollect() // initial run on startup
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runCostCollect()
		}
	}
}
