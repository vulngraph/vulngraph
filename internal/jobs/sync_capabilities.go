// Capability-proof plumbing for the sync worker (see
// internal/app/connector.ProvenCapability and connector_proven_capabilities).
//
// Mirrors CompletedEnumerations end to end: a collector records a per-sweep
// claim (collect.Result.ProvenCapabilities / MarkCapabilityProven), this file
// persists it, and the NEXT sweep reads it back — by handing it to the
// collector through cfg rather than through a typed value, because the
// collect package (and every provider package under it) must stay decoupled
// from app domains. This file is the one seam allowed to know both shapes.
//
// Kept out of sync.go, which sits near the file-size ceiling.
package jobs

import (
	"context"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/connector"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// configWithProvenCapabilities returns a copy of c.Config with
// collect.ProvenCapabilitiesConfigKey set to the comma-separated capabilities
// already proven for this connector in a PRIOR sweep. A copy, never a mutation
// of c.Config in place: that map is the decrypted credential config and other
// callers in this same Work() invocation must not see a synthetic key spliced
// into it.
//
// Best-effort: a read failure logs and falls back to c.Config unchanged,
// which is the pre-proof behaviour (ownership decides alone) — the safe
// default, not a new failure mode.
func configWithProvenCapabilities(ctx context.Context, connectors *connector.Service, c connector.Connector) map[string]string {
	caps, err := connectors.ListProvenCapabilities(ctx, c.ID)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("connector_id", c.ID).
			Msg("sync: proven-capabilities read failed — collecting without prior proof (falls back to ownership-only checks)")
		return c.Config
	}
	if len(caps) == 0 {
		return c.Config
	}
	names := make([]string, len(caps))
	for i, cap := range caps {
		names[i] = string(cap)
	}
	cfg := make(map[string]string, len(c.Config)+1)
	for k, v := range c.Config {
		cfg[k] = v
	}
	cfg[collect.ProvenCapabilitiesConfigKey] = strings.Join(names, ",")
	return cfg
}

// recordProvenCapabilities persists every capability this sweep proved
// (collect.Result.ProvenCapabilities) so a LATER sweep's denial can be
// judged against it via configWithProvenCapabilities above. Recording is
// monotonic and idempotent at the repo layer (ON CONFLICT DO NOTHING) — calling this every sweep a capability keeps
// proving itself is harmless.
//
// Best-effort per capability: one write failure must not stop the others
// from being recorded, and must not fail an otherwise-successful sync — the
// worst case is next sweep re-deriving the same proof from cfg being one
// sweep behind, not data loss (proof already reached ClickHouse/asset
// ingest independently of this ledger).
func recordProvenCapabilities(ctx context.Context, connectors *connector.Service, connectorID string, capabilities []string, at time.Time) {
	for _, cap := range capabilities {
		if cap == "" {
			continue
		}
		if err := connectors.RecordProvenCapability(ctx, connectorID, connector.ProvenCapability(cap), at); err != nil {
			log.FromContext(ctx).Warn().Err(err).
				Str("connector_id", connectorID).Str("capability", cap).
				Msg("sync: recording proven capability failed (retried next sweep it proves again)")
		}
	}
}
