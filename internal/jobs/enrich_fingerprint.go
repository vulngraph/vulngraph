package jobs

import (
	"context"
	"strings"
	"sync"

	"github.com/vulngraph/vulngraph/internal/app/enrichcache"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// fingerprintInput projects a finding's static fields onto FingerprintInput.
// Used by tests and as the base for fingerprintFor (which adds graph context).
func fingerprintInput(f finding.Finding) enrichcache.FingerprintInput {
	return enrichcache.FingerprintInput{
		FindingID:      f.ID,
		CheckID:        f.CheckID,
		Type:           f.Type,
		Severity:       string(f.Severity),
		ResourceID:     f.ResourceID,
		KnownExploited: f.KnownExploited,
		RootCause:      rootCauseCounts(f),
		SecretValidity: f.Metadata[finding.SecretValidityKey],
	}
}

// rootCauseMetaKeys are the membership counts of each root-cause finding kind
// that decide whether it must re-score (enrichcache.FingerprintInput.RootCause).
var rootCauseMetaKeys = map[string][]string{
	"base_image": {"base_layer_kev", "base_layer_cves", "running_images", "exposed_workloads"},
	"vm_vuln":    {"affected_instances", "exposed_instances"},
}

func rootCauseCounts(f finding.Finding) string {
	keys := rootCauseMetaKeys[f.Source]
	if len(keys) == 0 {
		return ""
	}
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = k + "=" + f.Metadata[k]
	}
	return strings.Join(parts, ",")
}

// fingerprintFor builds the full FingerprintInput for a finding, enriching the
// static fields with graph context when a GraphContextProvider is wired, and
// returns the graph context to store beside it.
//
// A graph read that errors — or a reachability lookup Ladybug cannot answer
// because the node is missing mid-rebuild — is not a measurement: that field
// carries prev's last measured value forward (enrichcache.CarryForward). Hashing
// its zero value instead ("not exposed", "" reach) would change the
// fingerprint, force a full enrich and an alert, then do it again when the read
// recovers.
//
// IsExposedEdge and PrivescBucket run in parallel to halve wait time on pool
// contention. After nodeSignalsCache pre-population in SyncFromSources, both
// are typically cache hits (zero Ladybug latency), but parallelism guards cold starts.
func (w *EnrichWorker) fingerprintFor(ctx context.Context, f finding.Finding, prev enrichcache.GraphContext) (enrichcache.FingerprintInput, enrichcache.GraphContext) {
	in := fingerprintInput(f)
	if w.graph == nil || f.ResourceID == "" {
		return in, enrichcache.GraphContext{}
	}
	// A panic in any w.graph.* call (nil-map access, Ladybug driver panic) must not
	// take down the enrich worker — the parent frame isn't on the goroutine stack.
	recoverSignal := func(name string) {
		if p := recover(); p != nil {
			log.FromContext(ctx).Error().Interface("panic", p).
				Str("finding_id", f.ID).Str("signal", name).
				Msg("enrich: fingerprint signal goroutine panicked")
		}
	}
	var (
		m  enrichcache.Measured
		wg sync.WaitGroup
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer recoverSignal("is_exposed")
		if exposed, err := w.graph.IsExposedEdge(ctx, f.ResourceID); err == nil {
			in.IsExposed, m.Exposed = exposed, true
		}
	}()
	go func() {
		defer wg.Done()
		defer recoverSignal("privesc_bucket")
		if bucket, err := w.graph.PrivescBucket(ctx, f.ResourceID); err == nil {
			in.PrivescBucket, m.Privesc = bucket, true
		}
	}()
	// Reachability bucket — only when the provider supports it (Ladybug). The non-Ladybug
	// fallback doesn't, so ReachBucket stays "" and never churns the cache there.
	if r, ok := w.graph.(interface {
		InternetHops(context.Context, string) (int, bool, error)
	}); ok {
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer recoverSignal("internet_hops")
			if hops, found, err := r.InternetHops(ctx, f.ResourceID); err == nil && found {
				in.ReachBucket, m.Reach = enrichcache.ReachBucketFor(hops, found), true
			}
		}()
	}
	wg.Wait()
	return enrichcache.CarryForward(in, m, prev)
}
