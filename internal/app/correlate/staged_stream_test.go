package correlate

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type countedStreamRule struct {
	limit       int
	emitted     int
	annotated   int
	annotations bool
	cancel      context.CancelFunc
}

func (*countedStreamRule) Name() string                 { return "counted_stream" }
func (*countedStreamRule) InterestedIn() []string       { return []string{"ec2_instance"} }
func (*countedStreamRule) Correlate(Graph) []asset.Edge { panic("staged analysis called slice API") }
func (*countedStreamRule) CorrelateAssets(Graph) []asset.Annotation {
	panic("staged analysis called annotation slice API")
}
func (r *countedStreamRule) Edges(Graph) iter.Seq[asset.Edge] {
	return func(yield func(asset.Edge) bool) {
		if r.annotations {
			return
		}
		for i := range r.count() {
			r.emitted++
			if r.cancel != nil {
				r.cancel()
			}
			if !yield(asset.Edge{SrcID: fmt.Sprintf("source-%d", i), DstID: "target", EdgeType: EdgeDNSPointsTo}) {
				return
			}
		}
	}
}
func (r *countedStreamRule) Annotations(Graph) iter.Seq[asset.Annotation] {
	return func(yield func(asset.Annotation) bool) {
		if !r.annotations {
			return
		}
		for i := range r.count() {
			r.annotated++
			if !yield(asset.Annotation{ID: fmt.Sprintf("declaration-%d", i), Source: asset.ManifestDriftSource, Metadata: map[string]string{"drift": driftDeclaredNotLive}}) {
				return
			}
		}
	}
}

func TestStagedStreamsStopAtBudgetWithoutPublishing(t *testing.T) {
	for _, annotations := range []bool{false, true} {
		t.Run(fmt.Sprintf("annotations=%v", annotations), func(t *testing.T) {
			rule := &countedStreamRule{annotations: annotations}
			limits := DefaultStagedViewLimits()
			limits.OutputRows = 3
			writer := &fakeWriter{}
			_, err := NewService(&stagedFakeLoader{}, writer, []Rule{rule}).WithStagedViews(limits).Correlate(context.Background())
			require.ErrorIs(t, err, ErrStagedBudget)
			require.Equal(t, 4, rule.emitted+rule.annotated, "one rejected item must stop the producer")
			require.Empty(t, writer.got)
			require.Empty(t, writer.annotations)
		})
	}
}

func TestStagedCancellationStopsProducerAndPreservesPending(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ci := &CIAccess{pending: []PendingVerify{{TargetARN: "previous-complete"}}}
	rule := &countedStreamRule{cancel: cancel}
	writer := &fakeWriter{}
	_, err := NewService(&stagedFakeLoader{}, writer, []Rule{ci, rule}).WithStagedViews(DefaultStagedViewLimits()).Correlate(ctx)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, 1, rule.emitted)
	require.Equal(t, []PendingVerify{{TargetARN: "previous-complete"}}, ci.PendingLiveVerify())
	require.Empty(t, writer.got)
}

func TestStagedLaterRuleFailurePreservesPending(t *testing.T) {
	for _, annotations := range []bool{false, true} {
		ci := &CIAccess{pending: []PendingVerify{{TargetARN: "previous-complete"}}}
		rule := &countedStreamRule{annotations: annotations}
		limits := DefaultStagedViewLimits()
		limits.OutputRows = 1
		writer := &fakeWriter{}
		_, err := NewService(&stagedFakeLoader{}, writer, []Rule{ci, rule}).WithStagedViews(limits).Correlate(context.Background())
		require.ErrorIs(t, err, ErrStagedBudget)
		require.Equal(t, []PendingVerify{{TargetARN: "previous-complete"}}, ci.PendingLiveVerify())
		require.Empty(t, writer.got)
		require.Empty(t, writer.annotations)
	}
}

type failedPublishWriter struct{ fakeWriter }

func (*failedPublishWriter) IngestEdges(context.Context, []asset.Edge) error {
	return errors.New("publication failed")
}
func TestStagedFailedPublicationPreservesPending(t *testing.T) {
	ci := &CIAccess{pending: []PendingVerify{{TargetARN: "previous-complete"}}}
	rows := []asset.Asset{dnsRecord("dns", "A", "203.0.113.9"), {ID: "target", Type: "ec2_instance", PublicIP: "203.0.113.9"}}
	_, err := NewService(&stagedFakeLoader{fakeLoader: fakeLoader{assets: rows}}, &failedPublishWriter{}, []Rule{ci, DNSPointsTo{}}).WithStagedViews(DefaultStagedViewLimits()).Correlate(context.Background())
	require.ErrorContains(t, err, "publication failed")
	require.Equal(t, []PendingVerify{{TargetARN: "previous-complete"}}, ci.PendingLiveVerify())
}

func TestEveryStagedRuleHasProducerStopBoundary(t *testing.T) {
	for _, rule := range allRules {
		require.Implements(t, (*edgeStreamer)(nil), rule, rule.Name())
		if _, ok := rule.(AssetAnnotator); ok {
			require.Implements(t, (*annotationStreamer)(nil), rule, rule.Name())
		}
	}
}

func (r *countedStreamRule) count() int {
	if r.limit > 0 {
		return r.limit
	}
	return 1000000
}

type failedPrefixWriter struct {
	fakeWriter
	calls    int
	fail     bool
	versions []time.Time
}

func (w *failedPrefixWriter) IngestEdges(ctx context.Context, rows []asset.Edge) error {
	w.calls++
	if w.fail && w.calls == 2 {
		return errors.New("second page failed")
	}
	return w.fakeWriter.IngestEdges(ctx, rows)
}
func (w *failedPrefixWriter) WriteAnnotations(ctx context.Context, version time.Time, rows []asset.Annotation) error {
	w.calls++
	if w.fail && w.calls == 2 {
		return errors.New("second page failed")
	}
	w.versions = append(w.versions, version)
	return w.fakeWriter.WriteAnnotations(ctx, version, rows)
}
func TestStagedPublicationFailureReportsVisiblePrefix(t *testing.T) {
	for _, annotations := range []bool{false, true} {
		t.Run(fmt.Sprintf("annotations=%v", annotations), func(t *testing.T) {
			ci := &CIAccess{pending: []PendingVerify{{TargetARN: "previous-complete"}}}
			rule := &countedStreamRule{limit: 3, annotations: annotations}
			limits := DefaultStagedViewLimits()
			limits.PageRows = 1
			writer := &failedPrefixWriter{fail: true}
			loader := &stagedFakeLoader{}
			service := NewService(loader, writer, []Rule{ci, rule}).WithStagedViews(limits)
			count, err := service.Correlate(context.Background())
			require.ErrorContains(t, err, "second page failed")
			require.Zero(t, count, "failed publication must not report a completed pass")
			require.Equal(t, 1, len(writer.got)+len(writer.annotations), "first committed page remains visible")
			stats := loader.snapshot.Stats()
			require.True(t, stats.PublicationStarted)
			require.False(t, stats.PublicationComplete)
			require.Equal(t, 1, stats.PublishedEdgeRows+stats.PublishedAnnotationRows)
			require.Equal(t, []PendingVerify{{TargetARN: "previous-complete"}}, ci.PendingLiveVerify())
			if annotations {
				require.Len(t, writer.versions, 1)
				require.False(t, writer.versions[0].IsZero(), "visible annotation prefix carries its allocated version; no rollback is claimed")
			}
			writer.fail = false
			_, err = service.Correlate(context.Background())
			require.NoError(t, err)
			require.True(t, loader.snapshot.Stats().PublicationComplete)
			require.Empty(t, ci.PendingLiveVerify(), "only a completed retry publishes the new pending state")
		})
	}
}
