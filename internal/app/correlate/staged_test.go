package correlate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

type stagedFakeLoader struct {
	fakeLoader
	snapshot       *stagedFile
	failAfterInput error
}

func (f *stagedFakeLoader) StageView(_ context.Context, types []string, limits StagedViewLimits) (stagedView, error) {
	s, err := newStagedFile(limits)
	if err != nil {
		return nil, err
	}
	f.snapshot = s
	for _, a := range f.assets {
		if !slices.Contains(types, a.Type) {
			continue
		}
		if err := s.appendInput(s.input, a); err != nil {
			return s, err
		}
	}
	if f.failAfterInput != nil {
		return s, f.failAfterInput
	}
	s.stats.SourceQueries = 1
	s.stats.SourceComplete = true
	return s, nil
}

func stagedFixture() []asset.Asset {
	role := "arn:aws:iam::222222222222:role/shared"
	rows := []asset.Asset{
		{ID: role, Type: "iam_role", AccountID: "222222222222"},
		{ID: "serviceAccount:shared@p2.iam.gserviceaccount.com", Type: "gcp_service_account", AccountID: "p2"},
		{ID: "dns-cross-account", Type: "dns_record", AccountID: "dns-account", Metadata: map[string]string{"values": "203.0.113.2"}},
		{ID: "declared-tf", Type: "declared_tf_resource", Metadata: map[string]string{"repo": "org/repo", "target_id": "vm-07"}},
		{ID: "org/repo", Type: "github_repo", Name: "repo"},
	}
	for i := 0; i < 40; i++ {
		rows = append(rows, asset.Asset{ID: fmt.Sprintf("vm-%02d", i), Type: "ec2_instance", AccountID: "111111111111", PublicIP: "203.0.113.2", Metadata: map[string]string{"iam_role_arn": role, "security_groups": "sg-shared"}})
		rows = append(rows, asset.Asset{ID: fmt.Sprintf("gce-%02d", i), Type: "gce_instance", AccountID: fmt.Sprintf("p%d", i%2+1), Metadata: map[string]string{"exec_role": "serviceAccount:shared@p2.iam.gserviceaccount.com", "network": "default", "network_tags": "worker"}})
	}
	for _, project := range []string{"p1", "p2"} {
		rows = append(rows, asset.Asset{ID: "fw-" + project, Type: "gcp_firewall", AccountID: project, Metadata: map[string]string{"network": "default", "target_tags": "worker", "source_tags": "worker", "direction": "INGRESS", "allowed": "tcp:443"}})
	}
	return rows
}

func TestStagedRuleParityAndCrossScope(t *testing.T) {
	for _, rule := range allRules {
		t.Run(fmt.Sprintf("%T", rule), func(t *testing.T) {
			rows := stagedFixture()
			expected := &fakeWriter{}
			_, err := NewService(fakeLoader{assets: rows}, expected, []Rule{rule}).Correlate(context.Background())
			require.NoError(t, err)
			loader := &stagedFakeLoader{fakeLoader: fakeLoader{assets: rows}}
			got := &fakeWriter{}
			limits := DefaultStagedViewLimits()
			limits.PageRows = 3
			_, err = NewService(loader, got, []Rule{rule}).WithStagedViews(limits).Correlate(context.Background())
			require.NoError(t, err)
			require.ElementsMatch(t, expected.got, got.got)
			require.ElementsMatch(t, expected.annotations, got.annotations)
			_, err = os.Stat(loader.snapshot.input.Name())
			require.ErrorIs(t, err, os.ErrNotExist)
			_, err = os.Stat(loader.snapshot.output.Name())
			require.ErrorIs(t, err, os.ErrNotExist)
			if _, ok := rule.(DNSPointsTo); ok {
				require.Len(t, got.got, maxDNSTargetsPerValue, "global target cap must not restart per page")
			}
			if _, ok := rule.(EC2InstanceProfile); ok {
				require.Len(t, got.got, 40, "cross-account role survives context partitioning")
			}
		})
	}
}

func TestStagedBudgetsAndPartialSourcePublishNothing(t *testing.T) {
	for _, tc := range []struct {
		name      string
		adjust    func(*StagedViewLimits)
		sourceErr error
	}{
		{name: "source_rows", adjust: func(l *StagedViewLimits) { l.Rows = 2 }},
		{name: "index", adjust: func(l *StagedViewLimits) { l.IndexBytes = 100 }},
		{name: "disk", adjust: func(l *StagedViewLimits) { l.DiskBytes = 100 }},
		{name: "complete_context", adjust: func(l *StagedViewLimits) { l.ContextBytes = 1000 }},
		{name: "output_rows", adjust: func(l *StagedViewLimits) { l.OutputRows = 2 }},
		{name: "output_bytes", adjust: func(l *StagedViewLimits) { l.OutputBytes = 100 }},
		{name: "late_source_error", sourceErr: errors.New("source interrupted after rows")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loader := &stagedFakeLoader{fakeLoader: fakeLoader{assets: stagedFixture()}, failAfterInput: tc.sourceErr}
			writer := &fakeWriter{}
			limits := DefaultStagedViewLimits()
			if tc.adjust != nil {
				tc.adjust(&limits)
			}
			_, err := NewService(loader, writer, []Rule{EC2InstanceProfile{}, DNSPointsTo{}}).WithStagedViews(limits).Correlate(context.Background())
			if tc.sourceErr != nil {
				require.ErrorIs(t, err, tc.sourceErr)
			} else {
				require.ErrorIs(t, err, ErrStagedBudget)
			}
			require.Empty(t, writer.got)
			require.Empty(t, writer.annotations)
			_, err = os.Stat(loader.snapshot.input.Name())
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	}
}

func TestStagedStatefulEmptySweepResets(t *testing.T) {
	rule := &CIAccess{}
	rows := []asset.Asset{declaredCIAccessAsset("r", "aws", "ci.yml", map[string]string{"target_arn": "arn:aws:iam::999999999999:role/missing", "account_id": "999999999999"})}
	loader := &stagedFakeLoader{fakeLoader: fakeLoader{assets: rows}}
	service := NewService(loader, &fakeWriter{}, []Rule{rule}).WithStagedViews(DefaultStagedViewLimits())
	_, err := service.Correlate(context.Background())
	require.NoError(t, err)
	require.NotEmpty(t, rule.PendingLiveVerify())
	loader.assets = nil
	_, err = service.Correlate(context.Background())
	require.NoError(t, err)
	require.Empty(t, rule.PendingLiveVerify())
}

func TestStagedIndexedReplayAndConfidenceDedupe(t *testing.T) {
	limits := DefaultStagedViewLimits()
	limits.PageRows = 2
	s, err := newStagedFile(limits)
	require.NoError(t, err)
	defer func() { require.NoError(t, s.Close()) }()
	for i := 0; i < 30; i++ {
		require.NoError(t, s.appendInput(s.input, asset.Asset{ID: fmt.Sprint(i), Type: "gce_instance", AccountID: fmt.Sprint(i % 3)}))
	}
	for _, account := range s.Accounts([]string{"gce_instance"}) {
		count := 0
		require.NoError(t, s.Read(context.Background(), []string{"gce_instance"}, &account, 2, 1<<20, func(page []asset.Asset) error { count += len(page); return nil }))
		require.Equal(t, 10, count)
	}
	require.EqualValues(t, 30, s.Stats().ReplayRows, "project reads must not scan other projects")
	require.Equal(t, 3, s.Stats().ReplayPasses, "one indexed replay per project, not one rescan per page")
	low := asset.Edge{SrcID: "a", DstID: "b", EdgeType: "x", Properties: map[string]string{"confidence": "low"}}
	high := low
	high.Properties = map[string]string{"confidence": "high"}
	require.NoError(t, s.StageEdges([]asset.Edge{low, high, low}))
	var got []asset.Edge
	n, err := s.Publish(context.Background(), func(page []asset.Edge) error { got = append(got, page...); return nil }, func([]asset.Annotation) error { return nil })
	require.NoError(t, err)
	require.Equal(t, 1, n)
	require.Equal(t, []asset.Edge{high}, got)
	info, err := s.input.Stat()
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

func TestStagedPartialUsesCompleteSnapshotAndPreservesCrossScope(t *testing.T) {
	rows := stagedFixture()
	loader := &stagedFakeLoader{fakeLoader: fakeLoader{assets: rows}}
	writer := &fakeWriter{}
	limits := DefaultStagedViewLimits()
	limits.PageRows = 3
	_, err := NewService(loader, writer, []Rule{EC2InstanceProfile{}, ExecutesAs{}}).WithStagedViews(limits).PartialCorrelate(context.Background(), []string{"vm-01"})
	require.NoError(t, err)
	require.Len(t, writer.got, 80)
}

type stagedCostObserver struct{ costs []StagedViewStats }

func (*stagedCostObserver) ObserveCorrelateView(int, int)         {}
func (o *stagedCostObserver) ObserveStagedView(s StagedViewStats) { o.costs = append(o.costs, s) }

func TestStagedFailedSourceRetainsCostsAndClosesFiles(t *testing.T) {
	loader := &stagedFakeLoader{fakeLoader: fakeLoader{assets: stagedFixture()}, failAfterInput: errors.New("late read failure")}
	writer := &fakeWriter{}
	observer := &stagedCostObserver{}
	_, err := NewService(loader, writer, []Rule{ExecutesAs{}}).WithViewMetrics(observer).WithStagedViews(DefaultStagedViewLimits()).Correlate(context.Background())
	require.ErrorIs(t, err, loader.failAfterInput)
	require.Empty(t, writer.got)
	require.Len(t, observer.costs, 1)
	require.False(t, observer.costs[0].SourceComplete)
	require.Positive(t, observer.costs[0].SpoolBytes)
	require.Positive(t, observer.costs[0].SourceRows)
	_, err = os.Stat(loader.snapshot.input.Name())
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestStagedContextBudgetBeforeDecodingAndAnonymousFiles(t *testing.T) {
	s, err := newStagedFile(DefaultStagedViewLimits())
	require.NoError(t, err)
	defer func() { require.NoError(t, s.Close()) }()
	_, err = os.Stat(s.input.Name())
	require.ErrorIs(t, err, os.ErrNotExist, "no crash residue path")
	for i := 0; i < 20; i++ {
		require.NoError(t, s.appendInput(s.input, asset.Asset{ID: fmt.Sprint(i), Type: "iam_role"}))
	}
	require.ErrorIs(t, s.CheckContext([]string{"iam_role"}, nil, 20, 1<<20), ErrStagedBudget)
	require.ErrorIs(t, s.CheckContext([]string{"iam_role"}, nil, 100, 10), ErrStagedBudget)
	require.Zero(t, s.Stats().ReplayRows, "reject incomplete context before decoding any page")
	require.NoError(t, s.CheckContext([]string{"iam_role"}, nil, 100, 1<<20))
}
