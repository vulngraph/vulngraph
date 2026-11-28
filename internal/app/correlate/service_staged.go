package correlate

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// StagedViewLimits are explicit resource ceilings. Input/output
// bytes are serialized bytes, not a claim that decoded Go heap equals that size.
type StagedViewLimits struct {
	AggregationSpillBytes int64
	Rows                  int // Optional test ceiling; zero means byte budgets govern.
	IndexBytes            int64
	DiskBytes             int64
	ContextBytes          int64
	PageBytes             int64
	PageRows              int
	OutputRows            int // Optional test ceiling; zero means byte budgets govern.
	OutputBytes           int64
}

func DefaultStagedViewLimits() StagedViewLimits {
	return StagedViewLimits{AggregationSpillBytes: 128 << 20, IndexBytes: 512 << 20, DiskBytes: 1 << 30, ContextBytes: 16 << 20,
		// Match the edge writer's 2,000-row maximum to avoid a tiny second
		// insert for every 2,048-row page.
		PageBytes: 2 << 20, PageRows: 2000, OutputBytes: 768 << 20}
}

// StagedViewStats includes all source and replay work, including failed runs.
type StagedViewStats struct {
	PublicationStarted      bool  `json:"publication_started"`
	PublishedEdgeRows       int   `json:"published_edge_rows"`
	PublishedAnnotationRows int   `json:"published_annotation_rows"`
	PublicationComplete     bool  `json:"publication_complete"`
	SourceComplete          bool  `json:"source_complete"`
	IndexChargeBytes        int64 `json:"index_charge_bytes"`
	SourceQueries           int   `json:"source_queries"`
	SourceRows              int   `json:"source_rows"`
	SourceChargeBytes       int64 `json:"source_charge_bytes"`
	SpoolBytes              int64 `json:"spool_bytes"`
	ReplayPasses            int   `json:"replay_passes"`
	ReplayRows              int64 `json:"replay_rows"`
	ReplayBytes             int64 `json:"replay_bytes"`
	ReplayChargeBytes       int64 `json:"replay_charge_bytes"`
	SpoolReadCalls          int64 `json:"spool_read_calls"`
	SpoolReadBytes          int64 `json:"spool_read_bytes"`
	OutputRows              int   `json:"output_rows"`
	OutputBytes             int64 `json:"output_bytes"`
}

type StagedViewObserver interface {
	ObserveStagedView(StagedViewStats)
}

type stagedBudgetObserver interface {
	ObserveCorrelateBuffer(buffer string, used, limit int64)
}

type stagedView interface {
	CheckContext([]string, *string, int, int64) error
	Count(types []string) int
	Accounts(types []string) []string
	Read(context.Context, []string, *string, int, int64, func([]asset.Asset) error) error
	StageEdges([]asset.Edge) error
	StageAnnotations([]asset.Annotation) error
	Publish(context.Context, func([]asset.Edge) error, func([]asset.Annotation) error) (int, error)
	Stats() StagedViewStats
	Close() error
}

type stagedViewLoader interface {
	StageView(context.Context, []string, StagedViewLimits) (stagedView, error)
}

// WithStagedViews uses a complete disk-backed source and bounded rule replay.
func (s *Service) WithStagedViews(limits StagedViewLimits) *Service {
	s.staged = &limits
	return s
}

func (s *Service) correlateStaged(ctx context.Context, rules []Rule, version time.Time, changed []asset.Asset) (int, error) {
	loader, ok := s.repo.(stagedViewLoader)
	if !ok {
		return 0, fmt.Errorf("staged correlate: repository has no snapshot support")
	}
	types := neededTypesFor(rules)
	if changed == nil {
		types = correlationTypes
	}
	snapshot, err := loader.StageView(ctx, types, *s.staged)
	if snapshot == nil {
		return 0, fmt.Errorf("staged correlate: %w", err)
	}
	defer func() {
		stats := snapshot.Stats()
		log.FromContext(ctx).Info().Interface("cost", stats).Msg("correlate staged snapshot finished")
		if s.viewObserver != nil {
			s.viewObserver.ObserveCorrelateView(stats.SourceRows, s.staged.Rows)
		}
		if observer, ok := s.viewObserver.(stagedBudgetObserver); ok {
			observer.ObserveCorrelateBuffer("index", stats.IndexChargeBytes, s.staged.IndexBytes)
			observer.ObserveCorrelateBuffer("spool", stats.SpoolBytes+stats.OutputBytes, s.staged.DiskBytes)
			observer.ObserveCorrelateBuffer("output", stats.OutputBytes, s.staged.OutputBytes)
		}
		if observer, ok := s.viewObserver.(StagedViewObserver); ok {
			observer.ObserveStagedView(stats)
		}
		if closeErr := snapshot.Close(); closeErr != nil {
			log.FromContext(ctx).Error().Err(closeErr).Msg("close correlate snapshot")
		}
	}()
	if err != nil {
		return 0, fmt.Errorf("staged correlate: %w", err)
	}
	// Re-read changed IDs from this complete snapshot. The seed read chooses
	// affected rules; its earlier observation must not overwrite this snapshot.
	changedSet := make(map[string]bool, len(changed))
	changedTypes := typesOf(changed)
	changedAccounts := make(map[string]bool)
	for _, a := range changed {
		changedSet[a.ID] = true
		if a.Type == "aws_scp_set" && a.AccountID != "" {
			changedAccounts[a.AccountID] = true
		}
	}
	run := func(rule Rule, input []asset.Asset) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, a := range input {
			if changedSet[a.ID] && a.Type == "aws_scp_set" && a.AccountID != "" {
				changedAccounts[a.AccountID] = true
			}
		}
		graph := NewGraph(input)
		if changed != nil {
			graph.changedIDs, graph.changedTypes, graph.changedSCPAccounts = changedSet, changedTypes, changedAccounts
		}
		streamer, ok := rule.(edgeStreamer)
		if !ok {
			return fmt.Errorf("rule has no bounded edge stream")
		}
		for edge := range streamer.Edges(graph) {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := snapshot.StageEdges([]asset.Edge{edge}); err != nil {
				return err
			}
		}
		if changed == nil {
			if _, ok := rule.(AssetAnnotator); ok {
				annotator, ok := rule.(annotationStreamer)
				if !ok {
					return fmt.Errorf("rule has no bounded annotation stream")
				}
				for annotation := range annotator.Annotations(graph) {
					if err := ctx.Err(); err != nil {
						return err
					}
					if err := snapshot.StageAnnotations([]asset.Annotation{annotation}); err != nil {
						return err
					}
				}
			}
			if reporter, ok := rule.(DemotionReporter); ok {
				logDemotions(log.FromContext(ctx), rule.Name(), reporter.Demotions(graph))
			}
		}
		return nil
	}
	// Pending live verification is a result of the entire successful pass. Keep
	// stateful rules private until output publication succeeds, including when a
	// later rule or annotation hits its budget. Correlation jobs remain serialized.
	pending := make(map[*CIAccess]*CIAccess)
	for _, rule := range rules {
		if original, ok := rule.(*CIAccess); ok {
			staged := &CIAccess{}
			pending[original] = staged
			rule = staged
		}
		if err := s.runStagedRule(ctx, snapshot, rule, run); err != nil {
			return 0, fmt.Errorf("staged rule %s: %w", rule.Name(), err)
		}
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	count, err := snapshot.Publish(ctx, func(edges []asset.Edge) error { return s.assets.IngestEdges(ctx, edges) },
		func(annotations []asset.Annotation) error {
			return s.assets.WriteAnnotations(ctx, version, annotations)
		})
	if err != nil {
		return 0, err
	}
	for original, staged := range pending {
		original.mu.Lock()
		original.pending = staged.pending
		original.mu.Unlock()
	}
	return count, nil
}

func (s *Service) runStagedRule(ctx context.Context, snapshot stagedView, rule Rule, run func(Rule, []asset.Asset) error) error {
	types := rule.InterestedIn()
	var contextTypes []string
	var anchor string
	switch rule.(type) {
	case ExecutesAs:
		// This index is metadata-driven for every type in the captured view.
		// InterestedIn controls partial activation, not the full-sweep index.
		types = correlationTypes
		contextTypes = []string{"iam_role", "gcp_service_account", "azure_service_principal", "azure_managed_identity"}
	case EC2InstanceProfile:
		contextTypes = []string{"iam_role"}
	case InternetReachability:
		contextTypes = []string{"security_group", "gcp_firewall", "azure_public_ip"}
	case SharedSecurityGroup:
		types = correlationTypes
		contextTypes = []string{"security_group"}
	case DataClassification:
		contextTypes = []string{}
	case IAMEffectivePermissions:
		contextTypes = []string{"aws_scp_set"}
	case K8sServiceTargets:
		contextTypes = []string{"k8s_service"}
	case K8sPodServiceAccount:
		contextTypes = []string{"k8s_service_account"}
	case DeploysTo:
		contextTypes = []string{"github_repo"}
	case TFOwnership:
		anchor = "declared_tf_resource"
		contextTypes = []string{anchor}
	case DNSPointsTo:
		anchor = "dns_record"
	case GCPFirewallApplies, GCPFirewallReachability:
		anchor = "gcp_firewall"
	}
	// Absence is usable only after StageView has successfully consumed the whole
	// source. Still call the rule once: stateful empty-sweep resets are required.
	if anchor != "" && snapshot.Count([]string{anchor}) == 0 {
		return run(rule, nil)
	}
	switch rule.(type) {
	case DNSPointsTo:
		return s.runStagedDNS(ctx, snapshot)
	case GCPFirewallApplies, GCPFirewallReachability:
		for _, account := range snapshot.Accounts([]string{"gcp_firewall"}) {
			input, err := s.readStagedContext(ctx, snapshot, types, &account)
			if err != nil {
				return err
			}
			if err := run(rule, input); err != nil {
				return err
			}
		}
		return nil
	}
	if contextTypes == nil {
		input, err := s.readStagedContext(ctx, snapshot, types, nil)
		if err != nil {
			return err
		}
		return run(rule, input)
	}
	contextRows, err := s.readStagedContext(ctx, snapshot, contextTypes, nil)
	if err != nil {
		return err
	}
	var pageTypes []string
	for _, kind := range types {
		if !slices.Contains(contextTypes, kind) {
			pageTypes = append(pageTypes, kind)
		}
	}
	called := false
	err = snapshot.Read(ctx, pageTypes, nil, s.staged.PageRows, s.staged.PageBytes, func(page []asset.Asset) error {
		called = true
		input := make([]asset.Asset, 0, len(contextRows)+len(page))
		input = append(input, contextRows...)
		input = append(input, page...)
		return run(rule, input)
	})
	if err != nil {
		return err
	}
	if !called {
		return run(rule, contextRows)
	}
	return nil
}

func (s *Service) readStagedContext(ctx context.Context, snapshot stagedView, types []string, account *string) ([]asset.Asset, error) {
	// Complete-context memory is constrained by bytes. The old whole-estate
	// count breaker does not apply to this already bounded immutable snapshot.
	maxRows := snapshot.Count(types) + 1
	if err := snapshot.CheckContext(types, account, maxRows, s.staged.ContextBytes); err != nil {
		return nil, err
	}
	var input []asset.Asset
	err := snapshot.Read(ctx, types, account, maxRows, s.staged.ContextBytes, func(page []asset.Asset) error {
		// A context is indivisible. More than one page is a budget failure, never
		// a truncated context presented to a rule as complete.
		if input != nil {
			return fmt.Errorf("complete rule context: %w", ErrStagedBudget)
		}
		input = page
		return nil
	})
	return input, err
}
