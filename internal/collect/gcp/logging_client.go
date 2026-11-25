package gcp

import (
	"context"
	"fmt"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	logging "google.golang.org/api/logging/v2"
	monitoring "google.golang.org/api/monitoring/v3"
	storage "google.golang.org/api/storage/v1"
)

// newLoggingClient builds the real loggingAPI via ADC.
func newLoggingClient(ctx context.Context) (loggingAPI, error) {
	l, err := logging.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newLoggingClient: %w", err)
	}
	m, err := monitoring.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newLoggingClient: %w", err)
	}
	s, err := storage.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newLoggingClient: %w", err)
	}
	rm, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newLoggingClient: %w", err)
	}
	return &realLogging{logging: l, monitoring: m, storage: s, rm: rm}, nil
}

type realLogging struct {
	logging    *logging.Service
	monitoring *monitoring.Service
	storage    *storage.Service
	rm         *cloudresourcemanager.Service
}

func (r *realLogging) Sinks(ctx context.Context, parent string) ([]*logging.LogSink, error) {
	var out []*logging.LogSink
	if err := r.logging.Sinks.List(parent).Pages(ctx, func(p *logging.ListSinksResponse) error {
		out = append(out, p.Sinks...)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("Sinks %s: %w", parent, err)
	}
	return out, nil
}

func (r *realLogging) Metrics(ctx context.Context, projectID string) ([]*logging.LogMetric, error) {
	var out []*logging.LogMetric
	if err := r.logging.Projects.Metrics.List("projects/"+projectID).Pages(ctx, func(p *logging.ListLogMetricsResponse) error {
		out = append(out, p.Metrics...)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("Metrics: %w", err)
	}
	return out, nil
}

func (r *realLogging) AlertPolicies(ctx context.Context, projectID string) ([]*monitoring.AlertPolicy, error) {
	var out []*monitoring.AlertPolicy
	if err := r.monitoring.Projects.AlertPolicies.List("projects/"+projectID).Pages(ctx, func(p *monitoring.ListAlertPoliciesResponse) error {
		out = append(out, p.AlertPolicies...)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("AlertPolicies: %w", err)
	}
	return out, nil
}

func (r *realLogging) BucketLocked(ctx context.Context, bucket string) (bool, error) {
	b, err := r.storage.Buckets.Get(bucket).Fields("retentionPolicy").Context(ctx).Do()
	if err != nil {
		return false, fmt.Errorf("BucketLocked %s: %w", bucket, err)
	}
	return b.RetentionPolicy != nil && b.RetentionPolicy.IsLocked, nil
}

func (r *realLogging) Ancestry(ctx context.Context, projectID string) ([]string, error) {
	return projectAncestry(ctx, r.rm, projectID)
}

// projectAncestry returns the project's folders and organization as
// resource names, nearest first (GetAncestry lists the project itself first).
func projectAncestry(ctx context.Context, rm *cloudresourcemanager.Service, projectID string) ([]string, error) {
	resp, err := rm.Projects.GetAncestry(projectID, &cloudresourcemanager.GetAncestryRequest{}).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("projectAncestry: %w", err)
	}
	parents, err := gcsPolicyParents(resp)
	if err != nil {
		return nil, fmt.Errorf("projectAncestry: %w", err)
	}
	return parents, nil
}
