package gcp

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	logging "google.golang.org/api/logging/v2"
	monitoring "google.golang.org/api/monitoring/v3"
)

// loggingAPI is the slice of Cloud Logging, Cloud Monitoring and Cloud
// Storage the project log-export and alerting posture needs.
type loggingAPI interface {
	// Sinks lists the log sinks on "projects/<id>", "folders/<n>" or
	// "organizations/<n>".
	Sinks(ctx context.Context, parent string) ([]*logging.LogSink, error)
	Metrics(ctx context.Context, projectID string) ([]*logging.LogMetric, error)
	AlertPolicies(ctx context.Context, projectID string) ([]*monitoring.AlertPolicy, error)
	// BucketLocked reports whether a Cloud Storage bucket has a locked
	// retention policy (Bucket Lock).
	BucketLocked(ctx context.Context, bucket string) (bool, error)
	// Ancestry returns the project's folders and organization, nearest first.
	Ancestry(ctx context.Context, projectID string) ([]string, error)
}

// collectLoggingSettings evaluates the project's log export (CIS GCP 2.3,
// 2.4) and change-alerting (2.5-2.12) posture into cloud_account keys. Each
// key is omitted when a read it depends on failed; the joined error flags the
// sweep partial.
//
// The organization-level answer (an aggregated catch-all sink on the
// organization) lands on the organization settings asset instead, when the
// organization's sinks are readable.
func collectLoggingSettings(ctx context.Context, client loggingAPI, projectID string) (map[string]string, orgSettings, error) {
	md := map[string]string{}
	var org orgSettings
	var errs []error

	projectSinks, err := client.Sinks(ctx, "projects/"+projectID)
	if err != nil {
		errs = append(errs, err)
	} else {
		org = evaluateSinks(ctx, client, projectID, projectSinks, md, &errs)
		lockedSinkBuckets(ctx, client, projectSinks, md, &errs)
	}

	metrics, mErr := client.Metrics(ctx, projectID)
	policies, pErr := client.AlertPolicies(ctx, projectID)
	if pErr != nil && serviceDisabledErr(ctx, pErr) {
		// Cloud Monitoring never enabled: no alert policy can exist.
		policies, pErr = nil, nil
	}
	errs = append(errs, mErr, pErr)
	if mErr == nil && pErr == nil {
		md["log_alerts_missing"] = strings.Join(missingLogAlerts(metrics, policies), ",")
		md["log_compute_alert_missing"] = strconv.FormatBool(!alertInPlace(metrics, policies, computeConfigAlert))
	}
	if err := errors.Join(errs...); err != nil {
		return md, org, fmt.Errorf("collectLoggingSettings: %w", err)
	}
	return md, org, nil
}

// catchAllSink reports whether a sink exports every log entry: enabled, with
// an empty filter and no active exclusion (an exclusion drops entries the
// empty filter would otherwise send).
func catchAllSink(s *logging.LogSink) bool {
	if s == nil || s.Disabled || strings.TrimSpace(s.Filter) != "" {
		return false
	}
	for _, e := range s.Exclusions {
		if e != nil && !e.Disabled {
			return false
		}
	}
	return true
}

// evaluateSinks decides CIS GCP 2.3: a catch-all sink on the project
// itself, or on a folder or the organization with includeChildren (an
// aggregated sink, which exports this project's entries too).
//
// One finding per root cause: when the organization's sinks are readable,
// its answer lands on the organization settings asset, and the project
// records only a positive ("true", covered by some sink) — a project with no
// sink of its own is the organization's missing aggregated sink, reported
// once there. The project says "false" only when it has no organization and
// every sink list was read. Folder and organization reads are optional
// grants (optionalRead): denied leaves the answer unknown, never partial.
func evaluateSinks(ctx context.Context, client loggingAPI, projectID string, sinks []*logging.LogSink, md map[string]string, errs *[]error) orgSettings {
	var found []string
	for _, s := range sinks {
		if catchAllSink(s) {
			found = append(found, "projects/"+projectID+"/sinks/"+s.Name)
		}
	}
	var org orgSettings
	known := true
	ancestors, err := client.Ancestry(ctx, projectID)
	if err != nil {
		optionalRead(ctx, "gcp project ancestry", err, errs)
		known = false
	}
	for _, parent := range ancestors {
		list, err := client.Sinks(ctx, parent)
		if err != nil {
			optionalRead(ctx, "gcp "+parent+" sinks", err, errs)
			known = false
			continue
		}
		var here []string
		for _, s := range list {
			if s != nil && s.IncludeChildren && catchAllSink(s) {
				here = append(here, parent+"/sinks/"+s.Name)
			}
		}
		found = append(found, here...)
		if strings.HasPrefix(parent, "organizations/") {
			org = orgSettings{org: parent, md: map[string]string{
				"log_catch_all_sink":  strconv.FormatBool(len(here) > 0),
				"log_catch_all_sinks": strings.Join(here, ","),
			}}
		}
	}
	switch {
	case len(found) > 0:
		md["log_catch_all_sink"] = "true"
		md["log_catch_all_sinks"] = strings.Join(found, ",")
	case known && !hasOrganization(ancestors):
		md["log_catch_all_sink"] = "false"
		md["log_catch_all_sinks"] = ""
	}
	return org
}

func hasOrganization(ancestors []string) bool {
	for _, a := range ancestors {
		if strings.HasPrefix(a, "organizations/") {
			return true
		}
	}
	return false
}

// lockedSinkBuckets decides CIS GCP 2.4 for the project's own sinks: every
// Cloud Storage destination must have a locked retention policy. A bucket
// that cannot be read (often one in another project) leaves the answer
// unknown unless another bucket is already seen unlocked.
func lockedSinkBuckets(ctx context.Context, client loggingAPI, sinks []*logging.LogSink, md map[string]string, errs *[]error) {
	var unlocked []string
	unknown := false
	seen := map[string]bool{}
	for _, s := range sinks {
		if s == nil || s.Disabled {
			continue
		}
		bucket, ok := strings.CutPrefix(s.Destination, "storage.googleapis.com/")
		if !ok || seen[bucket] {
			continue
		}
		seen[bucket] = true
		locked, err := client.BucketLocked(ctx, bucket)
		if err != nil {
			// A central log bucket usually lives in another project: a
			// denied read is an optional grant, not a partial sweep.
			optionalRead(ctx, "gcp log sink bucket "+bucket, err, errs)
			unknown = true
			continue
		}
		if !locked {
			unlocked = append(unlocked, bucket)
		}
	}
	if len(unlocked) > 0 || !unknown {
		md["log_sink_buckets_unlocked"] = strings.Join(unlocked, ",")
	}
}

// missingLogAlerts returns the CIS change alerts the project lacks. An alert
// is in place when an enabled alert policy with at least one notification
// channel either matches log entries with a covering filter directly (a
// log-match condition) or alerts on a user-defined log metric whose filter
// covers the change (filterCovers, logfilter.go). A policy that notifies
// nobody alerts nobody.
func missingLogAlerts(metrics []*logging.LogMetric, policies []*monitoring.AlertPolicy) []string {
	var missing []string
	for _, a := range logAlerts {
		if !alertInPlace(metrics, policies, a) {
			missing = append(missing, a.Name)
		}
	}
	return missing
}

// alertInPlace reports whether an enabled, notifying alert policy covers the
// change, directly or through a covering user-defined log metric.
func alertInPlace(metrics []*logging.LogMetric, policies []*monitoring.AlertPolicy, a logAlert) bool {
	var metricRefs []string
	for _, m := range metrics {
		if m != nil && !m.Disabled && filterCovers(m.Filter, a) {
			metricRefs = append(metricRefs, m.Name)
		}
	}
	return alertedOn(policies, a, metricRefs)
}

func alertedOn(policies []*monitoring.AlertPolicy, a logAlert, metrics []string) bool {
	for _, p := range policies {
		if p == nil || !p.Enabled || len(p.NotificationChannels) == 0 {
			continue
		}
		for _, c := range p.Conditions {
			if c == nil {
				continue
			}
			if c.ConditionMatchedLog != nil && filterCovers(c.ConditionMatchedLog.Filter, a) {
				return true
			}
			for _, m := range metrics {
				if conditionReferences(c, m) {
					return true
				}
			}
		}
	}
	return false
}

// conditionReferences reports whether an alert condition alerts on the
// user-defined log metric: by metric.type in a threshold or absence filter,
// or by name in an MQL or PromQL query.
func conditionReferences(c *monitoring.Condition, metric string) bool {
	typ := "logging.googleapis.com/user/" + metric
	inFilter := func(f string) bool { return strings.Contains(strings.ReplaceAll(f, `'`, `"`), `"`+typ+`"`) }
	switch {
	case c.ConditionThreshold != nil && inFilter(c.ConditionThreshold.Filter):
		return true
	case c.ConditionAbsent != nil && inFilter(c.ConditionAbsent.Filter):
		return true
	case c.ConditionMonitoringQueryLanguage != nil && strings.Contains(c.ConditionMonitoringQueryLanguage.Query, typ):
		return true
	case c.ConditionPrometheusQueryLanguage != nil &&
		strings.Contains(c.ConditionPrometheusQueryLanguage.Query, "logging_googleapis_com:user_"+metric):
		return true
	}
	return false
}
