package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/correlate"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/checks/benchmarks"
	"github.com/vulngraph/vulngraph/internal/collect"
)

// scanOptions are the parsed flags of `graph scan <provider>`.
type scanOptions struct {
	provider   string
	region     string
	regions    string
	roleARN    string
	project    string
	adminEmail string
	format     string
	only       string
	failOn     string
	severity   string
	checks     string
	compliance string
}

var severityOrder = []finding.Severity{
	finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow, finding.SeverityInfo,
}

// scanHelp carries the -h text so the caller can print it and exit 0.
type scanHelp struct{ text string }

func (h scanHelp) Error() string { return "scan: help requested" }

func parseScanArgs(args []string) (scanOptions, error) {
	usage := fmt.Errorf("usage: graph scan <%s> [flags] (graph scan <provider> -h lists the flags)", scanProviderNames())
	if len(args) == 0 {
		return scanOptions{}, usage
	}
	p, ok := scanProviders[args[0]]
	if !ok {
		return scanOptions{}, usage
	}
	o := scanOptions{provider: args[0]}
	var help bytes.Buffer
	fs := flag.NewFlagSet("scan "+args[0], flag.ContinueOnError)
	fs.SetOutput(&help)
	p.flags(fs, &o)
	fs.StringVar(&o.format, "format", "table", "output format: table, json or sarif")
	fs.StringVar(&o.only, "only", "", "limit findings to one area: data")
	fs.StringVar(&o.severity, "severity", "", "show only findings at or above this severity (--fail-on ignores this filter)")
	fs.StringVar(&o.checks, "check", "", "report only these comma-separated check IDs")
	fs.StringVar(&o.compliance, "compliance", "", "report only checks mapped to this benchmark ID ("+benchmarkIDList(args[0])+")")
	fs.StringVar(&o.failOn, "fail-on", "", "exit non-zero when a finding at or above this severity exists")
	fs.Usage = func() {
		fmt.Fprintf(&help, "usage: graph scan %s [flags]\ncredentials: %s\n\nflags:\n", args[0], p.credentials)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return scanOptions{}, scanHelp{text: help.String()}
		}
		return scanOptions{}, fmt.Errorf("scan: %w", err)
	}
	if fs.NArg() > 0 {
		return scanOptions{}, fmt.Errorf("scan: unexpected argument %q", fs.Arg(0))
	}
	if !slices.Contains([]string{"table", "json", "sarif"}, o.format) {
		return scanOptions{}, fmt.Errorf("scan: unknown --format %q (table, json or sarif)", o.format)
	}
	if o.only != "" && o.only != "data" {
		return scanOptions{}, fmt.Errorf("scan: unknown --only %q (data)", o.only)
	}
	for flagName, v := range map[string]string{"--fail-on": o.failOn, "--severity": o.severity} {
		if v != "" && severityRank(finding.Severity(v)) < 0 {
			return scanOptions{}, fmt.Errorf("scan: unknown %s %q (critical, high, medium, low, info)", flagName, v)
		}
	}
	return o, nil
}

// severityRank is 0 for critical up to 4 for info, -1 for anything else.
func severityRank(s finding.Severity) int { return slices.Index(severityOrder, s) }

// scanDataTypes are the asset types `--only data` keeps: every store the
// registered checks evaluate for data posture (buckets, databases, caches,
// warehouses, file systems, streams, secrets), plus the DSPM classifier's own
// list. It is wider than the DSPM list, which names only the types it
// classifies by name.
var scanDataTypes = append([]string{
	"s3_bucket", "s3_directory_bucket", "rds_instance", "rds_cluster", "rds_snapshot", "dynamodb_table",
	"docdb_cluster", "neptune_cluster", "redshift_cluster", "redshift_serverless_namespace", "redshift_serverless_workgroup",
	"opensearch_domain", "elasticache_cluster", "elasticache_replication_group", "efs_file_system", "fsx_file_system",
	"kinesis_stream", "secretsmanager_secret",
	"azure_storage_account", "azure_sql_server", "azure_sql_database", "azure_blob_container",
	"gcs_bucket", "cloudsql_instance", "cloud_sql_instance", "gcp_bigquery_dataset", "gcp_secret", "firestore_collection",
}, correlate.DataClassification{}.InterestedIn()...)

// scanFinding is the stable JSON shape of one finding. It is not the domain
// type: enrichment and lifecycle fields are zero in a scan and would read as
// measurements.
type scanFinding struct {
	CheckID      string            `json:"check_id"`
	Severity     finding.Severity  `json:"severity"`
	Title        string            `json:"title"`
	Description  string            `json:"description,omitempty"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	ResourceName string            `json:"resource_name,omitempty"`
	Region       string            `json:"region,omitempty"`
	Remediation  string            `json:"remediation,omitempty"`
	Evidence     map[string]string `json:"evidence,omitempty"`
}

// scanResult is what one scan produced, rendered as the JSON output.
type scanResult struct {
	Assets  int  `json:"assets"`
	Partial bool `json:"partial"`
	// HiddenBySeverity counts in-scope findings below --severity, so a filtered
	// scan cannot read as clean.
	HiddenBySeverity int           `json:"hidden_by_severity,omitempty"`
	Findings         []scanFinding `json:"findings"`
}

func toScanFindings(in []finding.Finding) []scanFinding {
	out := make([]scanFinding, 0, len(in))
	for _, f := range in {
		out = append(out, scanFinding{
			CheckID: f.CheckID, Severity: f.Severity, Title: f.Title, Description: f.Description,
			ResourceType: f.ResourceType, ResourceID: f.ResourceID, ResourceName: f.ResourceName,
			Region: f.Region, Remediation: f.Remediation, Evidence: f.Metadata,
		})
	}
	return out
}

const partialWarning = "collection was partial (a permission or API error skipped part of the account); absent findings are not proof of a clean account"

// runScan collects once, evaluates the registered checks in memory and
// renders the findings. Nothing is written to any datastore. The partial
// warning goes to errw for the machine formats; the table carries it inline.
func runScan(ctx context.Context, c collect.Collector, o scanOptions, cfg map[string]string, now time.Time, out, errw io.Writer) error {
	scope, err := scopeFilter(o)
	if err != nil {
		return err
	}
	res, err := c.Collect(ctx, cfg)
	if err != nil {
		return fmt.Errorf("scan: collect: %w", err)
	}
	var inScope []finding.Finding
	for _, f := range checks.Default().Run(res.Assets, now) {
		if scope(f) {
			inScope = append(inScope, f)
		}
	}
	sortFindings(inScope)

	// --fail-on looks at everything in scope; --severity only narrows what is shown.
	shown := inScope
	if o.severity != "" {
		limit := severityRank(finding.Severity(o.severity))
		shown = slices.DeleteFunc(slices.Clone(inScope), func(f finding.Finding) bool {
			r := severityRank(f.Severity)
			return r < 0 || r > limit
		})
	}
	result := scanResult{Assets: len(res.Assets), Partial: res.Partial, HiddenBySeverity: len(inScope) - len(shown), Findings: toScanFindings(shown)}
	if err := render(out, o.format, result); err != nil {
		return err
	}
	if res.Partial && o.format != "table" {
		if _, err := fmt.Fprintln(errw, "WARNING: "+partialWarning); err != nil {
			return fmt.Errorf("scan: write: %w", err)
		}
	}
	return failOnError(o, inScope, res.Partial)
}

func failOnError(o scanOptions, inScope []finding.Finding, partial bool) error {
	if o.failOn == "" {
		return nil
	}
	limit := severityRank(finding.Severity(o.failOn))
	for _, f := range inScope {
		if r := severityRank(f.Severity); r >= 0 && r <= limit {
			return fmt.Errorf("scan: %d finding(s) in scope, at least one at or above %s", len(inScope), o.failOn)
		}
	}
	if partial {
		return fmt.Errorf("scan: collection was partial, so the absence of findings at or above %s is not proof the account is clean", o.failOn)
	}
	return nil
}

// scopeFilter combines --only, --check and --compliance. Unknown check or
// benchmark IDs, a benchmark that does not apply to the provider, and an
// empty --check/--compliance intersection are errors, not empty results.
func scopeFilter(o scanOptions) (func(finding.Finding) bool, error) {
	onlyData := o.only == "data"

	var ids map[string]bool
	if o.checks != "" {
		registered := checks.Default().IDs()
		ids = map[string]bool{}
		for id := range strings.SplitSeq(o.checks, ",") {
			id = strings.TrimSpace(id)
			if !registered[id] {
				return nil, fmt.Errorf("scan: unknown check %q", id)
			}
			ids[id] = true
		}
	}
	if o.compliance != "" {
		mapped, err := benchmarkCheckIDs(o.compliance, o.provider)
		if err != nil {
			return nil, err
		}
		if ids == nil {
			ids = mapped
		} else {
			for id := range ids {
				if !mapped[id] {
					delete(ids, id)
				}
			}
			if len(ids) == 0 {
				return nil, fmt.Errorf("scan: none of the --check IDs belong to benchmark %q", o.compliance)
			}
		}
	}
	return func(f finding.Finding) bool {
		if onlyData && !slices.Contains(scanDataTypes, f.ResourceType) {
			return false
		}
		return ids == nil || ids[f.CheckID]
	}, nil
}

// benchmarkProvider is the asset provider name benchmarks list for a scan provider.
func benchmarkProvider(scanProvider string) string {
	if scanProvider == "googleworkspace" {
		return "google"
	}
	return scanProvider
}

// benchmarkIDList lists the benchmark IDs that apply to provider (all of them
// when provider is empty).
func benchmarkIDList(provider string) string {
	all, err := benchmarks.Load()
	if err != nil {
		return "see docs/quick-scan.md"
	}
	var ids []string
	for _, b := range all {
		if provider == "" || slices.Contains(b.Providers, benchmarkProvider(provider)) {
			ids = append(ids, b.ID)
		}
	}
	if len(ids) == 0 {
		return "none for this provider"
	}
	return strings.Join(ids, ", ")
}

// benchmarkCheckIDs returns every check ID the named benchmark maps to, for a
// benchmark that applies to the scanned provider.
func benchmarkCheckIDs(id, provider string) (map[string]bool, error) {
	all, err := benchmarks.Load()
	if err != nil {
		return nil, fmt.Errorf("scan: load benchmarks: %w", err)
	}
	for _, b := range all {
		if b.ID != id {
			continue
		}
		if !slices.Contains(b.Providers, benchmarkProvider(provider)) {
			return nil, fmt.Errorf("scan: benchmark %q does not apply to %s (it covers %s)", id, provider, strings.Join(b.Providers, ", "))
		}
		out := map[string]bool{}
		for _, c := range b.Controls {
			for _, cid := range c.CheckIDs {
				out[cid] = true
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("scan: unknown benchmark %q (for %s: %s)", id, provider, benchmarkIDList(provider))
}

// sortFindings orders by severity (unknown last), then resource and check.
func sortFindings(fs []finding.Finding) {
	rank := func(s finding.Severity) int {
		if r := severityRank(s); r >= 0 {
			return r
		}
		return len(severityOrder)
	}
	slices.SortStableFunc(fs, func(a, b finding.Finding) int {
		if d := rank(a.Severity) - rank(b.Severity); d != 0 {
			return d
		}
		return strings.Compare(a.ResourceID+a.CheckID, b.ResourceID+b.CheckID)
	})
}

func render(w io.Writer, format string, r scanResult) error {
	switch format {
	case "sarif":
		return renderSARIF(w, r)
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			return fmt.Errorf("scan: write: %w", err)
		}
		return nil
	}
	var rows strings.Builder
	rows.WriteString("SEVERITY\tCHECK\tRESOURCE\tREGION\tTITLE\n")
	for _, f := range r.Findings {
		fmt.Fprintf(&rows, "%s\t%s\t%s\t%s\t%s\n", f.Severity, f.CheckID, f.ResourceID, f.Region, f.Title)
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := tw.Write([]byte(rows.String())); err != nil {
		return fmt.Errorf("scan: write: %w", err)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("scan: write: %w", err)
	}
	var tail strings.Builder
	fmt.Fprintf(&tail, "\n%d finding(s) across %d asset(s)%s\n", len(r.Findings), r.Assets, severitySummary(r.Findings))
	if r.HiddenBySeverity > 0 {
		fmt.Fprintf(&tail, "%d lower-severity finding(s) hidden by --severity\n", r.HiddenBySeverity)
	}
	if r.Partial {
		tail.WriteString("WARNING: " + partialWarning + "\n")
	}
	if _, err := io.WriteString(w, tail.String()); err != nil {
		return fmt.Errorf("scan: write: %w", err)
	}
	return nil
}

// severitySummary renders " (2 critical, 5 high)" for the non-zero counts.
func severitySummary(fs []scanFinding) string {
	var parts []string
	for _, sev := range severityOrder {
		n := 0
		for _, f := range fs {
			if f.Severity == sev {
				n++
			}
		}
		if n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// scanCmd runs `graph scan <provider>`: a one-time, in-memory sweep of one
// account. Progress goes to errw so stdout stays machine-readable.
func scanCmd(ctx context.Context, args []string, getenv func(string) string, out, errw io.Writer) error {
	o, err := parseScanArgs(args)
	var help scanHelp
	if errors.As(err, &help) {
		if _, err := io.WriteString(out, help.text); err != nil {
			return fmt.Errorf("scan: write: %w", err)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if _, err := scopeFilter(o); err != nil {
		return err
	}
	p := scanProviders[o.provider]
	cfg, err := p.config(o, getenv)
	if err != nil {
		return err
	}
	start := time.Now()
	if _, err := fmt.Fprintf(errw, "scanning %s (read-only, nothing is stored)...\n", o.provider); err != nil {
		return fmt.Errorf("scan: write: %w", err)
	}
	if err := runScan(ctx, p.collector(), o, cfg, start.UTC(), out, errw); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(errw, "done in %s\n", time.Since(start).Round(time.Second)); err != nil {
		return fmt.Errorf("scan: write: %w", err)
	}
	return nil
}
