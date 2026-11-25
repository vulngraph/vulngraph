package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/correlate"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/checks/benchmarks"
	"github.com/vulngraph/vulngraph/internal/collect"
)

type fakeCollector struct {
	res collect.Result
	err error
}

func (f fakeCollector) Collect(context.Context, map[string]string) (collect.Result, error) {
	return f.res, f.err
}

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func publicBucket() asset.Asset {
	return asset.Asset{
		ID: "arn:aws:s3:::open", Name: "open", Type: "s3_bucket", Provider: asset.ProviderAWS, Region: "us-east-1",
		Metadata: map[string]string{"public": "true", "public_access_block": "false"},
	}
}

// openSG is a default security group that still carries rules (a different
// check and severity from publicBucket).
func openSG() asset.Asset {
	return asset.Asset{
		ID: "sg-1", Name: "default", Type: "security_group", Provider: asset.ProviderAWS, Region: "us-east-1",
		Metadata: map[string]string{"ingress_rules": "1", "egress_rules": "0"},
	}
}

// unencryptedVolume fires a medium-severity check, unlike the two low ones.
func unencryptedVolume() asset.Asset {
	return asset.Asset{
		ID: "vol-1", Name: "v", Type: "ebs_volume", Provider: asset.ProviderAWS, Region: "us-east-1",
		Metadata: map[string]string{"encrypted": "false"},
	}
}

// runFake runs runScan against a fake collector and decodes the JSON result.
func runFake(t *testing.T, res collect.Result, o scanOptions) (scanResult, string, error) {
	t.Helper()
	o.format = "json"
	if o.provider == "" {
		o.provider = "aws"
	}
	var out, errw bytes.Buffer
	err := runScan(context.Background(), fakeCollector{res: res}, o, nil, time.Unix(0, 0), &out, &errw)
	var got scanResult
	if out.Len() > 0 {
		require.NoError(t, json.Unmarshal(out.Bytes(), &got))
	}
	return got, errw.String(), err
}

func TestParseScanArgs(t *testing.T) {
	o, err := parseScanArgs([]string{"aws", "--only", "data", "--format", "json", "--fail-on", "high",
		"--region", "eu-west-1", "--regions", "a,b", "--role-arn", "arn:r", "--check", "x", "--compliance", "y", "--severity", "low"})
	require.NoError(t, err)
	assert.Equal(t, scanOptions{provider: "aws", only: "data", format: "json", failOn: "high", region: "eu-west-1",
		regions: "a,b", roleARN: "arn:r", checks: "x", compliance: "y", severity: "low"}, o)

	o, err = parseScanArgs([]string{"gcp", "--project", "p"})
	require.NoError(t, err)
	assert.Equal(t, "p", o.project)
	o, err = parseScanArgs([]string{"googleworkspace", "--admin-email", "a@x.com"})
	require.NoError(t, err)
	assert.Equal(t, "a@x.com", o.adminEmail)

	for _, bad := range [][]string{
		{}, {"nope"}, {"aws", "--format", "xml"}, {"aws", "--only", "iam"}, {"aws", "--fail-on", "urgent"},
		{"aws", "--severity", "urgent"}, {"aws", "extra"}, {"aws", "--nope"}, {"aws", "--region"},
	} {
		_, err := parseScanArgs(bad)
		assert.Error(t, err, bad)
	}
}

func TestScanCmd_HelpExitsCleanAndNamesCredentials(t *testing.T) {
	var out, errw bytes.Buffer
	require.NoError(t, scanCmd(context.Background(), []string{"azure", "-h"}, env(nil), &out, &errw))
	assert.Contains(t, out.String(), "AZURE_SUBSCRIPTION_ID")
	assert.Contains(t, out.String(), "--fail-on")
	assert.Empty(t, errw.String())
}

func TestScanCmd_ErrorsOnceAndStdoutStaysClean(t *testing.T) {
	var out, errw bytes.Buffer
	err := scanCmd(context.Background(), []string{"aws"}, env(nil), &out, &errw)
	require.ErrorContains(t, err, "AWS_ACCESS_KEY_ID")
	assert.Empty(t, out.String())
	assert.Empty(t, errw.String())
}

func TestScanProviderConfigs(t *testing.T) {
	t.Run("aws", func(t *testing.T) {
		_, err := awsScanConfig(scanOptions{region: "us-east-1"}, env(nil))
		require.ErrorContains(t, err, "AWS_ACCESS_KEY_ID")
		cfg, err := awsScanConfig(scanOptions{region: "eu-west-1", regions: "a,b"}, env(map[string]string{
			"AWS_ACCESS_KEY_ID": "ASIAEXAMPLE", "AWS_SECRET_ACCESS_KEY": "s", "AWS_SESSION_TOKEN": "t",
		}))
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"name": "cli-scan", "region": "eu-west-1", "regions": "a,b",
			"aws_access_key_id": "ASIAEXAMPLE", "aws_secret_access_key": "s", "aws_session_token": "t"}, cfg)
		cfg, err = awsScanConfig(scanOptions{region: "us-east-1", roleARN: "arn:aws:iam::1:role/r"}, env(nil))
		require.NoError(t, err)
		assert.Equal(t, "arn:aws:iam::1:role/r", cfg["role_arn"])
	})
	t.Run("azure", func(t *testing.T) {
		_, err := azureScanConfig(scanOptions{}, env(map[string]string{"AZURE_TENANT_ID": "t"}))
		require.ErrorContains(t, err, "AZURE_SUBSCRIPTION_ID")
		cfg, err := azureScanConfig(scanOptions{}, env(map[string]string{"AZURE_SUBSCRIPTION_ID": "s"}))
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"name": "cli-scan", "subscription_id": "s"}, cfg, "ambient login needs no service principal")
		cfg, err = azureScanConfig(scanOptions{}, env(map[string]string{
			"AZURE_SUBSCRIPTION_ID": "s", "AZURE_TENANT_ID": "t", "AZURE_CLIENT_ID": "c", "AZURE_CLIENT_SECRET": "x",
		}))
		require.NoError(t, err)
		assert.Equal(t, "t", cfg["tenant_id"])
		assert.Equal(t, "c", cfg["client_id"])
		assert.Equal(t, "x", cfg["client_secret"])
	})
	t.Run("okta", func(t *testing.T) {
		_, err := scanProviders["okta"].config(scanOptions{}, env(map[string]string{"OKTA_DOMAIN": "d"}))
		require.ErrorContains(t, err, "OKTA_API_TOKEN")
		cfg, err := scanProviders["okta"].config(scanOptions{}, env(map[string]string{"OKTA_DOMAIN": "d.okta.com", "OKTA_API_TOKEN": "x"}))
		require.NoError(t, err)
		assert.Equal(t, "d.okta.com", cfg["domain"])
		assert.Equal(t, "x", cfg["api_token"])
	})
	t.Run("gcp", func(t *testing.T) {
		_, err := gcpScanConfig(scanOptions{}, env(nil))
		require.ErrorContains(t, err, "--project")
		cfg, err := gcpScanConfig(scanOptions{}, env(map[string]string{"GOOGLE_CLOUD_PROJECT": "from-env"}))
		require.NoError(t, err)
		assert.Equal(t, "from-env", cfg["project_id"])
		cfg, err = gcpScanConfig(scanOptions{project: "from-flag"}, env(map[string]string{"GOOGLE_CLOUD_PROJECT": "from-env"}))
		require.NoError(t, err)
		assert.Equal(t, "from-flag", cfg["project_id"], "the flag wins over the environment")
	})
	t.Run("googleworkspace", func(t *testing.T) {
		_, err := googleScanConfig(scanOptions{adminEmail: "a@x.com"}, env(nil))
		require.ErrorContains(t, err, "GOOGLE_APPLICATION_CREDENTIALS")
		key := filepath.Join(t.TempDir(), "key.json")
		require.NoError(t, os.WriteFile(key, []byte(`{"type":"service_account"}`), 0o600))
		cfg, err := googleScanConfig(scanOptions{}, env(map[string]string{
			"GOOGLE_APPLICATION_CREDENTIALS": key, "GOOGLE_WORKSPACE_ADMIN_EMAIL": "admin@x.com",
		}))
		require.NoError(t, err)
		assert.JSONEq(t, `{"type":"service_account"}`, cfg["service_account_json"])
		assert.Equal(t, "admin@x.com", cfg["admin_email"])
		_, err = googleScanConfig(scanOptions{adminEmail: "a@x.com"}, env(map[string]string{"GOOGLE_APPLICATION_CREDENTIALS": filepath.Join(t.TempDir(), "missing.json")}))
		require.ErrorContains(t, err, "read service-account key")
	})
}

// mixedAssets fires several checks at more than one severity.
func mixedAssets(t *testing.T) []asset.Asset {
	t.Helper()
	fixture := []asset.Asset{publicBucket(), openSG(), unencryptedVolume()}
	res, _, err := runFake(t, collect.Result{Assets: fixture}, scanOptions{})
	require.NoError(t, err)
	sevs := map[finding.Severity]bool{}
	for _, f := range res.Findings {
		sevs[f.Severity] = true
	}
	require.Len(t, res.Findings, 3, "fixture must fire exactly the three checks")
	require.GreaterOrEqual(t, len(sevs), 2, "fixture must span at least two severities")
	return fixture
}

func TestRunScan_SeverityFilterKeepsOnlyAtOrAbove(t *testing.T) {
	assets := mixedAssets(t)
	all, _, err := runFake(t, collect.Result{Assets: assets}, scanOptions{})
	require.NoError(t, err)

	for _, limit := range severityOrder {
		got, _, err := runFake(t, collect.Result{Assets: assets}, scanOptions{severity: string(limit)})
		require.NoError(t, err)
		want := 0
		for _, f := range all.Findings {
			if severityRank(f.Severity) <= severityRank(limit) {
				want++
			}
		}
		assert.Len(t, got.Findings, want, "--severity %s", limit)
		for _, f := range got.Findings {
			assert.LessOrEqual(t, severityRank(f.Severity), severityRank(limit))
		}
	}
}

func TestRunScan_CheckFilterIsExact(t *testing.T) {
	assets := mixedAssets(t)
	all, _, err := runFake(t, collect.Result{Assets: assets}, scanOptions{})
	require.NoError(t, err)
	first := all.Findings[0].CheckID

	got, _, err := runFake(t, collect.Result{Assets: assets}, scanOptions{checks: first})
	require.NoError(t, err)
	require.NotEmpty(t, got.Findings)
	assert.Less(t, len(got.Findings), len(all.Findings), "--check must drop other checks")
	for _, f := range got.Findings {
		assert.Equal(t, first, f.CheckID)
	}
}

func TestRunScan_OnlyData(t *testing.T) {
	got, _, err := runFake(t, collect.Result{Assets: []asset.Asset{publicBucket(), openSG()}}, scanOptions{only: "data"})
	require.NoError(t, err)
	require.NotEmpty(t, got.Findings)
	for _, f := range got.Findings {
		assert.Equal(t, "s3_bucket", f.ResourceType)
	}
}

func TestRunScan_ComplianceAndIntersection(t *testing.T) {
	all, err := benchmarks.Load()
	require.NoError(t, err)
	var bench benchmarks.Benchmark
	for _, b := range all {
		if b.ID == "cis-aws-foundations" {
			bench = b
		}
	}
	require.NotEmpty(t, bench.Controls)
	mapped, err := benchmarkCheckIDs(bench.ID, "aws")
	require.NoError(t, err)
	require.NotEmpty(t, mapped)

	assets := mixedAssets(t)
	got, _, err := runFake(t, collect.Result{Assets: assets}, scanOptions{compliance: bench.ID})
	require.NoError(t, err)
	for _, f := range got.Findings {
		assert.True(t, mapped[f.CheckID], "%s is not mapped to %s", f.CheckID, bench.ID)
	}

	var inBench, outOfBench string
	for _, c := range checks.Default().All() {
		if mapped[c.ID] && inBench == "" {
			inBench = c.ID
		}
		if !mapped[c.ID] && outOfBench == "" {
			outOfBench = c.ID
		}
	}
	_, _, err = runFake(t, collect.Result{}, scanOptions{compliance: bench.ID, checks: outOfBench})
	require.ErrorContains(t, err, "none of the --check IDs")
	_, _, err = runFake(t, collect.Result{}, scanOptions{compliance: bench.ID, checks: inBench})
	require.NoError(t, err)

	_, _, err = runFake(t, collect.Result{}, scanOptions{provider: "gcp", compliance: bench.ID})
	require.ErrorContains(t, err, "does not apply to gcp")
	_, _, err = runFake(t, collect.Result{}, scanOptions{compliance: "no-such-benchmark"})
	require.ErrorContains(t, err, "unknown benchmark")
	_, _, err = runFake(t, collect.Result{}, scanOptions{checks: "no_such_check"})
	require.ErrorContains(t, err, "unknown check")
}

func TestRunScan_FailOn(t *testing.T) {
	assets := mixedAssets(t)
	all, _, err := runFake(t, collect.Result{Assets: assets}, scanOptions{})
	require.NoError(t, err)
	worst := all.Findings[0].Severity // sorted: most severe first

	_, _, err = runFake(t, collect.Result{Assets: assets}, scanOptions{failOn: string(worst)})
	require.ErrorContains(t, err, "at least one at or above")

	// --severity narrows the display only: it must not hide a failing finding.
	// worst is below critical here, so --severity critical shows nothing.
	require.NotEqual(t, finding.SeverityCritical, worst)
	shown, _, err := runFake(t, collect.Result{Assets: assets}, scanOptions{failOn: string(worst), severity: "critical"})
	require.Error(t, err)
	assert.Empty(t, shown.Findings)

	// A threshold above everything found passes.
	if worst != finding.SeverityCritical {
		stricter := severityOrder[severityRank(worst)-1]
		_, _, err = runFake(t, collect.Result{Assets: assets}, scanOptions{failOn: string(stricter)})
		require.NoError(t, err)
	}

	_, _, err = runFake(t, collect.Result{}, scanOptions{})
	require.NoError(t, err, "no --fail-on never fails on findings")
}

func TestRunScan_PartialIsNeverClean(t *testing.T) {
	_, _, err := runFake(t, collect.Result{Partial: true}, scanOptions{failOn: "high"})
	require.ErrorContains(t, err, "partial")

	_, _, err = runFake(t, collect.Result{Partial: true}, scanOptions{})
	require.NoError(t, err, "without --fail-on a partial scan only warns")

	// A real finding fails with the finding error, not the partial one.
	_, _, err = runFake(t, collect.Result{Assets: []asset.Asset{publicBucket()}, Partial: true}, scanOptions{failOn: "info"})
	require.ErrorContains(t, err, "at least one at or above")

	for _, format := range []string{"json", "sarif"} {
		var out, errw bytes.Buffer
		require.NoError(t, runScan(context.Background(), fakeCollector{res: collect.Result{Partial: true}},
			scanOptions{provider: "aws", format: format}, nil, time.Unix(0, 0), &out, &errw))
		assert.Contains(t, errw.String(), "partial", "--format %s must warn on stderr", format)
	}
	var out, errw bytes.Buffer
	require.NoError(t, runScan(context.Background(), fakeCollector{res: collect.Result{Partial: true}},
		scanOptions{provider: "aws", format: "table"}, nil, time.Unix(0, 0), &out, &errw))
	assert.Contains(t, out.String(), "partial")
	assert.Empty(t, errw.String(), "the table carries the warning inline")
}

func TestRunScan_CollectErrorSurfaces(t *testing.T) {
	_, _, err := func() (scanResult, string, error) {
		var out, errw bytes.Buffer
		err := runScan(context.Background(), fakeCollector{err: assert.AnError}, scanOptions{provider: "aws", format: "table"},
			nil, time.Unix(0, 0), &out, &errw)
		return scanResult{}, "", err
	}()
	require.ErrorIs(t, err, assert.AnError)
}

func TestRunScan_JSONShape(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, runScan(context.Background(), fakeCollector{res: collect.Result{Assets: []asset.Asset{publicBucket()}}},
		scanOptions{provider: "aws", format: "json"}, nil, time.Unix(0, 0), &out, &bytes.Buffer{}))
	var raw map[string]any
	require.NoError(t, json.Unmarshal(out.Bytes(), &raw))
	first := raw["findings"].([]any)[0].(map[string]any)
	for _, key := range []string{"check_id", "severity", "title", "resource_type", "resource_id"} {
		assert.Contains(t, first, key)
	}
	assert.NotContains(t, first, "Score", "domain-type fields must not leak")
	assert.NotContains(t, first, "CheckID")
}

func TestRunScan_TableOutputAndSummary(t *testing.T) {
	var out bytes.Buffer
	require.NoError(t, runScan(context.Background(), fakeCollector{res: collect.Result{Assets: []asset.Asset{publicBucket(), openSG()}}},
		scanOptions{provider: "aws", format: "table"}, nil, time.Unix(0, 0), &out, &bytes.Buffer{}))
	text := out.String()
	assert.Contains(t, text, "SEVERITY")
	assert.Contains(t, text, "arn:aws:s3:::open")
	assert.Regexp(t, `\d+ finding\(s\) across 2 asset\(s\) \(`, text)

	assert.Equal(t, "", severitySummary(nil))
	assert.Equal(t, " (2 critical, 1 high)", severitySummary([]scanFinding{
		{Severity: "critical"}, {Severity: "high"}, {Severity: "critical"},
	}))
}

func TestSortFindings_SeverityThenResourceUnknownLast(t *testing.T) {
	fs := []finding.Finding{
		{Severity: "weird", ResourceID: "a", CheckID: "x"},
		{Severity: finding.SeverityLow, ResourceID: "b", CheckID: "x"},
		{Severity: finding.SeverityCritical, ResourceID: "z", CheckID: "x"},
		{Severity: finding.SeverityCritical, ResourceID: "a", CheckID: "y"},
		{Severity: finding.SeverityCritical, ResourceID: "a", CheckID: "x"},
	}
	sortFindings(fs)
	var got []string
	for _, f := range fs {
		got = append(got, string(f.Severity)+":"+f.ResourceID+f.CheckID)
	}
	assert.Equal(t, []string{"critical:ax", "critical:ay", "critical:zx", "low:bx", "weird:ax"}, got)
}

func TestSARIF(t *testing.T) {
	t.Run("levels", func(t *testing.T) {
		for sev, want := range map[finding.Severity]string{
			finding.SeverityCritical: "error", finding.SeverityHigh: "error", finding.SeverityMedium: "warning",
			finding.SeverityLow: "note", finding.SeverityInfo: "note",
		} {
			assert.Equal(t, want, sarifLevel(sev), sev)
		}
	})
	t.Run("results, rule dedup and partial", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, renderSARIF(&buf, scanResult{Partial: true, Findings: []scanFinding{
			{CheckID: "c1", Severity: "high", Title: "t1", ResourceID: "r1", Remediation: "fix it"},
			{CheckID: "c1", Severity: "high", Title: "t1", ResourceID: "r2"},
		}}))
		var log sarifLog
		require.NoError(t, json.Unmarshal(buf.Bytes(), &log))
		run := log.Runs[0]
		require.Len(t, run.Tool.Driver.Rules, 1, "one rule per check")
		assert.Equal(t, "fix it", run.Tool.Driver.Rules[0].Help.Text)
		require.Len(t, run.Results, 2)
		assert.NotEqual(t, run.Results[0].PartialFingerprints, run.Results[1].PartialFingerprints)
		assert.Equal(t, "r1", run.Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
		assert.Contains(t, run.Results[0].Message.Text, "r1")
		require.Len(t, run.Invocations, 1)
		assert.False(t, run.Invocations[0].ExecutionSuccessful)
		assert.NotEmpty(t, run.Invocations[0].Notifications)
	})
	t.Run("empty serialises arrays", func(t *testing.T) {
		var buf bytes.Buffer
		require.NoError(t, renderSARIF(&buf, scanResult{}))
		assert.Contains(t, buf.String(), `"rules": []`)
		assert.Contains(t, buf.String(), `"results": []`)
		assert.Contains(t, buf.String(), `"executionSuccessful": true`)
	})
}

func TestScanDataTypes_CoverEveryDataStoreCheckTarget(t *testing.T) {
	keep, err := scopeFilter(scanOptions{only: "data", provider: "azure"})
	require.NoError(t, err)
	for _, typ := range []string{"azure_storage_account", "gcp_bigquery_dataset", "redshift_cluster", "opensearch_domain",
		"docdb_cluster", "neptune_cluster", "efs_file_system", "s3_bucket", "azure_blob_container"} {
		assert.True(t, keep(finding.Finding{ResourceType: typ}), typ)
	}
	assert.False(t, keep(finding.Finding{ResourceType: "security_group"}))

	// The list must not rot: every type that is not the DSPM classifier's own
	// must be one some registered check evaluates.
	evaluated := map[string]bool{}
	for _, c := range checks.Default().All() {
		evaluated[c.AssetType] = true
	}
	for _, typ := range scanDataTypes {
		if slices.Contains(correlate.DataClassification{}.InterestedIn(), typ) {
			continue
		}
		assert.True(t, evaluated[typ], "%s is in scanDataTypes but no registered check evaluates it", typ)
	}
}

func TestAzureScanConfig_PartialServicePrincipalIsAnError(t *testing.T) {
	_, err := azureScanConfig(scanOptions{}, env(map[string]string{
		"AZURE_SUBSCRIPTION_ID": "s", "AZURE_CLIENT_ID": "c", "AZURE_CLIENT_SECRET": "x",
	}))
	require.ErrorContains(t, err, "AZURE_TENANT_ID")
	require.ErrorContains(t, err, "incomplete")
}

func TestRunScan_SeverityHidesAreCounted(t *testing.T) {
	assets := mixedAssets(t)
	got, _, err := runFake(t, collect.Result{Assets: assets}, scanOptions{severity: "critical"})
	require.NoError(t, err)
	assert.Empty(t, got.Findings)
	assert.Equal(t, 3, got.HiddenBySeverity, "the three in-scope findings are hidden, not absent")

	var out bytes.Buffer
	require.NoError(t, runScan(context.Background(), fakeCollector{res: collect.Result{Assets: assets}},
		scanOptions{provider: "aws", format: "table", severity: "critical"}, nil, time.Unix(0, 0), &out, &bytes.Buffer{}))
	assert.Contains(t, out.String(), "3 lower-severity finding(s) hidden by --severity")
}

func TestBenchmarkIDList_IsPerProvider(t *testing.T) {
	assert.Contains(t, benchmarkIDList("aws"), "cis-aws-foundations")
	assert.NotContains(t, benchmarkIDList("aws"), "cis-gke")
	assert.Equal(t, "none for this provider", benchmarkIDList("okta"))
}

func TestSARIF_RegionAndSecuritySeverity(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, renderSARIF(&buf, scanResult{Findings: []scanFinding{{CheckID: "c", Severity: "critical", Title: "t", ResourceID: "r"}}}))
	assert.Contains(t, buf.String(), `"startLine": 1`)
	assert.Contains(t, buf.String(), `"security-severity": "9.5"`)
	for sev, want := range map[finding.Severity]string{"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"} {
		assert.Equal(t, want, securitySeverity(sev))
	}
}
