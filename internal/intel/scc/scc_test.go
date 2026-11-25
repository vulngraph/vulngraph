package scc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	securitycenter "google.golang.org/api/securitycenter/v1"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

var sccNow = time.Date(2026, 6, 14, 12, 0, 0, 0, time.UTC)

func TestMapSCCFinding_LinksComputeInstance(t *testing.T) {
	f := mapSCCFinding(&securitycenter.Finding{
		Name:         "organizations/246802468024/sources/123/findings/abc",
		Category:     "Malware: Malicious file on disk (YARA)",
		Severity:     "MEDIUM",
		ResourceName: "//compute.googleapis.com/projects/example-prod/zones/europe-west4-a/instances/web-1",
	}, sccNow)

	require.Equal(t, "gcp_scc", f.Source)
	require.Equal(t, "threat", f.Type)
	require.Equal(t, finding.SeverityMedium, f.Severity)
	require.Equal(t, "Malware: Malicious file on disk (YARA)", f.CheckID)
	require.Equal(t, "example-prod/web-1", f.ResourceID, "links to the gce_instance asset id")
	require.Equal(t, "gce_instance", f.ResourceType)
	require.NotEmpty(t, f.ID)

	// Deterministic on the SCC finding name.
	again := mapSCCFinding(&securitycenter.Finding{
		Name: "organizations/246802468024/sources/123/findings/abc", Category: "x",
	}, sccNow)
	require.Equal(t, f.ID, again.ID)
}

func TestSCCSeverity(t *testing.T) {
	require.Equal(t, finding.SeverityHigh, sccSeverity("CRITICAL"))
	require.Equal(t, finding.SeverityHigh, sccSeverity("HIGH"))
	require.Equal(t, finding.SeverityMedium, sccSeverity("MEDIUM"))
	require.Equal(t, finding.SeverityLow, sccSeverity("LOW"))
	require.Equal(t, finding.SeverityMedium, sccSeverity(""), "unknown defaults to medium")
}

func TestParseSCCResource(t *testing.T) {
	id, typ := parseSCCResource("//compute.googleapis.com/projects/p/zones/z/instances/n")
	require.Equal(t, "p/n", id)
	require.Equal(t, "gce_instance", typ)

	// Non-instance resource falls back to the raw name, no asset type.
	id, typ = parseSCCResource("//storage.googleapis.com/projects/p/buckets/b")
	require.Equal(t, "//storage.googleapis.com/projects/p/buckets/b", id)
	require.Empty(t, typ)

	id, typ = parseSCCResource("")
	require.Empty(t, id)
	require.Empty(t, typ)
}
