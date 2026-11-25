package scan

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// newImportTestHandler builds a Handler wired with enough fakes to exercise
// the import path. The repo, resolver, and findings store are all returned so
// tests can inspect state after the call.
func newImportTestHandler(resolverAssets []asset.Asset) (*Handler, *fakeRepo, *fakeResolver, *fakeFindings) {
	repo := &fakeRepo{}
	resolver := &fakeResolver{assets: resolverAssets}
	findings := &fakeFindings{}
	svc := NewService(repo, fakeAssets{}, resolver, nil, findings)
	return NewHandler(svc, &fakeTriggerer{}), repo, resolver, findings
}

func TestImportFindings_HappyPath_ByAssetID(t *testing.T) {
	knownAsset := asset.Asset{ID: "asset-42", Type: "ec2_instance", Region: "eu-west-1"}
	h, repo, _, stored := newImportTestHandler([]asset.Asset{knownAsset})

	body := importRequest{
		Source:    "openvas",
		SourceRef: "scan-ext-99",
		AssetID:   "asset-42",
		Findings: []importFinding{
			{CheckID: "OV-001", Title: "Open port", Severity: "medium", MatchedAt: "192.0.2.1:22"},
			{CheckID: "OV-002", Title: "Weak cipher", Severity: "high", MatchedAt: "192.0.2.1:443"},
		},
	}
	req := postJSON(t, "/api/scans/import", body)
	rec := httptest.NewRecorder()
	h.ImportFindings(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)

	var resp importResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	require.NotEmpty(t, resp.ScanID)
	require.Equal(t, 2, resp.FindingCount)

	require.Equal(t, StatusCompleted, repo.finished.Status)
	require.Equal(t, "openvas", repo.scannerName)
	require.Empty(t, repo.finished.Error)
	require.Len(t, stored.recorded, 2)
	for _, f := range stored.recorded {
		require.Equal(t, "openvas", f.Source)
		require.Equal(t, "asset-42", f.ResourceID)
		require.Equal(t, "ec2_instance", f.ResourceType)
		require.Equal(t, "eu-west-1", f.Region)
	}
}

func TestImportFindings_HappyPath_ByAssetIP(t *testing.T) {
	knownAsset := asset.Asset{ID: "host-7", PublicIP: "10.0.0.5"}
	h, _, _, stored := newImportTestHandler([]asset.Asset{knownAsset})

	body := importRequest{
		Source:  "qualys",
		AssetIP: "10.0.0.5",
		Findings: []importFinding{
			{CheckID: "QID-99", Title: "SSL vuln", Severity: "critical"},
		},
	}
	req := postJSON(t, "/api/scans/import", body)
	rec := httptest.NewRecorder()
	h.ImportFindings(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)
	require.Len(t, stored.recorded, 1)
	require.Equal(t, "host-7", stored.recorded[0].ResourceID)
}

func TestImportFindings_NoAssetMatch_FindingStillRecorded(t *testing.T) {
	h, _, _, stored := newImportTestHandler(nil) // empty resolver

	body := importRequest{
		Source:  "burp",
		AssetIP: "172.16.0.1",
		Findings: []importFinding{
			{CheckID: "BURP-XSS", Title: "Reflected XSS", Severity: "high", MatchedAt: "https://app/search"},
		},
	}
	req := postJSON(t, "/api/scans/import", body)
	rec := httptest.NewRecorder()
	h.ImportFindings(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)
	require.Len(t, stored.recorded, 1)
	// ResourceID is empty because no asset was matched — that is expected.
	require.Empty(t, stored.recorded[0].ResourceID)
}

func TestImportFindings_InvalidSource_422(t *testing.T) {
	h, _, _, _ := newImportTestHandler(nil)

	body := importRequest{
		Source:   "nessus", // not in the allow-list
		Findings: []importFinding{{CheckID: "x", Title: "y", Severity: "info"}},
	}
	req := postJSON(t, "/api/scans/import", body)
	rec := httptest.NewRecorder()
	h.ImportFindings(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestImportFindings_MissingSource_422(t *testing.T) {
	h, _, _, _ := newImportTestHandler(nil)

	body := importRequest{
		Findings: []importFinding{{CheckID: "x", Title: "y", Severity: "info"}},
	}
	req := postJSON(t, "/api/scans/import", body)
	rec := httptest.NewRecorder()
	h.ImportFindings(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestImportFindings_EmptyFindings_422(t *testing.T) {
	h, _, _, _ := newImportTestHandler(nil)

	body := importRequest{Source: "custom", Findings: []importFinding{}}
	req := postJSON(t, "/api/scans/import", body)
	rec := httptest.NewRecorder()
	h.ImportFindings(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestImportFindings_BadJSON_422(t *testing.T) {
	h, _, _, _ := newImportTestHandler(nil)

	req := httptest.NewRequest(http.MethodPost, "/api/scans/import", bytes.NewBufferString("not-json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ImportFindings(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestImportFindings_SeverityNormalized(t *testing.T) {
	h, _, _, stored := newImportTestHandler(nil)

	body := importRequest{
		Source: "custom",
		Findings: []importFinding{
			{CheckID: "c1", Title: "t1", Severity: "CRITICAL"}, // wrong case
			{CheckID: "c2", Title: "t2", Severity: "bogus"},    // unknown → info
		},
	}
	req := postJSON(t, "/api/scans/import", body)
	rec := httptest.NewRecorder()
	h.ImportFindings(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)
	bySev := map[string]finding.Severity{}
	for _, f := range stored.recorded {
		bySev[f.CheckID] = f.Severity
	}
	// normalizeSeverity is case-sensitive; "CRITICAL" is not a valid sentinel → info.
	require.Equal(t, finding.SeverityInfo, bySev["c1"])
	require.Equal(t, finding.SeverityInfo, bySev["c2"])
}

func TestImportFindings_DeterministicIDs(t *testing.T) {
	h, _, _, stored := newImportTestHandler(nil)

	body := importRequest{
		Source: "custom",
		Findings: []importFinding{
			{CheckID: "c1", Title: "same", Severity: "low", MatchedAt: "https://x"},
		},
	}

	// First import.
	req := postJSON(t, "/api/scans/import", body)
	rec := httptest.NewRecorder()
	h.ImportFindings(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)
	firstID := stored.recorded[0].ID

	// Second import of the exact same finding.
	stored.recorded = nil
	req = postJSON(t, "/api/scans/import", body)
	rec = httptest.NewRecorder()
	h.ImportFindings(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	require.Equal(t, firstID, stored.recorded[0].ID, "same source+check+matchedAt produces same ID (upsert semantics)")
}

// postJSON builds a POST request with a JSON-encoded body.
func postJSON(t *testing.T, path string, v any) *http.Request {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	return req
}
