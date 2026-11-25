package scan

import (
	"encoding/json"
	"net/http"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// importRequest is the JSON body for POST /api/scans/import.
type importRequest struct {
	// Source is the external scanner slug: "openvas", "qualys", "burp", "custom".
	Source string `json:"source"`
	// SourceRef is the scan ID in the external system (opaque; stored for traceability).
	SourceRef string `json:"source_ref"`
	// AssetID is the graph asset ID this import is attributed to.
	// Takes precedence over AssetIP when both are present.
	AssetID string `json:"asset_id"`
	// AssetIP is the public IP address used for best-effort asset attribution
	// when AssetID is not known.
	AssetIP  string          `json:"asset_ip"`
	Findings []importFinding `json:"findings"`
}

// importFinding is one finding entry in the import body.
type importFinding struct {
	CheckID     string `json:"check_id"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	// Reference is a URL or advisory identifier (CVE, NVD, vendor bulletin).
	Reference string `json:"reference"`
	// MatchedAt is the URL or location description where the issue was observed.
	MatchedAt string `json:"matched_at"`
}

type importResponse struct {
	ScanID       string `json:"scan_id"`
	FindingCount int    `json:"finding_count"`
}

// ImportFindings creates a synthetic completed scan run from externally
// supplied findings (OpenVAS, Qualys, Burp, custom). Admin-only.
// Route: POST /api/scans/import
func (h *Handler) ImportFindings(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req importRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("request body must be valid JSON"))
		return
	}

	if req.Source == "" {
		errs.WriteHTTPError(w, errs.InvalidInput("source is required"))
		return
	}
	if !validImportSources[req.Source] {
		errs.WriteHTTPError(w, errs.InvalidInput("source must be one of: openvas, qualys, burp, custom"))
		return
	}
	if len(req.Findings) == 0 {
		errs.WriteHTTPError(w, errs.InvalidInput("findings must not be empty"))
		return
	}

	svcReq := toServiceImportRequest(req)
	run, err := h.svc.ImportFindings(ctx, svcReq)
	if err != nil {
		log.FromContext(ctx).Error().Err(err).Str("source", req.Source).Msg("import findings failed")
		errs.WriteHTTPError(w, errs.Internal("failed to import findings"))
		return
	}

	writeJSON(ctx, w, http.StatusCreated, importResponse{
		ScanID:       run.ID,
		FindingCount: run.FindingCount,
	})
}

func toServiceImportRequest(req importRequest) ImportRequest {
	findings := make([]ImportFinding, len(req.Findings))
	for i, f := range req.Findings {
		findings[i] = ImportFinding(f)
	}
	return ImportRequest{
		Source:    req.Source,
		SourceRef: req.SourceRef,
		AssetID:   req.AssetID,
		AssetIP:   req.AssetIP,
		Findings:  findings,
	}
}
