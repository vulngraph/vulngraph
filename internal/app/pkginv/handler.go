package pkginv

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Submitter is the service surface the handler and the MCP tool call.
type Submitter interface {
	Submit(ctx context.Context, p Principal, pathAssetID string, req Request) (InventoryRecord, error)
}

// Handler serves PUT /api/assets/{id}/package-inventory and
// PUT /api/package-inventory.
type Handler struct {
	svc Submitter
}

func NewHandler(svc Submitter) *Handler { return &Handler{svc: svc} }

// rateLimitRetrySeconds is the Retry-After for a key over its per-asset budget
// (60 requests an hour refills one slot a minute).
const rateLimitRetrySeconds = 60

type scannerResponse struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// SubmitResponse is what a submission returns, over REST and MCP alike.
type SubmitResponse struct {
	Accepted          bool            `json:"accepted"`
	AssetID           string          `json:"asset_id"`
	Source            string          `json:"source"`
	Scanner           scannerResponse `json:"scanner"`
	ObservedAt        time.Time       `json:"observed_at"`
	Complete          bool            `json:"complete"`
	PackageCount      int             `json:"package_count"`
	InventoryKnown    bool            `json:"inventory_known"`
	CVEMatchableKnown bool            `json:"cve_matchable_known"`
	Gap               string          `json:"gap"`
}

// ToResponse shapes a stored claim for the wire.
func ToResponse(r InventoryRecord) SubmitResponse {
	return SubmitResponse{
		Accepted: true, AssetID: r.AssetID, Source: r.Source,
		Scanner:    scannerResponse{Name: r.Scanner.Name, Version: r.Scanner.Version},
		ObservedAt: r.ObservedAt, Complete: r.Complete, PackageCount: r.PackageCount,
		InventoryKnown: r.InventoryKnown, CVEMatchableKnown: r.CVEMatchableKnown, Gap: r.Gap,
	}
}

// PrincipalFromContext reads the API key RequireAuth attached. A session user
// yields a zero Principal, which MaySubmit refuses.
func PrincipalFromContext(ctx context.Context) Principal {
	k, ok := auth.APIKeyFromContext(ctx)
	if !ok {
		return Principal{}
	}
	return Principal{KeyID: k.ID, Scope: k.Scope, OwnerRole: string(k.OwnerRole)}
}

// PutForAsset replaces the calling key's inventory for the asset in the path.
func (h *Handler) PutForAsset(w http.ResponseWriter, r *http.Request) {
	h.put(w, r, r.PathValue("id"))
}

// Put replaces the calling key's inventory for the asset the body names by
// cloud_resource_id (or asset_id).
func (h *Handler) Put(w http.ResponseWriter, r *http.Request) {
	h.put(w, r, "")
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request, pathAssetID string) {
	p := PrincipalFromContext(r.Context())
	if !p.MaySubmit() {
		// The refusal is audited by the service; the body is never read.
		_, err := h.svc.Submit(r.Context(), p, pathAssetID, Request{})
		writeError(w, r, err)
		return
	}
	req, err := DecodeRequest(r.Body)
	if err != nil {
		writeError(w, r, err)
		return
	}
	rec, err := h.svc.Submit(r.Context(), p, pathAssetID, req)
	if err != nil {
		writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(ToResponse(rec)); err != nil {
		log.FromContext(r.Context()).Error().Err(err).Msg("write response failed")
	}
}

// writeError maps a domain error onto its RFC 9457 response.
func writeError(w http.ResponseWriter, r *http.Request, err error) {
	var tooBig *http.MaxBytesError
	switch {
	case errors.As(err, &tooBig):
		errs.WriteHTTPErrorCtx(r.Context(), w, "request body exceeds the package-inventory limit", http.StatusRequestEntityTooLarge)
	case errors.Is(err, ErrForbidden):
		errs.WriteHTTPError(w, errs.Forbidden("an inventory-scoped API key is required"))
	case errors.Is(err, ErrInvalid):
		errs.WriteHTTPError(w, errs.InvalidInput(strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": ")))
	case errors.Is(err, ErrAssetNotFound):
		errs.WriteHTTPError(w, errs.NotFound("no live VM asset with that identifier"))
	case errors.Is(err, ErrStale):
		errs.WriteHTTPError(w, errs.Conflict("a newer inventory from this source is already stored"))
	case errors.Is(err, ErrRateLimited):
		errs.WriteHTTPRateLimitError(r.Context(), w, rateLimitRetrySeconds)
	default:
		log.FromContext(r.Context()).Error().Err(err).Msg("package inventory submit failed")
		errs.WriteHTTPError(w, errs.Internal("failed to record package inventory"))
	}
}
