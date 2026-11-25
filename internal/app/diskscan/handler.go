package diskscan

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/vulngraph/vulngraph/pkg/errs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Asset-level states of a VM's disk scan. They match the disk_scan asset
// metadata values; "none" is also what an asset nothing has read reports, and
// never means the machine is clean.
const (
	AssetScanned    = "scanned"
	AssetNotEnabled = "not_enabled"
	AssetNone       = "none"
)

// Runs and volumes are what the handler reads from the service.
type Runs interface {
	ListRuns(ctx context.Context, connectorID string, limit int) ([]DiskScanRun, error)
	AssetVolumes(ctx context.Context, assetID string) ([]VolumeResult, error)
}

// AssetStamps returns the disk_scan state the sync overlay stamped on a VM
// (AssetScanned, AssetNotEnabled or AssetNone) and its gap. It returns
// ErrNotFound for an asset that does not exist.
type AssetStamps interface {
	DiskScanStamp(ctx context.Context, assetID string) (state, gap string, err error)
}

// ConnectorInfo is a connector's disk-scan opt-in as the API shows it. Role is
// the principal's identifier (an ARN, a client id, a service account), never a
// credential.
type ConnectorInfo struct {
	ConnectorID string
	Type        string
	Mode        DiskScanMode
	Role        string
	EnabledBy   string
	EnabledAt   time.Time
	// Confirmation is the exact sentence an admin must type to enable it.
	Confirmation string
}

// Actor is who asks for an opt-in change. ViaAPIKey is true for a request an
// API key authenticated, which the connector service refuses.
type Actor struct {
	ID        string
	Admin     bool
	ViaAPIKey bool
}

// ConnectorControl reads and changes connectors' disk-scan opt-in. The adapter
// (in cmd/graph) wraps the connector service, so this package never imports it.
// SetMode reports a refusal as one of ErrNotFound, ErrInvalid, ErrForbidden,
// ErrConfirmation, ErrUnsupported, ErrRoleMissing or ErrRoleShared.
type ConnectorControl interface {
	Info(ctx context.Context, connectorID string) (ConnectorInfo, error)
	SetMode(ctx context.Context, connectorID string, mode DiskScanMode, confirmation string, actor Actor) error
}

// ActorFunc reads who is asking from the request context. It is injected
// because the auth package cannot be imported here: the connector service
// imports this package and auth's tests import the connector service.
type ActorFunc func(ctx context.Context) Actor

// Handler serves the disk-scan read API and the opt-in route.
type Handler struct {
	runs   Runs
	stamps AssetStamps
	conns  ConnectorControl
	actor  ActorFunc
}

func NewHandler(runs Runs, stamps AssetStamps, conns ConnectorControl, actor ActorFunc) *Handler {
	return &Handler{runs: runs, stamps: stamps, conns: conns, actor: actor}
}

const warningText = "Disk scanning reads your VMs' disks from cloud snapshots. Reading existing snapshots needs a read-only " +
	"snapshot permission and costs snapshot-read charges. Creating snapshots needs a separate role that can create and " +
	"delete snapshots tagged vulngraph-disk-scan; the snapshots live for hours at most and are billed to your account."

const (
	defaultRunLimit = 50
	maxRunLimit     = 200
)

type countsResponse struct {
	Volumes    int `json:"volumes"`
	Scanned    int `json:"scanned"`
	Gaps       int `json:"gaps"`
	NotEnabled int `json:"not_enabled"`
}

// RunResponse is one run as the API and MCP show it.
type RunResponse struct {
	ID          string         `json:"id"`
	ConnectorID string         `json:"connector_id"`
	Status      string         `json:"status"`
	StartedAt   time.Time      `json:"started_at"`
	FinishedAt  *time.Time     `json:"finished_at,omitempty"`
	Counts      countsResponse `json:"counts"`
}

// ToRunResponse shapes a run for the wire.
func ToRunResponse(r DiskScanRun) RunResponse {
	out := RunResponse{
		ID: r.ID, ConnectorID: r.ConnectorID, Status: string(r.Status), StartedAt: r.StartedAt,
		Counts: countsResponse{Volumes: r.Counts.Volumes, Scanned: r.Counts.Scanned, Gaps: r.Counts.Gaps, NotEnabled: r.Counts.NotEnabled},
	}
	if !r.FinishedAt.IsZero() {
		t := r.FinishedAt
		out.FinishedAt = &t
	}
	return out
}

// List serves GET /api/disk-scans.
func (h *Handler) List(w http.ResponseWriter, r *http.Request) {
	limit := defaultRunLimit
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > maxRunLimit {
			errs.WriteHTTPError(w, errs.InvalidInput("limit must be between 1 and 200"))
			return
		}
		limit = n
	}
	runs, err := h.runs.ListRuns(r.Context(), r.URL.Query().Get("connector_id"), limit)
	if err != nil {
		writeError(w, r, "list disk scan runs", err)
		return
	}
	out := make([]RunResponse, len(runs))
	for i, run := range runs {
		out[i] = ToRunResponse(run)
	}
	writeJSON(r.Context(), w, http.StatusOK, map[string]any{"runs": out})
}

type volumeResponse struct {
	VolumeRef         string    `json:"volume_ref"`
	SnapshotID        string    `json:"snapshot_id,omitempty"`
	SnapshotSource    string    `json:"snapshot_source,omitempty"`
	Encrypted         bool      `json:"encrypted"`
	InventoryKnown    bool      `json:"inventory_known"`
	CVEMatchableKnown bool      `json:"cve_matchable_known"`
	Gap               string    `json:"gap,omitempty"`
	PackageCount      int       `json:"package_count"`
	ObservedAt        time.Time `json:"observed_at"`
}

// AssetResponse is one VM's disk-scan state. State is scanned, not_enabled or
// none; none and not_enabled both mean the disk was not read, never that the
// VM is clean. Volumes is empty unless a disk scan has results to show.
type AssetResponse struct {
	AssetID string           `json:"asset_id"`
	State   string           `json:"state"`
	Gap     string           `json:"gap,omitempty"`
	Volumes []volumeResponse `json:"volumes"`
}

// BuildAsset assembles an asset's response. A connector that is not enabled
// hides stored volumes, as the sync overlay does: switching the feature off
// hides what it found.
func BuildAsset(assetID, state, gap string, vols []VolumeResult) AssetResponse {
	switch state {
	case AssetScanned, AssetNotEnabled:
	default:
		state = AssetNone
	}
	out := AssetResponse{AssetID: assetID, State: state, Gap: gap, Volumes: []volumeResponse{}}
	if state == AssetNotEnabled {
		return out
	}
	for _, v := range vols {
		out.Volumes = append(out.Volumes, volumeResponse{
			VolumeRef: v.VolumeRef, SnapshotID: v.SnapshotID, SnapshotSource: string(v.SnapshotSource),
			Encrypted: v.Encrypted, InventoryKnown: v.InventoryKnown, CVEMatchableKnown: v.CVEMatchableKnown,
			Gap: v.Gap, PackageCount: v.PackageCount, ObservedAt: v.ObservedAt,
		})
	}
	return out
}

// GetAsset serves GET /api/assets/{id}/disk-scan.
func (h *Handler) GetAsset(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	state, gap, err := h.stamps.DiskScanStamp(r.Context(), id)
	if err != nil {
		writeError(w, r, "read asset disk scan state", err)
		return
	}
	vols, err := h.runs.AssetVolumes(r.Context(), id)
	if err != nil {
		writeError(w, r, "read asset disk scan volumes", err)
		return
	}
	writeJSON(r.Context(), w, http.StatusOK, BuildAsset(id, state, gap, vols))
}

// ModesFor lists the modes a connector type can be set to. GCP can read
// existing snapshots only; creating one is not available there yet.
func ModesFor(connectorType string) []DiskScanMode {
	if connectorType == "gcp" {
		return []DiskScanMode{DiskScanModeOff, DiskScanModeExistingSnapshots}
	}
	return []DiskScanMode{DiskScanModeOff, DiskScanModeExistingSnapshots, DiskScanModeCreateSnapshots}
}

// modeName is the wire name of a mode; off is "off", not the empty string.
func modeName(m DiskScanMode) string {
	if m == DiskScanModeOff {
		return "off"
	}
	return string(m)
}

func parseMode(s string) (DiskScanMode, bool) {
	if s == "off" {
		return DiskScanModeOff, true
	}
	m := DiskScanMode(s)
	return m, m != DiskScanModeOff && m.Valid()
}

type connectorResponse struct {
	ConnectorID  string       `json:"connector_id"`
	Type         string       `json:"type"`
	Mode         string       `json:"mode"`
	Modes        []string     `json:"modes"`
	Role         string       `json:"role,omitempty"`
	EnabledBy    string       `json:"enabled_by,omitempty"`
	EnabledAt    *time.Time   `json:"enabled_at,omitempty"`
	LastRun      *RunResponse `json:"last_run,omitempty"`
	Confirmation string       `json:"confirmation"`
	Warning      string       `json:"warning"`
}

// GetConnector serves GET /api/connectors/{id}/disk-scan.
func (h *Handler) GetConnector(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	info, err := h.conns.Info(r.Context(), id)
	if err != nil {
		writeError(w, r, "read connector disk scan", err)
		return
	}
	runs, err := h.runs.ListRuns(r.Context(), id, 1)
	if err != nil {
		writeError(w, r, "read connector disk scan runs", err)
		return
	}
	modes := ModesFor(info.Type)
	resp := connectorResponse{
		ConnectorID: info.ConnectorID, Type: info.Type, Mode: modeName(info.Mode), Modes: make([]string, len(modes)),
		Role: info.Role, EnabledBy: info.EnabledBy, Confirmation: info.Confirmation, Warning: warningText,
	}
	for i, m := range modes {
		resp.Modes[i] = modeName(m)
	}
	if !info.EnabledAt.IsZero() {
		t := info.EnabledAt
		resp.EnabledAt = &t
	}
	if len(runs) > 0 {
		lr := ToRunResponse(runs[0])
		resp.LastRun = &lr
	}
	writeJSON(r.Context(), w, http.StatusOK, resp)
}

type setRequest struct {
	Mode         string `json:"mode"`
	Confirmation string `json:"confirmation"`
}

// SetConnector serves PUT /api/connectors/{id}/disk-scan. The router gates it
// to an admin session; the connector service refuses an API-key actor again.
func (h *Handler) SetConnector(w http.ResponseWriter, r *http.Request) {
	var req setRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		errs.WriteHTTPError(w, errs.InvalidInput("request body must be JSON"))
		return
	}
	mode, ok := parseMode(req.Mode)
	if !ok {
		errs.WriteHTTPError(w, errs.InvalidInput(`mode must be "off", "existing_snapshots" or "create_snapshots"`))
		return
	}
	id := r.PathValue("id")
	info, err := h.conns.Info(r.Context(), id)
	if err != nil {
		writeError(w, r, "read connector disk scan", err)
		return
	}
	if !modeAllowed(info.Type, mode) {
		errs.WriteHTTPError(w, errs.Conflict("this connector type cannot use that disk scan mode yet"))
		return
	}
	if err := h.conns.SetMode(r.Context(), id, mode, req.Confirmation, h.actor(r.Context())); err != nil {
		writeError(w, r, "set connector disk scan", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func modeAllowed(connectorType string, m DiskScanMode) bool {
	for _, allowed := range ModesFor(connectorType) {
		if allowed == m {
			return true
		}
	}
	return false
}

func writeError(w http.ResponseWriter, r *http.Request, what string, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		errs.WriteHTTPError(w, errs.NotFound("not found"))
	case errors.Is(err, ErrForbidden):
		errs.WriteHTTPError(w, errs.Forbidden("disk scanning can be changed only by an admin signed in as a person"))
	case errors.Is(err, ErrConfirmation):
		errs.WriteHTTPError(w, errs.InvalidInput("the typed confirmation does not match the required sentence"))
	case errors.Is(err, ErrInvalid):
		errs.WriteHTTPError(w, errs.InvalidInput("invalid disk scan mode"))
	case errors.Is(err, ErrUnsupported):
		errs.WriteHTTPError(w, errs.Conflict("disk scanning is not supported for this connector type"))
	case errors.Is(err, ErrRoleMissing):
		errs.WriteHTTPError(w, errs.Conflict("creating snapshots needs the dedicated disk scan role set on the connector"))
	case errors.Is(err, ErrRoleShared):
		errs.WriteHTTPError(w, errs.Conflict("the disk scan role must differ from the collection, read-only and execute roles"))
	default:
		log.FromContext(r.Context()).Error().Err(err).Msg(what + " failed")
		errs.WriteHTTPError(w, errs.Internal("failed to "+what))
	}
}

func writeJSON(ctx context.Context, w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.FromContext(ctx).Error().Err(err).Msg("write response failed")
	}
}
