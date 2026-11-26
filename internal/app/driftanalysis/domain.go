// Package driftanalysis asks an LLM agent whether a batch of inventory changes
// on one connector changes exposure and whether a scan is worth running. The
// verdict is advisory: no code path turns it into a scan. domain.go is pure:
// no infrastructure imports.
package driftanalysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"
)

// MaxBatchAssets caps one batch; a larger change set sets Batch.Truncated.
const MaxBatchAssets = 200

// Batch status.
const (
	StatusPending  = "pending"
	StatusAnalysed = "analysed"
	StatusUnknown  = "unknown"
	// StatusBaseline marks a connector's first batch: it only sets the
	// watermark and is never sent to the model.
	StatusBaseline = "baseline"
)

// Why a batch is unknown. Budget and LLMError are transient and retried;
// Ungrounded and NoChanges are not.
const (
	ReasonBudget     = "budget"
	ReasonLLMError   = "llm_error"
	ReasonUngrounded = "ungrounded"
	ReasonNoChanges  = "no_changes"
)

// Exposure judgement values.
const (
	ExposureIncreased = "increased"
	ExposureDecreased = "decreased"
	ExposureUnchanged = "unchanged"
	ExposureUnknown   = "unknown"
)

// Confidence values.
const (
	ConfidenceLow    = "low"
	ConfidenceMedium = "medium"
	ConfidenceHigh   = "high"
)

// Scan recommendation, derived from ScanRecommended and ScanRecommendedKnown.
const (
	RecommendationRecommended = "recommended"
	RecommendationNotNeeded   = "not_needed"
	RecommendationUnknown     = "unknown"
)

// Evidence sources: what a Ref points at.
const (
	EvidenceAsset   = "asset"
	EvidenceProfile = "profile"
)

// Change kinds.
const (
	KindNewAsset        = "new_asset"
	KindNewExposure     = "new_exposure"
	KindRemovedExposure = "removed_exposure"
	KindChanged         = "changed"
)

var (
	ErrNotFound = errors.New("driftanalysis: not found")
	// ErrDisabled is returned when no analyst is configured.
	ErrDisabled = errors.New("driftanalysis: disabled")
	// ErrUngrounded: the analyst's reply cited nothing it was shown, or could
	// not be parsed. The batch becomes unknown, never a verdict.
	ErrUngrounded = errors.New("driftanalysis: verdict is not grounded in the batch")
)

// Tx is the storage transaction a repo hands to an EnqueueFunc. The jobs
// package asserts it to its driver's transaction type.
type Tx any

// EnqueueFunc runs inside the transaction that inserts a batch row, so the
// batch and its analyse job commit together or not at all.
type EnqueueFunc func(ctx context.Context, tx Tx, b Batch) error

// Batch is one connector's inventory changes between two watermarks.
type Batch struct {
	ID          string
	ConnectorID string
	WindowStart time.Time
	WindowEnd   time.Time
	AssetIDs    []string
	// Truncated: more assets changed than MaxBatchAssets; the rest were not
	// analysed.
	Truncated     bool
	Status        string
	Attempts      int
	UnknownReason string
	// Verdict is the zero value unless Status is analysed.
	Verdict    Verdict
	CreatedAt  time.Time
	AnalysedAt time.Time
}

// BatchID is deterministic in the connector and the newest change in the
// batch, so discovering the same window twice yields the same row.
func BatchID(connectorID string, windowEnd time.Time) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d", connectorID, windowEnd.UTC().UnixMicro())))
	return hex.EncodeToString(sum[:])
}

// ChangeItem is one asset-level observation in a verdict.
type ChangeItem struct {
	Kind    string `json:"kind"`
	AssetID string `json:"asset_id"`
	Note    string `json:"note"`
}

// EvidenceRef cites something the model was shown: an asset id or a profile id.
type EvidenceRef struct {
	Source string `json:"source"`
	Ref    string `json:"ref"`
	Fact   string `json:"fact"`
}

// Verdict is the agent's advisory read of a batch. The zero value says
// nothing: ScanRecommended is only meaningful when ScanRecommendedKnown.
type Verdict struct {
	Summary           string       `json:"summary"`
	Changes           []ChangeItem `json:"changes"`
	ExposureJudgement string       `json:"exposure_judgement"`
	ScanRecommended   bool         `json:"scan_recommended"`
	// ScanRecommendedKnown false means unknown, not "no scan needed".
	ScanRecommendedKnown bool          `json:"scan_recommended_known"`
	Reason               string        `json:"reason"`
	Confidence           string        `json:"confidence"`
	Evidence             []EvidenceRef `json:"evidence"`
	Model                string        `json:"model"`
	AnalysedAt           time.Time     `json:"analysed_at"`
}

// Recommendation maps the bool and its Known flag to the three-state value
// consumers show. Unknown is its own state.
func (v Verdict) Recommendation() string {
	switch {
	case !v.ScanRecommendedKnown:
		return RecommendationUnknown
	case v.ScanRecommended:
		return RecommendationRecommended
	default:
		return RecommendationNotNeeded
	}
}

// AssetChange is what changed on one asset, read from the sync's hash table.
type AssetChange struct {
	AssetID    string
	Name       string
	AssetType  string
	Region     string
	PublicIP   string
	Kind       string
	Field      string
	OldValue   string
	NewValue   string
	DetectedAt time.Time
}

// AssetFact is what the platform measured about one changed asset. It is only
// meaningful when the matching Facts.*Known flag is true.
type AssetFact struct {
	AssetID        string
	InternetFacing bool
	OpenFindings   int
	MaxScore       int
}

// Facts are deterministic inputs gathered by the platform, not the model. A
// false Known flag means that lookup failed and the matching data is absent,
// not empty.
type Facts struct {
	ExposureKnown bool
	FindingsKnown bool
	Assets        []AssetFact
	// ExternalChangedIDs are changed assets that gained or have a public IP.
	ExternalChangedIDs []string
}

// AnalysisInput is everything the analyst may see and cite.
type AnalysisInput struct {
	Batch   Batch
	Changes []AssetChange
	Facts   Facts
}

// ExternalChanged lists the changed assets that gained or hold a public IP.
func ExternalChanged(changes []AssetChange) []string {
	var ids []string
	for _, c := range changes {
		if c.Kind == KindNewExposure || (c.Kind == KindNewAsset && c.PublicIP != "") {
			ids = append(ids, c.AssetID)
		}
	}
	return ids
}

// allKnown reports whether every lookup behind a "no scan needed" answer
// succeeded and the whole batch was read.
func (in AnalysisInput) allKnown() bool {
	f := in.Facts
	return f.ExposureKnown && f.FindingsKnown && !in.Batch.Truncated
}

// Gate is the deterministic check on a model verdict; the model is never
// trusted. Evidence must cite an asset id the model was shown, and at least
// one citation must survive, else ErrUngrounded. "No scan needed" survives
// only when every fact is known and the batch was not truncated; otherwise it
// becomes unknown. A "yes" is always allowed. Confidence drops to low
// whenever a fact is missing.
func Gate(v Verdict, in AnalysisInput) (Verdict, error) {
	assets := make(map[string]bool, len(in.Changes))
	for _, c := range in.Changes {
		assets[c.AssetID] = true
	}

	var evidence []EvidenceRef
	for _, e := range v.Evidence {
		known := e.Source == EvidenceAsset && assets[e.Ref]
		if known && e.Fact != "" {
			evidence = append(evidence, e)
		}
	}
	if len(evidence) == 0 {
		return Verdict{}, ErrUngrounded
	}
	v.Evidence = evidence

	var changes []ChangeItem
	for _, c := range v.Changes {
		if assets[c.AssetID] {
			changes = append(changes, c)
		}
	}
	v.Changes = changes

	if !slices.Contains([]string{ExposureIncreased, ExposureDecreased, ExposureUnchanged}, v.ExposureJudgement) || !in.Facts.ExposureKnown {
		v.ExposureJudgement = ExposureUnknown
	}

	if v.ScanRecommendedKnown && !v.ScanRecommended && !in.allKnown() {
		v.ScanRecommended, v.ScanRecommendedKnown = false, false
	}
	if !v.ScanRecommendedKnown {
		v.ScanRecommended = false
	}

	if !in.allKnown() || !slices.Contains([]string{ConfidenceLow, ConfidenceMedium, ConfidenceHigh}, v.Confidence) {
		v.Confidence = ConfidenceLow
	}
	return v, nil
}
