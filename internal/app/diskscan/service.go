package diskscan

// Service contract for the other disk-scan chunks (jobs, sync overlay, API).
//
// Runs
//
//	StartRun(ctx, connectorID) (DiskScanRun, error)
//	    Opens a run. A connector whose mode is off yields a persisted run with
//	    Status not_enabled and a nil error: "not enabled" is a state, not a
//	    failure, and callers MUST check run.Status before planning volumes.
//	RecordResult(ctx, runID, DiskScanTarget, VolumeResult) error
//	    Idempotent per (run, asset, volume). Refuses a result that would read as
//	    clean for a disk that was not read: InventoryKnown=false needs a valid
//	    Gap, no package count and no CVE-matchable claim; InventoryKnown=true
//	    must carry no Gap.
//	FinishRun(ctx, runID, planned int, runErr error) (DiskScanRun, error)
//	    Derives the counts and the status from the stored volume rows;
//	    volumes that never recorded a result leave the run partial.
//	GetRun / ListRuns(ctx, connectorID, limit) / ListVolumes(ctx, runID)
//
// Reading
//
//	Latest(ctx, assetIDs) (map[string]VolumeResult, error)
//	    The sync overlay's reader: per asset, its boot volume's newest result
//	    (else its newest). An asset with no result is absent from the map and
//	    must be read as unknown. A newer failed scan supersedes an older good
//	    one, so a disk that stopped being readable never keeps a stale inventory.
//
// Connectors
//
//	EnabledConnectors(ctx) ([]ConnectorSettings, error)
//	Grant(ctx, connectorID) (engine.ConnectorGrant, error)
//	    The input to engine.Authorize; no OptIn is minted here.
//
// Snapshot registry (the sweeper's source)
//
//	RegisterSnapshotIntent(ctx, SnapshotIntent) (SnapshotIntent, error)
//	    Written BEFORE any create call. Keyed by (run, volume): a retried job
//	    gets its existing row back. A row with an empty SnapshotID means the
//	    create may or may not have happened, so look for the run's tagged
//	    snapshot before creating another.
//	AttachSnapshot(ctx, intentID, snapshotID) error
//	MarkDeleted(ctx, intentID) error            // also for an intent whose create failed for certain
//	MarkDeletedBySnapshot(ctx, provider, snapshotID) error
//	ListOrphans(ctx) ([]SnapshotIntent, error)  // undeleted and past their delete-after time
//
// Cache
//
//	CacheGet(ctx, provider, snapshotID) (CacheEntry, bool, error)
//	CachePut(ctx, CacheEntry) error
//	    Expired entries read as a miss. ExpiresAt bounds negative entries (a
//	    permission denial is cached for 24h under a caller-chosen key).

import (
	"context"
	"fmt"
	"slices"
	"time"

	engine "github.com/vulngraph/vulngraph/internal/scanner/diskscan"
)

const (
	// DefaultSnapshotTTL is how long a snapshot the scanner created may live
	// before the sweeper deletes it.
	DefaultSnapshotTTL = 6 * time.Hour

	orphanBatch = 500
	maxListRuns = 200
)

// ConnectorSettings is a connector's disk-scan opt-in as the service needs it.
// Role and OtherRoles are identifiers, never secrets.
type ConnectorSettings struct {
	ConnectorID string
	Type        string
	Mode        DiskScanMode
	Role        string
	OtherRoles  []string
}

// ConnectorSource reads connector opt-ins. The connector service is adapted to
// it where the services are wired.
type ConnectorSource interface {
	DiskScanSettings(ctx context.Context, connectorID string) (ConnectorSettings, error)
	DiskScanEnabled(ctx context.Context) ([]ConnectorSettings, error)
}

// SnapshotIntent is a registry row for a snapshot the scanner is about to
// create or has created. SnapshotID is empty until the provider answers.
type SnapshotIntent struct {
	ID          string
	RunID       string
	ConnectorID string
	Provider    string
	Region      string
	VolumeRef   string
	SnapshotID  string
	CreatedAt   time.Time
	DeleteAfter time.Time
	DeletedAt   time.Time // zero while the snapshot may still exist
}

// CacheEntry is a stored scan result for one snapshot. Result carries only the
// outcome fields (Encrypted, InventoryKnown, CVEMatchableKnown, Gap,
// PackageCount); Extents are the disk ranges the scan read.
type CacheEntry struct {
	Provider   string
	SnapshotID string
	Digest     string
	Extents    []engine.Extent
	Result     VolumeResult
	CachedAt   time.Time
	ExpiresAt  time.Time // zero: no expiry
}

// Repository is the storage the service needs.
type Repository interface {
	InsertRun(ctx context.Context, run DiskScanRun) (DiskScanRun, error)
	GetRun(ctx context.Context, id string) (DiskScanRun, error)
	ListRuns(ctx context.Context, connectorID string, limit int) ([]DiskScanRun, error)
	FinishRun(ctx context.Context, run DiskScanRun) error
	CountVolumes(ctx context.Context, runID string) (RunCounts, error)
	UpsertVolume(ctx context.Context, boot bool, res VolumeResult) error
	LatestVolumes(ctx context.Context, assetIDs []string) ([]VolumeResult, error)
	ListVolumes(ctx context.Context, runID string) ([]VolumeResult, error)

	InsertIntent(ctx context.Context, in SnapshotIntent) error
	GetIntent(ctx context.Context, runID, volumeRef string) (SnapshotIntent, error)
	AttachSnapshot(ctx context.Context, intentID, snapshotID string) error
	MarkDeleted(ctx context.Context, intentID string, at time.Time) error
	MarkDeletedBySnapshot(ctx context.Context, provider, snapshotID string, at time.Time) error
	ListOrphans(ctx context.Context, now time.Time, limit int) ([]SnapshotIntent, error)

	GetCache(ctx context.Context, provider, snapshotID string, now time.Time) (CacheEntry, bool, error)
	PutCache(ctx context.Context, e CacheEntry) error
}

// Service holds disk-scan orchestration state: runs, per-volume results, the
// snapshot registry and the result cache. It never calls a cloud API.
type Service struct {
	repo  Repository
	conns ConnectorSource
	now   func() time.Time
	ttl   time.Duration
}

func NewService(repo Repository, conns ConnectorSource) *Service {
	return &Service{repo: repo, conns: conns, now: time.Now, ttl: DefaultSnapshotTTL}
}

// WithClock replaces the clock; tests and the sweeper inject one.
func (s *Service) WithClock(now func() time.Time) *Service {
	s.now = now
	return s
}

// WithSnapshotTTL sets how long a created snapshot may live.
func (s *Service) WithSnapshotTTL(d time.Duration) *Service {
	s.ttl = d
	return s
}

func (s *Service) utcNow() time.Time { return s.now().UTC() }

// StartRun opens a run for a connector. See the contract above for the
// not_enabled case.
func (s *Service) StartRun(ctx context.Context, connectorID string) (DiskScanRun, error) {
	set, err := s.conns.DiskScanSettings(ctx, connectorID)
	if err != nil {
		return DiskScanRun{}, fmt.Errorf("StartRun: %w", err)
	}
	now := s.utcNow()
	run := DiskScanRun{ConnectorID: connectorID, Status: StatusRunning, StartedAt: now}
	if !set.Mode.Enabled() {
		run.Status, run.FinishedAt = StatusNotEnabled, now
	}
	stored, err := s.repo.InsertRun(ctx, run)
	if err != nil {
		return DiskScanRun{}, fmt.Errorf("StartRun: %w", err)
	}
	return stored, nil
}

// RecordResult stores one volume's outcome.
func (s *Service) RecordResult(ctx context.Context, runID string, t DiskScanTarget, res VolumeResult) error {
	if runID == "" || t.AssetID == "" || t.VolumeRef == "" {
		return fmt.Errorf("RecordResult: run, asset and volume are required: %w", ErrInvalid)
	}
	res.RunID, res.AssetID, res.VolumeRef = runID, t.AssetID, t.VolumeRef
	if err := validateResult(res); err != nil {
		return fmt.Errorf("RecordResult: %w", err)
	}
	if res.ObservedAt.IsZero() {
		res.ObservedAt = s.utcNow()
	}
	if err := s.repo.UpsertVolume(ctx, t.Boot, res); err != nil {
		return fmt.Errorf("RecordResult: %w", err)
	}
	return nil
}

var validGaps = []string{
	GapNotEnabled, GapNoSnapshotAvailable, GapSnapshotPending, GapEncryptedNoKey, GapUnsupportedFS,
	GapUnsupportedPartition, GapReadError, GapOverCap, GapPermissionDenied, GapStale,
}

// validateResult refuses a VolumeResult that could read as clean for a disk
// whose packages were not read.
func validateResult(r VolumeResult) error {
	switch r.SnapshotSource {
	case SourceNone, SourceReused, SourceCreated, SourceImageBaseline:
	default:
		return fmt.Errorf("snapshot source %q: %w", r.SnapshotSource, ErrInvalid)
	}
	if r.PackageCount < 0 {
		return fmt.Errorf("negative package count: %w", ErrInvalid)
	}
	if r.InventoryKnown {
		if r.Gap != GapNone {
			return fmt.Errorf("known inventory with gap %q: %w", r.Gap, ErrInvalid)
		}
		return nil
	}
	if !slices.Contains(validGaps, r.Gap) {
		return fmt.Errorf("unknown inventory needs a gap, got %q: %w", r.Gap, ErrInvalid)
	}
	if r.CVEMatchableKnown || r.PackageCount != 0 {
		return fmt.Errorf("unknown inventory carries a verdict or package count: %w", ErrInvalid)
	}
	return nil
}

// FinishRun closes a run. planned is the number of volumes the run enqueued.
func (s *Service) FinishRun(ctx context.Context, runID string, planned int, runErr error) (DiskScanRun, error) {
	run, err := s.repo.GetRun(ctx, runID)
	if err != nil {
		return DiskScanRun{}, fmt.Errorf("FinishRun: %w", err)
	}
	counts, err := s.repo.CountVolumes(ctx, runID)
	if err != nil {
		return DiskScanRun{}, fmt.Errorf("FinishRun: %w", err)
	}
	counts.Volumes = planned
	run.Counts, run.FinishedAt = counts, s.utcNow()
	run.Status = runStatus(counts, runErr)
	if runErr != nil {
		run.Err = runErr.Error()
	}
	if err := s.repo.FinishRun(ctx, run); err != nil {
		return DiskScanRun{}, fmt.Errorf("FinishRun: %w", err)
	}
	return run, nil
}

func runStatus(c RunCounts, runErr error) RunStatus {
	recorded := c.Scanned + c.Gaps + c.NotEnabled
	switch {
	case runErr != nil && recorded == 0:
		return StatusFailed
	case c.Volumes > 0 && c.NotEnabled == c.Volumes:
		return StatusNotEnabled
	case runErr == nil && c.Scanned == c.Volumes:
		return StatusSucceeded
	default:
		return StatusPartial
	}
}

func (s *Service) GetRun(ctx context.Context, id string) (DiskScanRun, error) {
	run, err := s.repo.GetRun(ctx, id)
	if err != nil {
		return DiskScanRun{}, fmt.Errorf("GetRun: %w", err)
	}
	return run, nil
}

// ListRuns returns the newest runs, for one connector or (empty id) all.
func (s *Service) ListRuns(ctx context.Context, connectorID string, limit int) ([]DiskScanRun, error) {
	if limit <= 0 || limit > maxListRuns {
		limit = maxListRuns
	}
	runs, err := s.repo.ListRuns(ctx, connectorID, limit)
	if err != nil {
		return nil, fmt.Errorf("ListRuns: %w", err)
	}
	return runs, nil
}

func (s *Service) ListVolumes(ctx context.Context, runID string) ([]VolumeResult, error) {
	vols, err := s.repo.ListVolumes(ctx, runID)
	if err != nil {
		return nil, fmt.Errorf("ListVolumes: %w", err)
	}
	for i := range vols {
		vols[i] = guardUnknown(vols[i])
	}
	return vols, nil
}

// Latest returns each asset's newest result; assets with none are absent.
func (s *Service) Latest(ctx context.Context, assetIDs []string) (map[string]VolumeResult, error) {
	if len(assetIDs) == 0 {
		return map[string]VolumeResult{}, nil
	}
	rows, err := s.repo.LatestVolumes(ctx, assetIDs)
	if err != nil {
		return nil, fmt.Errorf("Latest: %w", err)
	}
	out := make(map[string]VolumeResult, len(rows))
	for _, r := range rows {
		out[r.AssetID] = guardUnknown(r)
	}
	return out, nil
}

// guardUnknown is the read-side backstop for validateResult and the table
// CHECKs: a row that claims neither a known inventory nor a gap reads as a
// read error, never as clean.
func guardUnknown(r VolumeResult) VolumeResult {
	if !r.InventoryKnown {
		if r.Gap == GapNone {
			r.Gap = GapReadError
		}
		r.CVEMatchableKnown, r.PackageCount = false, 0
	}
	return r
}

// EnabledConnectors lists connectors whose disk-scan mode is not off.
func (s *Service) EnabledConnectors(ctx context.Context) ([]ConnectorSettings, error) {
	all, err := s.conns.DiskScanEnabled(ctx)
	if err != nil {
		return nil, fmt.Errorf("EnabledConnectors: %w", err)
	}
	out := make([]ConnectorSettings, 0, len(all))
	for _, c := range all {
		if c.Mode.Enabled() {
			out = append(out, c)
		}
	}
	return out, nil
}

// Grant returns what engine.Authorize needs for a connector.
func (s *Service) Grant(ctx context.Context, connectorID string) (engine.ConnectorGrant, error) {
	set, err := s.conns.DiskScanSettings(ctx, connectorID)
	if err != nil {
		return engine.ConnectorGrant{}, fmt.Errorf("Grant: %w", err)
	}
	return engine.ConnectorGrant{Mode: string(set.Mode), DiskScanRole: set.Role, OtherRoles: set.OtherRoles}, nil
}

// RegisterSnapshotIntent records that a snapshot is about to be created. Call
// it before the create call. A retry with the same run and volume gets the
// existing row back.
func (s *Service) RegisterSnapshotIntent(ctx context.Context, in SnapshotIntent) (SnapshotIntent, error) {
	if in.RunID == "" || in.ConnectorID == "" || in.Provider == "" || in.VolumeRef == "" {
		return SnapshotIntent{}, fmt.Errorf("RegisterSnapshotIntent: run, connector, provider and volume are required: %w", ErrInvalid)
	}
	now := s.utcNow()
	in.ID, in.SnapshotID, in.DeletedAt = "", "", time.Time{}
	in.CreatedAt, in.DeleteAfter = now, now.Add(s.ttl)
	if err := s.repo.InsertIntent(ctx, in); err != nil {
		return SnapshotIntent{}, fmt.Errorf("RegisterSnapshotIntent: %w", err)
	}
	stored, err := s.repo.GetIntent(ctx, in.RunID, in.VolumeRef)
	if err != nil {
		return SnapshotIntent{}, fmt.Errorf("RegisterSnapshotIntent: %w", err)
	}
	return stored, nil
}

// AttachSnapshot records the provider's snapshot id on an intent.
func (s *Service) AttachSnapshot(ctx context.Context, intentID, snapshotID string) error {
	if intentID == "" || snapshotID == "" {
		return fmt.Errorf("AttachSnapshot: intent and snapshot ids are required: %w", ErrInvalid)
	}
	if err := s.repo.AttachSnapshot(ctx, intentID, snapshotID); err != nil {
		return fmt.Errorf("AttachSnapshot: %w", err)
	}
	return nil
}

// MarkDeleted records that an intent's snapshot is gone, or never existed.
func (s *Service) MarkDeleted(ctx context.Context, intentID string) error {
	if err := s.repo.MarkDeleted(ctx, intentID, s.utcNow()); err != nil {
		return fmt.Errorf("MarkDeleted: %w", err)
	}
	return nil
}

// MarkDeletedBySnapshot records a deletion found by snapshot id, such as one
// the sweeper listed by tag. A snapshot with no registry row is a no-op.
func (s *Service) MarkDeletedBySnapshot(ctx context.Context, provider, snapshotID string) error {
	if err := s.repo.MarkDeletedBySnapshot(ctx, provider, snapshotID, s.utcNow()); err != nil {
		return fmt.Errorf("MarkDeletedBySnapshot: %w", err)
	}
	return nil
}

// ListOrphans returns registry rows that are not deleted and are past their
// delete-after time, oldest first.
func (s *Service) ListOrphans(ctx context.Context) ([]SnapshotIntent, error) {
	rows, err := s.repo.ListOrphans(ctx, s.utcNow(), orphanBatch)
	if err != nil {
		return nil, fmt.Errorf("ListOrphans: %w", err)
	}
	return rows, nil
}

// CacheGet returns a stored result; an expired or absent entry is a miss.
func (s *Service) CacheGet(ctx context.Context, provider, snapshotID string) (CacheEntry, bool, error) {
	e, ok, err := s.repo.GetCache(ctx, provider, snapshotID, s.utcNow())
	if err != nil {
		return CacheEntry{}, false, fmt.Errorf("CacheGet: %w", err)
	}
	if ok {
		e.Result = guardUnknown(e.Result)
	}
	return e, ok, nil
}

// CachePut stores a result under (provider, snapshot id), replacing an older one.
func (s *Service) CachePut(ctx context.Context, e CacheEntry) error {
	if e.Provider == "" || e.SnapshotID == "" {
		return fmt.Errorf("CachePut: provider and snapshot id are required: %w", ErrInvalid)
	}
	if err := validateResult(e.Result); err != nil {
		return fmt.Errorf("CachePut: %w", err)
	}
	if e.CachedAt.IsZero() {
		e.CachedAt = s.utcNow()
	}
	if err := s.repo.PutCache(ctx, e); err != nil {
		return fmt.Errorf("CachePut: %w", err)
	}
	return nil
}
