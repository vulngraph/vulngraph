package jobs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/diskscan"
	engine "github.com/vulngraph/vulngraph/internal/scanner/diskscan"
)

var fakeNow = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

// fakeDiskSvc is an in-memory diskScanService that records what was asked of it.
type fakeDiskSvc struct {
	mode    diskscan.DiskScanMode
	enabled []diskscan.ConnectorSettings
	runs    []diskscan.DiskScanRun

	latest   map[string]diskscan.VolumeResult
	recorded []diskscan.VolumeResult
	packages []diskscan.PackageSet
	intents  map[string]*diskscan.SnapshotIntent
	cache    map[string]diskscan.CacheEntry
	orphans  []diskscan.SnapshotIntent

	events       []string
	finished     []string
	markedIntent []string
	markedSnap   []string
	planned      int
}

func newFakeDiskSvc(mode diskscan.DiskScanMode) *fakeDiskSvc {
	return &fakeDiskSvc{
		mode: mode, intents: map[string]*diskscan.SnapshotIntent{}, cache: map[string]diskscan.CacheEntry{},
		latest: map[string]diskscan.VolumeResult{},
	}
}

func (f *fakeDiskSvc) event(s string) { f.events = append(f.events, s) }

func (f *fakeDiskSvc) EnabledConnectors(context.Context) ([]diskscan.ConnectorSettings, error) {
	return f.enabled, nil
}

func (f *fakeDiskSvc) PlanRun(ctx context.Context, id string, enqueue diskscan.EnqueueFunc) (diskscan.DiskScanRun, error) {
	run := diskscan.DiskScanRun{ID: "run-1", ConnectorID: id, Status: diskscan.StatusRunning, StartedAt: fakeNow}
	if err := enqueue(ctx, fakeDiskTx{}, run); err != nil {
		return diskscan.DiskScanRun{}, err
	}
	f.planned++
	return run, nil
}

func (f *fakeDiskSvc) FinishRun(_ context.Context, runID string, _ int, _ error) (diskscan.DiskScanRun, error) {
	f.finished = append(f.finished, runID)
	return diskscan.DiskScanRun{ID: runID}, nil
}

func (f *fakeDiskSvc) ListRuns(context.Context, string, int) ([]diskscan.DiskScanRun, error) {
	return f.runs, nil
}

func (f *fakeDiskSvc) ListVolumes(_ context.Context, runID string) ([]diskscan.VolumeResult, error) {
	var out []diskscan.VolumeResult
	for _, r := range f.recorded {
		if r.RunID == runID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeDiskSvc) Latest(_ context.Context, ids []string) (map[string]diskscan.VolumeResult, error) {
	out := map[string]diskscan.VolumeResult{}
	for _, id := range ids {
		if r, ok := f.latest[id]; ok {
			out[id] = r
		}
	}
	return out, nil
}

func (f *fakeDiskSvc) RecordResult(_ context.Context, runID string, t diskscan.DiskScanTarget, res diskscan.VolumeResult) error {
	res.RunID, res.AssetID, res.VolumeRef = runID, t.AssetID, t.VolumeRef
	f.event("record:" + res.Gap)
	f.recorded = append(f.recorded, res)
	return nil
}

func (f *fakeDiskSvc) RecordPackages(_ context.Context, set diskscan.PackageSet) error {
	f.event("packages")
	f.packages = append(f.packages, set)
	return nil
}

func (f *fakeDiskSvc) Packages(context.Context, []string) ([]diskscan.PackageSet, error) {
	return f.packages, nil
}

func (f *fakeDiskSvc) Grant(context.Context, string) (engine.ConnectorGrant, error) {
	return engine.ConnectorGrant{Mode: string(f.mode), DiskScanRole: "grant-role"}, nil
}

func (f *fakeDiskSvc) RegisterSnapshotIntent(_ context.Context, in diskscan.SnapshotIntent) (diskscan.SnapshotIntent, error) {
	key := in.RunID + "|" + in.VolumeRef
	if got, ok := f.intents[key]; ok {
		return *got, nil
	}
	f.event("intent")
	in.ID = "intent-" + in.VolumeRef
	f.intents[key] = &in
	return in, nil
}

func (f *fakeDiskSvc) AttachSnapshot(_ context.Context, id, snapshotID string) error {
	for _, in := range f.intents {
		if in.ID == id {
			in.SnapshotID = snapshotID
		}
	}
	return nil
}

func (f *fakeDiskSvc) MarkDeleted(_ context.Context, id string) error {
	f.event("mark-deleted")
	f.markedIntent = append(f.markedIntent, id)
	return nil
}

func (f *fakeDiskSvc) MarkDeletedBySnapshot(_ context.Context, _, snapshotID string) error {
	f.markedSnap = append(f.markedSnap, snapshotID)
	return nil
}

func (f *fakeDiskSvc) ListOrphans(context.Context) ([]diskscan.SnapshotIntent, error) {
	return f.orphans, nil
}

func (f *fakeDiskSvc) CacheGet(_ context.Context, provider, snapshotID string) (diskscan.CacheEntry, bool, error) {
	e, ok := f.cache[provider+"|"+snapshotID]
	return e, ok, nil
}

func (f *fakeDiskSvc) CachePut(_ context.Context, e diskscan.CacheEntry) error {
	f.cache[e.Provider+"|"+e.SnapshotID] = e
	return nil
}

// fakeDiskTx is the transaction the fake service hands the enqueue callback.
type fakeDiskTx struct{ pgx.Tx }

type fakeDiskInserter struct{ params []river.InsertManyParams }

func (f *fakeDiskInserter) insertTx(_ context.Context, _ pgx.Tx, params []river.InsertManyParams) error {
	f.params = append(f.params, params...)
	return nil
}

type fakeAssets struct{ byType map[string][]asset.Asset }

func (f fakeAssets) ListByType(_ context.Context, t string, _ int) ([]asset.Asset, error) {
	return f.byType[t], nil
}

func (f fakeAssets) ByIDs(_ context.Context, ids []string) ([]asset.Asset, error) {
	var out []asset.Asset
	for _, a := range f.byType["ebs_volume"] {
		for _, id := range ids {
			if a.ID == id {
				out = append(out, a)
			}
		}
	}
	return out, nil
}

// fakeSource is an in-memory disk.
type fakeSource struct {
	r      *bytes.Reader
	closed bool
}

func newFakeSource() *fakeSource { return &fakeSource{r: bytes.NewReader(make([]byte, 4096))} }

func (s *fakeSource) ReadAt(p []byte, off int64) (int, error) {
	n, err := s.r.ReadAt(p, off)
	if errors.Is(err, io.EOF) && n == len(p) {
		err = nil
	}
	return n, err
}
func (s *fakeSource) Size() int64  { return 4096 }
func (s *fakeSource) Close() error { s.closed = true; return nil }

// fakeCloud counts every mutating call, which is the point of the tests.
type fakeCloud struct {
	snaps           []engine.Snapshot
	listErr         error
	openErr         error
	waitErr         error
	createErr       error
	deleteErr       error
	existing        *engine.Snapshot // tagged snapshot a prior attempt left for the run
	created         int
	deleted         []string
	released        int
	listCalls       int
	waitCalls       int
	changed         []engine.Extent
	changedErr      error
	tagged          []engine.Snapshot
	snapshotEr      error
	grants, revokes int
	providerIns     []DiskOptIns
	releaseIns      []DiskOptIns
}

func (c *fakeCloud) Provider(ins DiskOptIns) engine.Provider {
	c.providerIns = append(c.providerIns, ins)
	return fakeProvider{c: c, ins: ins}
}

func (c *fakeCloud) Snapshotter(engine.OptIn) (engine.Snapshotter, error) {
	if c.snapshotEr != nil {
		return nil, c.snapshotEr
	}
	return fakeSnapshotter{c}, nil
}

func (c *fakeCloud) WaitCompleted(context.Context, engine.Snapshot) error {
	c.waitCalls++
	return c.waitErr
}

func (c *fakeCloud) Release(_ context.Context, ins DiskOptIns, _ engine.Snapshot) error {
	c.released++
	if ins.Read.Valid() {
		c.revokes++
	}
	c.releaseIns = append(c.releaseIns, ins)
	return nil
}

type fakeProvider struct {
	c   *fakeCloud
	ins DiskOptIns
}

func (p fakeProvider) ListReusable(context.Context, engine.VolumeRef) ([]engine.Snapshot, error) {
	p.c.listCalls++
	return p.c.snaps, p.c.listErr
}

func (p fakeProvider) Open(context.Context, engine.Snapshot) (engine.BlockSource, error) {
	if p.ins.Read.Valid() {
		p.c.grants++ // the Azure-style read grant is taken before the bytes are read
	}
	if p.c.openErr != nil {
		return nil, p.c.openErr
	}
	return newFakeSource(), nil
}

func (p fakeProvider) Changed(context.Context, engine.Snapshot, engine.Snapshot) ([]engine.Extent, error) {
	return p.c.changed, p.c.changedErr
}

type fakeSnapshotter struct{ c *fakeCloud }

func (s fakeSnapshotter) CreateTagged(_ context.Context, _ engine.OptIn, vol engine.VolumeRef, _ string) (engine.Snapshot, error) {
	if s.c.createErr != nil {
		return engine.Snapshot{}, s.c.createErr
	}
	if s.c.existing != nil {
		return *s.c.existing, nil
	}
	s.c.created++
	return engine.Snapshot{ID: fmt.Sprintf("snap-new-%d", s.c.created), Provider: "aws", Region: vol.Region, VolumeID: vol.VolumeID,
		Ephemeral: true, CreatedAt: fakeNow}, nil
}

func (s fakeSnapshotter) DeleteTagged(_ context.Context, _ engine.OptIn, snap engine.Snapshot) error {
	if s.c.deleteErr != nil {
		return s.c.deleteErr
	}
	s.c.deleted = append(s.c.deleted, snap.ID)
	return nil
}

func (s fakeSnapshotter) ListTagged(context.Context, engine.OptIn) ([]engine.Snapshot, error) {
	return s.c.tagged, nil
}

type fakeClouds struct {
	cloud      *fakeCloud
	role       string
	others     []string
	openErr    error
	sealCalls  int
	sealedFor  []string
	sealedExp  []time.Time
	resolveErr error
}

func (f *fakeClouds) Seal(_ context.Context, connectorID, runID string, exp time.Time) ([]byte, error) {
	f.sealCalls++
	f.sealedExp = append(f.sealedExp, exp)
	f.sealedFor = append(f.sealedFor, connectorID+"|"+runID)
	return []byte("sealed"), nil
}

func (f *fakeClouds) Open(context.Context, string, string, []byte) (DiskScanAccess, error) {
	if f.openErr != nil {
		return DiskScanAccess{}, f.openErr
	}
	return DiskScanAccess{Role: f.role, OtherRoles: f.others, Cloud: f.cloud}, nil
}

func (f *fakeClouds) Resolve(context.Context, string) (DiskScanAccess, error) {
	if f.resolveErr != nil {
		return DiskScanAccess{}, f.resolveErr
	}
	return DiskScanAccess{Role: f.role, OtherRoles: f.others, Cloud: f.cloud}, nil
}
