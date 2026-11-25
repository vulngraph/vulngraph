package pkginv

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/distro"
)

var clock = time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)

type fakeRepo struct {
	mu   sync.Mutex
	recs map[string]InventoryRecord
}

func newFakeRepo() *fakeRepo { return &fakeRepo{recs: map[string]InventoryRecord{}} }

func (f *fakeRepo) Get(_ context.Context, source, assetID string) (InventoryRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.recs[source+"|"+assetID]
	return r, ok, nil
}

func (f *fakeRepo) Upsert(_ context.Context, rec InventoryRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := rec.Source + "|" + rec.AssetID
	if prev, ok := f.recs[k]; ok && prev.ObservedAt.After(rec.ObservedAt) {
		return ErrStale
	}
	f.recs[k] = rec
	return nil
}

func (f *fakeRepo) ListForAssets(_ context.Context, ids []string) ([]InventoryRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []InventoryRecord
	for _, r := range f.recs {
		for _, id := range ids {
			if r.AssetID == id {
				out = append(out, r)
			}
		}
	}
	return out, nil
}

type fakeAssets struct {
	assets map[string]asset.Asset
	live   map[string]bool
	edges  []asset.Edge
	pkgs   []asset.Asset
	ingest int
}

func (f *fakeAssets) Get(_ context.Context, id string) (asset.Asset, error) {
	a, ok := f.assets[id]
	if !ok {
		return asset.Asset{}, fmt.Errorf("Get: %w", asset.ErrNotFound)
	}
	return a, nil
}

func (f *fakeAssets) LiveIDs(_ context.Context, ids []string) ([]string, error) {
	var out []string
	for _, id := range ids {
		if f.live[id] {
			out = append(out, id)
		}
	}
	return out, nil
}

func (f *fakeAssets) Ingest(_ context.Context, assets []asset.Asset, edges []asset.Edge) error {
	f.ingest++
	f.pkgs = append(f.pkgs, assets...)
	f.edges = append(f.edges, edges...)
	return nil
}

type fakeTimes map[string]time.Time

func (f fakeTimes) AssetDeletions(_ context.Context, ids []string) (map[string]time.Time, error) {
	return f.pick(ids), nil
}

func (f fakeTimes) Tombstones(_ context.Context, ids []string) (map[string]time.Time, error) {
	return f.pick(ids), nil
}

func (f fakeTimes) pick(ids []string) map[string]time.Time {
	out := map[string]time.Time{}
	for _, id := range ids {
		if t, ok := f[id]; ok {
			out[id] = t
		}
	}
	return out
}

type auditRow struct {
	action, targetType, targetID string
	details                      map[string]any
}

type fakeAudit struct{ rows []auditRow }

func (f *fakeAudit) Record(_ context.Context, action, targetType, targetID string, details map[string]any) {
	f.rows = append(f.rows, auditRow{action, targetType, targetID, details})
}

type allowN struct{ left int }

func (a *allowN) Allow(string) (bool, time.Duration) {
	if a.left <= 0 {
		return false, time.Minute
	}
	a.left--
	return true, 0
}

type rig struct {
	svc      *Service
	repo     *fakeRepo
	assets   *fakeAssets
	audit    *fakeAudit
	deleted  fakeTimes
	forgot   fakeTimes
	limiter  *allowN
	keyA     Principal
	keyB     Principal
	advisory distro.Sources
}

const vmID = "i-0abc"

func newRig(t *testing.T) *rig {
	t.Helper()
	r := &rig{
		repo: newFakeRepo(),
		assets: &fakeAssets{
			assets: map[string]asset.Asset{
				vmID:      {ID: vmID, Type: "ec2_instance", LastSeen: clock.Add(-time.Hour)},
				"i-other": {ID: "i-other", Type: "ec2_instance", LastSeen: clock.Add(-time.Hour)},
				"bucket":  {ID: "bucket", Type: "s3_bucket", LastSeen: clock.Add(-time.Hour)},
			},
			live: map[string]bool{vmID: true, "i-other": true, "bucket": true},
		},
		audit:    &fakeAudit{},
		deleted:  fakeTimes{},
		forgot:   fakeTimes{},
		limiter:  &allowN{left: 1000},
		keyA:     Principal{KeyID: "key-a", Scope: "inventory", OwnerRole: "admin"},
		keyB:     Principal{KeyID: "key-b", Scope: "inventory", OwnerRole: "admin"},
		advisory: distro.Sources{distro.SourceOSV: true},
	}
	r.svc = NewService(r.repo, r.assets, r.deleted, r.forgot, r.audit, r.limiter, func() distro.Sources { return r.advisory })
	r.svc.now = func() time.Time { return clock }
	return r
}

// goodRequest is a complete, fresh Ubuntu 22.04 inventory that the server believes.
func goodRequest() Request {
	return Request{
		OS:         &RequestOS{ID: "ubuntu", VersionID: "22.04"},
		ObservedAt: clock.Add(-time.Hour).Format(time.RFC3339),
		Scanner:    RequestScan{Name: "acme-agent", Version: "1.4.2"},
		Complete:   true,
		Packages: []RequestPkg{
			{Name: "libssl3", Version: "3.0.2-0ubuntu1.10", SourceName: "openssl"},
			{Name: "bash", Version: "5.1-6ubuntu1", SourceName: "bash"},
		},
	}
}

func TestSubmit_Accepted(t *testing.T) {
	r := newRig(t)
	rec, err := r.svc.Submit(context.Background(), r.keyA, vmID, goodRequest())
	require.NoError(t, err)
	require.True(t, rec.InventoryKnown)
	require.True(t, rec.CVEMatchableKnown)
	require.Empty(t, rec.Gap)
	require.Equal(t, "byoa:key-a:acme-agent", rec.Source)
	require.Len(t, r.assets.edges, 2)
	require.Len(t, r.audit.rows, 1)
	require.Equal(t, "inventory.submit", r.audit.rows[0].action)
	require.Equal(t, "accepted", r.audit.rows[0].details["outcome"])
	require.Equal(t, 2, r.audit.rows[0].details["package_count"])
	require.Equal(t, true, r.audit.rows[0].details["complete"])
	require.Equal(t, "acme-agent", r.audit.rows[0].details["scanner"])
}

// The server decides known-ness. Incomplete, stale and unknown-release inventories are gaps,
// and a gap writes no edges: a clean-looking VM needs a known inventory.
func TestByoaCannotMarkClean(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Request)
		advise  distro.Sources
		wantGap string
	}{
		{"complete defaults to false", func(q *Request) { q.Complete = false }, nil, GapIncomplete},
		{"stale capture", func(q *Request) { q.ObservedAt = clock.Add(-8 * 24 * time.Hour).Format(time.RFC3339) }, nil, GapStale},
		{"no os block", func(q *Request) { q.OS = nil }, nil, asset.CVEGapUnknownRelease},
		{"unrecognised distro", func(q *Request) { q.OS = &RequestOS{ID: "plan9", VersionID: "4"} }, nil, asset.CVEGapUnknownRelease},
		{"advisory source switched off", func(*Request) {}, distro.Sources{}, asset.CVEGapAdvisorySourceDisabled},
		{"source-keyed distro without source names", func(q *Request) {
			for i := range q.Packages {
				q.Packages[i].SourceName = ""
			}
		}, nil, asset.CVEGapNoSourceNames},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			if tc.advise != nil {
				r.advisory = tc.advise
			}
			q := goodRequest()
			tc.mutate(&q)
			rec, err := r.svc.Submit(context.Background(), r.keyA, vmID, q)
			require.NoError(t, err)
			require.False(t, rec.InventoryKnown, "InventoryKnown must be false")
			require.False(t, rec.CVEMatchableKnown, "CVEMatchableKnown must be false")
			require.Equal(t, tc.wantGap, rec.Gap)
			require.Empty(t, r.assets.edges, "a gap must write no runs_package edges")
			require.Zero(t, r.assets.ingest)
		})
	}
}

// Only the named asset gains edges; the body's asset_id cannot redirect a write and a
// non-VM or other asset is never a target.
func TestByoaCannotWriteOutsideNamedAsset(t *testing.T) {
	r := newRig(t)
	q := goodRequest()
	q.AssetID = "i-other"
	rec, err := r.svc.Submit(context.Background(), r.keyA, vmID, q)
	require.NoError(t, err)
	require.Equal(t, vmID, rec.AssetID, "the path wins over the body")
	require.NotEmpty(t, r.assets.edges)
	for _, e := range r.assets.edges {
		require.Equal(t, vmID, e.SrcID)
		require.Equal(t, "runs_package", e.EdgeType)
		require.Equal(t, "package", e.DstType)
	}
	for _, a := range r.assets.pkgs {
		require.Equal(t, "package", a.Type, "only package assets are written, never the VM or any other asset")
	}

	t.Run("a non-VM asset is refused", func(t *testing.T) {
		r := newRig(t)
		_, err := r.svc.Submit(context.Background(), r.keyA, "bucket", goodRequest())
		require.ErrorIs(t, err, ErrAssetNotFound)
		require.Zero(t, r.assets.ingest)
	})
	t.Run("an unknown asset is never created", func(t *testing.T) {
		r := newRig(t)
		_, err := r.svc.Submit(context.Background(), r.keyA, "i-nope", goodRequest())
		require.ErrorIs(t, err, ErrAssetNotFound)
		require.Zero(t, r.assets.ingest)
		require.Empty(t, r.repo.recs)
	})
	t.Run("cloud_resource_id names exactly one asset", func(t *testing.T) {
		r := newRig(t)
		q := goodRequest()
		q.CloudResourceID = "i-other"
		rec, err := r.svc.Submit(context.Background(), r.keyA, "", q)
		require.NoError(t, err)
		require.Equal(t, "i-other", rec.AssetID)
	})
	t.Run("no identifier at all", func(t *testing.T) {
		r := newRig(t)
		_, err := r.svc.Submit(context.Background(), r.keyA, "", goodRequest())
		require.ErrorIs(t, err, ErrInvalid)
	})
}

func TestByoaCannotResurrectDeletedAsset(t *testing.T) {
	cases := []struct {
		name  string
		setup func(*rig)
	}{
		{"deletion proof newer than last_seen", func(r *rig) { r.deleted[vmID] = clock.Add(-30 * time.Minute) }},
		{"deletion proof equal to last_seen", func(r *rig) { r.deleted[vmID] = clock.Add(-time.Hour) }},
		{"forget tombstone", func(r *rig) { r.forgot[vmID] = clock.Add(-30 * time.Minute) }},
		{"not live under the ephemeral gate", func(r *rig) { r.assets.live[vmID] = false }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			tc.setup(r)
			_, err := r.svc.Submit(context.Background(), r.keyA, vmID, goodRequest())
			require.ErrorIs(t, err, ErrAssetNotFound)
			require.Zero(t, r.assets.ingest)
			require.Empty(t, r.repo.recs)
		})
	}
	t.Run("a resource that came back is not deleted", func(t *testing.T) {
		r := newRig(t)
		r.deleted[vmID] = clock.Add(-2 * time.Hour) // before last_seen
		_, err := r.svc.Submit(context.Background(), r.keyA, vmID, goodRequest())
		require.NoError(t, err)
	})
}

func TestSubmit_IdempotentReplaceNewerWinsOlderRejected(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	q := goodRequest()
	first, err := r.svc.Submit(ctx, r.keyA, vmID, q)
	require.NoError(t, err)
	edgesAfterFirst := len(r.assets.edges)

	again, err := r.svc.Submit(ctx, r.keyA, vmID, q)
	require.NoError(t, err)
	require.Equal(t, first, again, "the same body twice is idempotent")
	require.Len(t, r.repo.recs, 1, "one stored inventory per source and asset")
	seen := map[string]bool{}
	for _, e := range r.assets.edges[edgesAfterFirst:] {
		seen[e.DstID] = true
	}
	require.Len(t, seen, 2, "the replay writes the same edge keys, not new ones")

	newer := goodRequest()
	newer.ObservedAt = clock.Add(-time.Minute).Format(time.RFC3339)
	newer.Packages = newer.Packages[:1]
	got, err := r.svc.Submit(ctx, r.keyA, vmID, newer)
	require.NoError(t, err)
	require.Equal(t, 1, got.PackageCount)
	require.Len(t, r.repo.recs, 1)
	require.True(t, got.ObservedAt.After(first.ObservedAt))

	older := goodRequest()
	older.ObservedAt = clock.Add(-3 * time.Hour).Format(time.RFC3339)
	edges := len(r.assets.edges)
	_, err = r.svc.Submit(ctx, r.keyA, vmID, older)
	require.ErrorIs(t, err, ErrStale)
	require.Len(t, r.assets.edges, edges, "a stale submission writes nothing")
	stored, _, _ := r.repo.Get(ctx, got.Source, vmID)
	require.Equal(t, got, stored, "and does not replace the stored claim")
	last := r.audit.rows[len(r.audit.rows)-1]
	require.Equal(t, "rejected", last.details["outcome"])
	require.Equal(t, "stale", last.details["reason"])
}

func TestSubmit_SourceIsolationBetweenKeys(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	a, err := r.svc.Submit(ctx, r.keyA, vmID, goodRequest())
	require.NoError(t, err)

	older := goodRequest()
	older.ObservedAt = clock.Add(-5 * time.Hour).Format(time.RFC3339)
	older.Complete = false
	b, err := r.svc.Submit(ctx, r.keyB, vmID, older)
	require.NoError(t, err, "key B's older claim is its own source, not a stale replay of A's")
	require.NotEqual(t, a.Source, b.Source)
	require.Len(t, r.repo.recs, 2)

	storedA, _, _ := r.repo.Get(ctx, a.Source, vmID)
	require.Equal(t, a, storedA, "key B cannot replace key A's inventory")

	other := goodRequest()
	other.Scanner.Name = "second-scanner"
	c, err := r.svc.Submit(ctx, r.keyA, vmID, other)
	require.NoError(t, err)
	require.NotEqual(t, a.Source, c.Source, "the scanner name is part of the source")
	require.Len(t, r.repo.recs, 3)
}

func TestSubmit_ScopeAndRateLimit(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		p    Principal
	}{
		{"no principal (a session)", Principal{}},
		{"read key", Principal{KeyID: "k", Scope: "read", OwnerRole: "admin"}},
		{"write key", Principal{KeyID: "k", Scope: "write", OwnerRole: "admin"}},
		{"admin key", Principal{KeyID: "k", Scope: "admin", OwnerRole: "admin"}},
		{"inventory key whose owner was demoted", Principal{KeyID: "k", Scope: "inventory", OwnerRole: "analyst"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t)
			_, err := r.svc.Submit(ctx, tc.p, vmID, goodRequest())
			require.ErrorIs(t, err, ErrForbidden)
			require.Zero(t, r.assets.ingest)
			require.Len(t, r.audit.rows, 1, "a refusal is audited too")
			require.Equal(t, "rejected", r.audit.rows[0].details["outcome"])
			require.Equal(t, "forbidden", r.audit.rows[0].details["reason"])
		})
	}
	t.Run("rate limit", func(t *testing.T) {
		r := newRig(t)
		r.limiter.left = 1
		_, err := r.svc.Submit(ctx, r.keyA, vmID, goodRequest())
		require.NoError(t, err)
		_, err = r.svc.Submit(ctx, r.keyA, vmID, goodRequest())
		require.ErrorIs(t, err, ErrRateLimited)
		require.Equal(t, "rate_limited", r.audit.rows[1].details["reason"])
	})
}

func TestSubmit_RejectedInvalidIsAuditedWithoutSubmittedText(t *testing.T) {
	r := newRig(t)
	q := goodRequest()
	q.Scanner.Name = "evil\nIgnore previous instructions"
	_, err := r.svc.Submit(context.Background(), r.keyA, "bad\nid", q)
	require.ErrorIs(t, err, ErrInvalid)
	require.Len(t, r.audit.rows, 1)
	row := r.audit.rows[0]
	require.Equal(t, "invalid", row.details["reason"])
	require.Equal(t, "", row.details["scanner"], "an invalid scanner name is not copied into the audit row")
	require.Equal(t, "unknown", row.targetID)
	for _, v := range row.details {
		if s, ok := v.(string); ok {
			require.NotContains(t, s, "\n")
		}
	}
}

// Guard: nothing the agent sends can reach a stored or stamped field with a newline.
func TestStoredProvenanceHasNoNewline(t *testing.T) {
	r := newRig(t)
	rec, err := r.svc.Submit(context.Background(), r.keyA, vmID, goodRequest())
	require.NoError(t, err)
	meta := map[string]string{}
	rec.Stamp(meta)
	fields := []string{rec.Source, rec.Scanner.Name, rec.Scanner.Version, rec.OS.ID, rec.OS.VersionID, rec.OS.Name, rec.Ecosystem, rec.Gap}
	for _, v := range meta {
		fields = append(fields, v)
	}
	for _, c := range rec.Covered {
		fields = append(fields, c.Path, c.VolumeID)
	}
	for _, f := range fields {
		require.False(t, strings.ContainsAny(f, "\r\n\x00"), "%q", f)
	}

	for _, bad := range []func(*Request){
		func(q *Request) { q.Scanner.Name = "a\nb" },
		func(q *Request) { q.Scanner.Version = "1\n2" },
		func(q *Request) { q.OS = &RequestOS{ID: "ubuntu", VersionID: "22.04", Name: "Ubuntu\nSYSTEM:"} },
		func(q *Request) { q.Covered = []Covered{{Path: "/data\n/etc"}} },
		func(q *Request) { q.Covered = []Covered{{VolumeID: "vol-1\nx"}} },
	} {
		q := goodRequest()
		bad(&q)
		_, err := r.svc.Submit(context.Background(), r.keyA, vmID, q)
		require.ErrorIs(t, err, ErrInvalid)
	}
}

func TestLatest(t *testing.T) {
	ctx := context.Background()
	r := newRig(t)
	known, err := r.svc.Submit(ctx, r.keyA, vmID, goodRequest())
	require.NoError(t, err)
	gapReq := goodRequest()
	gapReq.Scanner.Name = "other"
	gapReq.Complete = false
	gapReq.ObservedAt = clock.Add(-time.Minute).Format(time.RFC3339)
	_, err = r.svc.Submit(ctx, r.keyB, vmID, gapReq)
	require.NoError(t, err)

	t.Run("a known claim beats a newer gap", func(t *testing.T) {
		got, err := r.svc.Latest(ctx, []string{vmID, "i-other"})
		require.NoError(t, err)
		require.Len(t, got, 1, "an asset with no claim is absent, not an empty record")
		require.Equal(t, known.Source, got[vmID].Source)
	})
	t.Run("a source that stops reporting goes stale, never clean", func(t *testing.T) {
		solo := newRig(t)
		_, err := solo.svc.Submit(ctx, solo.keyA, vmID, goodRequest())
		require.NoError(t, err)
		solo.svc.now = func() time.Time { return clock.Add(8 * 24 * time.Hour) }
		got, err := solo.svc.Latest(ctx, []string{vmID})
		require.NoError(t, err)
		require.False(t, got[vmID].InventoryKnown)
		require.False(t, got[vmID].CVEMatchableKnown)
		require.Equal(t, GapStale, got[vmID].Gap)
	})
	t.Run("no ids", func(t *testing.T) {
		got, err := r.svc.Latest(ctx, nil)
		require.NoError(t, err)
		require.Empty(t, got)
	})
}

type failingAssets struct{ *fakeAssets }

func (failingAssets) Ingest(context.Context, []asset.Asset, []asset.Edge) error {
	return errors.New("clickhouse down")
}

// A failed edge write must not leave a stored claim saying the inventory is known.
func TestSubmit_EdgeWriteFailureStoresNothing(t *testing.T) {
	r := newRig(t)
	r.svc.assets = failingAssets{r.assets}
	_, err := r.svc.Submit(context.Background(), r.keyA, vmID, goodRequest())
	require.Error(t, err)
	require.Empty(t, r.repo.recs)
	require.Equal(t, "error", r.audit.rows[0].details["reason"])
}
