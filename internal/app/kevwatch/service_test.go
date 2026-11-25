package kevwatch

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// memRepo mirrors PGRepo's semantics: Commit upserts the catalog and inserts
// only additions not already recorded.
type memRepo struct {
	catalog   map[string]Entry
	events    map[string]Addition
	knownErr  error
	commitErr error
	committed int
}

func newMemRepo() *memRepo {
	return &memRepo{catalog: map[string]Entry{}, events: map[string]Addition{}}
}

func (m *memRepo) KnownCVEs(context.Context) (map[string]bool, error) {
	if m.knownErr != nil {
		return nil, m.knownErr
	}
	out := map[string]bool{}
	for id := range m.catalog {
		out[id] = true
	}
	return out, nil
}

func (m *memRepo) Commit(_ context.Context, entries []Entry, additions []Addition) ([]Addition, error) {
	if m.commitErr != nil {
		return nil, m.commitErr
	}
	m.committed++
	for _, e := range entries {
		m.catalog[e.CVEID] = e
	}
	var inserted []Addition
	for _, a := range additions {
		if _, ok := m.events[a.CVEID]; ok {
			continue
		}
		m.events[a.CVEID] = a
		inserted = append(inserted, a)
	}
	return inserted, nil
}

func (m *memRepo) ListAdditions(context.Context, int) ([]Addition, error) {
	var out []Addition
	for _, a := range m.events {
		out = append(out, a)
	}
	return out, nil
}

var today = time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)

func svcAt(repo Repo) *Service {
	s := NewService(repo)
	s.now = func() time.Time { return today.Add(12 * time.Hour) }
	return s
}

func cves(adds []Addition) []string {
	out := make([]string, len(adds))
	for i, a := range adds {
		out[i] = a.CVEID
	}
	return out
}

// The first refresh seeds the back catalog silently and reports only what
// CISA added within the bootstrap window.
func TestReconcile_BootstrapReportsOnlyRecentAdditions(t *testing.T) {
	repo := newMemRepo()
	got, err := svcAt(repo).Reconcile(context.Background(), []Entry{
		{CVEID: "CVE-2021-44228", DateAdded: time.Date(2021, 12, 10, 0, 0, 0, 0, time.UTC)},
		{CVEID: "cve-2026-0001", DateAdded: today.AddDate(0, 0, -2), Name: "recent"},
		{CVEID: "CVE-2026-0002"}, // unknown dateAdded: not evidence of recency
	}, map[string]int{"CVE-2026-0001": 4})
	require.NoError(t, err)
	require.Equal(t, []Addition{{CVEID: "CVE-2026-0001", DateAdded: today.AddDate(0, 0, -2), Name: "recent", OpenFindings: 4}}, got)
	require.Len(t, repo.catalog, 3, "the whole catalog is seeded")
}

// After the seed, every CVE new to the catalog is an addition — whatever its
// dateAdded says — and each is reported exactly once.
func TestReconcile_DiffsAgainstTheStoredCatalog(t *testing.T) {
	repo := newMemRepo()
	svc := svcAt(repo)
	_, err := svc.Reconcile(context.Background(), []Entry{{CVEID: "CVE-2021-44228"}}, nil)
	require.NoError(t, err)

	next := []Entry{
		{CVEID: "CVE-2021-44228"},
		{CVEID: "CVE-2019-0001", DateAdded: time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC)},
		{CVEID: "CVE-2026-0003"},
	}
	got, err := svc.Reconcile(context.Background(), next, map[string]int{"CVE-2026-0003": 2})
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"CVE-2019-0001", "CVE-2026-0003"}, cves(got))

	again, err := svc.Reconcile(context.Background(), next, nil)
	require.NoError(t, err)
	require.Empty(t, again, "a refresh with no catalog change reports nothing")
}

// An addition already recorded (a concurrent or retried refresh that saw the
// same diff) is not reported again.
func TestReconcile_IsIdempotentPerCVE(t *testing.T) {
	repo := newMemRepo()
	repo.catalog["CVE-OLD"] = Entry{CVEID: "CVE-OLD"}
	repo.events["CVE-2026-0004"] = Addition{CVEID: "CVE-2026-0004"}
	got, err := svcAt(repo).Reconcile(context.Background(), []Entry{{CVEID: "CVE-OLD"}, {CVEID: "CVE-2026-0004"}}, nil)
	require.NoError(t, err)
	require.Empty(t, got)
}

func TestReconcile_ErrorsAreReturnedNotSwallowed(t *testing.T) {
	boom := errors.New("pg down")
	repo := newMemRepo()
	repo.knownErr = boom
	_, err := svcAt(repo).Reconcile(context.Background(), []Entry{{CVEID: "CVE-1"}}, nil)
	require.ErrorIs(t, err, boom)
	require.Zero(t, repo.committed, "an unreadable catalog must not be read as empty and re-bootstrapped")

	repo = newMemRepo()
	repo.commitErr = boom
	_, err = svcAt(repo).Reconcile(context.Background(), []Entry{{CVEID: "CVE-1"}}, nil)
	require.ErrorIs(t, err, boom)
}

func TestReconcile_SkipsBlankIDs(t *testing.T) {
	repo := newMemRepo()
	repo.catalog["CVE-OLD"] = Entry{CVEID: "CVE-OLD"}
	got, err := svcAt(repo).Reconcile(context.Background(), []Entry{{CVEID: "  "}, {CVEID: " cve-2026-9 "}}, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"CVE-2026-9"}, cves(got))
	require.NotContains(t, repo.catalog, "")
}

type limitRepo struct {
	memRepo
	got int
}

func (l *limitRepo) ListAdditions(_ context.Context, limit int) ([]Addition, error) {
	l.got = limit
	return nil, nil
}

func TestRecent_ClampsTheLimit(t *testing.T) {
	for in, want := range map[int]int{0: DefaultListLimit, -3: DefaultListLimit, 10: 10, 10_000: MaxListLimit} {
		repo := &limitRepo{}
		_, err := NewService(repo).Recent(context.Background(), in)
		require.NoError(t, err)
		require.Equal(t, want, repo.got, "limit %d", in)
	}
}
