package jobs

import (
	"context"
	"errors"
	"testing"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/intel/osv"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
)

// fakeMalFeedQuerier scripts FetchSince without a pool — MalFeedWorker.pool
// stays nil in these tests, so the watermark read/write is skipped and
// lastSHA is always "" (mirrors the cold-start path exactly; the actual
// watermark persistence is covered by MalFeedClient's own tests and the
// integration test for the sqlc query).
type fakeMalFeedQuerier struct {
	records []osv.MalRecord
	headSHA string
	err     error
}

func (f *fakeMalFeedQuerier) FetchSince(context.Context, string) ([]osv.MalRecord, string, error) {
	return f.records, f.headSHA, f.err
}

func TestMalFeedWorker_Work_CreatesFindingForMatchedPackage(t *testing.T) {
	pkg := osv.Package{Ecosystem: "npm", Name: "keyv", Version: "6.0.0"}
	store := &fakeFindingStore{}
	w := &MalFeedWorker{
		querier: &fakeMalFeedQuerier{headSHA: "sha1", records: []osv.MalRecord{{
			Affected: []osv.Package{pkg},
			Vuln:     osv.Vuln{ID: "MAL-2026-11524", Summary: "Malicious code in keyv (npm)", Severity: finding.SeverityCritical},
		}}},
		assets: &fakePackageStore{assets: []asset.Asset{
			pkgAsset("pkg:npm/keyv@6.0.0", "npm", "keyv", "6.0.0"),
			{ID: "org/repo", Type: "github_repo"}, // not a package, never matched
		}},
		findings: store,
	}

	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshMalFeedArgs]{}))
	require.Len(t, store.recorded, 1)
	got := store.recorded[0]
	require.Equal(t, "supply_chain", got.Source)
	require.Equal(t, "MAL-2026-11524", got.CheckID)
	require.Equal(t, finding.SeverityCritical, got.Severity, "MAL-* is critical by construction (resolveSeverity)")
	require.Equal(t, "pkg:npm/keyv@6.0.0", got.ResourceID)
}

func TestMalFeedWorker_Work_NoMatchIsNoop(t *testing.T) {
	store := &fakeFindingStore{}
	w := &MalFeedWorker{
		querier: &fakeMalFeedQuerier{headSHA: "sha1", records: []osv.MalRecord{{
			Affected: []osv.Package{{Ecosystem: "npm", Name: "keyv", Version: "6.0.0"}},
			Vuln:     osv.Vuln{ID: "MAL-2026-11524"},
		}}},
		assets: &fakePackageStore{assets: []asset.Asset{
			// A different version of the same package — no match.
			pkgAsset("pkg:npm/keyv@5.0.0", "npm", "keyv", "5.0.0"),
		}},
		findings: store,
	}

	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshMalFeedArgs]{}))
	require.Empty(t, store.recorded)
}

// TestMalFeedWorker_Work_NoNewRecordsIsNotAnError mirrors refresh_osv's own
// "len(pkgs)==0 → return nil" posture (osv.go): FetchSince returning zero
// records (nothing new since the last watermark) must not fail the job and
// trip River retries against a healthy-but-quiet response.
func TestMalFeedWorker_Work_NoNewRecordsIsNotAnError(t *testing.T) {
	w := &MalFeedWorker{
		querier:  &fakeMalFeedQuerier{headSHA: "sha1", records: nil},
		assets:   &fakePackageStore{},
		findings: &fakeFindingStore{},
	}
	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshMalFeedArgs]{}))
}

func TestMalFeedWorker_Work_FetchError(t *testing.T) {
	w := &MalFeedWorker{
		querier:  &fakeMalFeedQuerier{err: errors.New("github unreachable")},
		assets:   &fakePackageStore{},
		findings: &fakeFindingStore{},
	}
	require.Error(t, w.Work(context.Background(), &river.Job[RefreshMalFeedArgs]{}))
}

// TestMalFeedWorker_Work_NeverResolvesFindings proves the two jobs'
// responsibilities stay partitioned as designed: this job only ever adds
// findings. An existing open supply_chain finding on a package the feed does
// NOT currently name must be left untouched — resolution stays owned entirely
// by refresh_osv's own reconcile pass (osv.go).
func TestMalFeedWorker_Work_NeverResolvesFindings(t *testing.T) {
	existingID := dbutil.DeterministicID("CVE-2021-23337", "pkg:npm/lodash@4.17.20")
	store := &fakeFindingStore{list: []finding.Finding{
		{ID: existingID, Source: "supply_chain", ResourceID: "pkg:npm/lodash@4.17.20", CheckID: "CVE-2021-23337"},
	}}
	w := &MalFeedWorker{
		querier: &fakeMalFeedQuerier{headSHA: "sha1", records: []osv.MalRecord{{
			Affected: []osv.Package{{Ecosystem: "npm", Name: "keyv", Version: "6.0.0"}},
			Vuln:     osv.Vuln{ID: "MAL-2026-11524"},
		}}},
		assets: &fakePackageStore{assets: []asset.Asset{
			pkgAsset("pkg:npm/lodash@4.17.20", "npm", "lodash", "4.17.20"),
		}},
		findings: store,
	}

	require.NoError(t, w.Work(context.Background(), &river.Job[RefreshMalFeedArgs]{}))
	require.Empty(t, store.resolved, "MalFeedWorker must never resolve a finding — that stays refresh_osv's job")
}

// TestMalFeedWorker_DuplicateWithRefreshOSVIsIdempotent proves the two jobs
// produce byte-identical finding IDs for the same advisory+purl — they share
// the exact supplyChainFinding helper, not two divergent ID schemes — so a
// package this job catches and the next refresh_osv run also confirms is an
// idempotent upsert, never a duplicate row.
func TestMalFeedWorker_DuplicateWithRefreshOSVIsIdempotent(t *testing.T) {
	pkg := osv.Package{Ecosystem: "npm", Name: "keyv", Version: "6.0.0"}
	purl := "pkg:npm/keyv@6.0.0"
	vuln := osv.Vuln{ID: "MAL-2026-11524"}

	malStore := &fakeFindingStore{}
	malW := &MalFeedWorker{
		querier:  &fakeMalFeedQuerier{headSHA: "sha1", records: []osv.MalRecord{{Affected: []osv.Package{pkg}, Vuln: vuln}}},
		assets:   &fakePackageStore{assets: []asset.Asset{pkgAsset(purl, "npm", "keyv", "6.0.0")}},
		findings: malStore,
	}
	require.NoError(t, malW.Work(context.Background(), &river.Job[RefreshMalFeedArgs]{}))
	require.Len(t, malStore.recorded, 1)

	osvStore := &fakeFindingStore{}
	osvW := &OSVWorker{
		querier:  &fakeOSVQuerier{affected: map[osv.Package][]osv.Vuln{pkg: {vuln}}},
		assets:   &fakePackageStore{assets: []asset.Asset{pkgAsset(purl, "npm", "keyv", "6.0.0")}},
		findings: osvStore,
	}
	require.NoError(t, osvW.Work(context.Background(), &river.Job[RefreshOSVArgs]{}))
	require.Len(t, osvStore.recorded, 1)

	require.Equal(t, malStore.recorded[0].ID, osvStore.recorded[0].ID,
		"same advisory+purl must produce the same deterministic finding ID from both jobs")
}
