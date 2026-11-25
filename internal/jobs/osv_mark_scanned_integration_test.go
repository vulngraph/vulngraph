//go:build integration

package jobs

import (
	"context"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
	"github.com/vulngraph/vulngraph/internal/intel/osv"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
)

// A package whose advisory read came back incomplete must not be stamped as
// scanned: the stamp skips it for osvRescanAfter, so a transient OSV failure
// would hide its advisories for a week instead of being retried next run.
func TestOSVWorker_IncompletePackagesNotMarkedScanned(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	eco := "npm"
	suffix := time.Now().Format("150405.000000")
	complete := osv.Package{Ecosystem: eco, Name: "it-osv-complete-" + suffix, Version: "1.0.0"}
	partial := osv.Package{Ecosystem: eco, Name: "it-osv-partial-" + suffix, Version: "1.0.0"}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM osv_scanned_packages WHERE name = ANY($1)",
			[]string{complete.Name, partial.Name})
	})

	w := &OSVWorker{
		querier: &fakeOSVQuerier{
			affected:   map[osv.Package][]osv.Vuln{},
			incomplete: map[osv.Package]bool{partial: true},
		},
		assets: &fakePackageStore{assets: []asset.Asset{
			pkgAsset("pkg:npm/"+complete.Name+"@1.0.0", eco, complete.Name, "1.0.0"),
			pkgAsset("pkg:npm/"+partial.Name+"@1.0.0", eco, partial.Name, "1.0.0"),
		}},
		findings: &fakeFindingStore{},
		pool:     pool,
	}
	require.NoError(t, w.Work(ctx, &river.Job[RefreshOSVArgs]{}))

	rows, err := sqlcgen.New(pool).GetScannedPackagesSince(ctx, time.Now().Add(-time.Hour))
	require.NoError(t, err)
	marked := map[string]bool{}
	for _, r := range rows {
		marked[r.Name] = true
	}
	require.True(t, marked[complete.Name], "a fully-read package is stamped scanned")
	require.False(t, marked[partial.Name], "an incomplete read is retried next run, not hidden for a week")
}

// A new binary under an already-scanned source package (libssl3 appearing next
// to openssl at the same source version) is queried at once — the whole source
// package is rescanned — instead of waiting out osvRescanAfter with no
// findings. A source whose binaries were all there at its scan stays skipped.
func TestOSVWorker_NewBinaryUnderScannedSourceRescansNow(t *testing.T) {
	ctx := context.Background()
	pool, err := db.NewPool(ctx, pgDSN, db.MaxConnsWorker)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	eco := "SUSE:15.5"
	suffix := time.Now().Format("150405.000000")
	grown, steady := "it-osv-grown-"+suffix, "it-osv-steady-"+suffix
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DELETE FROM osv_scanned_packages WHERE name = ANY($1)", []string{grown, steady})
	})
	require.NoError(t, sqlcgen.New(pool).MarkPackagesScanned(ctx, sqlcgen.MarkPackagesScannedParams{
		Ecosystems: []string{eco, eco}, Names: []string{grown, steady}, Versions: []string{"1.0", "1.0"},
	}))

	bin := func(source, name string, firstSeen time.Time) asset.Asset {
		a := pkgAsset("pkg:rpm/suse/"+name+"@1.0", eco, name, "1.0")
		a.Metadata[pkginventory.MetaSourcePackage] = source
		a.FirstDiscoveredAt = firstSeen
		return a
	}
	before, after := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	q := &fakeOSVQuerier{affected: map[osv.Package][]osv.Vuln{}}
	w := &OSVWorker{
		querier: q,
		assets: &fakePackageStore{assets: []asset.Asset{
			bin(grown, grown, before), bin(grown, "lib"+grown, after), // new binary since the scan
			bin(steady, steady, before), bin(steady, "lib"+steady, before),
		}},
		findings: &fakeFindingStore{},
		pool:     pool,
	}
	require.NoError(t, w.Work(ctx, &river.Job[RefreshOSVArgs]{}))
	require.Equal(t, []osv.Package{{Ecosystem: eco, Name: grown, Version: "1.0"}}, q.queried,
		"only the source that gained a binary is rescanned")
}
