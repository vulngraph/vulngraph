package jobs

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/db/sqlcgen"
	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/internal/intel/osv"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// osvRescanAfter is how long before a previously-scanned package is eligible
// for re-scanning. Weekly is long enough to catch newly-published advisories
// without hammering OSV with the whole inventory on every daily run.
const osvRescanAfter = 7 * 24 * time.Hour

// osvReconcilePageLimit paginates the open-supply_chain scan in the reconcile
// pass at List's max page size (same reason as kevListPageLimit).
const osvReconcilePageLimit = 200

// OSVQuerier resolves package versions to the advisories affecting them.
// *osv.Client implements it; tests fake it.
type OSVQuerier interface {
	// Query returns advisories per package plus the packages whose advisory
	// hydration was incomplete this run (a lower bound — the reconcile must not
	// resolve findings on those, since an absent advisory may be a transient miss
	// rather than a withdrawal).
	Query(ctx context.Context, pkgs []osv.Package) (result map[osv.Package][]osv.Vuln, incomplete map[osv.Package]bool, err error)
}

// PackageStore is the slice of the asset service the advisory jobs need: one
// pass over the live package inventory, a page at a time (a full-row
// aggregation of a large inventory OOMs under ClickHouse's per-query limit).
type PackageStore interface {
	ScanLivePackages(ctx context.Context, fn func([]asset.PackageCoord) error) (asset.PackageScan, error)
}

// RefreshOSVArgs sweeps the package inventory through OSV and records one
// supply-chain finding per affected package×advisory.
type RefreshOSVArgs struct{}

func (RefreshOSVArgs) Kind() string { return "refresh_osv" }

// InsertOpts puts the refresh on the enrich queue: it fans out over the whole
// inventory, which would tie up the single LLM-bound respond worker for too
// long. Singleton with 3 attempts (periodicSingletonOpts): the Postgres scan
// cursor makes a retry resume rather than restart, and the daily tick is the
// retry past that.
func (RefreshOSVArgs) InsertOpts() river.InsertOpts {
	return periodicSingletonOpts(queueEnrich, 3)
}

// Timeout overrides River's default 1-minute timeout. A full first-run scan of
// a large package inventory (many OSV batches + advisory hydration) can take a
// long time. Incremental daily runs are far faster — only packages outside
// osvRescanAfter are queried.
func (OSVWorker) Timeout(_ *river.Job[RefreshOSVArgs]) time.Duration {
	return 45 * time.Minute
}

// OSVWorker queries OSV for every package asset and records the findings.
type OSVWorker struct {
	river.WorkerDefaults[RefreshOSVArgs]
	querier  OSVQuerier
	assets   PackageStore
	findings FindingStore
	pool     *pgxpool.Pool
	// departures reads the evidence a package that left the inventory is
	// judged on (package_departure.go). A missing reader proves nothing: no
	// departure resolves except by aging out.
	departures departureReaders
}

func (w *OSVWorker) Work(ctx context.Context, _ *river.Job[RefreshOSVArgs]) error {
	// Nil querier: the feed is switched off (INTEL_OSV_DISABLED / OFFLINE_MODE)
	// and the periodic is not scheduled; a stray job completes as a no-op.
	if w.querier == nil {
		log.FromContext(ctx).Debug().Msg("osv: feed disabled — skipping refresh")
		return nil
	}
	// Load packages already scanned within the rescan window, with when — skip
	// those unless a purl mapping to one appeared after its scan. pool is nil
	// only in unit tests; skip the optimisation in that case.
	alreadyScanned := map[osv.Package]time.Time{}
	var q *sqlcgen.Queries
	if w.pool != nil {
		q = sqlcgen.New(w.pool)
		recentRows, err := q.GetScannedPackagesSince(ctx, time.Now().Add(-osvRescanAfter))
		if err != nil {
			return fmt.Errorf("Work: load scanned packages: %w", err)
		}
		for _, r := range recentRows {
			alreadyScanned[osv.Package{Ecosystem: r.Ecosystem, Name: r.Name, Version: r.Version}] = r.ScannedAt
		}
	}

	// Page through the package inventory, skipping recently-scanned ones.
	// live tracks every valid package seen this run regardless of scan
	// recency — used below to prune osv_scanned_packages rows for packages
	// that no longer exist (see DeleteOrphanedScannedPackages).
	//
	// purlFor is one-to-many: source-keyed distributions are queried by source
	// package at the source version (distro.AdvisoryQuery), so libssl3 and
	// openssl at one version are ONE query whose advisories land on both
	// binaries' nodes.
	//
	// unsourced holds the purls of source-keyed packages whose node carries no
	// source name (dpkg via SSM, GCP OS Config — or an image-scanned node last
	// rewritten by one of those). They are still asked by binary name, which
	// matches only binaries that share their source's name, so the answer is a
	// lower bound and the reconcile must never read an absence there as a fix.
	//
	// held keeps the purls of recently-scanned packages until the pass is
	// over: one first seen after its package's scan (a new binary under an
	// already-scanned source, a new image shipping a scanned version) puts the
	// whole package back in the scan now rather than up to osvRescanAfter later.
	// It keeps only what a rescan queues (id, binary name, unsourced), never
	// the coordinate's metadata map: it spans most of the inventory.
	live := make(map[osv.Package]bool)
	var inv packageInventory
	purlFor := make(map[osv.Package][]string)
	binaryName := map[string]string{}
	unsourced := map[string]bool{}
	unserved := map[string]int{}
	held := map[osv.Package][]heldPurl{}
	// unverified: purls this job holds no complete advisory read for — not
	// queryable here, asked by binary name, or incomplete this run. An upgrade
	// onto one is not claimed as a fix (resolveDepartures) until it is read.
	unverified := map[string]bool{}
	rescan := map[osv.Package]bool{}
	queue := func(p osv.Package, h heldPurl) {
		purlFor[p] = append(purlFor[p], h.id)
		binaryName[h.id] = h.binary
		if h.unsourced {
			unsourced[h.id] = true
		}
	}
	scan, err := w.assets.ScanLivePackages(ctx, func(coords []asset.PackageCoord) error {
		for _, a := range coords {
			eco := a.Metadata["ecosystem"]
			name, version := distro.AdvisoryQuery(eco, a.Metadata["package"], a.Metadata["version"],
				a.Metadata[pkginventory.MetaSourcePackage], a.Metadata[pkginventory.MetaSourceVersion])
			p := osv.Package{Ecosystem: eco, Name: name, Version: version}
			if p.Ecosystem == "" || p.Name == "" || p.Version == "" || p.Version == "0.0.0" {
				// 0.0.0 is GitHub's placeholder for indirect deps with no pinned version —
				// OSV can't match without a real version, so skip rather than burn quota.
				unverified[a.ID] = true
				continue
			}
			if !osv.Supported(eco) {
				// Amazon Linux / Oracle Linux are matched by the distro advisory
				// feeds (distro_advisories.go); CentOS by nothing. Counted, never
				// sent: one such query fails OSV's whole batch.
				family, _, _ := strings.Cut(eco, ":")
				unserved[family]++
				unverified[a.ID] = true
				continue
			}
			live[p] = true
			f, keyed := distro.FamilyOf(eco)
			h := heldPurl{id: a.ID, binary: a.Metadata["package"],
				unsourced: keyed && f.SourceKeyed && a.Metadata[pkginventory.MetaSourcePackage] == ""}
			if h.unsourced {
				unverified[a.ID] = true // its advisory read is a lower bound
			}
			if scannedAt, ok := alreadyScanned[p]; ok {
				held[p] = append(held[p], h)
				// A zero FirstSeen is unknown: keep the skip rather than rescan
				// every node without one on every run.
				if !a.FirstSeen.IsZero() && a.FirstSeen.After(scannedAt) {
					rescan[p] = true
				}
				continue
			}
			queue(p, h)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("Work: list packages: %w", err)
	}
	inv = packageInventory{ids: scan.LiveIDs, listedAt: scan.ListedAt, unverified: unverified}
	for p := range rescan {
		for _, h := range held[p] {
			queue(p, h)
		}
	}
	held = nil

	logger := log.FromContext(ctx)
	if len(unserved) > 0 {
		logger.Info().Interface("packages_by_family", unserved).
			Msg("osv refresh: packages on ecosystems OSV does not serve skipped (distro advisory feeds or no source)")
	}

	// The full pagination above completed without error, so `live` is a
	// trustworthy snapshot of the current inventory — prune every
	// osv_scanned_packages row for a package no longer in it (an image rebuild
	// that bumped a version, or nothing running it any more). Left alone, such
	// a row is never re-queried and never ages out, permanently depressing the
	// oldest-scan gauge; and a package that left the inventory has its
	// findings resolved as resource_gone below, so if it comes back it must be
	// re-queried on the next run to reopen them, not skipped as recently
	// scanned.
	if q != nil {
		ecosystems := make([]string, 0, len(live))
		names := make([]string, 0, len(live))
		versions := make([]string, 0, len(live))
		for p := range live {
			ecosystems = append(ecosystems, p.Ecosystem)
			names = append(names, p.Name)
			versions = append(versions, p.Version)
		}
		pruned, err := q.DeleteOrphanedScannedPackages(ctx, sqlcgen.DeleteOrphanedScannedPackagesParams{
			Cutoff:     inv.listedAt,
			Ecosystems: ecosystems,
			Names:      names,
			Versions:   versions,
		})
		if err != nil {
			// Non-fatal: worst case a stale row lingers one more cycle.
			logger.Warn().Err(err).Msg("osv: failed to prune orphaned scanned packages")
		} else if pruned > 0 {
			logger.Info().Int64("pruned", pruned).Msg("osv: pruned orphaned scanned-package rows")
		}
	}

	pkgs := make([]osv.Package, 0, len(purlFor))
	for p := range purlFor {
		pkgs = append(pkgs, p)
	}

	logger.Info().
		Int("total_scanned", len(alreadyScanned)).
		Int("new_to_scan", len(pkgs)).
		Msg("osv refresh: incremental scan")

	if len(pkgs) == 0 {
		logger.Info().Msg("osv refresh: nothing new to scan")
		// Still reconcile packages that left the inventory, and still regroup:
		// VM inventories change between refreshes even when no package needed
		// a fresh advisory lookup.
		w.reconcile(ctx, inv, nil, nil, nil, nil)
		enqueueVMVuln(ctx)
		enqueueBaseImages(ctx)
		return nil
	}

	affected, incomplete, err := w.querier.Query(ctx, pkgs)
	if err != nil {
		return fmt.Errorf("Work: query osv: %w", err)
	}
	for p := range incomplete {
		for _, purl := range purlFor[p] {
			unverified[purl] = true
		}
	}

	// Mark every fully-read package as scanned — even ones with no findings —
	// but never an incomplete one: the stamp skips it for osvRescanAfter, so a
	// transient hydrate/paging failure would hide its advisories for a week
	// rather than being retried on the next run.
	ecosystems := make([]string, 0, len(pkgs))
	names := make([]string, 0, len(pkgs))
	versions := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		if incomplete[p] {
			continue
		}
		ecosystems = append(ecosystems, p.Ecosystem)
		names = append(names, p.Name)
		versions = append(versions, p.Version)
	}
	if q != nil {
		if err := q.MarkPackagesScanned(ctx, sqlcgen.MarkPackagesScannedParams{
			Ecosystems: ecosystems,
			Names:      names,
			Versions:   versions,
		}); err != nil {
			// Non-fatal: worst case we re-scan these packages next run.
			logger.Warn().Err(err).Msg("osv: failed to mark packages scanned")
		}
	}

	now := time.Now()
	var found []finding.Finding
	for p, vulns := range affected {
		for _, h := range osv.Hits(vulns) {
			for _, purl := range purlFor[p] {
				found = append(found, supplyChainFinding(p, purl, binaryName[purl], h, now))
			}
		}
	}
	if len(found) > 0 {
		if err := w.findings.RecordObserved(ctx, found); err != nil {
			return fmt.Errorf("Work: record findings: %w", err)
		}
		enqueueEnrich(ctx, found)
		// Immediately kick a KEV refresh so newly-ingested supply-chain findings
		// with CVE IDs get their known_exploited flag set before the daily KEV
		// periodic fires.
		if client, cerr := river.ClientFromContextSafely[pgx.Tx](ctx); cerr == nil {
			if _, err := client.Insert(ctx, RefreshKEVArgs{}, nil); err != nil {
				logger.Warn().Err(err).Msg("osv: could not enqueue kev refresh")
			}
		}
	}

	// Reconcile: a package re-scanned this run whose advisory was
	// withdrawn or patched no longer appears in `found`, so its previously-open
	// supply_chain finding must resolve — otherwise a fixed CVE dangles until the
	// 365d TTL. Scoped to purls actually scanned this run (the incremental scan
	// skips recently-scanned packages, so a finding on a NOT-scanned purl is left
	// untouched — absence there means "not re-checked", not "resolved").
	if len(unsourced) > 0 {
		logger.Info().Int("packages", len(unsourced)).
			Msg("osv refresh: source-keyed distro packages without a source name asked by binary name — lower bound, excluded from the reconcile")
	}
	w.reconcile(ctx, inv, purlFor, incomplete, unsourced, found)

	logger.Info().
		Int("scanned", len(pkgs)).
		Int("findings", len(found)).
		Msg("osv inventory refreshed")
	enqueueVMVuln(ctx)
	enqueueBaseImages(ctx)
	return nil
}

// reconcile runs reconcileSupplyChain and logs its outcome. Best-effort: a
// list/resolve error is logged without failing the refresh.
func (w *OSVWorker) reconcile(ctx context.Context, inv packageInventory, purlFor map[osv.Package][]string, incomplete map[osv.Package]bool, unsourced map[string]bool, found []finding.Finding) {
	fixed, gone, err := w.reconcileSupplyChain(ctx, inv, purlFor, incomplete, unsourced, found)
	logger := log.FromContext(ctx)
	if err != nil {
		logger.Warn().Err(err).Msg("osv: supply-chain reconcile skipped")
	}
	logger.Info().Int("fixed", fixed).Int("resource_gone", gone).Msg("osv: supply-chain reconcile")
}

// reconcileSupplyChain resolves open supply_chain findings two ways, never
// both on one finding:
//   - fixed: the package was re-scanned this run but no longer has the
//     matching advisory (patched/withdrawn);
//   - departed: the package has left the live inventory (inv.gone) and every
//     runner it had is accounted for (resolveDepartures) — fixed when it was
//     upgraded in place or within its lineage, else resource_gone, which is
//     not a remediation claim.
//
// Returns the counts resolved.
func (w *OSVWorker) reconcileSupplyChain(ctx context.Context, inv packageInventory, purlFor map[osv.Package][]string, incomplete map[osv.Package]bool, unsourced map[string]bool, found []finding.Finding) (fixed, gone int, err error) {
	// Only reconcile purls whose advisory set was FULLY read this run. A package
	// with an incomplete hydrate, or a source-keyed binary asked by its own name,
	// has a lower-bound `found`, so resolving its "missing" findings could close a
	// still-valid advisory — strictly worse than leaving it to dangle.
	scannedPurls := make(map[string]bool, len(purlFor))
	for pkg, purls := range purlFor {
		if !incomplete[pkg] {
			for _, purl := range purls {
				if !unsourced[purl] {
					scannedPurls[purl] = true
				}
			}
		}
	}
	currentIDs := make(map[string]bool, len(found))
	for _, f := range found {
		currentIDs[f.ID] = true
	}

	var (
		toFix, departed []finding.Finding
		cursor          string
	)
	for {
		batch, err := w.findings.List(ctx, finding.Filter{Source: "supply_chain", Limit: osvReconcilePageLimit, Cursor: cursor})
		if err != nil {
			return 0, 0, fmt.Errorf("reconcileSupplyChain: list: %w", err)
		}
		for _, f := range batch {
			switch {
			case inv.gone(f):
				departed = append(departed, f)
			// Only touch findings on packages we actually re-scanned this run; if
			// the advisory is gone from the fresh scan, close it.
			case scannedPurls[f.ResourceID] && !currentIDs[f.ID]:
				toFix = append(toFix, f)
			}
		}
		if len(batch) < osvReconcilePageLimit {
			break
		}
		cursor = finding.EncodeCursor(batch[len(batch)-1], false)
	}
	verified := func(purl string) bool { return inv.ids[purl] && !inv.unverified[purl] }
	upgraded, toGone := resolveDepartures(ctx, w.departures, "refresh_osv", departed, verified, time.Now())
	toFix = append(toFix, upgraded...)
	if err := w.findings.Resolve(ctx, toFix, finding.ReasonFixed); err != nil {
		return 0, 0, fmt.Errorf("reconcileSupplyChain: resolve fixed: %w", err)
	}
	if err := w.findings.Resolve(ctx, toGone, finding.ReasonResourceGone); err != nil {
		return len(toFix), 0, fmt.Errorf("reconcileSupplyChain: resolve gone: %w", err)
	}
	return len(toFix), len(toGone), nil
}

// packageInventory is one COMPLETE pass over the live package listing
// (asset.Service.ScanLivePackages): its live-id set and when it started. Built
// only once every page read without error — a listing that failed part-way
// returns before any reconcile, so a read error never resolves anything.
type packageInventory struct {
	ids      map[string]bool
	listedAt time.Time
	// unverified holds the live purls without a complete advisory read this
	// run (OSV refresh only; nil elsewhere).
	unverified map[string]bool
}

// heldPurl is what a rescan queues for one already-scanned purl.
type heldPurl struct {
	id, binary string
	unsourced  bool
}

// gone reports whether f is a package finding whose package has left the live
// inventory — no fresh runs_package/depends_on edge points at it. That makes it
// a CANDIDATE only: a lapsed edge looks the same during a producer outage, so
// resolveDepartures decides on positive evidence (package_departure.go). A
// producer that observes the package again reopens it (RecordObserved clears
// ResolvedAt).
//
// Two degraded inputs are refused rather than read as "gone":
//   - an EMPTY inventory: zero live packages is what a broken producer
//     pipeline looks like too, and resolving the whole estate on it would turn
//     an outage into a mass closure;
//   - a finding observed AFTER the listing began: its producer saw the package
//     after this snapshot was taken (an image scan ingesting a new package
//     mid-run), so absence from the snapshot says nothing about it.
func (inv packageInventory) gone(f finding.Finding) bool {
	return len(inv.ids) > 0 &&
		f.ResourceType == "package" &&
		!inv.ids[f.ResourceID] &&
		f.LastObservedAt.Before(inv.listedAt)
}

// OSVScanStaleness reads the Postgres half of the OSV scan-staleness gauge
// (internal/obs/metrics.go): how many packages osv_scanned_packages has ever
// recorded, and the oldest scanned_at among them. The ClickHouse half —
// current package-inventory size — comes separately from
// asset.Service.CountPackages; the two are combined by the caller
// (cmd/graph/worker_metrics.go) because they live in different stores.
//
// Mirrors QueueDepths' posture (obs.go): log and return zero-value on failure
// rather than propagating an error, so one failed metrics read never blocks a
// scrape.
func OSVScanStaleness(ctx context.Context, pool *pgxpool.Pool) (scannedCount int64, oldest time.Time, err error) {
	q := sqlcgen.New(pool)
	row, err := q.GetOSVScanStaleness(ctx)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("OSVScanStaleness: query failed — osv scan-staleness metrics skipped this scrape")
		return 0, time.Time{}, fmt.Errorf("OSVScanStaleness: %w", err)
	}
	if row.ScannedCount == 0 {
		return 0, time.Time{}, nil // nothing scanned yet — oldest is meaningless, not "epoch"
	}
	return row.ScannedCount, row.OldestScannedAt, nil
}

// upgradeRemediation names the fix. Source-keyed distributions are queried by
// SOURCE package, so the fixed version is the source's: for a binary built
// from a differently-named source (libssl3 from openssl) the text says so, or
// it pairs the binary's name with another package's version.
func upgradeRemediation(binary, source, fixed string) string {
	if binary == "" || binary == source {
		return fmt.Sprintf("Upgrade %s to %s or later.", source, fixed)
	}
	return fmt.Sprintf("Upgrade %s to the build from source package %s %s or later.", binary, source, fixed)
}

// supplyChainFinding shapes one hit into a finding on the binary package purl
// (named name). The hit's check id is one CVE of the advisory — a distro
// advisory bundling several CVEs becomes one finding per CVE, so KEV and EPSS see
// each — or the advisory id when it names none, and ALWAYS for a MAL-*
// (OpenSSF malicious-packages) advisory whatever CVE it aliases.
//
// A malicious-package advisory that also has a CVE alias is not a rare edge
// case — it's the norm for the highest-profile campaigns, which are exactly
// the ones that get a CVE assigned. isMaliciousPackage
// (internal/app/enrich/sources_supply_chain.go) gates purely on a "MAL-"
// CheckID prefix, so preferring the CVE alias here would silently defeat that
// check, reinstating the must-fix/score-floor demotion it exists to prevent
// on precisely the incidents that matter most.
//
// The id is DeterministicID(checkID, purl) — unchanged from the per-advisory
// scheme for an advisory's first CVE — and the advisory ids stay as references.
func supplyChainFinding(p osv.Package, purl, name string, h osv.Hit, now time.Time) finding.Finding {
	v := h.Vuln
	malicious := osv.IsMalicious(v.ID)
	title, description := h.Describe(p.Name)
	remediation := "No fixed version published yet; review the advisory."
	if fixed := v.FixedVersion(p); fixed != "" {
		remediation = upgradeRemediation(name, p.Name, fixed)
	}
	meta := map[string]string{"advisory": h.Advisory()}
	// A malicious package is not remediated by upgrading. The advisory says the
	// published artefact contains hostile code, so anything that installed it
	// must be treated as compromised — "no fixed version published yet" reads as
	// "wait for one", which is the opposite of what this needs.
	if malicious {
		remediation = fmt.Sprintf(
			"Remove %s immediately — there is no fixed version, the published package is malicious. "+
				"Treat every host and CI job that installed it as compromised: rotate the credentials and "+
				"tokens reachable from those builds, then audit for outbound exfiltration around the install time.",
			name)
		if cve := v.CVE(); cve != "" {
			// Preserved even though it lost the CheckID slot above, so KEV
			// (internal/intel/kev) and EPSS (internal/app/enrich/sources_epss.go)
			// can still match this finding by its CVE alias via their
			// Metadata["cve"] fallback — a confirmed-malicious package is not
			// exempt from also being a tracked, possibly actively-exploited CVE.
			meta["cve"] = cve
		}
	}
	return finding.Finding{
		ID:           dbutil.DeterministicID(h.CheckID, purl),
		Source:       "supply_chain",
		Type:         "vulnerable_dependency",
		Severity:     h.Severity,
		Title:        title,
		Description:  description,
		ResourceType: "package",
		ResourceID:   purl,
		ResourceName: name,
		Region:       "global",
		CheckID:      h.CheckID,
		Remediation:  remediation,
		DetectedAt:   now,
		Metadata:     meta,
	}
}
