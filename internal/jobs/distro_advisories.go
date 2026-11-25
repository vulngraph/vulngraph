package jobs

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/intel/rpmver"
	"github.com/vulngraph/vulngraph/internal/intel/updateinfo"
	dbutil "github.com/vulngraph/vulngraph/pkg/db"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// The distro advisory refresh matches Amazon Linux (ALAS) and Oracle Linux
// (ELSA) packages — the rpm distributions OSV does not carry — against their
// vendors' updateinfo feeds (internal/intel/updateinfo). It writes the SAME
// supply_chain finding the OSV refresh writes (source, type, resource, id
// scheme), so the VM fleet regroup (vmvuln.go), KEV and EPSS work unchanged.
//
// One finding per (CVE × package version): an advisory bundles several CVEs,
// and KEV/EPSS match one CVE per finding — keying on the advisory id, or on its
// first CVE, would hide a known-exploited CVE listed second.

const distroAdvisoryRecordBatch = 500

// DistroAdvisoryFetcher returns one release's security advisories.
// *updateinfo.Client implements it; tests fake it.
type DistroAdvisoryFetcher interface {
	Fetch(ctx context.Context, src updateinfo.Source) ([]updateinfo.Advisory, error)
}

// RefreshDistroAdvisoriesArgs sweeps Amazon Linux / Oracle Linux packages
// through their vendor advisory feeds.
type RefreshDistroAdvisoriesArgs struct{}

func (RefreshDistroAdvisoriesArgs) Kind() string { return "refresh_distro_advisories" }

// InsertOpts: the enrich lane, beside the OSV refresh it mirrors — it records
// findings and enqueues their enrichment.
func (RefreshDistroAdvisoriesArgs) InsertOpts() river.InsertOpts {
	return periodicSingletonOpts(queueEnrich, 3)
}

// DistroAdvisoryWorker runs the refresh. sources are the enabled feeds' releases
// (INTEL_ALAS_DISABLED / INTEL_ELSA_DISABLED drop theirs); a nil fetcher or no
// sources is "every distro feed off".
type DistroAdvisoryWorker struct {
	river.WorkerDefaults[RefreshDistroAdvisoriesArgs]
	fetcher  DistroAdvisoryFetcher
	sources  []updateinfo.Source
	assets   PackageStore
	findings FindingStore
	// departures: see OSVWorker.departures.
	departures departureReaders
}

// Timeout: a cold start downloads every release's updateinfo (~40 MB
// compressed across Oracle's repositories); steady state is conditional GETs.
func (DistroAdvisoryWorker) Timeout(_ *river.Job[RefreshDistroAdvisoriesArgs]) time.Duration {
	return 30 * time.Minute
}

// distroPkg is one installed rpm package node.
type distroPkg struct {
	purl, name, version string
}

func (w *DistroAdvisoryWorker) Work(ctx context.Context, _ *river.Job[RefreshDistroAdvisoriesArgs]) error {
	logger := log.FromContext(ctx)
	if w.fetcher == nil || len(w.sources) == 0 {
		logger.Debug().Msg("distro advisories: every feed disabled — skipping refresh")
		return nil
	}
	pkgs, inv, err := w.inventory(ctx)
	if err != nil {
		return fmt.Errorf("Work: %w", err)
	}

	now := time.Now()
	var (
		found     []finding.Finding
		evaluated = map[string]bool{} // purls whose release's advisories were read in full
		attempted int
		failed    []string
	)
	for _, src := range w.sources {
		list := pkgs[src.Ecosystem]
		if len(list) == 0 {
			continue // no host runs the release: no download
		}
		attempted++
		advs, err := w.fetcher.Fetch(ctx, src)
		if err != nil {
			// Unread is not clean: this release's purls are left out of the
			// reconcile, so its open findings stay open.
			logger.Warn().Err(err).Str("ecosystem", src.Ecosystem).Msg("distro advisories: feed unavailable — release skipped, findings left as they were")
			failed = append(failed, src.Ecosystem)
			continue
		}
		found = append(found, matchDistroAdvisories(src, list, advs, now)...)
		for _, p := range list {
			evaluated[p.purl] = true
		}
	}

	for start := 0; start < len(found); start += distroAdvisoryRecordBatch {
		if err := w.findings.RecordObserved(ctx, found[start:min(start+distroAdvisoryRecordBatch, len(found))]); err != nil {
			return fmt.Errorf("Work: record findings: %w", err)
		}
	}
	if len(found) > 0 {
		enqueueEnrich(ctx, found)
		if client, cerr := river.ClientFromContextSafely[pgx.Tx](ctx); cerr == nil {
			if _, err := client.Insert(ctx, RefreshKEVArgs{}, nil); err != nil {
				logger.Warn().Err(err).Msg("distro advisories: could not enqueue kev refresh")
			}
		}
	}
	resolved, err := w.reconcile(ctx, inv, evaluated, found)
	if err != nil {
		logger.Warn().Err(err).Msg("distro advisories: reconcile skipped")
	}
	enqueueVMVuln(ctx)

	logger.Info().Int("releases", attempted).Strs("failed", failed).
		Int("findings", len(found)).Int("resolved", resolved).
		Msg("distro advisories refreshed")
	if attempted > 0 && len(failed) == attempted {
		return fmt.Errorf("Work: every distro advisory feed failed: %s", strings.Join(failed, ", "))
	}
	return nil
}

// inventory pages the live package assets and keeps those on a release some
// source covers, grouped by ecosystem coordinate, plus the complete live
// listing the reconcile reads package departures from.
func (w *DistroAdvisoryWorker) inventory(ctx context.Context) (map[string][]distroPkg, packageInventory, error) {
	wanted := make(map[string]bool, len(w.sources))
	for _, s := range w.sources {
		wanted[s.Ecosystem] = true
	}
	out := map[string][]distroPkg{}
	scan, err := w.assets.ScanLivePackages(ctx, func(coords []asset.PackageCoord) error {
		for _, c := range coords {
			eco := c.Metadata["ecosystem"]
			p := distroPkg{purl: c.ID, name: c.Metadata["package"], version: c.Metadata["version"]}
			if wanted[eco] && p.name != "" && p.version != "" {
				out[eco] = append(out[eco], p)
			}
		}
		return nil
	})
	if err != nil {
		return nil, packageInventory{}, fmt.Errorf("inventory: %w", err)
	}
	return out, packageInventory{ids: scan.LiveIDs, listedAt: scan.ListedAt}, nil
}

// matchDistroAdvisories returns one finding per (CVE × package) for every
// advisory that fixes an installed package at a version newer than the one
// installed, compared with rpm semantics. When several advisories fix the same
// CVE in the same package, the newest fix and the highest severity win: one
// upgrade past it closes them all.
func matchDistroAdvisories(src updateinfo.Source, pkgs []distroPkg, advs []updateinfo.Advisory, now time.Time) []finding.Finding {
	byName := map[string][]*updateinfo.Advisory{}
	for i := range advs {
		for name := range advs[i].Fixed {
			byName[name] = append(byName[name], &advs[i])
		}
	}
	type hit struct {
		pkg   distroPkg
		check string
		adv   *updateinfo.Advisory
		fixed string
		sev   finding.Severity
	}
	hits := map[string]*hit{}
	for _, p := range pkgs {
		for _, a := range byName[p.name] {
			fixed := a.Fixed[p.name]
			// A kernel-line advisory fixes only its own line: a 5.15 fix is
			// not an upgrade target for a host on 5.4.
			if a.Stream != "" && !updateinfo.OnStream(p.version, a.Stream) {
				continue
			}
			if rpmver.Compare(p.version, fixed) >= 0 {
				continue
			}
			checks := a.CVEs
			if len(checks) == 0 {
				checks = []string{a.ID}
			}
			for _, check := range checks {
				id := dbutil.DeterministicID(check, p.purl)
				h := hits[id]
				if h == nil {
					hits[id] = &hit{pkg: p, check: check, adv: a, fixed: fixed, sev: a.Severity}
					continue
				}
				if rpmver.Compare(fixed, h.fixed) > 0 {
					h.adv, h.fixed = a, fixed
				}
				if severityRank(a.Severity) > severityRank(h.sev) {
					h.sev = a.Severity
				}
			}
		}
	}
	out := make([]finding.Finding, 0, len(hits))
	for id, h := range hits {
		url := src.AdvisoryURL(h.adv.ID)
		meta := map[string]string{
			"advisory":        h.adv.ID,
			"advisory_source": src.Feed,
			"advisory_url":    url,
			"fixed_version":   h.fixed,
		}
		if strings.HasPrefix(h.check, "CVE-") {
			meta["cve"] = h.check
		}
		desc := h.adv.Title
		if len(h.adv.CVEs) > 1 {
			desc += "\n\nThe advisory also fixes: " + strings.Join(h.adv.CVEs, ", ") + "."
		}
		out = append(out, finding.Finding{
			ID:           id,
			Source:       "supply_chain",
			Type:         "vulnerable_dependency",
			Severity:     h.sev,
			Title:        fmt.Sprintf("%s in %s (%s)", h.check, h.pkg.name, h.adv.ID),
			Description:  desc + "\n\n" + url,
			ResourceType: "package",
			ResourceID:   h.pkg.purl,
			ResourceName: h.pkg.name,
			Region:       "global",
			CheckID:      h.check,
			Remediation:  fmt.Sprintf("Upgrade %s to %s or later (%s).", h.pkg.name, h.fixed, h.adv.ID),
			DetectedAt:   now,
			Metadata:     meta,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// reconcile resolves this feed's open findings on packages evaluated in full
// this run whose advisory no longer matches (the host was patched) as fixed,
// and those on packages whose departure from the live inventory is proven
// (resolveDepartures) as fixed when upgraded, else resource_gone — the OSV
// refresh does the same for every package finding, but it may be switched off
// while these feeds are on. Packages on a release whose
// feed failed are not in evaluated and are never resolved as fixed.
func (w *DistroAdvisoryWorker) reconcile(ctx context.Context, inv packageInventory, evaluated map[string]bool, found []finding.Finding) (int, error) {
	if len(evaluated) == 0 && len(inv.ids) == 0 {
		return 0, nil
	}
	current := make(map[string]bool, len(found))
	for _, f := range found {
		current[f.ID] = true
	}
	feeds := map[string]bool{}
	for _, s := range w.sources {
		feeds[s.Feed] = true
	}
	var (
		stale, departed []finding.Finding
		cursor          string
	)
	for {
		batch, err := w.findings.List(ctx, finding.Filter{Source: "supply_chain", Limit: osvReconcilePageLimit, Cursor: cursor})
		if err != nil {
			return 0, fmt.Errorf("reconcile: list: %w", err)
		}
		for _, f := range batch {
			if !feeds[f.Metadata["advisory_source"]] {
				continue
			}
			switch {
			case inv.gone(f):
				departed = append(departed, f)
			case evaluated[f.ResourceID] && !current[f.ID]:
				stale = append(stale, f)
			}
		}
		if len(batch) < osvReconcilePageLimit {
			break
		}
		cursor = finding.EncodeCursor(batch[len(batch)-1], false)
	}
	verified := func(purl string) bool { return evaluated[purl] }
	upgraded, gone := resolveDepartures(ctx, w.departures, "refresh_distro_advisories", departed, verified, time.Now())
	stale = append(stale, upgraded...)
	if err := w.findings.Resolve(ctx, stale, finding.ReasonFixed); err != nil {
		return 0, fmt.Errorf("reconcile: resolve fixed: %w", err)
	}
	if err := w.findings.Resolve(ctx, gone, finding.ReasonResourceGone); err != nil {
		return len(stale), fmt.Errorf("reconcile: resolve gone: %w", err)
	}
	return len(stale) + len(gone), nil
}
