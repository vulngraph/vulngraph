package jobs

import (
	"context"
	"sort"
	"strings"
	"time"

	"golang.org/x/mod/semver"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/internal/graphschema"
	"github.com/vulngraph/vulngraph/internal/intel/rpmver"
	"github.com/vulngraph/vulngraph/internal/obs"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// Package departure: when a package leaves the live inventory (no fresh
// runs_package/depends_on edge), its findings resolve only on POSITIVE
// evidence that nothing runs it any more. A lapsed edge is not that evidence:
// it lapses identically when its producer is down — an SSM outage, an image
// stuck in scan backoff, an expired connector credential — while the resource
// keeps running the package. So every runner that had an edge into the
// package inside graph_edges' TTL must be accounted for, one of two ways:
//
//   - superseded: the runner's producer read its inventory again well after
//     the edge's last stamp, and the package was not in it (producers write a
//     runner's edges only on a successful read, so a newer stamp on the
//     runner's other edges IS that read);
//   - gone (assetGone): the sync recorded the runner deleted by a COMPLETE
//     sweep after its last sighting, or it has not been seen for longer than
//     the edge TTL (the bounded fallback for collectors that cannot prove a
//     complete enumeration).
//
// A runner with neither withholds the package. Once its edges age out of the
// TTL the package has no runner evidence at all, and a finding last observed
// before the TTL resolves as resource_gone (aged_out) — withheld findings are
// bounded, never held open forever.
//
// A proven departure is "fixed" when the same package (same purl apart from
// the version) now runs at a NEWER version — under the ecosystem's own
// comparator — on the same runner, or on a live runner of the same lineage
// (the ASG / MIG / AMI fleet, or the image repository a rebuild replaced the
// image in), and that newer purl carries no open finding for the same check.
// Otherwise it is resource_gone.

const (
	// departureMargin separates "a later read" from the skew inside one write
	// (a producer stamps one runner's edges over seconds to minutes). Three
	// collector cadences: a later read is hours later, never minutes.
	departureMargin = 6 * time.Hour
	// departureBatch bounds one evidence read: purls per PackageRunners call,
	// ids per ByIDs/AssetDeletions/EdgesOutBatch/ByResourceIDs call.
	departureBatch = 200
	// departureListLimit is asset.ListByType's ceiling; a lineage listing that
	// reaches it may be truncated, so no "fixed" is claimed from it.
	departureListLimit = 20000
	// graphEdgeTTL is graph_edges' TTL: how far back runner
	// evidence reaches.
	graphEdgeTTL = 30 * 24 * time.Hour
	// absenceFallback bounds how long missing evidence holds a finding open:
	// an asset unseen for longer is presumed gone, and a package with no runner
	// evidence left resolves once its finding was last observed before it.
	absenceFallback = graphEdgeTTL + departureMargin
)

// PackageDepartureStore is the slice of the asset service the departure
// evidence is read through.
type PackageDepartureStore interface {
	PackageRunners(ctx context.Context, packageIDs []string) ([]asset.PackageRunner, error)
	ByIDs(ctx context.Context, ids []string) ([]asset.Asset, error)
	ListByType(ctx context.Context, assetType string, limit int) ([]asset.Asset, error)
	EdgesOutBatch(ctx context.Context, srcIDs []string, edgeType string) ([]asset.Edge, error)
}

// DeletionRecords reads the sync's proven deletions (connector.Service).
type DeletionRecords interface {
	AssetDeletions(ctx context.Context, ids []string) (map[string]time.Time, error)
}

// departureFindingReader checks an upgrade target for a still-open finding.
type departureFindingReader interface {
	ByResourceIDs(ctx context.Context, ids []string) ([]finding.Finding, error)
}

// DepartureObserver publishes departure outcomes. *obs.Metrics satisfies it.
type DepartureObserver interface {
	ObservePackageDepartures(job string, counts map[string]int)
}

// departureReaders is everything a departure judgement reads. A nil reader
// proves nothing: with any missing, no departure resolves except by aging out.
type departureReaders struct {
	assets    PackageDepartureStore
	deletions DeletionRecords
	findings  departureFindingReader
	metrics   DepartureObserver
}

// newDepartureReaders wires the readers from the worker deps, leaving any
// absent service nil (a typed-nil pointer in an interface would read as wired).
func newDepartureReaders(deps Deps) departureReaders {
	var d departureReaders
	if deps.Assets != nil {
		d.assets = deps.Assets
	}
	if deps.Connectors != nil {
		d.deletions = deps.Connectors
	}
	if deps.Findings != nil {
		d.findings = deps.Findings
	}
	if deps.Metrics != nil {
		d.metrics = deps.Metrics
	}
	return d
}

func (d departureReaders) wired() bool {
	return d.assets != nil && d.deletions != nil && d.findings != nil
}

// assetGone reports whether an asset that dropped out of collection is gone:
// the sync recorded it deleted (a complete sweep, its scope proven enumerated)
// after its last sighting, or it has been unseen for longer than
// absenceFallback. A deletion recorded before a later sighting is a resource
// that came back.
func assetGone(a asset.Asset, deletedAt, now time.Time) bool {
	if a.LastSeen.IsZero() {
		return false
	}
	if !deletedAt.IsZero() && deletedAt.After(a.LastSeen) {
		return true
	}
	return now.Sub(a.LastSeen) > absenceFallback
}

// agedOut reports whether a finding with no evidence left to judge it was last
// observed before the absence fallback. An unknown observation time (zero, or
// ClickHouse's epoch) is not old — it is unknown, and stays open.
func agedOut(f finding.Finding, now time.Time) bool {
	return f.LastObservedAt.Year() > 2000 && now.Sub(f.LastObservedAt) > absenceFallback
}

// assetDeletions reads the recorded deletions of ids in batches. A failed
// batch leaves its ids without a record — they prove nothing beyond the
// absence fallback — and is reported so the caller can count it.
func assetDeletions(ctx context.Context, d DeletionRecords, ids []string) (map[string]time.Time, bool) {
	out := map[string]time.Time{}
	if d == nil {
		return out, len(ids) == 0
	}
	ok := true
	for start := 0; start < len(ids); start += departureBatch {
		rows, err := d.AssetDeletions(ctx, ids[start:min(start+departureBatch, len(ids))])
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Msg("departure: deletion records unreadable — batch proves nothing this run")
			ok = false
			continue
		}
		for id, at := range rows {
			out[id] = at
		}
	}
	return out, ok
}

// purlParts splits a purl into its version-free identity and its version:
// "pkg:rpm/amzn/openssl@1:1.0.2k?arch=x86_64" → ("pkg:rpm/amzn/openssl?arch=x86_64",
// "1:1.0.2k"). The qualifiers stay in the identity — another arch is another
// package, not an upgrade.
func purlParts(purl string) (key, version string) {
	at := strings.LastIndex(purl, "@")
	if at < 0 {
		return purl, ""
	}
	key, version = purl[:at], purl[at+1:]
	if q := strings.IndexAny(version, "?#"); q >= 0 {
		key += version[q:]
		version = version[:q]
	}
	return key, version
}

// versionNewer reports whether next is newer than prev under the purl type's
// own version order. ok is false where no comparator exists (apk, Maven,
// PyPI, …): an upgrade there is not claimed — the departure resolves
// resource_gone rather than a "fixed" nobody can verify.
func versionNewer(purlType, prev, next string) (newer, ok bool) {
	switch purlType {
	case "rpm":
		return rpmver.Compare(next, prev) > 0, true
	case "deb":
		return distro.CompareDpkg(next, prev) > 0, true
	case "npm", "cargo", "golang":
		a, b := "v"+strings.TrimPrefix(prev, "v"), "v"+strings.TrimPrefix(next, "v")
		if !semver.IsValid(a) || !semver.IsValid(b) {
			return false, false
		}
		return semver.Compare(b, a) > 0, true
	}
	return false, false
}

// purlType is the purl's type segment ("pkg:deb/debian/…" → "deb").
func purlType(purl string) string {
	typ, _, _ := strings.Cut(strings.TrimPrefix(purl, "pkg:"), "/")
	return typ
}

// lineageOf is the remediation unit a deleted runner is replaced within: its
// fleet (ASG / MIG / AMI) for a VM, its repository for a container image. ok is
// false for anything replaced by something unrelated (a hand-built host, a
// repo, a disk).
func lineageOf(a asset.Asset) (key string, ok bool) {
	if isVMType(a.Type) {
		f := fleetOf(a)
		if f.kind == "instance" {
			return "", false
		}
		return a.Type + "|" + f.key(), true
	}
	if a.Type == "container_image" && a.Name != "" {
		return "image|" + asset.NormalizeImageRef(a.Name), true
	}
	return "", false
}

func isVMType(t string) bool {
	for _, v := range graphschema.VMAssetTypes {
		if v == t {
			return true
		}
	}
	return false
}

// superseded: the runner's producer read it again, well after this edge's
// last stamp, without the package.
func superseded(r asset.PackageRunner) bool {
	return r.InventoryAt.Sub(r.EdgeAt) > departureMargin
}

// departureVerdict is one package's judgement.
type departureVerdict struct {
	outcome string   // obs.Departure*; "" = no runner evidence at all
	targets []string // the newer purls an upgrade moved to (outcome fixed)
}

// departureEvidence is what one pass read about the candidate packages.
type departureEvidence struct {
	runners  map[string][]asset.PackageRunner // by package
	readErr  map[string]bool                  // packages whose runners could not be read
	assets   map[string]asset.Asset           // runner rows, by id
	deletion map[string]time.Time             // recorded deletions, by runner id
	now      time.Time
}

func (e departureEvidence) runnerGone(id string) bool {
	a, ok := e.assets[id]
	return ok && assetGone(a, e.deletion[id], e.now)
}

// accounted reports whether every runner of pkg is superseded or gone.
func (e departureEvidence) accounted(pkg string) bool {
	for _, r := range e.runners[pkg] {
		if !superseded(r) && !e.runnerGone(r.RunnerID) {
			return false
		}
	}
	return true
}

// judgeDepartures returns a verdict per purl. Read failures withhold only the
// packages they concern: one package with too many runners, or one failed
// batch, never stalls every other departure. It judges departureBatch purls
// at a time, so the runner evidence held at once is one batch's — a
// fleet-wide AMI change departs thousands of packages with thousands of
// runners each. The lineage listings are read once and shared.
func judgeDepartures(ctx context.Context, d departureReaders, purls []string, now time.Time) map[string]departureVerdict {
	out := map[string]departureVerdict{}
	if !d.wired() {
		for _, p := range purls {
			out[p] = departureVerdict{outcome: obs.DepartureWithheldReadErr}
		}
		return out
	}
	lineages := &lineageIndex{store: d.assets, now: now}
	for start := 0; start < len(purls); start += departureBatch {
		judgeBatch(ctx, d, lineages, purls[start:min(start+departureBatch, len(purls))], now, out)
	}
	return out
}

// judgeBatch judges one batch of purls into out.
func judgeBatch(ctx context.Context, d departureReaders, lineages *lineageIndex, purls []string, now time.Time, out map[string]departureVerdict) {
	ev := readDepartureEvidence(ctx, d, purls, now)
	var proven []string
	for _, p := range purls {
		switch {
		case ev.readErr[p]:
			out[p] = departureVerdict{outcome: obs.DepartureWithheldReadErr}
		case len(ev.runners[p]) == 0:
			out[p] = departureVerdict{} // no evidence: the caller's age fallback decides
		case !ev.accounted(p):
			out[p] = departureVerdict{outcome: obs.DepartureWithheld}
		default:
			proven = append(proven, p)
		}
	}
	upgrades, failed := upgradedPackages(ctx, d, lineages, ev, proven)
	for _, p := range proven {
		switch {
		case failed[p]:
			out[p] = departureVerdict{outcome: obs.DepartureWithheldReadErr}
		case len(upgrades[p]) > 0:
			out[p] = departureVerdict{outcome: obs.DepartureFixed, targets: upgrades[p]}
		default:
			out[p] = departureVerdict{outcome: obs.DepartureGone}
		}
	}
}

func readDepartureEvidence(ctx context.Context, d departureReaders, purls []string, now time.Time) departureEvidence {
	ev := departureEvidence{runners: map[string][]asset.PackageRunner{}, readErr: map[string]bool{}, assets: map[string]asset.Asset{}, now: now}
	logger := log.FromContext(ctx)
	add := func(rs []asset.PackageRunner) {
		for _, r := range rs {
			ev.runners[r.PackageID] = append(ev.runners[r.PackageID], r)
		}
	}
	for start := 0; start < len(purls); start += departureBatch {
		batch := purls[start:min(start+departureBatch, len(purls))]
		rs, err := d.assets.PackageRunners(ctx, batch)
		if err == nil {
			add(rs)
			continue
		}
		// Isolate the failure to the package that causes it.
		logger.Warn().Err(err).Int("packages", len(batch)).Msg("departure: runner batch unreadable — retrying per package")
		for _, p := range batch {
			rs, err := d.assets.PackageRunners(ctx, []string{p})
			if err != nil {
				logger.Warn().Err(err).Str("package", p).Msg("departure: runners unreadable — package withheld")
				ev.readErr[p] = true
				continue
			}
			add(rs)
		}
	}
	seen := map[string]bool{}
	var runnerIDs []string
	for _, rs := range ev.runners {
		for _, r := range rs {
			if !seen[r.RunnerID] {
				seen[r.RunnerID] = true
				runnerIDs = append(runnerIDs, r.RunnerID)
			}
		}
	}
	sort.Strings(runnerIDs)
	// A runner whose row or deletion record could not be read is simply not
	// proven gone: it withholds its packages, which is the safe direction.
	for start := 0; start < len(runnerIDs); start += departureBatch {
		rows, err := d.assets.ByIDs(ctx, runnerIDs[start:min(start+departureBatch, len(runnerIDs))])
		if err != nil {
			logger.Warn().Err(err).Msg("departure: runner rows unreadable — batch proves nothing this run")
			continue
		}
		for _, a := range rows {
			ev.assets[a.ID] = a
		}
	}
	ev.deletion, _ = assetDeletions(ctx, d.deletions, runnerIDs)
	return ev
}

// upgradedPackages returns, per proven departure, the newer purls of the same
// package now run by a superseded runner itself or by a live runner sharing a
// deleted runner's lineage. failed marks packages whose successors could not
// be read: they are withheld rather than mislabelled resource_gone.
func upgradedPackages(ctx context.Context, d departureReaders, lineages *lineageIndex, ev departureEvidence, proven []string) (map[string][]string, map[string]bool) {
	successors := map[string]map[string]bool{} // package → runner ids
	byEdgeType := map[string]map[string]bool{} // edge type → runner ids to read
	want := func(edgeType, id string) {
		if byEdgeType[edgeType] == nil {
			byEdgeType[edgeType] = map[string]bool{}
		}
		byEdgeType[edgeType][id] = true
	}
	wantLineage := map[string]bool{}
	deletedLineage := map[string][]string{} // package → lineage keys
	for _, p := range proven {
		successors[p] = map[string]bool{}
		for _, r := range ev.runners[p] {
			if superseded(r) {
				successors[p][r.RunnerID] = true
				want(r.EdgeType, r.RunnerID)
				continue
			}
			if key, ok := lineageOf(ev.assets[r.RunnerID]); ok {
				wantLineage[key] = true
				deletedLineage[p] = append(deletedLineage[p], key)
			}
		}
	}
	members, lineageFailed := lineages.members(ctx, wantLineage)
	failed := map[string]bool{}
	for p, keys := range deletedLineage {
		for _, k := range keys {
			if lineageFailed[k] {
				failed[p] = true
			}
			for _, id := range members[k] {
				successors[p][id] = true
				want("runs_package", id)
			}
		}
	}
	current, runnerFailed := currentPackages(ctx, d.assets, byEdgeType)
	upgrades := map[string][]string{}
	for _, p := range proven {
		key, version := purlParts(p)
		typ := purlType(p)
		targets := map[string]bool{}
		for id := range successors[p] {
			if runnerFailed[id] {
				failed[p] = true
			}
			for _, purl := range current[id] {
				k, v := purlParts(purl)
				if k != key {
					continue
				}
				if newer, ok := versionNewer(typ, version, v); ok && newer {
					targets[purl] = true
				}
			}
		}
		for t := range targets {
			upgrades[p] = append(upgrades[p], t)
		}
		sort.Strings(upgrades[p])
	}
	return upgrades, failed
}

// lineageIndex lists the live runners of each lineage, reading each runner
// type's listing at most once per judgement. A listing at its ceiling may be
// truncated and contributes no members — a missing successor only costs the
// "fixed" label. A failed listing marks its lineages failed.
type lineageIndex struct {
	store  PackageDepartureStore
	now    time.Time
	byKey  map[string][]string // lineage key → live runner ids
	read   map[string]bool     // runner types listed (successfully or not)
	failed map[string]bool     // runner types whose listing failed
}

func lineageType(key string) string {
	typ, _, _ := strings.Cut(key, "|")
	if typ == "image" {
		return "container_image"
	}
	return typ
}

// members returns the live runners of each wanted lineage, and which wanted
// lineages could not be listed.
func (l *lineageIndex) members(ctx context.Context, want map[string]bool) (map[string][]string, map[string]bool) {
	if l.byKey == nil {
		l.byKey, l.read, l.failed = map[string][]string{}, map[string]bool{}, map[string]bool{}
	}
	cutoff := l.now.Add(-vmLiveWindow)
	for k := range want {
		typ := lineageType(k)
		if l.read[typ] {
			continue
		}
		l.read[typ] = true
		rows, err := l.store.ListByType(ctx, typ, departureListLimit)
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("type", typ).Msg("departure: lineage listing unreadable")
			l.failed[typ] = true
			continue
		}
		if len(rows) >= departureListLimit {
			continue
		}
		for _, a := range rows {
			if a.LastSeen.Before(cutoff) {
				continue
			}
			if key, ok := lineageOf(a); ok {
				l.byKey[key] = append(l.byKey[key], a.ID)
			}
		}
	}
	out, failed := map[string][]string{}, map[string]bool{}
	for k := range want {
		if l.failed[lineageType(k)] {
			failed[k] = true
		}
		out[k] = l.byKey[k]
	}
	return out, failed
}

// currentPackages reads each runner's fresh package edges of the given type.
func currentPackages(ctx context.Context, store PackageDepartureStore, byEdgeType map[string]map[string]bool) (map[string][]string, map[string]bool) {
	out, failed := map[string][]string{}, map[string]bool{}
	for edgeType, set := range byEdgeType {
		ids := make([]string, 0, len(set))
		for id := range set {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for start := 0; start < len(ids); start += departureBatch {
			batch := ids[start:min(start+departureBatch, len(ids))]
			edges, err := store.EdgesOutBatch(ctx, batch, edgeType)
			if err != nil {
				log.FromContext(ctx).Warn().Err(err).Msg("departure: successor inventory unreadable")
				for _, id := range batch {
					failed[id] = true
				}
				continue
			}
			for _, e := range edges {
				out[e.SrcID] = append(out[e.SrcID], e.DstID)
			}
		}
	}
	return out, failed
}

// resolveDepartures decides the candidate package findings — each on a package
// absent from a complete live listing. It returns those to resolve fixed and
// resource_gone; the rest stay open. A fixed verdict applies to a finding only
// when no upgrade target still carries an open finding for the same check
// (the newer version still vulnerable is a departure, not a fix), and only
// when targetRead vouches that every target's advisories were read in full —
// an absent finding on a target nobody queried is not "cured", so the
// finding is withheld until the target is read. The outcome counts are logged
// and published under job.
func resolveDepartures(ctx context.Context, d departureReaders, job string, candidates []finding.Finding, targetRead func(purl string) bool, now time.Time) (fixed, gone []finding.Finding) {
	purlSet := map[string]bool{}
	var purls []string
	for _, f := range candidates {
		if !purlSet[f.ResourceID] {
			purlSet[f.ResourceID] = true
			purls = append(purls, f.ResourceID)
		}
	}
	sort.Strings(purls)
	verdicts := judgeDepartures(ctx, d, purls, now)
	stillOpen, readOK := openTargetChecks(ctx, d.findings, verdicts)

	counts := map[string]int{}
	for _, f := range candidates {
		v := verdicts[f.ResourceID]
		outcome := v.outcome
		switch outcome {
		case "":
			outcome = obs.DepartureWithheld
			if agedOut(f, now) {
				outcome = obs.DepartureAgedOut
			}
		case obs.DepartureFixed:
			switch {
			case !readOK:
				outcome = obs.DepartureWithheldReadErr
			case !allRead(v.targets, targetRead):
				outcome = obs.DepartureWithheld
			case stillOpen[f.CheckID+"\x00"+f.ResourceID]:
				outcome = obs.DepartureGone
			}
		}
		counts[outcome]++
		switch outcome {
		case obs.DepartureFixed:
			fixed = append(fixed, f)
		case obs.DepartureGone, obs.DepartureAgedOut:
			gone = append(gone, f)
		}
	}
	log.FromContext(ctx).Info().Str("job", job).Interface("outcomes", counts).
		Msg("departure: package findings on packages that left the inventory")
	if d.metrics != nil {
		d.metrics.ObservePackageDepartures(job, counts)
	}
	return fixed, gone
}

// allRead reports whether every target's advisories were read in full; a nil
// targetRead vouches for none.
func allRead(targets []string, targetRead func(string) bool) bool {
	if targetRead == nil {
		return false
	}
	for _, t := range targets {
		if !targetRead(t) {
			return false
		}
	}
	return true
}

// openTargetChecks returns, keyed check\x00departed-purl, the checks still open
// on an upgrade target of that purl. ok is false when a target could not be
// read, so no fixed verdict stands on an unread target.
func openTargetChecks(ctx context.Context, store departureFindingReader, verdicts map[string]departureVerdict) (map[string]bool, bool) {
	out := map[string]bool{}
	targetOf := map[string][]string{} // target purl → departed purls
	var targets []string
	for p, v := range verdicts {
		for _, t := range v.targets {
			if targetOf[t] == nil {
				targets = append(targets, t)
			}
			targetOf[t] = append(targetOf[t], p)
		}
	}
	if len(targets) == 0 {
		return out, true
	}
	if store == nil {
		return out, false
	}
	sort.Strings(targets)
	for start := 0; start < len(targets); start += departureBatch {
		rows, err := store.ByResourceIDs(ctx, targets[start:min(start+departureBatch, len(targets))])
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Msg("departure: upgrade targets' findings unreadable — fixed verdicts withheld")
			return out, false
		}
		for _, f := range rows {
			if f.Resolved() || f.CheckID == "" {
				continue
			}
			for _, p := range targetOf[f.ResourceID] {
				out[f.CheckID+"\x00"+p] = true
			}
		}
	}
	return out, true
}
