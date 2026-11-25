package main

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/v1/google"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/belief"
	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/enrichcache"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/forget"
	"github.com/vulngraph/vulngraph/internal/app/graphstore"
	"github.com/vulngraph/vulngraph/internal/app/scan"
	"github.com/vulngraph/vulngraph/internal/db"
	"github.com/vulngraph/vulngraph/internal/intel/epss"
	"github.com/vulngraph/vulngraph/internal/intel/osv"
	"github.com/vulngraph/vulngraph/internal/intel/scc"
	"github.com/vulngraph/vulngraph/internal/jobs"
	"github.com/vulngraph/vulngraph/internal/llm"
	"github.com/vulngraph/vulngraph/internal/obs"
	"github.com/vulngraph/vulngraph/internal/reason"
	"github.com/vulngraph/vulngraph/internal/scanner/imagevuln"
	"github.com/vulngraph/vulngraph/internal/scanner/nuclei"
	"github.com/vulngraph/vulngraph/pkg/log"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

// bundledScanner builds the scanner both the worker and the scanner pod run:
// every bundled connector, narrowed by SCAN_SCANNERS. An unknown name in
// SCAN_SCANNERS refuses startup rather than leaving nothing enabled.
func bundledScanner(getenv func(string) string) (scan.Scanner, error) {
	s, err := scan.NewMultiScanner(enabledScanners(getenv), nuclei.New())
	if err != nil {
		return nil, fmt.Errorf("SCAN_SCANNERS: %w", err)
	}
	return s, nil
}

// enabledScanners parses SCAN_SCANNERS (comma-separated connector names) into
// the set NewMultiScanner uses. An empty or unset value returns an empty map,
// which enables every bundled scanner.
func enabledScanners(getenv func(string) string) map[string]bool {
	raw := strings.TrimSpace(getenv("SCAN_SCANNERS"))
	if raw == "" {
		return nil
	}
	enabled := map[string]bool{}
	for name := range strings.SplitSeq(raw, ",") {
		if name = strings.TrimSpace(name); name != "" {
			enabled[name] = true
		}
	}
	return enabled
}

// openGraphDB opens the ladybug in-memory graph engine when LADYBUG_INTERNAL_PORT
// is set (the enable signal: in-memory mode needs no data path). Returns nil
// when ladybug is disabled. An engine the operator asked for that fails to
// open is an error: running on without it would read as a worker that was
// never configured for a graph, with reach and blast-radius signals silently
// gone.
func openGraphDB(getenv func(string) string) (*graphstore.Service, error) {
	return openGraphDBWith(getenv, graphstore.Open)
}

type graphOpener func(path string, bufferPoolMB, poolSize, queryThreads int, snapshotPath string) (*graphstore.Service, error)

func openGraphDBWith(getenv func(string) string, open graphOpener) (*graphstore.Service, error) {
	if getenv("LADYBUG_INTERNAL_PORT") == "" {
		return nil, nil
	}
	// 1280MB default: too small a pool fails on large graphs, too large a pool
	// starves the Go heap at peak respond-agent load (many concurrent LLM calls
	// spike memory). Size it together with the container memory limit.
	// Resolved via workerLadybugBufferMB so the memory budget (applyMemoryBudget)
	// and the pool itself can never read different values.
	bufferMB := workerLadybugBufferMB(getenv)
	poolSize := 0 // 0 = use graphstore default (8)
	if v := getenv("LADYBUG_POOL_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			poolSize = n
		}
	}
	queryThreads := 0 // 0 = use graphstore default (2)
	if v := getenv("LADYBUG_QUERY_THREADS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			queryThreads = n
		}
	}
	// LADYBUG_SNAPSHOT_PATH: where topology snapshots are written after each full
	// rebuild and read at startup. Unset or empty uses /data/ladybug/snapshot.gz.
	// Snapshots cannot be disabled, so mount a writable volume there (the chart's
	// ladybug.snapshotEnabled), or every restart logs a write failure and
	// cold-rebuilds from ClickHouse.
	snapshotPath := getenv("LADYBUG_SNAPSHOT_PATH")
	if snapshotPath == "" {
		snapshotPath = "/data/ladybug/snapshot.gz"
	}
	db, err := open("", bufferMB, poolSize, queryThreads, snapshotPath)
	if err != nil {
		return nil, fmt.Errorf("openGraphDB: LADYBUG_INTERNAL_PORT is set but the graph engine failed to open: %w", err)
	}
	// LADYBUG_LOAD_THREADS: COPY bulk-load parallelism. 0 = graphstore default
	// (min(NumCPU,4)). The COPY loader partitions rel-table inserts across these.
	if v := getenv("LADYBUG_LOAD_THREADS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			db.SetLoadThreads(n)
		}
	}
	return db, nil
}

// openServeReplica opens the serve pod's own Ladybug replica when
// SERVE_LADYBUG_ENABLED is on, and returns nil when it is off. A replica the
// operator asked for that fails to open is an error: serving on without it
// would look like a pod that was never configured for one.
func openServeReplica(getenv func(string) string, open graphOpener) (*graphstore.Service, int, error) {
	// Smaller than the worker's pool — serve is read-only, no BFS. Resolved via
	// serveLadybugBufferMB so the memory budget and the pool agree.
	bufMB, err := serveLadybugBufferMB(getenv)
	if err != nil || bufMB == 0 {
		return nil, 0, err
	}
	// SERVE_LADYBUG_SNAPSHOT_PATH (optional) lets the serve replica warm-start from
	// its own snapshot on a container restart instead of a full ClickHouse read.
	svc, err := open("", bufMB, 0, 0, getenv("SERVE_LADYBUG_SNAPSHOT_PATH"))
	if err != nil {
		return nil, 0, fmt.Errorf("openServeReplica: SERVE_LADYBUG_ENABLED is set but the replica failed to open: %w", err)
	}
	return svc, bufMB, nil
}

// severityAdjudicator builds the belief-grounded severity adjudicator when
// ADJUDICATOR_ENABLED is on, else nil. It spends LLM budget, so it is off by
// default and bounded by the moderate cost posture (DefaultSweepConfig: 40/sweep
// cap, N-cascade, plus change-driven caching so a stable finding is judged
// once). Defaults to the provider's default model, same as the remediation
// reasoner; ADJUDICATOR_MODEL runs a cheaper tier.
func severityAdjudicator(ctx context.Context, getenv func(string) string, ch *db.CH, client llm.Client) (*belief.Adjudicator, error) {
	on, err := jobs.SwitchFromEnv(getenv, jobs.AdjudicatorEnabledEnv)
	if err != nil || !on {
		return nil, err
	}
	model := getenv("ADJUDICATOR_MODEL")
	adj := belief.NewAdjudicator(belief.NewCHRepo(ch), reason.New(client, model), belief.DefaultSweepConfig())
	log.FromContext(ctx).Info().Str("model", model).Msg("worker: severity adjudicator enabled (moderate posture)")
	return adj, nil
}

// retryLadybugSync keeps rebuilding the worker's Ladybug graph with capped backoff
// until it reports Ready() (or ctx is cancelled). It's the safety net for a
// failed initial load: without it the worker would sit unready — and serve's
// Cypher would lean entirely on its own replica — until the next correlate sweep
// (up to 30 min). A correlate sweep that succeeds first satisfies the loop, so
// the two never fight for long (SyncFromSources serialises on the swap lock).
func retryLadybugSync(ctx context.Context, svc *graphstore.Service, syncFn jobs.LadybugSyncer) {
	if svc == nil || syncFn == nil {
		return
	}
	backoff := 5 * time.Second
	const maxBackoff = 2 * time.Minute
	for !svc.Ready() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if svc.Ready() {
			return
		}
		if err := syncFn.Sync(ctx); err != nil {
			log.FromContext(ctx).Warn().Err(err).Dur("next_retry", backoff).
				Msg("worker: background ladybug resync failed — will retry")
			backoff = min(backoff*2, maxBackoff)
			continue
		}
	}
	log.FromContext(ctx).Info().Msg("worker: background ladybug resync succeeded — graph ready")
}

// refreshLadybugAfterWarmStart runs a single background sync after a snapshot
// warm-start to catch the graph up to the current ClickHouse topology. The
// snapshot already satisfies readiness, so this is best-effort with light retry
// (a correlate sweep would refresh it anyway, just later).
func refreshLadybugAfterWarmStart(ctx context.Context, syncFn jobs.LadybugSyncer) {
	if syncFn == nil {
		return
	}
	backoff := 5 * time.Second
	const maxBackoff = 2 * time.Minute
	for attempt := 0; attempt < 5; attempt++ {
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if err := syncFn.Sync(ctx); err != nil {
			log.FromContext(ctx).Warn().Err(err).Msg("worker: post-warm-start ladybug refresh failed — will retry")
			backoff = min(backoff*2, maxBackoff)
			continue
		}
		log.FromContext(ctx).Info().Msg("worker: ladybug refreshed to current topology after warm-start")
		return
	}
}

// beliefFormer adapts belief.Service to enrich.BeliefFormer, mapping the enrich
// primitive inputs to belief.SeverityInputs (keeps enrich independent of belief).
type beliefFormer struct{ svc *belief.Service }

func (b beliefFormer) FormBelief(ctx context.Context, in enrich.BeliefInput) error {
	_, err := b.svc.Form(ctx, belief.SeverityInputs{
		FindingID: in.FindingID, ResourceID: in.ResourceID,
		Score: in.Score, Band: in.Band,
		MustFixClass: in.MustFixClass, MustFixReason: in.MustFixReason,
		TrustEntry: in.TrustEntry, PageFloor: in.PageFloor, HighFloor: in.HighFloor,
	})
	return err
}

// imageVulnOSVAdapter adapts osv.Client to imagevuln.VulnQuerier, batched: one
// Query call resolves every package in an image, preserving severity + fixed
// version.
type imageVulnOSVAdapter struct{ c *osv.Client }

// errOSVIncomplete: OSV answered, but not in full — an advisory failed to
// hydrate or a package's ecosystem was refused. The answer is a lower bound, and
// a scanner that published it would call the missing advisories clean.
var errOSVIncomplete = errors.New("osv: advisory lookup incomplete")

func (a imageVulnOSVAdapter) VulnsFor(ctx context.Context, pkgs []imagevuln.Package) (map[imagevuln.Package][]imagevuln.Vuln, error) {
	osvPkgs := make([]osv.Package, len(pkgs))
	for i, p := range pkgs {
		osvPkgs[i] = osv.Package{Ecosystem: p.Ecosystem, Name: p.Name, Version: p.Version}
	}
	res, incomplete, err := a.c.Query(ctx, osvPkgs)
	if err != nil {
		return nil, err
	}
	if len(incomplete) > 0 {
		return nil, fmt.Errorf("%w: %d of %d packages", errOSVIncomplete, len(incomplete), len(pkgs))
	}
	out := make(map[imagevuln.Package][]imagevuln.Vuln, len(res))
	for op, vulns := range res {
		ip := imagevuln.Package{Ecosystem: op.Ecosystem, Name: op.Name, Version: op.Version}
		for _, h := range osv.Hits(vulns) {
			title, description := h.Describe(op.Name)
			v := imagevuln.Vuln{
				CheckID:      h.CheckID,
				Advisory:     h.Advisory(),
				Title:        title,
				Description:  description,
				Severity:     h.Severity,
				FixedVersion: h.Vuln.FixedVersion(op),
			}
			if osv.IsMalicious(h.CheckID) {
				v.CVE = h.Vuln.CVE()
			}
			out[ip] = append(out[ip], v)
		}
	}
	return out, nil
}

// ladybugSyncFn wraps a graphstore.Service as a jobs.LadybugSyncer closure.
// On each sync it reads the topology_version from sync_state:
//   - unchanged since the last sync → RefreshSignals (no Ladybug rebuild, fast)
//   - changed or unknown → SyncFromSources, which decides rebuild-vs-skip via
//     its load-digest gate
//
// Returns nil when svc is nil (ladybug disabled).
func ladybugSyncFn(svc *graphstore.Service, assetSvc *asset.Service, findingSvc *finding.Service, chClient *db.CH, epssCache *epss.Cache, metrics *obs.Metrics) jobs.LadybugSyncer {
	if svc == nil {
		return nil
	}
	signals := &graphSignalSource{findings: findingSvc, epss: epssCache}
	// Record the sync path from INSIDE graphstore, not in this closure: an
	// observation here would miss every serve-pod rebuild even though both pods
	// expose /metrics.
	svc.WithSyncMetrics(metrics)

	return jobs.LadybugSyncFn(func(ctx context.Context) error {
		topoVersion, err := readTopologyVersion(ctx, chClient)
		if err == nil && topoVersion != 0 && topoVersion == svc.LastTopologyVersion() {
			// Topology unchanged — fast signal-only refresh.
			return svc.RefreshSignals(ctx, signals)
		}
		// Topology changed (or first sync, or version read failed) — hand off to
		// SyncFromSources, which owns the real rebuild-vs-skip decision via its
		// own load-digest gate. SyncFromSources records the sync path and the
		// rebuild duration itself.
		ctx, end := obs.SpanJob(ctx, "ladybug.rebuild")
		defer end()
		return svc.SyncFromSources(ctx, topoVersion, assetSvc, assetSvc, signals)
	})
}

const readTopoVersionQ = `SELECT max(version) FROM sync_state FINAL WHERE key = 'topology_version'`

// toUnixTimestamp64Milli gives millisecond resolution so two correlate sweeps
// completing within the same wall-clock second get distinct versions.
// toUnixTimestamp (second precision) would let the second run silently skip a
// full Ladybug rebuild even though topology changed.
const bumpTopoVersionQ = `INSERT INTO sync_state (key, version) VALUES ('topology_version', toUnixTimestamp64Milli(now64()))`

// readTopologyVersion reads the current topology version from sync_state.
// Returns 0 on error or when the table doesn't exist yet (migration not applied).
func readTopologyVersion(ctx context.Context, ch *db.CH) (uint64, error) {
	var version uint64
	err := ch.Select(ctx, func(rows driver.Rows) error {
		for rows.Next() {
			if err := rows.Scan(&version); err != nil {
				return err
			}
		}
		return rows.Err()
	}, readTopoVersionQ)
	if err != nil {
		return 0, err
	}
	return version, nil
}

// bumpTopologyVersion writes a new monotonic topology_version to sync_state.
// Called by the correlate worker after every completed full sweep, whether or not
// topology changed.
func bumpTopologyVersion(ctx context.Context, ch *db.CH) error {
	return ch.Exec(ctx, bumpTopoVersionQ)
}

// topologyBumperFn returns a jobs.TopologyBumper backed by a CH Exec call.
// Returns nil when ch is nil (CH not configured).
func topologyBumperFn(ch *db.CH) jobs.TopologyBumper {
	if ch == nil {
		return nil
	}
	return topologyBumperCH{ch: ch}
}

type topologyBumperCH struct{ ch *db.CH }

func (t topologyBumperCH) BumpTopologyVersion(ctx context.Context) error {
	return bumpTopologyVersion(ctx, t.ch)
}

// graphSignalSource adapts finding.Service to graphstore.SignalSource, mapping
// the finding rollup into the graph's node-signal shape. Lives here (not in
// graphstore) so graphstore needn't import the finding domain.
type graphSignalSource struct {
	findings interface {
		SignalsByResource(ctx context.Context) (map[string]finding.ResourceSignals, error)
	}
	// epss is optional: when non-nil, EPSSScore is populated for package nodes
	// whose CveID is present in the catalog. nil = EPSSScore stays 0.
	epss interface {
		Score(cve string) (float64, bool)
	}
}

func (g *graphSignalSource) SignalsByResource(ctx context.Context) (map[string]graphstore.NodeSignals, error) {
	raw, err := g.findings.SignalsByResource(ctx)
	if err != nil {
		return nil, err
	}
	out := make(map[string]graphstore.NodeSignals, len(raw))
	for id, s := range raw {
		// Base on NewNodeSignals so InternetHops defaults to ReachUnknown, not the
		// zero value 0 (= "directly internet-exposed"). The reach overlay in
		// prewarmSignalCache is the only code that assigns a real hop count.
		sig := graphstore.NewNodeSignals()
		sig.HasKEV = s.HasKEV
		sig.Exploitable = s.Exploitable
		sig.MaxScore = int(s.MaxScore)
		sig.PrivescCount = s.PrivescCount
		sig.CveID = s.CveID
		if g.epss != nil && s.CveID != "" {
			if score, ok := g.epss.Score(s.CveID); ok {
				sig.EPSSScore = score
			}
		}
		out[id] = sig
	}
	return out, nil
}

// graphCtxSvc implements jobs.GraphContextProvider by combining the asset and
// finding services. It supplies the two graph-derived inputs for the enrichment
// fingerprint via two fast point queries.
type graphCtxSvc struct {
	assets interface {
		IsExposedEdge(ctx context.Context, assetID string) (bool, error)
	}
	findings interface {
		ByResourceIDs(ctx context.Context, ids []string) ([]finding.Finding, error)
	}
}

func (g *graphCtxSvc) IsExposedEdge(ctx context.Context, resourceID string) (bool, error) {
	return g.assets.IsExposedEdge(ctx, resourceID)
}

func (g *graphCtxSvc) PrivescBucket(ctx context.Context, resourceID string) (string, error) {
	findings, err := g.findings.ByResourceIDs(ctx, []string{resourceID})
	if err != nil {
		return "0", fmt.Errorf("PrivescBucket: %w", err)
	}
	count := 0
	for _, f := range findings {
		if f.Type == "ciem_privesc" {
			count++
		}
	}
	return enrichcache.PrivescBucketFor(count), nil
}

// parseDuration parses a Go duration string (e.g. "2h", "30m") and returns 0
// when the value is absent or unparseable. 0 in Deps fields means "use the
// hardcoded default in jobs/client.go".
func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return d
}

// imageVulnSource builds the image-vuln scanner, choosing where image filesystems
// come from.
//
// Default is the registry-pull source. IMAGE_SCAN_ROOT overrides it with a
// mounted, pre-unpacked rootfs (useful for local work), and IMAGE_SCAN_DISABLED
// turns the sweep off outright. Every CVE match is an api.osv.dev query, so the
// sweep is also off whenever the OSV feed is (INTEL_OSV_DISABLED / OFFLINE_MODE)
// — jobs.PeriodicConfigFromEnv applies the same rule to the scanner's schedule.
//
// Credentials: private ECR registries authenticate with the enabled AWS
// connector for the registry's account (ecr:GetAuthorizationToken, see
// docs/iam/ecr-image-pull-permission.md); then the GCP keychain (ADC-accessible
// Artifact/Container Registry); then anonymous for public registries (e.g.
// registry.k8s.io). The pod's docker config is consulted only when the operator
// opts in with IMAGE_REGISTRY_DOCKER_KEYCHAIN=true. Azure ACR and other private
// registries otherwise have no keychain — those images fail per image with a
// recorded reason rather than failing the run, a coverage gap rather than an
// outage.
//
// Network: image references come from connector data, so every registry dial
// is SSRF-guarded (safenet.NewGuardedTransport); a private registry on
// RFC-1918 space is reachable only once its prefix is listed in
// IMAGE_REGISTRY_ALLOW_PRIVATE. An invalid list stops the worker.
func imageVulnSource(ctx context.Context, getenv func(string) string, feeds jobs.Feeds, connectors connectorLister) (jobs.ImageVulnScanner, error) {
	logger := log.FromContext(ctx)
	imageScanOff, err := jobs.SwitchFromEnv(getenv, jobs.ImageScanDisabledEnv)
	if err != nil {
		return nil, fmt.Errorf("imageVulnSource: %w", err)
	}
	if !feeds.OSV {
		logger.Warn().Msg("worker: image-vuln scanner DISABLED — the OSV feed it matches against is switched off")
		return nil, nil
	}
	if imageScanOff {
		logger.Warn().Msg("worker: image-vuln scanner DISABLED — no OS-package visibility into container images")
		return nil, nil
	}
	osvAdapter := imageVulnOSVAdapter{osv.NewClient()}
	if root := strings.TrimSpace(getenv("IMAGE_SCAN_ROOT")); root != "" {
		logger.Info().Str("root", root).Msg("worker: image-vuln scanner enabled (local rootfs source)")
		return imagevuln.New(imagevuln.LocalImageSource{Root: root}, osvAdapter).
			WithAdvisorySources(feeds.AdvisorySources()), nil
	}
	allow, err := safenet.ParseAllowPrefixes(getenv("IMAGE_REGISTRY_ALLOW_PRIVATE"))
	if err != nil {
		return nil, fmt.Errorf("imageVulnSource: IMAGE_REGISTRY_ALLOW_PRIVATE: %w", err)
	}
	maxStream, err := imageScanMaxStream(getenv)
	if err != nil {
		return nil, fmt.Errorf("imageVulnSource: %w", err)
	}
	logger.Info().Int("private_prefixes_allowed", len(allow)).Msg("worker: image-vuln scanner enabled (registry-pull source)")
	return imagevuln.New(imagevuln.RegistryImageSource{
		Keychain:       registryKeychain(getenv, connectors),
		Transport:      safenet.NewGuardedTransport(registryDialTimeout, allow),
		MaxStreamBytes: maxStream,
	}, osvAdapter).WithAdvisorySources(feeds.AdvisorySources()), nil
}

// imageScanMaxStream reads IMAGE_SCAN_MAX_STREAM_GIB, the uncompressed layer
// bytes one image scan reads before it stops and reports scan_incomplete.
// Unset is 0, which the source reads as its 4 GiB default. The stream is never
// held in memory, so raising it costs pull time and bandwidth, not memory.
func imageScanMaxStream(getenv func(string) string) (int64, error) {
	raw := strings.TrimSpace(getenv("IMAGE_SCAN_MAX_STREAM_GIB"))
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("IMAGE_SCAN_MAX_STREAM_GIB: %q is not a positive whole number of GiB", raw)
	}
	return int64(n) << 30, nil
}

// registryDialTimeout bounds one registry connection and response header.
const registryDialTimeout = 30 * time.Second

// registryKeychain is the image pull's credential chain. The ambient docker
// keychain (~/.docker/config.json, $DOCKER_CONFIG) is opt-in: a scanner must
// not silently acquire whatever registry credentials happen to be on the pod
// and present them to a registry an attacker-influenced image ref names.
func registryKeychain(getenv func(string) string, connectors connectorLister) authn.Keychain {
	chain := []authn.Keychain{&imagevuln.ECRKeychain{Tokens: newECRTokenSource(connectors)}, google.Keychain}
	if strings.EqualFold(strings.TrimSpace(getenv("IMAGE_REGISTRY_DOCKER_KEYCHAIN")), "true") {
		chain = append(chain, authn.DefaultKeychain)
	}
	return authn.NewMultiKeychain(chain...)
}

// enrichMaxAge is the freshness backstop for the enrich change-gate.
// Unset or unparseable yields 0, which the worker reads as its built-in default.
func enrichMaxAge(getenv func(string) string) time.Duration {
	d, err := time.ParseDuration(strings.TrimSpace(getenv("ENRICH_MAX_AGE")))
	if err != nil {
		return 0
	}
	return d
}

// sccFetcher builds the GCP Security Command Center threat-finding feed, or nil
// when SCC_ORG_ID is unset (feed disabled — no worker/periodic registered).
// SCC_QUOTA_PROJECT is the project the API bills to (must have the SCC API
// enabled); empty uses ADC's default.
func sccFetcher(getenv func(string) string) jobs.SCCFetcher {
	org := strings.TrimSpace(getenv("SCC_ORG_ID"))
	if org == "" {
		return nil
	}
	return scc.NewFetcher(org, strings.TrimSpace(getenv("SCC_QUOTA_PROJECT")))
}

// forgetPopulation adapts asset.CHRepo to forget.PopulationReader, translating
// the two storage-shaped result types into the forget domain's own. Lives here,
// not in forget, so the domain that decides what to forget does not import the
// domain that stores assets (CLAUDE.md layering).
type forgetPopulation struct {
	repo *asset.CHRepo
}

func (f forgetPopulation) ScopeStaleness(ctx context.Context, connectorID string, types []string, absentBefore, confirmedBefore time.Time) ([]forget.StoredCount, error) {
	rows, err := f.repo.ScopeStaleness(ctx, connectorID, types, absentBefore, confirmedBefore)
	if err != nil {
		return nil, err
	}
	out := make([]forget.StoredCount, 0, len(rows))
	for _, r := range rows {
		out = append(out, forget.StoredCount{
			Region: r.Region, Type: r.Type,
			Stored: r.Stored, Absent: r.Absent, Confirmed: r.Confirmed,
		})
	}
	return out, nil
}

func (f forgetPopulation) ScopeCandidateIDs(ctx context.Context, connectorID, assetType, region string, confirmedBefore time.Time, limit int) ([]forget.Candidate, error) {
	rows, err := f.repo.ScopeCandidateIDs(ctx, connectorID, assetType, region, confirmedBefore, limit)
	if err != nil {
		return nil, err
	}
	out := make([]forget.Candidate, 0, len(rows))
	for _, r := range rows {
		out = append(out, forget.Candidate{ID: r.ID, LastSeen: r.LastSeen})
	}
	return out, nil
}

// forgetService builds the deletion-decision evaluator.
//
// FORGET_MODE selects shadow (default) or enforce. An unparseable value is
// logged at ERROR and treated as shadow: a typo in a deployment env var must
// never be the reason inventory starts being forgotten, and it must never be
// silent either.
//
// FORGET_ENFORCE_TYPES (comma-separated asset types, e.g.
// "security_group,vpc") scopes ModeEnforce to a subset of
// forget.TombstoneEligibleTypes: only a type on this list gets a tombstone
// written, and it has no effect under FORGET_MODE=shadow. Left unset, enforce
// mode enforces nothing (fail closed). A type outside
// forget.TombstoneEligibleTypes is an error, and the worker does not start.
//
// graphDB is passed as the edge-health source and may be nil (a pod without
// Ladybug). forget then refuses every scope with edge_health_unknown rather than
// assuming the topology was read in full — the counts are still recorded, which
// is the whole value in shadow mode.
func forgetService(ctx context.Context, getenv func(string) string, pool *pgxpool.Pool, repo *asset.CHRepo, graphDB *graphstore.Service, metrics *obs.Metrics) (*forget.Service, error) {
	logger := log.FromContext(ctx)
	mode, err := forget.ParseMode(getenv("FORGET_MODE"))
	if err != nil {
		logger.Error().Err(err).Msg("worker: FORGET_MODE not understood — running in shadow mode (nothing will be forgotten)")
	}
	enforceTypes, err := forget.ParseEnforceTypes(getenv("FORGET_ENFORCE_TYPES"))
	if err != nil {
		return nil, fmt.Errorf("FORGET_ENFORCE_TYPES: %w", err)
	}
	var edges forget.EdgeHealth
	if graphDB != nil {
		edges = graphDB
	}
	metrics.SetForgetEnforcing(mode == forget.ModeEnforce)
	switch {
	case mode == forget.ModeEnforce && len(enforceTypes) > 0:
		configured := make([]string, 0, len(enforceTypes))
		for t := range enforceTypes {
			configured = append(configured, t)
		}
		logger.Warn().Strs("enforce_types", configured).
			Msg("worker: FORGET_MODE=enforce — proven-gone assets of the FORGET_ENFORCE_TYPES types will be TOMBSTONED (recorded, never deleted); every other audited type stays shadow-only")
	case mode == forget.ModeEnforce:
		logger.Warn().Msg("worker: FORGET_MODE=enforce but FORGET_ENFORCE_TYPES is unset — enforcing NOTHING (fail closed); every audited type stays shadow-only until a type is added to FORGET_ENFORCE_TYPES")
	default:
		logger.Info().Msg("worker: deletion authority in shadow mode — decisions recorded, nothing acted on")
	}
	return forget.NewService(mode, enforceTypes, forgetPopulation{repo: repo}, forget.NewPGRepo(pool), edges, metrics), nil
}
