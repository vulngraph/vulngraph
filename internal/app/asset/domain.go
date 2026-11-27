// Package asset owns the cloud asset inventory and the relationship graph
// between assets. Assets and edges are stored in
// ClickHouse; an asset is also a graph node, so blast radius is a bounded
// traversal over edges between asset IDs.
package asset

import (
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/graphschema"
)

// Provider is the cloud/source an asset came from.
type Provider string

const (
	ProviderAWS        Provider = "aws"
	ProviderGCP        Provider = "gcp"
	ProviderGitHub     Provider = "github"
	ProviderKubernetes Provider = "kubernetes"
	ProviderAzure      Provider = "azure"
)

// Values for the `public_access` metadata key, set by collectors alongside
// `public` to grade what the public flag actually proves. Confirmed means the
// resource was observed unauthenticated-reachable (public bucket policy/ACL,
// function URL with no auth). Possible means configuration merely permits or
// does not prevent exposure — a missing public-access-block, an API behind
// optional authorizers, a network-reachable database that still requires
// credentials. graphstore grades Asset.public_tier from this key.
//
// Reachability correlation emits exposed_to_internet for BOTH tiers and copies
// the grade onto the edge under EdgePropPublicAccess — the tier decides how far
// from the internet the BFS starts and whether the node is LABELLED exposed, not
// whether the edge exists (see correlate/domain.go).
const (
	PublicAccessConfirmed = "confirmed"
	PublicAccessPossible  = "possible"
	// PublicAccessNone is an OBSERVATION, not a silence: the collector read the
	// resource policy and it grants nothing to the public. It exists so that an
	// absent key means one thing only — "not read" — because a check written as
	// `public_access == confirmed` cannot otherwise tell a clean result from a
	// blind one, and its silence gets scored as a pass either way.
	PublicAccessNone = "none"

	// EdgePropPublicAccess is the exposed_to_internet edge property carrying the
	// tier above. Declared here, beside the vocabulary it holds, so the producer
	// (correlate) and the two consumers (the graphstore reach BFS and the
	// ClickHouse exposure point-query) cannot drift on the spelling.
	EdgePropPublicAccess = "public_access"
)

// Package-inventory known-ness, stamped by the cloud collectors on every VM
// (ec2_instance, gce_instance) so that "no runs_package edges" can never be read
// as "nothing vulnerable installed". MetaPackageInventory names where the VM's
// software inventory came from; PackageInventoryNone is an OBSERVATION that no
// usable inventory exists (agent not installed, offline, stale, denied, over a
// cost cap), and MetaPackageInventoryGap says which. An ABSENT key means the
// collector never asked, and reads exactly like none: only PackageInventoryKnown
// may license a claim built on the absence of a package.
//
// MetaPackageCVEMatchable is the second half of known-ness: an inventory whose
// packages no advisory source can fully match (no feed for the OS, an end-of-life
// release, binary names against a feed keyed by source package) can be missing
// CVEs, so a VM with a known inventory and zero CVE findings is still only clean
// when this is "true". MetaPackageCVEGap says why it is "false" (CVEGap* below).
const (
	MetaPackageInventory           = "package_inventory"
	MetaPackageInventoryGap        = "package_inventory_gap"
	MetaPackageInventoryObservedOn = "package_inventory_observed_on" // UTC date the agent captured it — a day, not an instant, so the asset hash stays stable between agent runs
	MetaPackageEcosystem           = "package_ecosystem"             // OSV ecosystem the packages were stamped with
	MetaPackageCVEMatchable        = "package_cve_matchable"
	MetaPackageCVEGap              = "package_cve_gap"

	PackageInventorySSM      = "ssm"
	PackageInventoryOSConfig = "osconfig"
	PackageInventoryDisk     = "disk" // read from a VM disk snapshot (agentless disk scan)
	PackageInventoryNone     = "none"

	// MetaDiskScan says whether a VM's disk was read: DiskScanScanned, or
	// DiskScanNotEnabled when the connector has not opted in, or DiskScanNone
	// when it is enabled but no readable disk produced an inventory.
	// MetaDiskScanGap is then the diskscan gap value. Absent reads as none.
	MetaDiskScan    = "disk_scan"
	MetaDiskScanGap = "disk_scan_gap"

	DiskScanScanned    = "scanned"
	DiskScanNotEnabled = "not_enabled"
	DiskScanNone       = "none"

	// CVEGapEOLDistro: the release is past end of life and its vendor publishes
	// no further advisories (CentOS Linux, Amazon Linux 1/2).
	CVEGapEOLDistro = "eol_distro"
	// CVEGapNoAdvisorySource: no advisory source covers the distribution.
	CVEGapNoAdvisorySource = "no_advisory_source"
	// CVEGapNoSourceNames: the source keys advisories by source package and the
	// inventory reports binary names only (dpkg via SSM, every GCP OS Config list).
	CVEGapNoSourceNames = "no_source_package_names"
	// CVEGapUnknownRelease: the release could not be read, so no release-scoped
	// advisory set can be chosen.
	CVEGapUnknownRelease = "unknown_release"
	// CVEGapAdvisorySourceDisabled: the advisory source covering the
	// distribution is switched off in this deployment (INTEL_OSV_DISABLED,
	// INTEL_ALAS_DISABLED, INTEL_ELSA_DISABLED, OFFLINE_MODE), so nothing is
	// matched against it.
	CVEGapAdvisorySourceDisabled = "advisory_source_disabled"
	// CVEGapPackageDBUnread: the scanned filesystem runs a known distribution
	// but its OS package database yielded no packages — an rpm database that
	// could not be read in full (corrupt, an unknown format, too large), or no
	// dpkg/apk/rpm database the scanner reads at all — so none of its OS
	// packages were inventoried.
	CVEGapPackageDBUnread = "package_db_unread"
	// CVEGapScanIncomplete: the image scan stopped before reading every layer
	// (the stream or retention cap, a corrupt or unreadable layer). Layers are
	// read newest-first, so what was lost is the oldest — usually the base
	// layer carrying os-release and the OS package database.
	CVEGapScanIncomplete = "scan_incomplete"
)

// MetaPublicIPKnown is "false" on an asset whose collector could not read
// whether it has a public IP this sweep (an Azure VM whose NIC read failed).
// Its PublicIP is then "" for want of an answer, not because the address went
// away, so change tracking keeps the last observed address rather than report
// a lost exposure.
const MetaPublicIPKnown = "public_ip_known"

// PublicIPUnread reports whether a's collector could not read its public IP.
func PublicIPUnread(a Asset) bool { return a.Metadata[MetaPublicIPKnown] == "false" }

// MetaAccessorsKnown is "false" on an asset whose collector could not read who
// may access it (a secret whose IAM policy read failed), so the inbound edges
// that would name its dependents were never emitted this sweep.
const MetaAccessorsKnown = "accessors_known"

// DependentsUnread reports whether a's inbound dependent edges are incomplete
// because the collector could not read them. A dependents count taken from the
// graph for such an asset is a lower bound, not a measurement: it must never
// support "nothing relies on this".
func DependentsUnread(a Asset) bool {
	return a.Metadata[MetaAccessorsKnown] == "false"
}

// Base-image identity of a container_image, as the image-vuln sweep recorded
// it (ADR 088). The keys are set on an in-memory copy of the image asset by the
// base-image job, never written to the assets table: several collectors
// rewrite a container_image row whole on every sync, so a scanner-written key
// there would be erased within one sync interval.
const (
	MetaBaseImage       = "base_image"        // the base image the image names; "" unless annotated
	MetaBaseImageDigest = "base_image_digest" // the named base's digest, when it gives one
	MetaBaseImageSource = "base_image_source" // annotation | os_release | unknown
	MetaBaseOS          = "base_os"           // base OS release coordinate ("Debian:12"); absent when unknown
	// MetaWorkloadExposed: "true" when a workload running the image is directly
	// internet-exposed, "false" when none is; set alongside the base keys.
	MetaWorkloadExposed = "workload_internet_exposed"
)

// ImageBase is one container image's recorded base identity, keyed by the
// container_image asset id. A digest is immutable, so the identity of a
// scanned image never changes; ScannedAt is the last scan that confirmed it.
type ImageBase struct {
	ImageID         string
	BaseImage       string
	BaseImageDigest string
	BaseImageSource string
	BaseOS          string
	ScannedAt       time.Time
}

// PackageInventoryKnown reports whether a VM's runs_package edges are a complete
// observation of what is installed on it.
func PackageInventoryKnown(meta map[string]string) bool {
	v := meta[MetaPackageInventory]
	return v == PackageInventorySSM || v == PackageInventoryOSConfig || v == PackageInventoryDisk || v == PackageInventoryBYOA
}

// PackageCVEClaimable reports whether a VM's package inventory can support a CVE
// verdict either way: known, AND on an OS whose packages an advisory feed covers.
func PackageCVEClaimable(meta map[string]string) bool {
	return PackageInventoryKnown(meta) && meta[MetaPackageCVEMatchable] == "true"
}

// Asset is one discovered resource. ID is the provider-native identifier
// (ARN, GCP resource name, "org/repo") and is globally unique across providers.
type Asset struct {
	ID           string
	Name         string
	Type         string // ec2_instance, gcs_bucket, github_repo, ...
	Provider     Provider
	Region       string
	AccountID    string
	Endpoint     string
	PublicIP     string
	PrivateIP    string
	Domain       string
	Tags         map[string]string
	Metadata     map[string]string
	RiskScore    uint8 // 0-100
	DiscoveredAt time.Time
	LastSeen     time.Time

	// FirstDiscoveredAt is the asset's TRUE first observation, immutable under
	// re-collection — the asset-side twin of finding.FirstDetectedAt.
	// DiscoveredAt is NOT immutable: every collector stamps `now` on it on
	// every sweep, so it means "last collected", not "first discovered".
	// Service.Ingest pins FirstDiscoveredAt on every write by carrying the
	// previous value forward (Service.earliest), the same mechanism
	// finding.Service.RecordObserved uses. Zero means "unknown", never 1970.
	FirstDiscoveredAt time.Time
}

// SyncProjection narrows what a bulk sync read materialises in Go memory.
//
// It exists because the graph loader is the one reader that needs almost none of an
// asset's Tags/Metadata/edge properties, and decoding all of them for every asset in
// a full graph rebuild costs memory disproportionate to what's actually read — a
// meaningful multiple of RSS on a worker with a fixed memory budget.
//
// The zero value means "everything", so a reader that has not thought about projection
// keeps today's behaviour.
type SyncProjection struct {
	// MetadataKeys narrows Metadata to these keys. Empty means every key.
	MetadataKeys []string
	// EdgePropertyKeys narrows each Edge's Properties to these keys. Empty means
	// every key.
	EdgePropertyKeys []string
	// SkipTags leaves Tags nil. Only safe for readers that never touch them —
	// graphstore is one (nothing under internal/app/graphstore reads .Tags), while the
	// asset API, correlate's deploys_to label matching, enrich's safety guard and the
	// respond context pack all do, and they use different queries.
	SkipTags bool
}

// Edge is a directed relationship between two assets, e.g. a security group
// "protects" an instance, or a repo "deploys_to" a workload.
type Edge struct {
	SrcID      string
	SrcType    string
	DstID      string
	DstType    string
	EdgeType   string // protects, runs_in, deploys_to, can_access, ...
	Properties map[string]string
}

// PackageRunner is one runner that shipped or depended on a package at some
// point inside graph_edges' TTL — the evidence a package's departure from the
// live inventory is judged on. A lapsed edge alone proves nothing: it lapses
// the same way when the runner's producer is down.
type PackageRunner struct {
	PackageID  string
	RunnerID   string
	RunnerType string
	EdgeType   string    // runs_package or depends_on
	EdgeAt     time.Time // the runner→package edge's newest stamp
	// InventoryAt is the runner's newest stamp on ANY edge of EdgeType: when
	// its producer last observed its package inventory. Producers write a
	// runner's edges only on a successful read, so InventoryAt well after
	// EdgeAt means the producer re-read the runner and the package was gone.
	InventoryAt time.Time
}

// AssetSyncResult is the outcome of the bulk asset fetch for the Ladybug sync.
// Truncated is set when the fetch hit syncAssetLimit: the graph may be
// missing assets, so the build must treat its coverage as incomplete.
type AssetSyncResult struct {
	Assets    []Asset
	Truncated bool
}

// EdgeSyncResult is the outcome of a bulk edge fetch for the Ladybug sync: the
// edges plus completeness accounting, so the graph build can distinguish "this
// node has no attack path" from "we didn't fetch the edges that would show one".
type EdgeSyncResult struct {
	Edges []Edge
	// TruncatedTypes marks edge types whose fetch hit a row cap — coverage for
	// them is partial (deterministically so: the bulk query orders before
	// capping, but partial nonetheless).
	TruncatedTypes map[string]bool
	// BulkPassFailed is set when the bulk-tier query errored entirely and the
	// sync continued with critical edges only.
	BulkPassFailed bool
}

// FetchComplete reports whether the fetch covered every synced edge tier in
// full: no pass errored, no type hit a row cap. This is the completeness
// check — graphstore's fidelity gate refuses to publish a build for which it
// is false.
//
// ReachComplete (below) is a narrower, different check: it only asks about
// the Reach/Inherit edge types, which graphschema.TestReachAndInheritTypesAreCritical
// forces into the uncapped critical tier. In a healthy build ReachComplete is
// always true even when FetchComplete is false — it is a tier-misconfiguration
// detector, not a substitute for completeness. Do not use one in place of the
// other.
//
// Detail() renders the same facts for a log line and an alert annotation.
func (r EdgeSyncResult) FetchComplete() bool {
	return !r.BulkPassFailed && len(r.TruncatedTypes) == 0
}

// Detail describes the fetch's coverage in one operator-readable clause, for the log
// line and the refusal reason. Empty when coverage was complete.
func (r EdgeSyncResult) Detail() string {
	var parts []string
	if r.BulkPassFailed {
		parts = append(parts, "bulk pass errored")
	}
	if len(r.TruncatedTypes) > 0 {
		trunc := make([]string, 0, len(r.TruncatedTypes))
		for t := range r.TruncatedTypes {
			trunc = append(trunc, t)
		}
		sort.Strings(trunc)
		parts = append(parts, "types truncated at a row cap: "+strings.Join(trunc, ", "))
	}
	return strings.Join(parts, "; ")
}

// ReachComplete reports whether every edge type the internet_hops computation
// depends on (Reach types, plus Inherit types since reachability propagates
// across containment without costing a hop) was fetched without truncation.
// When false, internet_hops must degrade to ReachUnknown (fail-open) instead
// of ReachNone — otherwise a finding whose real attack path is simply
// missing from the graph gets silently demoted to "contained".
func (r EdgeSyncResult) ReachComplete() bool {
	for _, types := range []map[string]bool{
		graphschema.ReachEdgeTypes(),
		graphschema.InheritEdgeTypes(),
		graphschema.InheritReverseEdgeTypes(),
	} {
		for t := range types {
			if r.TruncatedTypes[t] {
				return false
			}
			if r.BulkPassFailed && graphschema.TierOf(t) == graphschema.TierBulk {
				return false
			}
		}
	}
	return true
}

// BlastRadius is the set of assets reachable from a seed asset within a hop
// budget, with the seed included at depth 0.
type BlastRadius struct {
	SeedID    string
	Assets    []Asset
	Edges     []Edge
	MaxDepth  int
	Truncated bool // hit the node budget before exhausting the frontier
}

// BlastAccountCounts summarizes the same attacker-direction walk as BlastRadius.
// The seed is excluded. Accountless or missing assets each count independently.
// A truncated walk cannot establish the account distribution of the full graph.
type BlastAccountCounts struct {
	Total     int
	ByAccount map[string]int
	Truncated bool
}

// Filter narrows a List query. Zero values mean "no filter". Provider/Type/
// Region/AccountID are exact matches; Search is a case-insensitive substring on
// name or id. Cursor is the opaque keyset token from a prior page.
type Filter struct {
	Provider  string
	Type      string
	Region    string
	AccountID string
	Search    string
	Exposed   bool // only assets with an ExposedToInternet edge
	MinScore  int  // only assets with risk_score >= MinScore (0 = no filter)
	Limit     int
	Cursor    string
}

// Summary is the inventory breakdown that drives the asset filter UI: total
// count plus counts by provider and by type.
type Summary struct {
	Total      int
	ByProvider map[string]int
	ByType     map[string]int
}

// NormalizeImageRef lowercases a container image reference and strips its tag,
// digest and trailing punctuation, so "eu.gcr.io/p/svc:9f2c…", "eu.gcr.io/p/svc"
// and "EU.GCR.IO/p/svc@sha256:…" all key alike.
//
// It lives in the domain because the image→repo join keys BOTH sides with it:
// the GitHub collector normalises the references it harvests from repo text, and
// the correlate ImageOwnership rule normalises the live container_image names it
// joins them against. Two copies of these rules that drifted apart would drop
// the edge silently.
func NormalizeImageRef(ref string) string {
	ref = strings.ToLower(strings.TrimSpace(ref))
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	// A tag is the last ':' AFTER the last '/', so a port in the registry host
	// ("localhost:5000/img") is never mistaken for one.
	if i := strings.LastIndex(ref, ":"); i > strings.LastIndex(ref, "/") {
		ref = ref[:i]
	}
	return strings.TrimRight(ref, "/.,;\"'")
}

var (
	ErrNotFound      = errors.New("asset: not found")
	ErrInvalidFilter = errors.New("asset: invalid filter")
	ErrBadCursor     = errors.New("asset: invalid cursor")
)
