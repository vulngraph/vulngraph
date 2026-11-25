// Package upstream reads the public, machine-readable lists the benchmark
// matrices are pinned to (Prowler's compliance JSONs, kube-bench's cfg tree,
// the AWS Security Hub controls reference, the Azure Policy regulatory
// initiatives) and diffs them against internal/checks/benchmarks.
//
// It never touches the network. Everything it reads comes from a Bundle: an
// fs.FS of raw upstream payloads under stable paths. cmd/benchmark-watch
// fills a bundle over HTTPS; tests and --offline runs read a recorded one.
// Asking for files goes through Wanted, so the command fetches only what the
// diff will read.
package upstream

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Kind is where a matrix's control-ID list comes from.
type Kind string

const (
	// KindProwler: prowler/compliance/<provider>/<prefix>_<version>_<provider>.json.
	KindProwler Kind = "prowler"
	// KindKubeBench: kube-bench cfg/<prefix><version>/*.yaml.
	KindKubeBench Kind = "kube-bench"
	// KindSecurityHub: the FSBP rows of the Security Hub controls reference,
	// or `aws securityhub list-security-control-definitions` output.
	KindSecurityHub Kind = "securityhub"
)

// Source binds one benchmark matrix to its upstream control list.
type Source struct {
	Benchmark string
	Kind      Kind
	// Provider is the Prowler compliance directory (KindProwler).
	Provider string
	// KubeBenchPrefix names the kube-bench cfg directories of this benchmark
	// ("eks-" → eks-1.8.0). For KindProwler sources it is a second place a
	// newer version can appear; IDs are still read from Prowler.
	KubeBenchPrefix string
	// AzurePolicy: also read the Azure Policy regulatory initiatives for a
	// newer CIS Azure version. The initiatives map Azure Policy definitions,
	// not control lists, so they only ever signal a version.
	AzurePolicy bool
}

// Sources is every matrix's upstream. A matrix without an entry fails
// TestEveryMatrixHasAnUpstream: a control list nobody re-reads is one that
// silently drifts.
var Sources = []Source{
	{Benchmark: "aws-fsbp", Kind: KindSecurityHub},
	{Benchmark: "cis-aws-foundations", Kind: KindProwler, Provider: "aws"},
	{Benchmark: "cis-azure-foundations", Kind: KindProwler, Provider: "azure", AzurePolicy: true},
	{Benchmark: "cis-aks", Kind: KindKubeBench, KubeBenchPrefix: "aks-"},
	{Benchmark: "cis-eks", Kind: KindKubeBench, KubeBenchPrefix: "eks-"},
	{Benchmark: "cis-gcp-foundation", Kind: KindProwler, Provider: "gcp"},
	{Benchmark: "cis-gke", Kind: KindKubeBench, KubeBenchPrefix: "gke-"},
	{Benchmark: "cis-kubernetes", Kind: KindProwler, Provider: "kubernetes", KubeBenchPrefix: "cis-"},
}

// SourceFor returns the upstream of a benchmark matrix.
func SourceFor(benchmark string) (Source, bool) {
	i := slices.IndexFunc(Sources, func(s Source) bool { return s.Benchmark == benchmark })
	if i < 0 {
		return Source{}, false
	}
	return Sources[i], true
}

// ProwlerProviders are the Prowler compliance directories read.
var ProwlerProviders = []string{"aws", "azure", "gcp", "kubernetes"}

// Bundle paths. Each holds the raw HTTP body of one upstream URL; the
// command maps a path to its URL.
const (
	// PathSecurityHubReference is the Security Hub controls reference page.
	PathSecurityHubReference = "securityhub/controls-reference.html"
	// PathSecurityHubAPI is `aws securityhub list-security-control-definitions
	// --standards-arn <FSBP>` output. When present it replaces the page.
	PathSecurityHubAPI = "securityhub/fsbp-controls.json"
	// PathKubeBenchIndex lists kube-bench's cfg directory.
	PathKubeBenchIndex = "kube-bench/index.json"
	// PathAzurePolicyIndex lists the Azure Policy regulatory initiatives.
	PathAzurePolicyIndex = "azure-policy/index.json"
	// PathNISTCatalog is the NIST SP 800-53 Rev. 5 OSCAL catalog, read for
	// control titles (US government work, public domain).
	PathNISTCatalog = "nist/sp800-53-rev5-catalog.json"
)

// ProwlerIndexPath lists one Prowler compliance directory.
func ProwlerIndexPath(provider string) string { return "prowler/" + provider + "/index.json" }

// ProwlerFilePath is one Prowler compliance JSON.
func ProwlerFilePath(provider, file string) string { return "prowler/" + provider + "/" + file }

// KubeBenchDirIndexPath lists one kube-bench cfg directory.
func KubeBenchDirIndexPath(dir string) string { return "kube-bench/" + dir + "/index.json" }

// KubeBenchFilePath is one kube-bench cfg file.
func KubeBenchFilePath(dir, file string) string { return "kube-bench/" + dir + "/" + file }

// SecurityHubPagePath is one per-service Security Hub controls page (read for
// each control's related requirements).
func SecurityHubPagePath(page string) string { return "securityhub/pages/" + page }

// version is a dotted numeric version, compared with trailing zeros
// ignored: Prowler names CIS AWS 7.0.0 "7.0".
type version []int

func parseVersion(s string) (version, error) {
	parts := strings.Split(strings.TrimPrefix(s, "v"), ".")
	out := make(version, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("parseVersion %q: %w", s, err)
		}
		out = append(out, n)
	}
	for len(out) > 1 && out[len(out)-1] == 0 {
		out = out[:len(out)-1]
	}
	return out, nil
}

func (v version) compare(o version) int { return slices.Compare(v, o) }

// newest returns the greatest version string in vs ("" when empty).
func newest(vs []string) string {
	best, bestV := "", version(nil)
	for _, s := range vs {
		v, err := parseVersion(s)
		if err != nil {
			continue
		}
		if best == "" || v.compare(bestV) > 0 {
			best, bestV = s, v
		}
	}
	return best
}

// nearestAtMost returns the version in vs equal to pinned, else the greatest
// below it ("" when none is at or below pinned).
func nearestAtMost(vs []string, pinned string) string {
	pv, err := parseVersion(pinned)
	if err != nil {
		return ""
	}
	best, bestV := "", version(nil)
	for _, s := range vs {
		v, err := parseVersion(s)
		if err != nil || v.compare(pv) > 0 {
			continue
		}
		if best == "" || v.compare(bestV) > 0 {
			best, bestV = s, v
		}
	}
	return best
}

// sameVersion reports whether two version strings name the same release.
func sameVersion(a, b string) bool {
	av, err1 := parseVersion(a)
	bv, err2 := parseVersion(b)
	return err1 == nil && err2 == nil && av.compare(bv) == 0
}
