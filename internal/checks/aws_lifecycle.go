package checks

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Vendor lifecycle tables for AWS-managed runtimes. Hand-maintained from the
// AWS documentation, the same way internal/distro maintains OS lifecycles;
// update them when AWS publishes a new schedule. An identifier absent from a
// table is unknown and never graded.

// day parses a table date. Panics only on a malformed literal in this file,
// which TestLifecycleTablesParse catches.
func day(s string) time.Time {
	t, err := time.Parse(time.DateOnly, s)
	if err != nil {
		panic("aws_lifecycle: bad date " + s)
	}
	return t
}

// lambdaRuntimeDeprecation maps a Lambda runtime identifier to the date AWS
// deprecates it: after it, the runtime gets no security patches. Source:
// https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html (supported
// and deprecated tables, read 2026-10-09). Runtimes with no scheduled date
// (previews) are omitted.
var lambdaRuntimeDeprecation = map[string]time.Time{
	// Node.js
	"nodejs":         day("2016-08-30"),
	"nodejs4.3":      day("2020-03-05"),
	"nodejs4.3-edge": day("2020-03-05"),
	"nodejs6.10":     day("2019-08-12"),
	"nodejs8.10":     day("2020-03-06"),
	"nodejs10.x":     day("2021-07-30"),
	"nodejs12.x":     day("2023-03-31"),
	"nodejs14.x":     day("2023-12-04"),
	"nodejs16.x":     day("2024-06-12"),
	"nodejs18.x":     day("2025-09-01"),
	"nodejs20.x":     day("2026-04-30"),
	"nodejs22.x":     day("2027-04-30"),
	"nodejs24.x":     day("2028-04-30"),
	// Python
	"python2.7":  day("2021-07-15"),
	"python3.6":  day("2022-07-18"),
	"python3.7":  day("2023-12-04"),
	"python3.8":  day("2024-10-14"),
	"python3.9":  day("2025-12-15"),
	"python3.10": day("2026-10-31"),
	"python3.11": day("2027-06-30"),
	"python3.12": day("2028-10-31"),
	"python3.13": day("2029-06-30"),
	"python3.14": day("2029-06-30"),
	// Java
	"java8":         day("2024-01-08"),
	"java8.al2":     day("2027-06-30"),
	"java11":        day("2027-06-30"),
	"java17":        day("2027-06-30"),
	"java8.al2023":  day("2029-06-30"),
	"java11.al2023": day("2029-06-30"),
	"java17.al2023": day("2029-06-30"),
	"java21":        day("2029-06-30"),
	"java25":        day("2029-06-30"),
	// .NET
	"dotnetcore1.0": day("2019-06-27"),
	"dotnetcore2.0": day("2019-05-30"),
	"dotnetcore2.1": day("2022-01-05"),
	"dotnetcore3.1": day("2023-04-03"),
	"dotnet5.0":     day("2022-05-10"),
	"dotnet6":       day("2024-12-20"),
	"dotnet7":       day("2024-05-14"),
	"dotnet8":       day("2026-11-10"),
	"dotnet9":       day("2026-11-10"),
	"dotnet10":      day("2028-11-14"),
	// Ruby
	"ruby2.5": day("2021-07-30"),
	"ruby2.7": day("2023-12-07"),
	"ruby3.2": day("2026-03-31"),
	"ruby3.3": day("2027-03-31"),
	"ruby3.4": day("2028-03-31"),
	"ruby4.0": day("2029-03-31"),
	// Go and OS-only
	"go1.x":           day("2024-01-08"),
	"provided":        day("2024-01-08"),
	"provided.al2":    day("2026-07-31"),
	"provided.al2023": day("2029-06-30"),
}

func tableKeys(m map[string]time.Time) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// lambdaRuntimeDeprecated reports a runtime AWS has deprecated as of now.
func lambdaRuntimeDeprecated(a asset.Asset) bool {
	d, ok := lambdaRuntimeDeprecation[a.Metadata["runtime"]]
	return ok && !time.Now().Before(d)
}

// eksVersionSupport is one Kubernetes minor version's EKS support window.
type eksVersionSupport struct {
	standardEnd, extendedEnd time.Time
}

// eksVersionCalendar is the EKS Kubernetes release calendar. Source:
// https://docs.aws.amazon.com/eks/latest/userguide/kubernetes-versions.html
// (read 2026-10-09). A version OLDER than every entry is past the end of
// extended support (EKS supports each version for 26 months, and the table
// keeps every version still inside that window), so it is graded as such; a
// version newer than every entry is not graded until the table learns it.
var eksVersionCalendar = map[string]eksVersionSupport{
	"1.31": {standardEnd: day("2025-11-26"), extendedEnd: day("2026-11-26")},
	"1.32": {standardEnd: day("2026-03-23"), extendedEnd: day("2027-03-23")},
	"1.33": {standardEnd: day("2026-07-29"), extendedEnd: day("2027-07-29")},
	"1.34": {standardEnd: day("2026-12-02"), extendedEnd: day("2027-12-02")},
	"1.35": {standardEnd: day("2027-03-27"), extendedEnd: day("2028-03-27")},
	"1.36": {standardEnd: day("2027-08-02"), extendedEnd: day("2028-08-02")},
	"1.37": {standardEnd: day("2027-12-01"), extendedEnd: day("2028-12-01")},
}

// eksMinor parses "1.31" (or "1.31.x") into its minor number.
func eksMinor(v string) (int, bool) {
	major, rest, ok := strings.Cut(strings.TrimSpace(v), ".")
	if !ok || major != "1" {
		return 0, false
	}
	minor, _, _ := strings.Cut(rest, ".")
	n, err := strconv.Atoi(minor)
	return n, err == nil
}

// eksSupportPhase classifies a cluster version: "standard", "extended" (past
// standard support, still patched at extra cost), "ended" (past extended
// support), or "" when the version is unknown.
func eksSupportPhase(version string, now time.Time) string {
	minor, ok := eksMinor(version)
	if !ok {
		return ""
	}
	key := "1." + strconv.Itoa(minor)
	s, listed := eksVersionCalendar[key]
	if !listed {
		oldest := -1
		for k := range eksVersionCalendar {
			if m, ok := eksMinor(k); ok && (oldest < 0 || m < oldest) {
				oldest = m
			}
		}
		if oldest >= 0 && minor < oldest {
			return "ended"
		}
		return ""
	}
	switch {
	case !now.Before(s.extendedEnd):
		return "ended"
	case !now.Before(s.standardEnd):
		return "extended"
	}
	return "standard"
}

var awsEKSUnsupportedVersion = Check{
	ID:          "aws-eks-unsupported-version",
	Title:       "EKS cluster runs a Kubernetes version past standard support",
	Description: "The cluster's Kubernetes minor version is past the end of EKS standard support. In extended support AWS still patches the control plane, at extra cost, for 12 more months; past extended support the version receives no fixes and EKS force-upgrades the control plane at a time of its choosing, leaving add-ons and nodes behind.",
	Remediation: "Upgrade the control plane one minor version at a time (`aws eks update-cluster-version --name NAME --kubernetes-version 1.NN`), checking deprecated APIs first, then upgrade add-ons and node groups to match.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAWS,
	AssetType:   "eks_cluster",
	Violates: func(a asset.Asset) bool {
		p := eksSupportPhase(a.Metadata["version"], time.Now())
		return p == "extended" || p == "ended"
	},
	// Still patched in extended support (Low); unpatched past it (High).
	SeverityFor: func(a asset.Asset) finding.Severity {
		if eksSupportPhase(a.Metadata["version"], time.Now()) == "ended" {
			return finding.SeverityHigh
		}
		return finding.SeverityLow
	},
	TitleFor: func(a asset.Asset) string {
		if eksSupportPhase(a.Metadata["version"], time.Now()) == "ended" {
			return "EKS cluster runs a Kubernetes version past the end of all support"
		}
		return "EKS cluster runs a Kubernetes version in paid extended support"
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"version": a.Metadata["version"], "support_phase": eksSupportPhase(a.Metadata["version"], time.Now())}
	},
	TableProbes: append([]string{"1.20"}, eksCalendarKeys()...),
}

func eksCalendarKeys() []string {
	out := make([]string, 0, len(eksVersionCalendar))
	for k := range eksVersionCalendar {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func awsLifecycleChecks() []Check {
	return []Check{awsEKSUnsupportedVersion}
}
