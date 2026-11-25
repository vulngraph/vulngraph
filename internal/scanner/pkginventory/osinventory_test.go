package pkginventory

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/distro"
)

func TestInventoryEcosystem(t *testing.T) {
	tests := []struct {
		distro, version string
		want            string
	}{
		{"ubuntu", "22.04", "Ubuntu:22.04:LTS"},
		{"ubuntu", "23.10", "Ubuntu:23.10"},
		{"ubuntu", "", "Ubuntu"},
		{"debian", "12", "Debian:12"},
		{"debian", "11.7", "Debian:11"},
		{"almalinux", "9.3", "AlmaLinux:9"},
		{"rocky", "8.9", "Rocky Linux:8"},
		{"Rocky", "", "Rocky Linux"},
		{"amzn", "2023", "Amazon Linux:2023"},
		{"amzn", "2", "Amazon Linux:2"},
		{"amzn", "2018.03", "Amazon Linux:1"},
		{"rhel", "9.2", "Red Hat:9"},
		{"ol", "8.9", "Oracle Linux:8"},
		{"centos", "7", "CentOS:7"},
		{"sles", "15.5", "SUSE:15.5"},
		{"opensuse-leap", "15.5", "openSUSE:Leap 15.5"},
		{"opensuse-tumbleweed", "20260901", "openSUSE:Tumbleweed"},
		// No package identity at all: the caller records no inventory.
		{"windows", "10.0.20348", ""},
		{"macos", "14.1", ""},
		{"", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.distro+"/"+tt.version, func(t *testing.T) {
			require.Equal(t, tt.want, InventoryEcosystem(tt.distro, tt.version))
		})
	}
}

// CVEGap is the honesty half: a VM with zero CVE findings is only clean when its
// packages can be matched in full by a live advisory source.
func TestCVEGap(t *testing.T) {
	now := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		ecosystem   string
		sourceNames bool
		want        string
	}{
		// Binary-keyed sources: an inventory's binary names are what they index.
		{"Red Hat:9", false, ""},
		{"AlmaLinux:9", false, ""},
		{"Amazon Linux:2023", false, ""},
		{"Oracle Linux:9", false, ""},
		// Source-keyed sources need the source names the rpm PackageId carries.
		{"SUSE:15.5", true, ""},
		{"SUSE:15.5", false, asset.CVEGapNoSourceNames},
		{"Rocky Linux:9", true, ""},
		{"Rocky Linux:9", false, asset.CVEGapNoSourceNames},
		{"openSUSE:Leap 16.0", true, ""},
		// dpkg inventories (SSM, OS Config) carry binary names only.
		{"Ubuntu:22.04:LTS", false, asset.CVEGapNoSourceNames},
		{"Debian:12", false, asset.CVEGapNoSourceNames},
		{"Debian:12", true, ""},
		// Past a FINAL end of life: no advisory will ever be published again.
		{"CentOS:7", true, asset.CVEGapEOLDistro},
		{"CentOS:8", true, asset.CVEGapEOLDistro},
		{"Amazon Linux:1", true, asset.CVEGapEOLDistro},
		{"Amazon Linux:2", true, asset.CVEGapEOLDistro},
		{"Debian:11", true, asset.CVEGapEOLDistro},
		{"openSUSE:Leap 15.5", true, asset.CVEGapEOLDistro},
		{"Alpine:v3.18", true, asset.CVEGapEOLDistro},
		// Past end of standard support with a paid extended tier still feeding the
		// source: matchable, and the end-of-life check reports it instead.
		{"Red Hat:7", false, ""},
		{"Ubuntu:20.04:LTS", true, ""},
		// CentOS Stream is supported but has no advisory feed.
		{"CentOS:9", true, asset.CVEGapNoAdvisorySource},
		{"Red Hat", false, asset.CVEGapUnknownRelease},
		{"Ubuntu", true, asset.CVEGapUnknownRelease},
		{"Debian", true, ""}, // unqualified Debian is a real, over-inclusive OSV ecosystem
		{"Gentoo:2", true, asset.CVEGapNoAdvisorySource},
	}
	all := distro.Sources{distro.SourceOSV: true, distro.SourceALAS: true, distro.SourceELSA: true}
	for _, tt := range tests {
		require.Equal(t, tt.want, CVEGap(tt.ecosystem, tt.sourceNames, all, now), "%s sourceNames=%v", tt.ecosystem, tt.sourceNames)
	}
}

// A switched-off advisory source matches nothing: its VMs are unmatchable, not
// matchable and clean. Each family is gated by ITS source only, and the zero
// value (a caller that never said which feeds are on) enables none.
func TestCVEGap_AdvisorySourceDisabled(t *testing.T) {
	now := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	noALAS := distro.Sources{distro.SourceOSV: true, distro.SourceELSA: true}
	require.Equal(t, asset.CVEGapAdvisorySourceDisabled, CVEGap("Amazon Linux:2023", false, noALAS, now))
	require.Equal(t, "", CVEGap("Oracle Linux:9", false, noALAS, now))
	require.Equal(t, "", CVEGap("Debian:12", true, noALAS, now))

	noOSV := distro.Sources{distro.SourceALAS: true, distro.SourceELSA: true}
	for _, eco := range []string{"Debian:12", "Ubuntu:22.04:LTS", "Red Hat:9", "SUSE:15.5", "Rocky Linux:9"} {
		require.Equal(t, asset.CVEGapAdvisorySourceDisabled, CVEGap(eco, true, noOSV, now), eco)
	}
	require.Equal(t, asset.CVEGapAdvisorySourceDisabled, CVEGap("Oracle Linux:9", false, distro.Sources{distro.SourceELSA: false}, now))
	require.Equal(t, asset.CVEGapAdvisorySourceDisabled, CVEGap("Red Hat:9", false, nil, now), "the zero value enables nothing")
	require.Equal(t, asset.CVEGapEOLDistro, CVEGap("CentOS:7", false, nil, now), "an end-of-life release says so first")
}

func TestSourceRPMName(t *testing.T) {
	tests := map[string]string{
		"openssl-3-3.0.8-150500.5.3.1.src.rpm":  "openssl-3",
		"openssl-1.0.2k-24.amzn2.0.4.src.rpm":   "openssl",
		"amazon-ssm-agent-2.3.1319.0-1.src.rpm": "amazon-ssm-agent",
		"(none)":                                "",
		"openssl_3.0.2-0ubuntu1.15_amd64.deb":   "",
		"bad.src.rpm":                           "",
		"":                                      "",
	}
	for in, want := range tests {
		require.Equal(t, want, SourceRPMName(in), in)
	}
}

func TestInventoryPackage(t *testing.T) {
	tests := []struct {
		name                           string
		pkgName, version, release, eps string
		want                           string
		ok                             bool
	}{
		{name: "dpkg full version passes through", pkgName: "openssl", version: "3.0.2-0ubuntu1.15", want: "3.0.2-0ubuntu1.15", ok: true},
		{name: "dpkg epoch already in version", pkgName: "tzdata", version: "1:2024a-0ubuntu0.22.04", eps: "1", want: "1:2024a-0ubuntu0.22.04", ok: true},
		{name: "rpm version-release joined", pkgName: "openssl-libs", version: "1.0.2k", release: "24.amzn2.0.4", want: "1.0.2k-24.amzn2.0.4", ok: true},
		{name: "rpm non-zero epoch prefixed", pkgName: "openssl-libs", version: "1.0.2k", release: "24.amzn2.0.4", eps: "1", want: "1:1.0.2k-24.amzn2.0.4", ok: true},
		{name: "rpm unset epoch dropped", pkgName: "bash", version: "4.2.46", release: "34.amzn2", eps: "(none)", want: "4.2.46-34.amzn2", ok: true},
		{name: "rpm zero epoch dropped", pkgName: "bash", version: "4.2.46", release: "34.amzn2", eps: "0", want: "4.2.46-34.amzn2", ok: true},
		{name: "release already suffixed is not doubled", pkgName: "glibc", version: "2.34-60.el9", release: "60.el9", want: "2.34-60.el9", ok: true},
		{name: "no version is no package", pkgName: "ghost", ok: false},
		{name: "no name is no package", version: "1.0", ok: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, ok := InventoryPackage("Debian:12", tt.pkgName, tt.version, tt.release, tt.eps, "ssm")
			require.Equal(t, tt.ok, ok)
			if ok {
				require.Equal(t, tt.want, p.Version)
				require.Equal(t, "Debian:12", p.Ecosystem)
			}
		})
	}
}

// A VM-inventoried package must land on the SAME node id the image scanner
// mints for it.
func TestInventoryGraph(t *testing.T) {
	now := time.Now()
	deb, _ := InventoryPackage("Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1.15", "", "", "ssm")
	dup := deb
	assets, edges := InventoryGraph("i-1", "ec2_instance", []InstalledPackage{deb, dup}, now)
	require.Len(t, assets, 1, "the same package twice is one node")
	require.Equal(t, "pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.15", assets[0].ID)
	require.Equal(t, PURL(deb), assets[0].ID, "must be the image scanner's node id")
	require.Equal(t, "Ubuntu:22.04:LTS", assets[0].Metadata["ecosystem"])
	require.Equal(t, "ec2_instance", assets[0].Metadata["origin"])
	require.Len(t, edges, 1)
	require.Equal(t, "runs_package", edges[0].EdgeType)
	require.Equal(t, "i-1", edges[0].SrcID)
	require.Equal(t, "ec2_instance", edges[0].SrcType)
	require.Equal(t, assets[0].ID, edges[0].DstID)

	rpm, _ := InventoryPackage("Amazon Linux:2", "openssl-libs", "1.0.2k", "24.amzn2.0.4", "1", "ssm")
	rpm.SourceName = "openssl"
	assets, edges = InventoryGraph("i-2", "ec2_instance", []InstalledPackage{rpm}, now)
	require.Len(t, assets, 1)
	require.Equal(t, "pkg:rpm/amazon/openssl-libs@1:1.0.2k-24.amzn2.0.4", assets[0].ID)
	require.Equal(t, "Amazon Linux:2", assets[0].Metadata["ecosystem"],
		"the coordinate is kept: the ALAS feed reads it and the OSV client excludes it per package")
	require.Equal(t, "openssl", assets[0].Metadata[MetaSourcePackage])
	require.Len(t, edges, 1)
	require.NotContains(t, PURL(rpm), "openssl@", "the source name is metadata, never part of the node id")
}
