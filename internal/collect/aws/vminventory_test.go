package aws

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/distro"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
)

// allAdvisory is every advisory feed switched on.
var allAdvisory = distro.Sources{distro.SourceOSV: true, distro.SourceALAS: true, distro.SourceELSA: true}

func TestMain(m *testing.M) {
	inventoryCallInterval = time.Microsecond
	os.Exit(m.Run())
}

// fakeSSM serves DescribeInstanceInformation from nodes and ListInventoryEntries
// from entries (per instance, paged by pageSize).
type fakeSSM struct {
	mu          sync.Mutex
	nodes       []ssmtypes.InstanceInformation
	describeErr error
	entries     map[string][]map[string]string
	captured    map[string]string
	listErr     map[string]error
	pageSize    int
	listCalls   map[string]int
	// compliance serves ListResourceComplianceSummaries by compliance type
	// (ssm_compliance_test.go).
	compliance    map[string][]ssmtypes.ResourceComplianceSummaryItem
	complianceErr map[string]error
}

func (f *fakeSSM) DescribeInstanceInformation(_ context.Context, _ *ssm.DescribeInstanceInformationInput, _ ...func(*ssm.Options)) (*ssm.DescribeInstanceInformationOutput, error) {
	if f.describeErr != nil {
		return nil, f.describeErr
	}
	return &ssm.DescribeInstanceInformationOutput{InstanceInformationList: f.nodes}, nil
}

func (f *fakeSSM) ListInventoryEntries(_ context.Context, in *ssm.ListInventoryEntriesInput, _ ...func(*ssm.Options)) (*ssm.ListInventoryEntriesOutput, error) {
	id := awssdk.ToString(in.InstanceId)
	f.mu.Lock()
	if f.listCalls == nil {
		f.listCalls = map[string]int{}
	}
	f.listCalls[id]++
	f.mu.Unlock()
	if err := f.listErr[id]; err != nil {
		return nil, err
	}
	all := f.entries[id]
	size := f.pageSize
	if size == 0 {
		size = 50
	}
	start := 0
	if in.NextToken != nil {
		_, _ = fmt.Sscanf(*in.NextToken, "%d", &start)
	}
	end := min(start+size, len(all))
	out := &ssm.ListInventoryEntriesOutput{Entries: all[start:end], CaptureTime: awssdk.String(f.captured[id])}
	if end < len(all) {
		out.NextToken = awssdk.String(fmt.Sprintf("%d", end))
	}
	return out, nil
}

func linuxNode(id, platform, version string) ssmtypes.InstanceInformation {
	return ssmtypes.InstanceInformation{
		InstanceId: awssdk.String(id), PlatformType: ssmtypes.PlatformTypeLinux,
		PlatformName: awssdk.String(platform), PlatformVersion: awssdk.String(version),
		PingStatus: ssmtypes.PingStatusOnline,
	}
}

func debEntries(n int) []map[string]string {
	out := make([]map[string]string, n)
	for i := range out {
		out[i] = map[string]string{"Name": fmt.Sprintf("pkg%d", i), "Version": "1.0-1ubuntu1"}
	}
	return out
}

func freshBudget() *inventoryBudget { return &inventoryBudget{remaining: inventorySweepBudget} }

func TestCollectSSMInventory_Verdicts(t *testing.T) {
	now := time.Now()
	captured := now.Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	fake := &fakeSSM{
		nodes: []ssmtypes.InstanceInformation{
			linuxNode("i-ubuntu", "Ubuntu", "22.04"),
			linuxNode("i-amzn", "Amazon Linux", "2"),
			linuxNode("i-rhel", "Red Hat Enterprise Linux", "9.2"),
			linuxNode("i-sles", "SLES", "15.5"),
			linuxNode("i-empty", "Ubuntu", "22.04"),
			linuxNode("i-stale", "Ubuntu", "22.04"),
			linuxNode("i-huge", "Ubuntu", "22.04"),
			{InstanceId: awssdk.String("i-win"), PlatformType: ssmtypes.PlatformTypeWindows, PlatformName: awssdk.String("Microsoft Windows Server 2022 Datacenter")},
			linuxNode("mi-onprem", "Ubuntu", "22.04"),
		},
		entries: map[string][]map[string]string{
			"i-ubuntu": {
				{"Name": "openssl", "Version": "3.0.2-0ubuntu1.15"},
				{"Name": "bash", "Version": "5.1-6ubuntu1"},
			},
			"i-amzn": {{"Name": "openssl-libs", "Version": "1.0.2k", "Release": "24.amzn2.0.4", "Epoch": "1"}},
			"i-rhel": {{"Name": "openssl-libs", "Version": "3.0.7", "Release": "27.el9", "Epoch": "1",
				"PackageId": "openssl-3.0.7-27.el9.src.rpm"}},
			"i-sles": {
				{"Name": "libopenssl3", "Version": "3.0.8", "Release": "150500.5.1", "PackageId": "openssl-3-3.0.8-150500.5.1.src.rpm"},
				{"Name": "gpg-pubkey", "Version": "39db7c82", "Release": "5f68629b", "PackageId": "(none)"},
			},
			"i-stale": {{"Name": "openssl", "Version": "3.0.2-0ubuntu1.1"}},
			"i-huge":  debEntries(inventoryMaxPages*2 + 1),
		},
		captured: map[string]string{
			"i-ubuntu": captured, "i-amzn": captured, "i-huge": captured, "i-rhel": captured, "i-sles": captured,
			"i-stale": now.Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339),
		},
		pageSize: 2,
	}
	got, err := collectSSMInventory(context.Background(), fake, newInventoryCache(), freshBudget(), "acct/eu-west-1", allAdvisory, now)
	require.NoError(t, err)

	require.Empty(t, got["i-ubuntu"].gap)
	require.Equal(t, "Ubuntu:22.04:LTS", got["i-ubuntu"].ecosystem)
	require.Equal(t, asset.CVEGapNoSourceNames, got["i-ubuntu"].cveGap,
		"OSV keys Ubuntu by source package; a dpkg inventory lists binaries (libssl3), so absence proves nothing")
	require.Len(t, got["i-ubuntu"].pkgs, 2)
	require.Equal(t, now.Add(-2*time.Hour).UTC().Format(time.DateOnly), got["i-ubuntu"].observedOn)

	require.Empty(t, got["i-amzn"].gap, "an Amazon Linux inventory is still an inventory")
	require.Equal(t, asset.CVEGapEOLDistro, got["i-amzn"].cveGap, "Amazon Linux 2 reached end of life on 2026-06-30")
	require.Equal(t, "1:1.0.2k-24.amzn2.0.4", got["i-amzn"].pkgs[0].Version)

	require.Equal(t, "Red Hat:9", got["i-rhel"].ecosystem)
	require.Empty(t, got["i-rhel"].cveGap, "OSV keys Red Hat by binary package name")
	require.Equal(t, "openssl", got["i-rhel"].pkgs[0].SourceName, "the rpm PackageId is the SOURCERPM")

	require.Equal(t, "SUSE:15.5", got["i-sles"].ecosystem)
	require.Empty(t, got["i-sles"].cveGap, "source names read off PackageId make the source-keyed SUSE feed matchable")
	require.Equal(t, "openssl-3", got["i-sles"].pkgs[0].SourceName)
	require.Empty(t, got["i-sles"].pkgs[1].SourceName)

	require.Equal(t, gapNoInventoryData, got["i-empty"].gap, "managed but never inventoried is not an empty host")
	require.Equal(t, gapStaleInventory, got["i-stale"].gap, "a month-old capture is not today's package list")
	require.Equal(t, gapOverPackageCap, got["i-huge"].gap, "a truncated list cannot support a verdict")
	require.Empty(t, got["i-huge"].pkgs)
	require.Equal(t, gapUnsupportedPlatform, got["i-win"].gap)
	require.NotContains(t, got, "mi-onprem", "hybrid nodes are not EC2 instances")

	// INTEL_OSV_DISABLED: Red Hat and SUSE are matched by OSV, which this
	// deployment never asks. Their inventories are still known; the absence of
	// a CVE finding on them means nothing.
	noOSV := distro.Sources{distro.SourceALAS: true, distro.SourceELSA: true}
	got, err = collectSSMInventory(context.Background(), fake, newInventoryCache(), freshBudget(), "acct/eu-west-1", noOSV, now)
	require.NoError(t, err)
	require.Empty(t, got["i-rhel"].gap)
	require.Equal(t, asset.CVEGapAdvisorySourceDisabled, got["i-rhel"].cveGap)
	require.Equal(t, asset.CVEGapAdvisorySourceDisabled, got["i-sles"].cveGap)
	require.Equal(t, asset.CVEGapEOLDistro, got["i-amzn"].cveGap)
}

// The cache is what keeps API cost bounded: a second sweep inside the refresh
// window makes no ListInventoryEntries call at all, and a fleet of hosts with the
// same package list shares one interned slice.
func TestCollectSSMInventory_CacheBoundsCost(t *testing.T) {
	now := time.Now()
	captured := now.UTC().Format(time.RFC3339)
	same := []map[string]string{{"Name": "openssl", "Version": "3.0.2-0ubuntu1.15"}}
	fake := &fakeSSM{
		nodes:    []ssmtypes.InstanceInformation{linuxNode("i-a", "Ubuntu", "22.04"), linuxNode("i-b", "Ubuntu", "22.04")},
		entries:  map[string][]map[string]string{"i-a": same, "i-b": same},
		captured: map[string]string{"i-a": captured, "i-b": captured},
	}
	cache := newInventoryCache()
	_, err := collectSSMInventory(context.Background(), fake, cache, freshBudget(), "acct/eu-west-1", allAdvisory, now)
	require.NoError(t, err)
	require.Equal(t, 1, fake.listCalls["i-a"])
	require.Len(t, cache.sets, 1, "identical package lists are interned")

	got, err := collectSSMInventory(context.Background(), fake, cache, freshBudget(), "acct/eu-west-1", allAdvisory, now.Add(time.Hour))
	require.NoError(t, err)
	require.Equal(t, 1, fake.listCalls["i-a"], "inside the refresh window nothing is re-read")
	require.Len(t, got["i-a"].pkgs, 1, "the cached list is still emitted")

	// i-b is terminated: its entry and, once unreferenced, its set are evicted.
	fake.nodes = fake.nodes[:1]
	_, err = collectSSMInventory(context.Background(), fake, cache, freshBudget(), "acct/eu-west-1", allAdvisory, now.Add(2*time.Hour))
	require.NoError(t, err)
	require.NotContains(t, cache.entries, "i-b")
	require.Len(t, cache.sets, 1)
	fake.nodes = nil
	_, err = collectSSMInventory(context.Background(), fake, cache, freshBudget(), "acct/eu-west-1", allAdvisory, now.Add(3*time.Hour))
	require.NoError(t, err)
	require.Empty(t, cache.sets)

	// Past the stale window with no refresh possible (budget spent), the cached
	// list is NOT re-emitted: that would re-stamp edges nobody re-observed.
	fake.nodes = []ssmtypes.InstanceInformation{linuxNode("i-a", "Ubuntu", "22.04")}
	_, err = collectSSMInventory(context.Background(), fake, cache, freshBudget(), "acct/eu-west-1", allAdvisory, now)
	require.NoError(t, err)
	got, err = collectSSMInventory(context.Background(), fake, cache, &inventoryBudget{}, "acct/eu-west-1", allAdvisory, now.Add(inventoryStaleAfter+time.Hour))
	require.NoError(t, err)
	require.Equal(t, gapPending, got["i-a"].gap)
}

// A brand-new instance has no inventory until the SSM agent's first capture
// (typically within the hour). Caching that negative for the full 20h refresh
// window left it reading as no_inventory_data for most of a day.
func TestCollectSSMInventory_NoDataRetriedSooner(t *testing.T) {
	now := time.Now()
	fake := &fakeSSM{nodes: []ssmtypes.InstanceInformation{linuxNode("i-new", "Ubuntu", "22.04")}}
	cache := newInventoryCache()
	got, err := collectSSMInventory(context.Background(), fake, cache, freshBudget(), "acct/eu-west-1", allAdvisory, now)
	require.NoError(t, err)
	require.Equal(t, gapNoInventoryData, got["i-new"].gap)
	require.Equal(t, 1, fake.listCalls["i-new"])

	_, err = collectSSMInventory(context.Background(), fake, cache, freshBudget(), "acct/eu-west-1", allAdvisory, now.Add(time.Hour))
	require.NoError(t, err)
	require.Equal(t, 1, fake.listCalls["i-new"], "a negative is still cached briefly")

	// The agent has now reported.
	fake.entries = map[string][]map[string]string{"i-new": debEntries(3)}
	fake.captured = map[string]string{"i-new": now.Add(2 * time.Hour).UTC().Format(time.RFC3339)}
	got, err = collectSSMInventory(context.Background(), fake, cache, freshBudget(), "acct/eu-west-1", allAdvisory, now.Add(inventoryNoDataRefreshAfter+time.Minute))
	require.NoError(t, err)
	require.Equal(t, 2, fake.listCalls["i-new"], "the negative expires long before the 20h refresh")
	require.Empty(t, got["i-new"].gap)
	require.Len(t, got["i-new"].pkgs, 3)
}

// The cache is shared by every AWS connector: sweeping one account must never
// evict another account's entries in the same region.
func TestCollectSSMInventory_EvictionIsAccountScoped(t *testing.T) {
	now := time.Now()
	fake := &fakeSSM{
		nodes:    []ssmtypes.InstanceInformation{linuxNode("i-a", "Ubuntu", "22.04")},
		entries:  map[string][]map[string]string{"i-a": {{"Name": "bash", "Version": "5.1-6ubuntu1"}}},
		captured: map[string]string{"i-a": now.UTC().Format(time.RFC3339)},
	}
	cache := newInventoryCache()
	_, err := collectSSMInventory(context.Background(), fake, cache, freshBudget(), "acct-1/eu-west-1", allAdvisory, now)
	require.NoError(t, err)

	other := &fakeSSM{} // a second account with no managed instances in the region
	_, err = collectSSMInventory(context.Background(), other, cache, freshBudget(), "acct-2/eu-west-1", allAdvisory, now)
	require.NoError(t, err)
	require.Contains(t, cache.entries, "i-a")
}

func TestCollectSSMInventory_DeniedReadsSayWhy(t *testing.T) {
	now := time.Now()
	denied := &smithy.GenericAPIError{Code: "AccessDeniedException", Message: "not authorized to perform ssm:ListInventoryEntries"}
	fake := &fakeSSM{
		nodes:   []ssmtypes.InstanceInformation{linuxNode("i-a", "Ubuntu", "22.04")},
		listErr: map[string]error{"i-a": denied},
	}
	got, err := collectSSMInventory(context.Background(), fake, newInventoryCache(), freshBudget(), "acct/eu-west-1", allAdvisory, now)
	require.NoError(t, err, "a read failure is per instance, never the region's")
	require.Equal(t, gapAccessDenied, got["i-a"].gap)
}

func TestRegionInventoryApply_StampsEveryInstance(t *testing.T) {
	now := time.Now()
	inst := func(id string) asset.Asset {
		return asset.Asset{ID: id, Type: "ec2_instance", Metadata: map[string]string{"instance_id": id}}
	}
	instances := []asset.Asset{inst("i-ok"), inst("i-amzn"), inst("i-unmanaged"), inst("i-pending")}
	r := &regionInventory{done: make(chan struct{}), inv: map[string]vmInventory{
		"i-ok": {ecosystem: "Ubuntu:22.04:LTS", observedOn: "2026-10-07", pkgs: []pkginventory.InstalledPackage{
			{Ecosystem: "Ubuntu:22.04:LTS", Name: "openssl", Version: "3.0.2-0ubuntu1.15"},
		}},
		"i-amzn": {ecosystem: "Amazon Linux:2", cveGap: asset.CVEGapEOLDistro, observedOn: "2026-10-07", pkgs: []pkginventory.InstalledPackage{
			{Ecosystem: "Amazon Linux:2", Name: "openssl-libs", Version: "1.0.2k-24.amzn2"},
		}},
		"i-pending": {gap: gapPending},
	}}
	close(r.done)
	seen := map[string]bool{"pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1.15": true}
	assets, edges := r.apply(context.Background(), instances, seen, now)

	require.Equal(t, asset.PackageInventorySSM, instances[0].Metadata[asset.MetaPackageInventory])
	require.Equal(t, "true", instances[0].Metadata[asset.MetaPackageCVEMatchable])
	require.Equal(t, "2026-10-07", instances[0].Metadata[asset.MetaPackageInventoryObservedOn])
	require.True(t, asset.PackageCVEClaimable(instances[0].Metadata))
	require.NotContains(t, instances[0].Metadata, asset.MetaPackageCVEGap)

	require.True(t, asset.PackageInventoryKnown(instances[1].Metadata))
	require.False(t, asset.PackageCVEClaimable(instances[1].Metadata), "known inventory, unmatchable OS")
	require.Equal(t, asset.CVEGapEOLDistro, instances[1].Metadata[asset.MetaPackageCVEGap], "the reason travels with the verdict")

	require.Equal(t, asset.PackageInventoryNone, instances[2].Metadata[asset.MetaPackageInventory])
	require.Equal(t, gapNotManaged, instances[2].Metadata[asset.MetaPackageInventoryGap])
	require.NotContains(t, instances[2].Metadata, asset.MetaPackageEcosystem, "no inventory must not carry coverage-looking keys")
	require.Equal(t, gapPending, instances[3].Metadata[asset.MetaPackageInventoryGap])
	require.False(t, asset.PackageInventoryKnown(instances[3].Metadata))

	// FSBP SSM.1 reads ssm_managed, written from the complete listing only.
	require.Equal(t, "true", instances[0].Metadata["ssm_managed"])
	require.Equal(t, "true", instances[3].Metadata["ssm_managed"], "a managed node with pending inventory is still managed")
	require.Equal(t, "false", instances[2].Metadata["ssm_managed"])

	require.Len(t, assets, 1, "the package already emitted by an earlier region is not re-emitted")
	require.Equal(t, "pkg:rpm/amazon/openssl-libs@1.0.2k-24.amzn2", assets[0].ID)
	require.Len(t, edges, 2, "every inventoried instance still gets its own edge")
}

func TestRegionInventoryApply_FailedReadIsNoneNotClean(t *testing.T) {
	inst := asset.Asset{ID: "i-1", Type: "ec2_instance", Metadata: map[string]string{}}
	for _, tt := range []struct {
		err error
		gap string
	}{
		{&smithy.GenericAPIError{Code: "AccessDeniedException"}, gapAccessDenied},
		{errors.New("throttled"), gapUnavailable},
	} {
		r := &regionInventory{done: make(chan struct{}), err: tt.err}
		close(r.done)
		assets, edges := r.apply(context.Background(), []asset.Asset{inst}, map[string]bool{}, time.Now())
		require.Empty(t, assets)
		require.Empty(t, edges)
		require.Equal(t, asset.PackageInventoryNone, inst.Metadata[asset.MetaPackageInventory])
		require.Equal(t, tt.gap, inst.Metadata[asset.MetaPackageInventoryGap])
		require.NotContains(t, inst.Metadata, "ssm_managed", "a failed listing proves nothing about management")
	}

	var nilInventory *regionInventory
	assets, edges := nilInventory.apply(context.Background(), []asset.Asset{{ID: "i-2", Metadata: map[string]string{}}}, nil, time.Now())
	require.Empty(t, assets)
	require.Empty(t, edges)
}

func TestSSMDistro(t *testing.T) {
	for name, want := range map[string]string{
		"Amazon Linux":                    "amzn",
		"Ubuntu":                          "ubuntu",
		"Debian GNU/Linux":                "debian",
		"Red Hat Enterprise Linux Server": "rhel",
		"CentOS Linux":                    "centos",
		"Rocky Linux":                     "rocky",
		"AlmaLinux":                       "almalinux",
		"SLES":                            "sles",
		"SUSE Linux Enterprise Server":    "sles",
		"Oracle Linux Server":             "ol",
		"openSUSE Leap":                   "opensuse-leap",
		"Microsoft Windows Server 2019":   "",
		"":                                "",
	} {
		require.Equal(t, want, ssmDistro(name), name)
	}
}
