package coverage

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/checks"
	"github.com/vulngraph/vulngraph/internal/distro"
)

func advisoryFixture() LiveFacts {
	return LiveFacts{MetaValues: []MetaValueCount{
		{AssetType: "ec2_instance", Key: asset.MetaPackageEcosystem, Value: "Amazon Linux:2023", Count: 7},
		{AssetType: "ec2_instance", Key: asset.MetaPackageEcosystem, Value: "CentOS:7", Count: 2},
		{AssetType: "ec2_instance", Key: asset.MetaPackageEcosystem, Value: "Ubuntu:22.04:LTS", Count: 3},
		{AssetType: "gce_instance", Key: asset.MetaPackageEcosystem, Value: "Ubuntu:22.04:LTS", Count: 1},
		{AssetType: "ec2_instance", Key: asset.MetaPackageEcosystem, Value: "", Count: 4},
		{AssetType: "ec2_instance", Key: asset.MetaPackageCVEGap, Value: asset.CVEGapEOLDistro, Count: 2},
		{AssetType: "ec2_instance", Key: asset.MetaPackageCVEGap, Value: asset.CVEGapNoSourceNames, Count: 3},
		{AssetType: "gce_instance", Key: asset.MetaPackageCVEGap, Value: asset.CVEGapNoSourceNames, Count: 1},
		{AssetType: "ec2_instance", Key: asset.MetaPackageCVEGap, Value: "", Count: 11},
	}}
}

func TestAdvisoryFacts(t *testing.T) {
	now := time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)
	rows, gaps := newIndex(checks.Default(), advisoryFixture(), true).advisoryFacts(now)

	byEco := map[string]AdvisoryRow{}
	for _, r := range rows {
		byEco[r.Ecosystem] = r
	}
	require.Equal(t, "Amazon Linux:2023", rows[0].Ecosystem, "largest population first")
	assert.Equal(t, distro.SourceALAS, byEco["Amazon Linux:2023"].Source)
	assert.Equal(t, uint64(4), byEco["Ubuntu:22.04:LTS"].VMs, "summed across VM types")
	assert.Equal(t, distro.SourceOSV, byEco["Ubuntu:22.04:LTS"].Source)
	assert.Contains(t, strings.Join(byEco["Ubuntu:22.04:LTS"].Notes, " "), "source package")
	assert.Empty(t, byEco["CentOS:7"].Source, "CentOS is never matched against RHEL advisories")
	assert.Contains(t, strings.Join(byEco["CentOS:7"].Notes, " "), "past end of life 2024-06-30")
	assert.Equal(t, uint64(4), byEco[""].VMs, "VMs without an inventory are counted, not dropped")

	assert.Equal(t, []GapRow{
		{Gap: asset.CVEGapEOLDistro, VMs: 2},
		{Gap: asset.CVEGapNoSourceNames, VMs: 4},
	}, gaps, "an absent gap key is not a gap reason")
	for _, g := range gaps {
		assert.NotEmpty(t, gapMeaning[g.Gap], g.Gap)
	}
}

// Every gap value the producers can stamp has a meaning in the report.
func TestGapMeaningCoversEveryGap(t *testing.T) {
	for _, g := range []string{asset.CVEGapEOLDistro, asset.CVEGapNoAdvisorySource, asset.CVEGapNoSourceNames,
		asset.CVEGapUnknownRelease, asset.CVEGapAdvisorySourceDisabled, asset.CVEGapPackageDBUnread, asset.CVEGapScanIncomplete} {
		assert.NotEmpty(t, gapMeaning[g], g)
	}
}

func TestRenderAdvisorySection(t *testing.T) {
	offline := offlineDoc(t)
	section := offline[strings.Index(offline, "## VM OS advisory coverage"):]
	assert.Contains(t, section, "ALAS (`cdn.amazonlinux.com` updateinfo)", "the declared source table renders without a cluster")
	assert.Contains(t, section[:min(len(section), 3000)], needsLive)

	r := Report{Live: true,
		Advisory:     []AdvisoryRow{{Ecosystem: "CentOS:7", VMs: 2, Notes: []string{"past end of life 2024-06-30"}}},
		AdvisoryGaps: []GapRow{{Gap: asset.CVEGapEOLDistro, VMs: 2}}}
	var b strings.Builder
	renderAdvisory(&b, r)
	assert.Contains(t, b.String(), "| `CentOS:7` | 2 | none | past end of life 2024-06-30 |")
	assert.Contains(t, b.String(), "| `eol_distro` | 2 |")
}

func TestMetaMeasuresIncludeTheAdvisorySplits(t *testing.T) {
	keys := map[string]bool{}
	for _, m := range metaMeasures() {
		keys[m.Key] = true
	}
	assert.True(t, keys[asset.MetaPackageEcosystem])
	assert.True(t, keys[asset.MetaPackageCVEGap])
	assert.True(t, keys[asset.MetaPackageInventory], "the lineage stages' splits are still measured")
}
