package coverage

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/distro"
)

// VM OS advisory coverage: which advisory source can match each inventoried
// OS release's packages, and why the VMs that cannot support a CVE verdict
// cannot. The lineage chain says HOW MANY VMs are CVE-matchable; this section
// says WHICH releases are not and for what reason, so a gap stays visible
// instead of hiding inside a percentage.

// vmTypes are the VM asset types the inventory collectors stamp.
var vmTypes = []string{"ec2_instance", "gce_instance", "azure_vm"}

// metaMeasure is one metadata key split measured over some asset types.
type metaMeasure struct {
	Key   string
	Types []string
}

// metaMeasures is every split the repository measures: each StageAssetMeta
// lineage stage's key, plus the two this section reads.
func metaMeasures() []metaMeasure {
	var out []metaMeasure
	for _, st := range LineageStages {
		if st.Kind == StageAssetMeta {
			out = append(out, metaMeasure{Key: st.MetaKey, Types: st.Types})
		}
	}
	return append(out,
		metaMeasure{Key: asset.MetaPackageEcosystem, Types: vmTypes},
		metaMeasure{Key: asset.MetaPackageCVEGap, Types: vmTypes},
	)
}

// AdvisoryRow is one inventoried OS release and the source covering it.
type AdvisoryRow struct {
	Ecosystem string
	VMs       uint64
	Source    string // distro.Source*, "" for none
	Notes     []string
}

// GapRow is how many VMs carry one package_cve_gap reason.
type GapRow struct {
	Gap string
	VMs uint64
}

// gapMeaning explains each asset.CVEGap* value.
var gapMeaning = map[string]string{
	asset.CVEGapEOLDistro:        "release is past a final end of life: the vendor publishes no further advisories",
	asset.CVEGapNoAdvisorySource: "no advisory source covers the distribution",
	asset.CVEGapNoSourceNames: "the source keys advisories by source package; the inventory lists binary names only " +
		"(dpkg via SSM and every GCP OS Config list — neither API reports a source package)",
	asset.CVEGapUnknownRelease: "the OS release could not be read, so no release-scoped advisory set applies",
	asset.CVEGapPackageDBUnread: "the OS packages live in a package database that could not be read in full " +
		"(a corrupt, unknown-format or oversized rpm database, or none the scanner reads); none were inventoried",
	asset.CVEGapScanIncomplete: "the image scan stopped before reading every layer (a size cap, a corrupt or " +
		"unreadable layer); the oldest layers, usually the OS base, were not inventoried",
	asset.CVEGapAdvisorySourceDisabled: "the advisory source covering the distribution is switched off " +
		"(`INTEL_OSV_DISABLED`, `INTEL_ALAS_DISABLED`, `INTEL_ELSA_DISABLED` or `OFFLINE_MODE`)",
}

// sourceLabel names an advisory source and the host it is fetched from.
func sourceLabel(src string) string {
	switch src {
	case distro.SourceOSV:
		return "OSV (`api.osv.dev`)"
	case distro.SourceALAS:
		return "ALAS (`cdn.amazonlinux.com` updateinfo)"
	case distro.SourceELSA:
		return "ELSA (`yum.oracle.com` updateinfo)"
	}
	return "none"
}

// advisoryFacts derives the section's rows from the measured splits.
func (i *index) advisoryFacts(now time.Time) ([]AdvisoryRow, []GapRow) {
	byEco := map[string]uint64{}
	byGap := map[string]uint64{}
	for k, n := range i.metaValues {
		switch k[1] {
		case asset.MetaPackageEcosystem:
			byEco[k[2]] += n
		case asset.MetaPackageCVEGap:
			if k[2] != "" {
				byGap[k[2]] += n
			}
		}
	}
	rows := make([]AdvisoryRow, 0, len(byEco))
	for eco, n := range byEco {
		row := AdvisoryRow{Ecosystem: eco, VMs: n}
		if eco == "" {
			row.Notes = []string{"no known package inventory"}
			rows = append(rows, row)
			continue
		}
		if f, ok := distro.FamilyOf(eco); ok {
			row.Source = f.Source
			if f.Source == "" {
				row.Notes = append(row.Notes, f.NoSourceReason)
			}
			if f.SourceKeyed {
				row.Notes = append(row.Notes, "keyed by source package: matchable only where the inventory carries source names (rpm via SSM, container image scans)")
			}
		}
		if l, ok := distro.EndOfLife(eco); ok && l.Past(now) {
			row.Notes = append(row.Notes, "past end of life "+l.End.Format(time.DateOnly))
		}
		rows = append(rows, row)
	}
	sort.Slice(rows, func(a, b int) bool {
		if rows[a].VMs != rows[b].VMs {
			return rows[a].VMs > rows[b].VMs
		}
		return rows[a].Ecosystem < rows[b].Ecosystem
	})
	gaps := make([]GapRow, 0, len(byGap))
	for g, n := range byGap {
		gaps = append(gaps, GapRow{Gap: g, VMs: n})
	}
	sort.Slice(gaps, func(a, b int) bool { return gaps[a].Gap < gaps[b].Gap })
	return rows, gaps
}

func renderAdvisory(b *strings.Builder, r Report) {
	b.WriteString("## VM OS advisory coverage\n\n")
	b.WriteString("Which advisory source can match each distribution's packages. A VM is only\n")
	b.WriteString("called clean by the absence of CVE findings when its whole inventory can be\n")
	b.WriteString("matched (`package_cve_matchable = true`); `package_cve_gap` says why not.\n\n")
	b.WriteString("| Distribution | Advisory source | Keyed by | Why none |\n|---|---|---|---|\n")
	for _, f := range distro.Families() {
		keyed := "binary package"
		if f.SourceKeyed {
			keyed = "source package"
		}
		if f.Source == "" {
			keyed = "—"
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s |\n", f.Name, sourceLabel(f.Source), keyed, f.NoSourceReason)
	}
	b.WriteString("\n")
	if !r.Live {
		b.WriteString(needsLive + "\n\n")
		return
	}
	warnIfIncomplete(b, r, stepMetaValues)
	b.WriteString("| OS release (`package_ecosystem`) | Fresh VMs | Advisory source | Notes |\n|---|---:|---|---|\n")
	for _, row := range r.Advisory {
		eco := "`" + row.Ecosystem + "`"
		if row.Ecosystem == "" {
			eco = "(none)"
		}
		fmt.Fprintf(b, "| %s | %d | %s | %s |\n", eco, row.VMs, sourceLabel(row.Source), strings.Join(row.Notes, "; "))
	}
	b.WriteString("\n| `package_cve_gap` | Fresh VMs | Meaning |\n|---|---:|---|\n")
	for _, g := range r.AdvisoryGaps {
		fmt.Fprintf(b, "| `%s` | %d | %s |\n", g.Gap, g.VMs, gapMeaning[g.Gap])
	}
	b.WriteString("\n")
}
