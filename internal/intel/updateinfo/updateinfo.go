// Package updateinfo is the distro advisory feed for the rpm distributions OSV
// does not carry: Amazon Linux (ALAS) and Oracle Linux (ELSA).
//
// Both vendors publish their security advisories as the yum repositories' own
// updateinfo.xml — the file `yum updateinfo` / `dnf updateinfo` read on every
// host, listing per advisory the exact package NEVRAs that fix it. That makes it
// the authoritative machine-readable source with fixed versions: the ALAS RSS
// feeds carry titles and CVEs but no package versions, and Oracle's OVAL is the
// same errata re-expressed as a 13 MB OVAL document. The repositories are
// public, unauthenticated and served from CDNs (cdn.amazonlinux.com,
// yum.oracle.com); this package reads them the way yum does and stores nothing
// beyond process memory.
package updateinfo

import (
	"encoding/xml"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/intel/rpmver"
)

// Advisory is one security advisory reduced to what matching needs.
type Advisory struct {
	ID       string // ALAS2-2024-2500, ALAS2023-2024-600, ELSA-2024-1234
	Title    string
	Severity finding.Severity
	CVEs     []string
	Issued   time.Time
	// Fixed maps each BINARY package name the advisory updates to its fixed
	// epoch:version-release. One entry per name: architectures share a version,
	// and where they did not the highest is kept (an install below it is not
	// patched on every architecture the advisory covers).
	Fixed map[string]string
	// Stream is the kernel line the advisory applies to (Repo.Stream), or
	// empty for a core-repository advisory. A matcher must apply a stream
	// advisory only to installed versions on its line (OnStream).
	Stream string
}

// xmlUpdate is one <update> element of updateinfo.xml.
type xmlUpdate struct {
	Type     string `xml:"type,attr"`
	ID       string `xml:"id"`
	Title    string `xml:"title"`
	Severity string `xml:"severity"`
	Issued   struct {
		Date string `xml:"date,attr"`
	} `xml:"issued"`
	References []struct {
		ID   string `xml:"id,attr"`
		Type string `xml:"type,attr"`
	} `xml:"references>reference"`
	Packages []struct {
		Name    string `xml:"name,attr"`
		Epoch   string `xml:"epoch,attr"`
		Version string `xml:"version,attr"`
		Release string `xml:"release,attr"`
		Arch    string `xml:"arch,attr"`
	} `xml:"pkglist>collection>package"`
}

// Parse stream-decodes an updateinfo.xml document and returns its security
// advisories. Non-security updates (bugfix, enhancement) are skipped, as are
// source rpms: an inventory lists installed binaries, and a src entry would
// only ever match a binary that happens to share the source's name.
//
// It streams one <update> at a time: Oracle's appstream updateinfo is ~35 MB
// uncompressed, and holding the DOM would cost several times that.
func Parse(r io.Reader) ([]Advisory, error) {
	dec := xml.NewDecoder(r)
	var out []Advisory
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, fmt.Errorf("Parse: %w", err)
		}
		start, ok := tok.(xml.StartElement)
		if !ok || start.Name.Local != "update" {
			continue
		}
		var u xmlUpdate
		if err := dec.DecodeElement(&u, &start); err != nil {
			return nil, fmt.Errorf("Parse: update: %w", err)
		}
		if a, ok := u.advisory(); ok {
			out = append(out, a)
		}
	}
}

func (u xmlUpdate) advisory() (Advisory, bool) {
	if u.Type != "security" || strings.TrimSpace(u.ID) == "" {
		return Advisory{}, false
	}
	a := Advisory{
		ID:       strings.TrimSpace(u.ID),
		Title:    strings.TrimSpace(u.Title),
		Severity: MapSeverity(u.Severity),
		Fixed:    map[string]string{},
	}
	if t, err := time.Parse(time.DateTime, strings.TrimSpace(u.Issued.Date)); err == nil {
		a.Issued = t
	}
	seen := map[string]bool{}
	for _, ref := range u.References {
		id := strings.ToUpper(strings.TrimSpace(ref.ID))
		if ref.Type == "cve" && strings.HasPrefix(id, "CVE-") && !seen[id] {
			seen[id] = true
			a.CVEs = append(a.CVEs, id)
		}
	}
	sort.Strings(a.CVEs)
	for _, p := range u.Packages {
		if p.Name == "" || p.Version == "" || p.Arch == "src" {
			continue
		}
		evr := EVR(p.Epoch, p.Version, p.Release)
		if cur, ok := a.Fixed[p.Name]; !ok || rpmver.Compare(evr, cur) > 0 {
			a.Fixed[p.Name] = evr
		}
	}
	if len(a.Fixed) == 0 {
		return Advisory{}, false
	}
	return a, true
}

// EVR renders an rpm epoch/version/release as the single string rpm compares,
// in the same form the inventory producers emit (internal/scanner/pkginventory:
// InventoryPackage): a zero or absent epoch is dropped.
func EVR(epoch, version, release string) string {
	s := version
	if release != "" {
		s += "-" + release
	}
	if epoch != "" && epoch != "0" {
		s = epoch + ":" + s
	}
	return s
}

// MapSeverity maps the vendors' ratings to finding severities. Amazon rates
// critical / important / medium / low, Oracle critical / important / moderate
// / low. An unrated advisory is medium: present but unranked is not a reason
// to page or to bury (the same default the OSV feed applies).
func MapSeverity(s string) finding.Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return finding.SeverityCritical
	case "important":
		return finding.SeverityHigh
	case "low":
		return finding.SeverityLow
	default:
		return finding.SeverityMedium
	}
}

// OnStream reports whether an rpm epoch:version-release is on a kernel line:
// "5.10.205-195.807.amzn2" and "0:5.10.1-1" are on "5.10", "5.4.17-…" is not on
// "5.15".
func OnStream(evr, stream string) bool {
	if _, rest, ok := strings.Cut(evr, ":"); ok {
		evr = rest
	}
	return strings.HasPrefix(evr, stream+".") || strings.HasPrefix(evr, stream+"-") || evr == stream
}

// ScopeToStream marks a stream repository's advisories with their line and
// keeps only the fixed versions ON it. The channels also carry a few packages
// off the kernel's line (dtrace, xfsprogs builds for that kernel); a fix for
// one of those cannot be scoped to a line, and matching it against the core
// repository's build of the same name would raise a CVE the host does not
// have — so it is dropped, a documented gap. An advisory left with nothing is
// dropped too.
func ScopeToStream(advs []Advisory, stream string) []Advisory {
	out := make([]Advisory, 0, len(advs))
	for _, a := range advs {
		fixed := map[string]string{}
		for name, evr := range a.Fixed {
			if OnStream(evr, stream) {
				fixed[name] = evr
			}
		}
		if len(fixed) == 0 {
			continue
		}
		a.Fixed, a.Stream = fixed, stream
		out = append(out, a)
	}
	return out
}

// merge folds advisories read from several repositories of one release (two
// architectures, baseos + appstream) into one list: the same advisory id is one
// advisory whose Fixed set is the union. The key is (id, stream): one id read
// from two kernel lines must stay two advisories, each scoped to its own line,
// or one line's fixes would be matched against the other's installs.
func merge(lists ...[]Advisory) []Advisory {
	byID := map[string]*Advisory{}
	var order []string
	for _, list := range lists {
		for _, a := range list {
			key := a.ID + "\x00" + a.Stream
			cur, ok := byID[key]
			if !ok {
				cp := a
				cp.Fixed = make(map[string]string, len(a.Fixed))
				for k, v := range a.Fixed {
					cp.Fixed[k] = v
				}
				byID[key] = &cp
				order = append(order, key)
				continue
			}
			for name, evr := range a.Fixed {
				if have, ok := cur.Fixed[name]; !ok || rpmver.Compare(evr, have) > 0 {
					cur.Fixed[name] = evr
				}
			}
			for _, cve := range a.CVEs {
				if !slices.Contains(cur.CVEs, cve) {
					cur.CVEs = append(cur.CVEs, cve)
				}
			}
			sort.Strings(cur.CVEs)
		}
	}
	out := make([]Advisory, 0, len(order))
	for _, id := range order {
		out = append(out, *byID[id])
	}
	return out
}
