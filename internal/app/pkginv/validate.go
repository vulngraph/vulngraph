package pkginv

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
)

// Request is the wire shape of one submission, shared by REST and MCP.
type Request struct {
	AssetID         string       `json:"asset_id"`
	CloudResourceID string       `json:"cloud_resource_id"`
	OS              *RequestOS   `json:"os"`
	Packages        []RequestPkg `json:"packages"`
	ObservedAt      string       `json:"observed_at"`
	Scanner         RequestScan  `json:"scanner"`
	Complete        bool         `json:"complete"`
	Covered         []Covered    `json:"covered"`
}

// RequestOS is the os block.
type RequestOS struct {
	ID        string `json:"id"`
	VersionID string `json:"version_id"`
	Name      string `json:"name"`
}

// RequestScan is the scanner block.
type RequestScan struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// RequestPkg is one package: a purl, or ecosystem, name and version.
type RequestPkg struct {
	PURL          string `json:"purl"`
	Ecosystem     string `json:"ecosystem"`
	Name          string `json:"name"`
	Version       string `json:"version"`
	SourceName    string `json:"source_name"`
	SourceVersion string `json:"source_version"`
	Epoch         string `json:"epoch"`
	Release       string `json:"release"`
}

// DecodeRequest reads one JSON object, rejecting unknown fields and trailing
// data. A body that exceeds the reader's size limit returns that error
// unwrapped into ErrInvalid so the transport can answer 413.
func DecodeRequest(r io.Reader) (Request, error) {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	var req Request
	if err := dec.Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			return Request{}, fmt.Errorf("DecodeRequest: %w", err)
		}
		return Request{}, invalid("body: not a valid inventory object (%v)", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return Request{}, invalid("body: trailing data after the inventory object")
	}
	return req, nil
}

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Field grammars. Everything stored or stamped matches one of these, so no
// stored field can hold a newline or any character an LLM prompt could be built
// from beyond the pattern.
var (
	reScannerName    = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	reScannerVersion = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]{0,62}$`)
	reOSID           = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	reOSVersion      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]{0,63}$`)
	reOSName         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._+()/-]{0,63}$`)
	rePkgName        = regexp.MustCompile(`^[A-Za-z0-9@][A-Za-z0-9._+~:@/-]{0,199}$`)
	rePkgVersion     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~:^-]{0,127}$`)
	reRelease        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$`)
	reEpoch          = regexp.MustCompile(`^[0-9]{1,9}$`)
	reCoveredPath    = regexp.MustCompile(`^/[A-Za-z0-9._/@+ -]{0,254}$`)
	reVolumeID       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	reResourceID     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+=,-]{0,511}$`)
)

// languageEcosystems are the non-OS ecosystems an agent may state; each has a
// purl type pkginventory.PURL knows.
var languageEcosystems = map[string]string{
	"npm": "npm", "PyPI": "pypi", "Go": "golang", "Maven": "maven", "crates.io": "cargo", "RubyGems": "gem",
}

// purlTypes maps a purl type to the language ecosystem it means; OS purl types
// (deb, rpm, apk) are handled by the OS block.
var purlTypes = map[string]string{
	"npm": "npm", "pypi": "PyPI", "golang": "Go", "maven": "Maven", "cargo": "crates.io", "gem": "RubyGems",
}

var osPurlScopes = map[string]string{
	"deb": "deb", "rpm": "rpm", "apk": "apk",
}

// Validate checks req against every rule and returns the normalised
// submission. now is the server clock. Errors wrap ErrInvalid and name the
// field and rule, never the submitted value.
func Validate(req Request, now time.Time) (Submission, error) {
	var s Submission
	if req.AssetID != "" && !reResourceID.MatchString(req.AssetID) {
		return s, invalid("asset_id: not a valid identifier")
	}
	if req.CloudResourceID != "" && !reResourceID.MatchString(req.CloudResourceID) {
		return s, invalid("cloud_resource_id: not a valid identifier")
	}
	s.AssetID, s.CloudResourceID, s.Complete = req.AssetID, req.CloudResourceID, req.Complete

	if !reScannerName.MatchString(req.Scanner.Name) {
		return s, invalid("scanner.name: required, 1-63 chars of a-z 0-9 . _ -")
	}
	if !reScannerVersion.MatchString(req.Scanner.Version) {
		return s, invalid("scanner.version: required, 1-63 chars of A-Z a-z 0-9 . _ + ~ -")
	}
	s.Scanner = Scanner{Name: req.Scanner.Name, Version: req.Scanner.Version}

	observed, err := time.Parse(time.RFC3339, req.ObservedAt)
	if err != nil {
		return s, invalid("observed_at: required, RFC 3339")
	}
	if observed.After(now.Add(MaxFutureSkew)) {
		return s, invalid("observed_at: more than 5 minutes in the future")
	}
	if observed.Before(now.Add(-MaxAge)) {
		return s, invalid("observed_at: older than 30 days")
	}
	s.ObservedAt = observed.UTC()

	if err := validateOS(req.OS, &s); err != nil {
		return s, err
	}
	if err := validateCovered(req.Covered, &s); err != nil {
		return s, err
	}
	if len(req.Packages) > MaxPackages {
		return s, invalid("packages: more than %d (over_package_cap); split by machine or drop the list", MaxPackages)
	}
	osFamily := pkginventory.InventoryEcosystem(s.OS.ID, s.OS.VersionID)
	seen := make(map[Package]bool, len(req.Packages))
	for i, rp := range req.Packages {
		p, err := validatePackage(rp, osFamily)
		if err != nil {
			return s, invalid("packages[%d]: %s", i, strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": "))
		}
		if !seen[p] {
			seen[p] = true
			s.Packages = append(s.Packages, p)
		}
	}
	return s, nil
}

func validateOS(o *RequestOS, s *Submission) error {
	if o == nil {
		return nil
	}
	if o.ID != "" && !reOSID.MatchString(o.ID) {
		return invalid("os.id: 1-64 chars of a-z 0-9 . _ -")
	}
	if o.VersionID != "" && !reOSVersion.MatchString(o.VersionID) {
		return invalid("os.version_id: 1-64 chars of A-Z a-z 0-9 . _ + ~ -")
	}
	if o.Name != "" && !reOSName.MatchString(o.Name) {
		return invalid("os.name: 1-64 printable chars of A-Z a-z 0-9 space . _ + ( ) / -")
	}
	s.OS = OS{ID: o.ID, VersionID: o.VersionID, Name: o.Name}
	return nil
}

func validateCovered(in []Covered, s *Submission) error {
	if len(in) > MaxCovered {
		return invalid("covered: more than %d entries", MaxCovered)
	}
	for i, c := range in {
		switch {
		case (c.Path == "") == (c.VolumeID == ""):
			return invalid("covered[%d]: exactly one of path or volume_id", i)
		case c.Path != "" && !reCoveredPath.MatchString(c.Path):
			return invalid("covered[%d].path: absolute path of printable ASCII, at most 255 chars", i)
		case c.VolumeID != "" && !reVolumeID.MatchString(c.VolumeID):
			return invalid("covered[%d].volume_id: 1-128 chars of A-Z a-z 0-9 . _ : / -", i)
		}
	}
	s.Covered = in
	return nil
}

// validatePackage turns one entry into a Package. osEcosystem is the ecosystem
// the os block resolves to ("" when it does not); an OS package whose family
// disagrees with it is refused.
func validatePackage(rp RequestPkg, osEcosystem string) (Package, error) {
	if rp.PURL != "" {
		if rp.Name != "" || rp.Version != "" {
			return Package{}, invalid("give a purl or ecosystem/name/version, not both")
		}
		return fromPURL(rp, osEcosystem)
	}
	p := Package{
		Name: rp.Name, Version: rp.Version,
		SourceName: rp.SourceName, SourceVersion: rp.SourceVersion, Epoch: rp.Epoch, Release: rp.Release,
	}
	switch eco := rp.Ecosystem; {
	case eco == "" || eco == "os":
	case languageEcosystems[eco] != "":
		p.Ecosystem = eco
	case osEcosystem != "" && eco == familyOf(osEcosystem):
	default:
		return Package{}, invalid("ecosystem: %q is not os, a language ecosystem, or the os block's family", eco)
	}
	return p, checkPackageFields(p)
}

func familyOf(ecosystem string) string {
	f, _, _ := strings.Cut(ecosystem, ":")
	return f
}

func checkPackageFields(p Package) error {
	switch {
	case !rePkgName.MatchString(p.Name):
		return invalid("name: 1-200 chars of A-Z a-z 0-9 . _ + ~ : @ / -")
	case !rePkgVersion.MatchString(p.Version):
		return invalid("version: 1-128 chars of A-Z a-z 0-9 . _ + ~ : ^ -")
	case p.SourceName != "" && !rePkgName.MatchString(p.SourceName):
		return invalid("source_name: 1-200 chars of A-Z a-z 0-9 . _ + ~ : @ / -")
	case p.SourceVersion != "" && !rePkgVersion.MatchString(p.SourceVersion):
		return invalid("source_version: 1-128 chars of A-Z a-z 0-9 . _ + ~ : ^ -")
	case p.Epoch != "" && !reEpoch.MatchString(p.Epoch):
		return invalid("epoch: digits only")
	case p.Release != "" && !reRelease.MatchString(p.Release):
		return invalid("release: 1-128 chars of A-Z a-z 0-9 . _ + ~ -")
	}
	return nil
}

// fromPURL parses pkg:type/[namespace/]name@version, without qualifiers or a
// subpath, into the same Package the structured form builds. The purl is only
// an encoding: the stored identity is always re-minted by pkginventory.PURL.
func fromPURL(rp RequestPkg, osEcosystem string) (Package, error) {
	rest, ok := strings.CutPrefix(rp.PURL, "pkg:")
	if !ok || strings.ContainsAny(rest, "?#") || len(rp.PURL) > 512 {
		return Package{}, invalid("purl: must be pkg:type/name@version with no qualifiers or subpath")
	}
	typ, path, ok := strings.Cut(rest, "/")
	at := strings.LastIndexByte(path, '@')
	if !ok || at <= 0 || at == len(path)-1 {
		return Package{}, invalid("purl: must be pkg:type/name@version")
	}
	version, err := url.PathUnescape(path[at+1:])
	if err != nil {
		return Package{}, invalid("purl: bad percent-encoding in the version")
	}
	var segs []string
	for _, seg := range strings.Split(path[:at], "/") {
		d, err := url.PathUnescape(seg)
		if err != nil || d == "" {
			return Package{}, invalid("purl: bad name segment")
		}
		segs = append(segs, d)
	}
	p := Package{Version: version, SourceName: rp.SourceName, SourceVersion: rp.SourceVersion, Epoch: rp.Epoch, Release: rp.Release}
	if eco, lang := purlTypes[typ]; lang {
		if rp.Ecosystem != "" && rp.Ecosystem != eco {
			return Package{}, invalid("purl type %q does not match ecosystem %q", typ, rp.Ecosystem)
		}
		p.Ecosystem, p.Name = eco, strings.Join(segs, "/")
		return p, checkPackageFields(p)
	}
	if osPurlScopes[typ] == "" || len(segs) != 2 {
		return Package{}, invalid("purl: type %q is not supported (deb, rpm, apk, npm, pypi, golang, maven, cargo, gem)", typ)
	}
	if osEcosystem == "" || !osPurlMatches(typ, segs[0], osEcosystem) {
		return Package{}, invalid("purl: %s/%s does not match the os block", typ, segs[0])
	}
	if rp.Ecosystem != "" && rp.Ecosystem != "os" && rp.Ecosystem != familyOf(osEcosystem) {
		return Package{}, invalid("purl type %q does not match ecosystem %q", typ, rp.Ecosystem)
	}
	p.Name = segs[1]
	return p, checkPackageFields(p)
}

// osPurlMatches reports whether a deb/rpm/apk purl of the given distro scope is
// what an OS of osEcosystem installs, using the purl the package assets are
// keyed by.
func osPurlMatches(typ, scope, osEcosystem string) bool {
	probe := pkginventory.PURL(pkginventory.InstalledPackage{Ecosystem: osEcosystem, Name: "x", Version: "1"})
	return strings.HasPrefix(probe, "pkg:"+typ+"/"+scope+"/")
}
