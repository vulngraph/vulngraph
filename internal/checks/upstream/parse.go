package upstream

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// githubListing decodes a GitHub contents-API directory listing into entry
// names. An object instead of an array is the API's error shape (rate limit,
// not found): an error, never an empty directory.
func githubListing(raw []byte) ([]string, error) {
	var entries []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(raw, &entries); err != nil {
		var apiErr struct {
			Message string `json:"message"`
		}
		if json.Unmarshal(raw, &apiErr) == nil && apiErr.Message != "" {
			return nil, fmt.Errorf("githubListing: API error: %s", apiErr.Message)
		}
		return nil, fmt.Errorf("githubListing: %w", err)
	}
	if len(entries) == 0 {
		return nil, errors.New("githubListing: empty listing")
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name)
	}
	return out, nil
}

// versionsMatching extracts the version group of re from each name and maps
// version → name.
func versionsMatching(names []string, re *regexp.Regexp) map[string]string {
	out := map[string]string{}
	for _, n := range names {
		if m := re.FindStringSubmatch(n); m != nil {
			if _, err := parseVersion(m[1]); err == nil {
				out[m[1]] = n
			}
		}
	}
	return out
}

func prowlerCISPattern(provider string) *regexp.Regexp {
	return regexp.MustCompile(`^cis_([0-9][0-9.]*)_` + regexp.QuoteMeta(provider) + `\.json$`)
}

func kubeBenchPattern(prefix string) *regexp.Regexp {
	return regexp.MustCompile(`^` + regexp.QuoteMeta(prefix) + `([0-9][0-9.]*)$`)
}

// azurePolicyCISPatterns match both naming generations of the CIS Azure
// initiatives: CIS_Azure_Foundations_v3.0.0.json and CISv2_0_0.json.
var (
	azureCISNew = regexp.MustCompile(`^CIS_Azure_Foundations_v([0-9][0-9.]*)\.json$`)
	azureCISOld = regexp.MustCompile(`^CISv([0-9]+(?:_[0-9]+)*)\.json$`)
)

func azurePolicyCISVersions(names []string) []string {
	var out []string
	for v := range versionsMatching(names, azureCISNew) {
		out = append(out, v)
	}
	for _, n := range names {
		if m := azureCISOld.FindStringSubmatch(n); m != nil {
			out = append(out, strings.ReplaceAll(m[1], "_", "."))
		}
	}
	sort.Strings(out)
	return out
}

// ProwlerFramework is the subset of a Prowler compliance JSON graph reads.
type ProwlerFramework struct {
	Framework    string               `json:"Framework"`
	Version      string               `json:"Version"`
	Provider     string               `json:"Provider"`
	Requirements []ProwlerRequirement `json:"Requirements"`
}

// ProwlerRequirement is one requirement and the Prowler checks mapped to it.
type ProwlerRequirement struct {
	ID         string           `json:"Id"`
	Name       string           `json:"Name"`
	Checks     []string         `json:"Checks"`
	Attributes []map[string]any `json:"Attributes"`
}

// decodeProwler parses a Prowler compliance JSON; a file with no
// requirements is a broken fetch, not an empty benchmark.
func decodeProwler(raw []byte) (ProwlerFramework, error) {
	var f ProwlerFramework
	if err := json.Unmarshal(raw, &f); err != nil {
		return ProwlerFramework{}, fmt.Errorf("decodeProwler: %w", err)
	}
	if len(f.Requirements) == 0 {
		return ProwlerFramework{}, errors.New("decodeProwler: no requirements")
	}
	return f, nil
}

// section returns the requirement's first Attributes "Section" string.
func (r ProwlerRequirement) section() string {
	if len(r.Attributes) == 0 {
		return ""
	}
	s, _ := r.Attributes[0]["Section"].(string)
	return s
}

func prowlerIDs(f ProwlerFramework) []string {
	out := make([]string, 0, len(f.Requirements))
	for _, r := range f.Requirements {
		out = append(out, r.ID)
	}
	return out
}

// kubeBenchFile is the subset of a kube-bench cfg file graph reads. IDs
// decode as strings from the scalar text, so `5.10` stays "5.10" rather
// than becoming the float 5.1.
type kubeBenchFile struct {
	Groups []struct {
		Checks []struct {
			ID string `yaml:"id"`
		} `yaml:"checks"`
	} `yaml:"groups"`
}

func kubeBenchIDs(raw []byte) ([]string, error) {
	var f kubeBenchFile
	if err := yaml.NewDecoder(bytes.NewReader(raw)).Decode(&f); err != nil {
		return nil, fmt.Errorf("kubeBenchIDs: %w", err)
	}
	var out []string
	for _, g := range f.Groups {
		for _, c := range g.Checks {
			if c.ID != "" {
				out = append(out, c.ID)
			}
		}
	}
	return out, nil
}

// kubeBenchConfigFiles are the cfg files that hold benchmark checks;
// config.yaml is kube-bench's own binary/path configuration.
func kubeBenchConfigFiles(names []string) []string {
	var out []string
	for _, n := range names {
		if strings.HasSuffix(n, ".yaml") && n != "config.yaml" {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// Control is one upstream control: its ID and the upstream's own title.
type Control struct {
	ID    string `json:"id"`
	Title string `json:"title,omitempty"`
}

var (
	shRow    = regexp.MustCompile(`(?s)<tr>(.*?)</tr>`)
	shCell   = regexp.MustCompile(`(?s)<td[^>]*>(.*?)</td>`)
	shCtrlID = regexp.MustCompile(`>\s*([A-Za-z0-9]+\.[0-9]+)\s*<`)
	tags     = regexp.MustCompile(`<[^>]+>`)
)

func cellText(s string) string {
	return strings.Join(strings.Fields(html.UnescapeString(tags.ReplaceAllString(s, ""))), " ")
}

// fsbpStandard is how the reference page's "Applicable standards" column
// names FSBP (with or without the "v1.0.0" suffix).
const fsbpStandard = "AWS Foundational Security Best Practices"

// securityHubReferenceFSBP returns the FSBP controls of the Security Hub
// controls reference page: every table row whose applicable-standards cell
// names FSBP. The reference page is the newest list AWS publishes (the
// per-standard page lags it).
func securityHubReferenceFSBP(raw []byte) ([]Control, error) {
	var out []Control
	rows := 0
	for _, row := range shRow.FindAllSubmatch(raw, -1) {
		cells := shCell.FindAllSubmatch(row[1], -1)
		if len(cells) < 3 {
			continue
		}
		id := shCtrlID.FindSubmatch(cells[0][1])
		if id == nil {
			continue
		}
		rows++
		if strings.Contains(cellText(string(cells[2][1])), fsbpStandard) {
			out = append(out, Control{ID: string(id[1]), Title: cellText(string(cells[1][1]))})
		}
	}
	if rows == 0 {
		return nil, errors.New("securityHubReferenceFSBP: no control rows (page layout changed?)")
	}
	if len(out) == 0 {
		return nil, errors.New("securityHubReferenceFSBP: no FSBP controls")
	}
	return out, nil
}

// securityHubAPIControls decodes ListSecurityControlDefinitions output.
func securityHubAPIControls(raw []byte) ([]Control, error) {
	var resp struct {
		SecurityControlDefinitions []struct {
			SecurityControlID string `json:"SecurityControlId"`
			Title             string `json:"Title"`
		} `json:"SecurityControlDefinitions"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("securityHubAPIControls: %w", err)
	}
	if len(resp.SecurityControlDefinitions) == 0 {
		return nil, errors.New("securityHubAPIControls: no controls")
	}
	out := make([]Control, 0, len(resp.SecurityControlDefinitions))
	for _, d := range resp.SecurityControlDefinitions {
		out = append(out, Control{ID: d.SecurityControlID, Title: d.Title})
	}
	return out, nil
}

// securityHubPages lists the per-service controls pages the reference page
// links to.
var shPageLink = regexp.MustCompile(`href="\./([a-z0-9-]+-controls\.html)`)

func securityHubPages(reference []byte) []string {
	set := map[string]bool{}
	for _, m := range shPageLink.FindAllSubmatch(reference, -1) {
		set[string(m[1])] = true
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// shRelated matches one control heading and its "Related requirements"
// paragraph on a per-service page.
var shRelated = regexp.MustCompile(`(?s)<h2 id="[^"]+">\[([A-Za-z0-9]+\.[0-9]+)\][^<]*</h2>\s*<p><b>Related requirements:</b>(.*?)</p>`)

// securityHubRelated maps control ID → its related-requirements text.
func securityHubRelated(page []byte) map[string]string {
	out := map[string]string{}
	for _, m := range shRelated.FindAllSubmatch(page, -1) {
		out[string(m[1])] = cellText(string(m[2]))
	}
	return out
}
