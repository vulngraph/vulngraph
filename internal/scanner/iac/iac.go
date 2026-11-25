// Package iac is a minimal, dependency-light infrastructure-as-code scanner: it
// parses Terraform HCL into a flat resource model and runs a catalog of
// high-impact misconfiguration checks over it. It is pure (no I/O, no cloud, no
// finding/asset imports) so it unit-tests against inline .tf fixtures; the
// GitHub collector fetches the files and maps the returned Issues onto findings.
//
// Scope (deliberately minimal): Terraform only, a hand-picked set of
// the highest-signal AWS misconfigurations. It is a shift-left signal on the repo,
// not a replacement for CSPM on the deployed resource. Linking an IaC resource to
// its deployed cloud asset (a source_code_defines edge) needs tfstate or a tagging
// convention to be reliable and is left as a follow-up.
package iac

import "sort"

// Severity mirrors the finding severities without importing the finding package
// (keeps iac a leaf). The collector maps these strings onto finding.Severity.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

// Issue is one misconfiguration found on one Terraform resource. Neutral by
// design: the caller keys it onto whatever asset it likes (today: the repo).
type Issue struct {
	RuleID   string // stable check id, e.g. "iac-tf-s3-public-acl"
	Title    string
	Severity string
	Resource string // Terraform address, e.g. `aws_s3_bucket.assets`
	File     string // source file the resource was declared in
	Detail   string // what specifically is wrong
	Fix      string // remediation hint
}

// Scan parses every Terraform file (name → content) and runs all checks,
// returning the issues in a stable order (by file, then resource, then rule).
// Files that fail to parse are skipped and reported via parseErrors so the caller
// can log them without failing the whole scan.
func Scan(files map[string]string) (issues []Issue, parseErrors map[string]error) {
	parseErrors = map[string]error{}
	var resources []Resource
	for name, content := range files {
		rs, err := ParseHCL(name, content)
		if err != nil {
			parseErrors[name] = err
			continue
		}
		resources = append(resources, rs...)
	}
	for _, r := range resources {
		for _, check := range checks {
			issues = append(issues, check(r)...)
		}
	}
	sort.Slice(issues, func(i, j int) bool {
		a, b := issues[i], issues[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Resource != b.Resource {
			return a.Resource < b.Resource
		}
		return a.RuleID < b.RuleID
	})
	if len(parseErrors) == 0 {
		parseErrors = nil
	}
	return issues, parseErrors
}
