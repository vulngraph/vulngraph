// Package nuclei is the ONLY package that imports the nuclei SDK.
// It adapts the SDK to the scan.Scanner interface, returning provider-neutral
// scan.Result values so nothing else in the codebase sees nuclei's types.
package nuclei

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	nucleiSdk "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"

	"github.com/vulngraph/vulngraph/internal/app/scan"
)

// Scan guardrails. Without these the SDK installs an UNLIMITED rate
// limiter and no scan deadline, so a scan blasts owned targets at full speed and
// can run/accumulate results unbounded in the worker — target-side DoS plus
// worker OOM. These are conservative fixed bounds, not tuned per-scan.
const (
	globalRateLimit     = 150 // max requests per globalRateInterval, across all hosts
	globalRateInterval  = time.Second
	templateConcurrency = 25 // templates run concurrently per host (SDK-recommended)
	hostConcurrency     = 25 // hosts scanned concurrently
	probeConcurrency    = 50 // concurrent HTTP probes (SDK-recommended)
	maxScanDuration     = 30 * time.Minute
)

// concurrency fills every field of nucleiSdk.Concurrency: the SDK rejects a
// zero in any of them, headless and javascript included, even though headless
// never runs. template and host bound templates and hosts in flight; payloads
// follow template.
func concurrency(template, host, probe int) nucleiSdk.Concurrency {
	return nucleiSdk.Concurrency{
		TemplateConcurrency:           template,
		HostConcurrency:               host,
		HeadlessHostConcurrency:       1,
		HeadlessTemplateConcurrency:   1,
		JavascriptTemplateConcurrency: template,
		TemplatePayloadConcurrency:    template,
		ProbeConcurrency:              probe,
	}
}

// Engine runs nuclei templates against targets via the embedded SDK. It is the
// reference scan.Scanner connector (Capability web).
type Engine struct {
	allowInternal bool
}

// New returns an engine that refuses private, loopback, link-local and
// metadata addresses unless scan.AllowInternalTargetsEnv opts in.
func New() *Engine { return &Engine{allowInternal: scan.AllowInternalTargets()} }

// sandboxOption blocks local file access always, and local network access
// unless allowInternal. Enforced in nuclei's dialer, so it also covers DNS
// records and redirects that point inward, not just the literal target.
//
// The SDK's own local-network deny list misses the IPv6 unspecified address
// (::, which reaches local listeners) and IPv4-mapped addresses, so those are
// added when restricted. scan.AlwaysBlockedTargets — link-local and the cloud
// metadata endpoints — is added either way: opting in to internal targets
// never opens the instance credentials.
func sandboxOption(allowInternal bool) nucleiSdk.NucleiSDKOptions {
	return func(e *nucleiSdk.NucleiEngine) error {
		if err := nucleiSdk.WithSandboxOptions(false, !allowInternal)(e); err != nil {
			return fmt.Errorf("sandboxOption: %w", err)
		}
		opts := e.Options()
		opts.ExcludeTargets = append(opts.ExcludeTargets, sandboxExcludes(allowInternal)...)
		return nil
	}
}

// restrictedExtraExcludes close the gaps in the SDK's local-network deny list.
var restrictedExtraExcludes = []string{
	"::/96",         // unspecified (::) and IPv4-compatible
	"::ffff:0:0/96", // IPv4-mapped: ::ffff:127.0.0.1 is loopback
	"fec0::/10",     // deprecated site-local
}

// sandboxExcludes is the dial-time deny list nuclei gets on top of its own.
func sandboxExcludes(allowInternal bool) []string {
	out := append([]string{}, scan.AlwaysBlockedTargets...)
	if !allowInternal {
		out = append(out, restrictedExtraExcludes...)
	}
	return out
}

// Name identifies this connector for attribution, dedup, and config selection.
func (e *Engine) Name() string { return "nuclei" }

// Capabilities reports that nuclei scans web (URL) targets.
func (e *Engine) Capabilities() scan.Capability { return scan.CapWeb }

// templateTagsFor derives contextually-relevant nuclei template tags from the
// target set. This avoids blasting all 8000+ templates at every host — instead
// we select only templates that match the asset types and technology stack.
func templateTagsFor(targets []scan.Target) (include, exclude []string) {
	typesSeen := map[string]bool{}
	technologyHints := map[string]bool{}

	for _, t := range targets {
		typesSeen[t.AssetType] = true
		for k, v := range t.Tags {
			lower := strings.ToLower(v)
			if strings.Contains(k, "service") || strings.Contains(k, "app") || strings.Contains(k, "product") {
				technologyHints[lower] = true
			}
		}
	}

	tagSet := map[string]bool{
		// Always: exposure detection + generic misconfigs
		"exposure":  true,
		"misconfig": true,
	}

	for assetType := range typesSeen {
		switch assetType {
		case "gcs_bucket", "s3_bucket":
			tagSet["storage"] = true
			tagSet["cloud"] = true
			tagSet["bucket"] = true
		case "gce_instance", "ec2_instance":
			tagSet["network"] = true
			tagSet["cloud"] = true
			tagSet["linux"] = true
		case "k8s_service", "k8s_deployment", "k8s_pod":
			tagSet["kubernetes"] = true
			tagSet["network"] = true
		case "load_balancer":
			tagSet["network"] = true
			tagSet["http"] = true
		case "dns_record":
			tagSet["dns"] = true
			tagSet["takeover"] = true
		}
	}

	// Technology hints from asset tags (e.g. "service-name: nginx")
	for hint := range technologyHints {
		switch {
		case strings.Contains(hint, "nginx"):
			tagSet["nginx"] = true
		case strings.Contains(hint, "apache"):
			tagSet["apache"] = true
		case strings.Contains(hint, "redis"):
			tagSet["redis"] = true
		case strings.Contains(hint, "mysql"), strings.Contains(hint, "postgres"):
			tagSet["database"] = true
		case strings.Contains(hint, "jenkins"):
			tagSet["jenkins"] = true
		case strings.Contains(hint, "wordpress"):
			tagSet["wordpress"] = true
		}
	}

	// Exclude noisy/intrusive/irrelevant tags for cloud infra, and the
	// credential-attempt templates (optInTags) that can lock accounts or trip
	// an IDS. A scan nobody configured never tries a login.
	exclude = append([]string{"fuzzing", "intrusive", "dos", "windows", "iis", "sharepoint", "lotus"}, optInTags...)

	for tag := range tagSet {
		include = append(include, tag)
	}
	return include, exclude
}

// optInTags are the credential-attempt template tags (default logins and
// brute force). They are excluded unless a scan profile names one explicitly.
var optInTags = []string{"default-login", "brute-force", "bruteforce"}

// scanTags picks the template tags for one scan. A non-empty templateTags (a
// scan profile's tags) replaces the asset-type heuristic; nil keeps the
// heuristic. The exclusion list (templateTagsFor) applies either way and is
// stripped from the include set, so a profile cannot opt into an excluded tag
// — except an optInTags entry the profile names, which leaves the exclusion
// list and is included. Profile tags that are all excluded are an error: an
// empty include set would mean no tag filter at all.
func scanTags(targets []scan.Target, templateTags []string) (include, exclude []string, err error) {
	include, exclude = templateTagsFor(targets)
	if len(templateTags) == 0 {
		return include, exclude, nil
	}
	optIn := make(map[string]bool, len(optInTags))
	for _, t := range optInTags {
		optIn[t] = true
	}
	excluded := make(map[string]bool, len(exclude))
	for _, t := range exclude {
		excluded[t] = true
	}
	include = include[:0:0]
	optedIn := map[string]bool{}
	for _, t := range templateTags {
		t = strings.ToLower(strings.TrimSpace(t))
		switch {
		case t == "":
		case optIn[t]:
			optedIn[t] = true
			include = append(include, t)
		case !excluded[t]:
			include = append(include, t)
		}
	}
	if len(include) == 0 {
		return nil, nil, fmt.Errorf("scanTags: no usable template tags in %v (all empty or excluded)", templateTags)
	}
	kept := exclude[:0:0]
	for _, t := range exclude {
		if !optedIn[t] {
			kept = append(kept, t)
		}
	}
	return include, kept, nil
}

// Scan runs nuclei templates against web targets. templateTags selects the
// templates when non-empty; nil selects them by asset type and technology
// hints (templateTagsFor), not all 8000+ templates. Only medium/high/critical
// severity templates run.
func (e *Engine) Scan(ctx context.Context, targets []scan.Target, templateTags []string) (scan.ScanOutput, error) {
	urls := make([]string, 0, len(targets))
	for _, t := range targets {
		if t.URL != "" {
			urls = append(urls, t.URL)
		}
	}
	if len(urls) == 0 {
		return scan.ScanOutput{}, nil
	}

	includeTags, excludeTags, err := scanTags(targets, templateTags)
	if err != nil {
		return scan.ScanOutput{}, fmt.Errorf("Scan: %w", err)
	}

	// Bound the whole scan so a stuck/slow target set cannot run forever.
	scanCtx, cancel := context.WithTimeout(ctx, maxScanDuration)
	defer cancel()

	if err := ensureTemplates(scanCtx); err != nil {
		return scan.ScanOutput{}, fmt.Errorf("Scan: %w", err)
	}

	ne, err := nucleiSdk.NewNucleiEngineCtx(scanCtx, append([]nucleiSdk.NucleiSDKOptions{
		nucleiSdk.WithTemplateFilters(nucleiSdk.TemplateFilters{
			Tags:        includeTags,
			ExcludeTags: excludeTags,
			Severity:    "medium,high,critical",
		}),
		nucleiSdk.WithGlobalRateLimitCtx(scanCtx, globalRateLimit, globalRateInterval),
		sandboxOption(e.allowInternal),
		nucleiSdk.WithConcurrency(concurrency(templateConcurrency, hostConcurrency, probeConcurrency)),
	}, egressOptions()...)...)
	if err != nil {
		return scan.ScanOutput{}, fmt.Errorf("Scan: new engine: %w", err)
	}
	defer ne.Close()

	ne.LoadTargets(urls, false)

	var (
		mu         sync.Mutex
		results    []scan.Result
		seenTplIDs = map[string]bool{}
	)
	err = ne.ExecuteCallbackWithCtx(scanCtx, func(ev *output.ResultEvent) {
		if ev == nil {
			return
		}
		cve, cvss := classification(ev)
		mu.Lock()
		results = append(results, scan.Result{
			Scanner:     "nuclei",
			TemplateID:  ev.TemplateID,
			Name:        ev.Info.Name,
			Severity:    ev.Info.SeverityHolder.Severity.String(),
			MatchedURL:  ev.Matched,
			Host:        ev.Host,
			Description: ev.Info.Description,
			Remediation: ev.Info.Remediation,
			Reference:   references(ev),
			Evidence:    strings.Join(ev.ExtractedResults, ", "),
			CVE:         cve,
			CVSS:        cvss,
		})
		seenTplIDs[ev.TemplateID] = true
		mu.Unlock()
	})
	if err != nil {
		return scan.ScanOutput{}, fmt.Errorf("Scan: execute: %w", err)
	}
	return scan.ScanOutput{
		Results:       results,
		TemplateTags:  includeTags,
		TemplateCount: len(seenTplIDs),
	}, nil
}

// references newline-joins a template's reference links, guarding the optional
// (and possibly nil) Reference holder in the nuclei result event.
func references(ev *output.ResultEvent) string {
	if ev.Info.Reference == nil {
		return ""
	}
	return strings.Join(ev.Info.Reference.ToSlice(), "\n")
}

// classification extracts the primary CVE id and CVSS score from a template's
// classification block, when present. Many nuclei templates key on a template
// id (e.g. "apache-struts-rce") rather than a CVE id, so the CVE lives only in
// the classification metadata — surfacing it lets KEV/EPSS enrichment join a
// template finding to its known-exploited/exploit-probability data.
func classification(ev *output.ResultEvent) (cve string, cvss float64) {
	c := ev.Info.Classification
	if c == nil {
		return "", 0
	}
	for _, id := range c.CVEID.ToSlice() {
		if id = strings.ToUpper(strings.TrimSpace(id)); strings.HasPrefix(id, "CVE-") {
			return id, c.CVSSScore
		}
	}
	return "", c.CVSSScore
}
