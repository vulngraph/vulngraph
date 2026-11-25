package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing/fstest"
	"time"

	"github.com/vulngraph/vulngraph/internal/checks/benchmarks"
	"github.com/vulngraph/vulngraph/internal/checks/upstream"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

const (
	fetchTimeout = 60 * time.Second
	// maxBody bounds one upstream payload; the largest (the NIST OSCAL
	// catalog) is about 10 MiB.
	maxBody = 64 << 20
	// maxRounds bounds the listing → file rounds Wanted drives (three today:
	// indexes, then kube-bench directory listings, then files).
	maxRounds = 6

	githubAPI   = "https://api.github.com/repos/"
	githubRaw   = "https://raw.githubusercontent.com/"
	shDocs      = "https://docs.aws.amazon.com/securityhub/latest/userguide/"
	nistCatalog = githubRaw + "usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
	fsbpARN     = "arn:aws:securityhub:%s::standards/aws-foundational-security-best-practices/v/1.0.0"
)

// safeName is what a bundle path segment taken from an upstream listing may
// look like; anything else (a "..", a slash) is refused, not fetched.
var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

type fetcher struct {
	client         *http.Client
	log            io.Writer
	securityHubAPI bool
}

func newFetcher(log io.Writer, securityHubAPI bool) *fetcher {
	return &fetcher{client: safenet.New(fetchTimeout), log: log, securityHubAPI: securityHubAPI}
}

// fill fetches every path upstream.Wanted asks for until it asks for
// nothing more.
func (f *fetcher) fill(bs []benchmarks.Benchmark, frameworks bool) (fstest.MapFS, error) {
	ctx := context.Background()
	mem := fstest.MapFS{}
	if f.securityHubAPI {
		if raw, err := securityHubAPI(ctx); err == nil {
			mem[upstream.PathSecurityHubAPI] = &fstest.MapFile{Data: raw}
		} else {
			_, _ = fmt.Fprintf(f.log, "securityhub API unavailable (%v); using the controls reference page\n", err)
		}
	}
	for round := 0; ; round++ {
		want, err := upstream.Wanted(mem, bs, frameworks)
		if err != nil {
			return nil, fmt.Errorf("fill: %w", err)
		}
		if len(want) == 0 {
			return mem, nil
		}
		if round == maxRounds {
			return nil, fmt.Errorf("fill: still wanting %d paths after %d rounds", len(want), maxRounds)
		}
		for _, p := range want {
			u, err := remote(p)
			if err != nil {
				return nil, fmt.Errorf("fill: %w", err)
			}
			raw, err := f.get(ctx, u)
			if err != nil {
				return nil, fmt.Errorf("fill: %s: %w", p, err)
			}
			mem[p] = &fstest.MapFile{Data: raw}
		}
	}
}

func (f *fetcher) get(ctx context.Context, u string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("get: %w", err)
	}
	if strings.HasPrefix(u, githubAPI) {
		req.Header.Set("Accept", "application/vnd.github+json")
		// Unauthenticated API calls are limited to 60 an hour; CI passes
		// its token.
		if tok := os.Getenv("GITHUB_TOKEN"); tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get %s: HTTP %d", u, resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, fmt.Errorf("get: %w", err)
	}
	if len(raw) > maxBody {
		return nil, fmt.Errorf("get %s: body over %d bytes", u, maxBody)
	}
	return raw, nil
}

// remote maps a bundle path to its upstream URL.
func remote(p string) (string, error) {
	seg := strings.Split(p, "/")
	for _, s := range seg {
		if !safeName.MatchString(s) {
			return "", fmt.Errorf("remote: unsafe path %q", p)
		}
	}
	switch {
	case p == upstream.PathSecurityHubReference:
		return shDocs + "securityhub-controls-reference.html", nil
	case p == upstream.PathNISTCatalog:
		return nistCatalog, nil
	case p == upstream.PathKubeBenchIndex:
		return githubAPI + "aquasecurity/kube-bench/contents/cfg", nil
	case p == upstream.PathAzurePolicyIndex:
		return githubAPI + "Azure/azure-policy/contents/built-in-policies/policySetDefinitions/" +
			url.PathEscape("Regulatory Compliance"), nil
	case len(seg) == 3 && seg[0] == "securityhub" && seg[1] == "pages":
		return shDocs + seg[2], nil
	case len(seg) == 3 && seg[0] == "prowler" && seg[2] == "index.json":
		return githubAPI + "prowler-cloud/prowler/contents/prowler/compliance/" + seg[1], nil
	case len(seg) == 3 && seg[0] == "prowler":
		return githubRaw + "prowler-cloud/prowler/master/prowler/compliance/" + seg[1] + "/" + seg[2], nil
	case len(seg) == 3 && seg[0] == "kube-bench" && seg[2] == "index.json":
		return githubAPI + "aquasecurity/kube-bench/contents/cfg/" + seg[1], nil
	case len(seg) == 3 && seg[0] == "kube-bench":
		return githubRaw + "aquasecurity/kube-bench/main/cfg/" + seg[1] + "/" + seg[2], nil
	}
	return "", fmt.Errorf("remote: no upstream for %q", p)
}

// securityHubAPI lists the FSBP standard's controls with the AWS CLI, which
// resolves credentials the usual way (env, profile, SSO, instance role).
// No credentials, Security Hub not enabled, or no CLI: an error, and the
// caller falls back to the public reference page.
func securityHubAPI(ctx context.Context) ([]byte, error) {
	if _, err := exec.LookPath("aws"); err != nil {
		return nil, errors.New("aws CLI not installed")
	}
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = os.Getenv("AWS_DEFAULT_REGION")
	}
	if region == "" {
		region = "us-east-1"
	}
	ctx, cancel := context.WithTimeout(ctx, 2*fetchTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "aws", "securityhub", "list-security-control-definitions",
		"--standards-arn", fmt.Sprintf(fsbpARN, region), "--region", region, "--output", "json")
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return nil, fmt.Errorf("securityHubAPI: %s", strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("securityHubAPI: %w", err)
	}
	return out, nil
}
