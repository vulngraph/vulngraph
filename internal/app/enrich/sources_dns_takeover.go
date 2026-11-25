package enrich

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// Resolver is the DNS-resolution verification source. It answers one
// question: does a hostname resolve? A concrete net-backed implementation is
// NetResolver; tests inject a fake.
type Resolver interface {
	// Resolves reports whether host resolves in DNS. found=false with a nil error
	// means NXDOMAIN / no-such-host (the target is gone — a dangling record). A
	// non-nil error is a transient failure (timeout, SERVFAIL) → inconclusive, the
	// caller must not draw a conclusion from it.
	Resolves(ctx context.Context, host string) (found bool, err error)
}

// takeoverCheckIDs are the pattern-only subdomain-takeover candidates (hygiene.go)
// this source verifies. They fire on any CNAME/ALIAS pointing at a takeover-prone
// platform; a live owned target trips them too, so they are candidates until an
// independent source corroborates.
var takeoverCheckIDs = map[string]bool{
	"dns-cname-takeover-risk":              true,
	"dns-wildcard-cname-takeover-risk":     true,
	"gcp-dns-cname-takeover-risk":          true,
	"gcp-dns-wildcard-cname-takeover-risk": true,
}

// DNSTakeover corroborates a subdomain-takeover candidate by resolving the
// record's CNAME/ALIAS target. It only *confirms* the NXDOMAIN class (the target
// no longer resolves → dangling → real takeover risk); a resolving target is left
// untouched, because DNS alone cannot prove ownership — an HTTP-layer "unclaimed"
// takeover (deleted S3 bucket whose platform domain still resolves) needs the
// nuclei fingerprint source (a later increment). Pure DNS lookups, no
// connection to the target, so there is no SSRF surface here.
//
// Guardrail: a transient resolver error never changes the score — absence of a
// confirmation is not a refutation.
type DNSTakeover struct {
	Assets   AssetGetter
	Resolver Resolver // nil disables the source (candidates keep their pattern severity)
}

func (DNSTakeover) Name() string { return sourceDNSTakeover }

func (d DNSTakeover) Evaluate(ctx context.Context, f finding.Finding) (Factor, bool, error) {
	if d.Assets == nil || d.Resolver == nil || !takeoverCheckIDs[f.CheckID] || f.ResourceID == "" {
		return Factor{}, false, nil
	}
	a, err := d.Assets.Get(ctx, f.ResourceID)
	if err != nil {
		return Factor{}, false, err // degrade: score without this source
	}
	target := firstDNSValue(a.Metadata["values"])
	if target == "" {
		return Factor{}, false, nil
	}
	found, rerr := d.Resolver.Resolves(ctx, target)
	if rerr != nil {
		return Factor{}, false, nil // transient — inconclusive, do not conclude
	}
	if found {
		return Factor{}, false, nil // target resolves — DNS can't refute, stay a candidate
	}
	// Confirmed dangling: the CNAME/ALIAS target does not resolve. Floor into the
	// high band so a corroborated takeover is never left in monitor.
	return Factor{
		Source: sourceDNSTakeover,
		Points: 40,
		Floor:  ThresholdHigh,
		Detail: "CNAME target " + target + " does not resolve (NXDOMAIN) — dangling record, subdomain takeover confirmable",
	}, true, nil
}

// firstDNSValue returns the first target from a record's comma-joined values,
// trimmed of whitespace and any trailing dot (FQDN form).
func firstDNSValue(values string) string {
	for _, v := range strings.Split(values, ",") {
		if v = strings.TrimSpace(v); v != "" {
			return strings.TrimSuffix(v, ".")
		}
	}
	return ""
}

// NetResolver is the production DNS source: net.Resolver with a per-lookup timeout.
type NetResolver struct {
	r       *net.Resolver
	timeout time.Duration
}

// NewNetResolver builds a NetResolver with the given per-lookup timeout.
func NewNetResolver(timeout time.Duration) *NetResolver {
	return &NetResolver{r: net.DefaultResolver, timeout: timeout}
}

func (n *NetResolver) Resolves(ctx context.Context, host string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, n.timeout)
	defer cancel()
	_, err := n.r.LookupHost(ctx, host)
	if err == nil {
		return true, nil
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return false, nil // NXDOMAIN — resolved cleanly to "does not exist"
	}
	return false, err // transient / other — inconclusive
}
