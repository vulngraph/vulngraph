package alertctx

import (
	"net/netip"
	"regexp"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// lookup is one way an identifier can name an asset: candidate keys to fetch
// and an exact predicate the fetched, current row must satisfy. The fetch is a
// prefilter over possibly-stale rows; accept is the real test.
type lookup struct {
	matchType MatchType
	conf      Confidence
	ids       []string // candidate asset ids
	ips       []string // candidate public/private IPs
	names     []string // candidate values of name, domain or endpoint
	accept    func(asset.Asset) bool
}

// plan is everything needed to resolve one input identifier.
type plan struct {
	input      string
	normalized string
	lookups    []lookup
}

var instanceIDRe = regexp.MustCompile(`^i-[0-9a-f]{8,17}$`)

// planFor classifies one identifier. Pure: no I/O. An empty identifier yields
// a plan with no lookups.
func planFor(input string) plan {
	in := strings.TrimSpace(input)
	p := plan{input: input, normalized: in}
	if in == "" {
		return p
	}
	if strings.HasPrefix(in, "arn:") {
		return planARN(p, in)
	}
	if addr, err := netip.ParseAddr(in); err == nil {
		return planIP(p, addr.Unmap())
	}
	if instanceIDRe.MatchString(in) {
		p.lookups = []lookup{idLookup(MatchInstanceID, in)}
		return p
	}
	if isEmail(in) {
		return planEmail(p, strings.ToLower(in))
	}
	if ns, name, ok := splitNamespaceName(in); ok {
		p.lookups = []lookup{idLookup(MatchID, in), k8sLookup(ns, name)}
		return p
	}
	if strings.Contains(in, ".") {
		return planDNS(p, in)
	}
	p.lookups = []lookup{idLookup(MatchID, in), nameLookup(in)}
	return p
}

// planARN maps an ARN to its asset. An STS assumed-role session ARN names a
// temporary session, never an asset: it collapses to the role it assumed.
func planARN(p plan, arn string) plan {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) == 6 && parts[2] == "sts" && strings.HasPrefix(parts[5], "assumed-role/") {
		roleName, _, _ := strings.Cut(strings.TrimPrefix(parts[5], "assumed-role/"), "/")
		if roleName != "" {
			account := parts[4]
			roleARN := "arn:" + parts[1] + ":iam::" + account + ":role/" + roleName
			p.normalized = roleARN
			// An assumed-role ARN omits the role's path, so a role under
			// /service-role/ has an asset id the collapsed ARN cannot equal.
			byName := lookup{
				matchType: MatchARN, conf: ConfHigh, names: []string{roleName},
				accept: func(a asset.Asset) bool {
					return a.Type == "iam_role" && a.AccountID == account && a.Name == roleName
				},
			}
			p.lookups = []lookup{idLookup(MatchARN, roleARN), byName}
			return p
		}
	}
	p.lookups = []lookup{idLookup(MatchARN, arn)}
	return p
}

func planIP(p plan, addr netip.Addr) plan {
	ip := addr.String()
	conf := ConfHigh
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		conf = ConfMedium // private ranges repeat across VPCs and accounts
	}
	p.normalized = ip
	p.lookups = []lookup{{
		matchType: MatchIP, conf: conf, ips: []string{ip},
		accept: func(a asset.Asset) bool { return a.PublicIP == ip || a.PrivateIP == ip },
	}}
	return p
}

func planEmail(p plan, email string) plan {
	p.normalized = email
	p.lookups = []lookup{idLookup(MatchID, email), {
		matchType: MatchEmail, conf: ConfHigh, names: []string{email},
		accept: func(a asset.Asset) bool {
			return strings.EqualFold(a.Name, email) || strings.EqualFold(a.Domain, email)
		},
	}}
	return p
}

func planDNS(p plan, in string) plan {
	host := strings.ToLower(strings.TrimSuffix(in, "."))
	p.normalized = host
	p.lookups = []lookup{idLookup(MatchID, in), {
		matchType: MatchDNS, conf: ConfHigh,
		names: []string{host, "https://" + host, "http://" + host},
		accept: func(a asset.Asset) bool {
			return strings.EqualFold(a.Name, host) || strings.EqualFold(a.Domain, host) ||
				strings.EqualFold(hostOf(a.Endpoint), host)
		},
	}}
	return p
}

func idLookup(mt MatchType, id string) lookup {
	return lookup{
		matchType: mt, conf: ConfExact, ids: []string{id},
		accept: func(a asset.Asset) bool { return a.ID == id },
	}
}

func nameLookup(name string) lookup {
	return lookup{
		matchType: MatchName, conf: ConfLow, names: []string{name},
		accept: func(a asset.Asset) bool { return a.Name == name },
	}
}

func k8sLookup(ns, name string) lookup {
	return lookup{
		matchType: MatchK8s, conf: ConfMedium, names: []string{name},
		accept: func(a asset.Asset) bool {
			return a.Provider == asset.ProviderKubernetes && a.Name == name &&
				(a.Metadata["namespace"] == ns || a.Tags["namespace"] == ns)
		},
	}
}

func isEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	return at > 0 && at == strings.LastIndexByte(s, '@') && at < len(s)-1 &&
		!strings.ContainsAny(s, " /:")
}

// splitNamespaceName recognises "namespace/name" (exactly one slash, no scheme
// or colon). It is also the shape of a GitHub "org/repo" id, which the exact-id
// lookup resolves alongside.
func splitNamespaceName(s string) (ns, name string, ok bool) {
	if strings.ContainsAny(s, " :") || strings.Count(s, "/") != 1 {
		return "", "", false
	}
	ns, name, _ = strings.Cut(s, "/")
	return ns, name, ns != "" && name != ""
}

// hostOf strips scheme, port and path from an endpoint URL.
func hostOf(endpoint string) string {
	h := endpoint
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexAny(h, "/?#"); i >= 0 {
		h = h[:i]
	}
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return h
}
