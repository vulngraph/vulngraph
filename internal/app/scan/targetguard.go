package scan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"

	"github.com/vulngraph/vulngraph/pkg/log"
	"github.com/vulngraph/vulngraph/pkg/safenet"
)

// ErrTargetRefused is returned when a scan target points somewhere the scanner
// may never connect to.
var ErrTargetRefused = errors.New("scan: target refused")

// AlwaysBlockedTargets are destinations no scanner may reach, even with
// AllowInternalTargetsEnv set: link-local space and the cloud instance-metadata
// endpoints, which hand out credentials to anything that asks. Prefixes are
// CIDRs; the rest are metadata hostnames. The nuclei engine passes this list
// to the SDK's dial-time deny list.
var AlwaysBlockedTargets = []string{
	"169.254.0.0/16",           // link-local; AWS/GCP/Azure IMDS at 169.254.169.254
	"fe80::/10",                // IPv6 link-local
	"fd00:ec2::254/128",        // AWS IMDS over IPv6
	"100.100.100.200/32",       // Alibaba Cloud metadata
	"192.0.0.192/32",           // Oracle Cloud metadata
	"168.63.129.16/32",         // Azure WireServer
	"64:ff9b::a9fe:0/112",      // 169.254.0.0/16 through a NAT64 gateway
	"::ffff:169.254.0.0/112",   // 169.254.0.0/16 as an IPv4-mapped address
	"metadata.google.internal", // GCP metadata hostname
	"metadata.goog",            // GCP metadata hostname
}

var alwaysBlockedPrefixes, alwaysBlockedHosts = func() ([]netip.Prefix, map[string]bool) {
	var prefixes []netip.Prefix
	hosts := map[string]bool{}
	for _, t := range AlwaysBlockedTargets {
		if p, err := netip.ParsePrefix(t); err == nil {
			prefixes = append(prefixes, p)
		} else {
			hosts[t] = true
		}
	}
	return prefixes, hosts
}()

func alwaysBlockedAddr(addr netip.Addr) bool {
	for _, p := range alwaysBlockedPrefixes {
		if p.Contains(addr) || p.Contains(addr.Unmap()) {
			return true
		}
	}
	return false
}

// checkTargetHost refuses a host that is, or resolves to, an address the
// scanner may not reach: any private or reserved address unless allowInternal,
// and the AlwaysBlockedTargets either way. It is a pre-check — the engine still
// enforces the policy at dial time, because DNS can change in between — so a
// host that does not resolve is let through: the dial guard still applies, and
// an unresolvable host cannot be connected to at all.
func checkTargetHost(ctx context.Context, host string, allowInternal bool) error {
	host = strings.TrimSuffix(strings.ToLower(strings.Trim(host, "[]")), ".")
	if host == "" {
		return fmt.Errorf("%w: empty host", ErrTargetRefused)
	}
	if alwaysBlockedHosts[host] {
		return fmt.Errorf("%w: %s is a cloud metadata endpoint", ErrTargetRefused, host)
	}
	ips := []string{host}
	if net.ParseIP(host) == nil {
		resolved, err := net.DefaultResolver.LookupHost(ctx, host)
		if err != nil {
			return nil
		}
		ips = resolved
	}
	for _, ip := range ips {
		if addr, err := netip.ParseAddr(ip); err == nil && alwaysBlockedAddr(addr) {
			return fmt.Errorf("%w: %s resolves to link-local or metadata address %s", ErrTargetRefused, host, ip)
		}
		if allowInternal {
			continue
		}
		// An IP literal: CheckPublicHost does no DNS here, only the range check.
		if err := safenet.CheckPublicHost(ctx, ip); errors.Is(err, safenet.ErrPrivateAddress) {
			return fmt.Errorf("%w: %s resolves to private address %s", ErrTargetRefused, host, ip)
		}
	}
	return nil
}

// guardConcurrency bounds the parallel DNS pre-checks of a target set.
const guardConcurrency = 8

// guardTargets drops every target checkTargetHost refuses and returns the
// refused hosts, so the caller can report what was not scanned.
func guardTargets(ctx context.Context, targets []Target, allowInternal bool) (kept []Target, refused []string) {
	refusedAt := make([]bool, len(targets))
	sem := make(chan struct{}, guardConcurrency)
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					log.FromContext(ctx).Error().Interface("panic", r).Str("host", t.Host).Msg("scan: target guard panicked; refusing target")
					refusedAt[i] = true
				}
			}()
			for _, h := range targetHosts(t) {
				if err := checkTargetHost(ctx, h, allowInternal); err != nil {
					log.FromContext(ctx).Warn().Err(err).Str("host", h).Msg("scan: target refused")
					refusedAt[i] = true
					return
				}
			}
		}()
	}
	wg.Wait()
	for i, t := range targets {
		if refusedAt[i] {
			refused = append(refused, strings.Join(targetHosts(t), ","))
		} else {
			kept = append(kept, t)
		}
	}
	return kept, refused
}

// targetHosts are the hosts a target can dial: Host and the URL's host, which
// a hand-built target need not keep in agreement.
func targetHosts(t Target) []string {
	hosts := []string{}
	if t.Host != "" {
		hosts = append(hosts, t.Host)
	}
	if t.URL != "" {
		h := ""
		if u, err := url.Parse(t.URL); err == nil {
			h = u.Hostname()
		}
		if h != t.Host || len(hosts) == 0 {
			// An unparseable URL yields "", which checkTargetHost refuses.
			hosts = append(hosts, h)
		}
	}
	return hosts
}
