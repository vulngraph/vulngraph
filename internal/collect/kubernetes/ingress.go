package kubernetes

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	networkingv1 "k8s.io/api/networking/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func ingressClass(ing networkingv1.Ingress) string {
	if ing.Spec.IngressClassName != nil {
		return strings.ToLower(*ing.Spec.IngressClassName)
	}
	return strings.ToLower(ing.Annotations["kubernetes.io/ingress.class"])
}

func ingressIsInternal(ing networkingv1.Ingress) bool {
	if strings.EqualFold(ing.Annotations["alb.ingress.kubernetes.io/scheme"], "internal") {
		return true
	}
	switch ingressClass(ing) {
	case "gce-internal", "nginx-private", "nginx-internal", "internal-nginx", "internal":
		return true
	default:
		return false
	}
}

func ingressExposure(ing networkingv1.Ingress) (internal bool, tier, address string) {
	var addresses []string
	for _, endpoint := range ing.Status.LoadBalancer.Ingress {
		addresses = append(addresses, endpoint.IP, endpoint.Hostname)
	}
	address, privateOnly, publicIP := lbAddress(addresses)
	declaredInternal := ingressIsInternal(ing)
	if privateOnly || (declaredInternal && !publicIP) {
		return true, "", address
	}
	// A controller address does not prove that its listener or firewall admits
	// internet traffic. Retain the possible path until that evidence is known.
	return false, asset.PublicAccessPossible, address
}

func ingressHostTLS(ing networkingv1.Ingress, host string) bool {
	for _, tls := range ing.Spec.TLS {
		if slices.Contains(tls.Hosts, host) || (host == "" && len(tls.Hosts) == 0) {
			return true
		}
	}
	return false
}

func ingressEndpoint(host string, tls bool) string {
	if host == "" {
		return ""
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Is6() {
		host = "[" + host + "]"
	}
	scheme := "http://"
	if tls {
		scheme = "https://"
	}
	return scheme + host
}

// ingressAssets retains host rules and the default backend independently of
// whether a controller has published an address yet.
func ingressAssets(ing networkingv1.Ingress, cluster string, now time.Time) ([]asset.Asset, []asset.Edge) {
	var assets []asset.Asset
	var edges []asset.Edge
	internal, tier, lbHost := ingressExposure(ing)
	if lbHost == "" && len(ing.Status.LoadBalancer.Ingress) > 0 {
		lbHost = ing.Status.LoadBalancer.Ingress[0].Hostname
		if lbHost == "" {
			lbHost = ing.Status.LoadBalancer.Ingress[0].IP
		}
	}
	byHost := map[string]string{}
	ensureHost := func(host string) string {
		if id, ok := byHost[host]; ok {
			return id
		}
		key, domain := host, host
		if key == "" {
			key, domain = "_default", lbHost
		}
		id := fmt.Sprintf("%s/ingress/%s/%s/%s", cluster, ing.Namespace, ing.Name, key)
		hasTLS := ingressHostTLS(ing, host)
		meta := map[string]string{
			"namespace": ing.Namespace, "ingress_name": ing.Name,
			"ingress_class": ingressClass(ing), "tls": strconv.FormatBool(hasTLS),
			"lb_hostname": lbHost, "public": strconv.FormatBool(!internal),
		}
		if tier != "" {
			meta["public_access"] = tier
		}
		assets = append(assets, asset.Asset{
			ID: id, Name: ing.Name + "/" + key, Type: "k8s_ingress",
			Provider: asset.ProviderKubernetes, Region: cluster, Domain: domain,
			Endpoint: ingressEndpoint(domain, hasTLS), Tags: ing.Labels, Metadata: meta,
			DiscoveredAt: now, LastSeen: now,
		})
		byHost[host] = id
		return id
	}
	// graph_edges stores one row per endpoint pair and type. Aggregate the
	// routes to each Service so multiple paths survive storage deduplication.
	type routeKey struct{ src, dst string }
	byRoute := map[routeKey]int{}
	paths := map[routeKey][]string{}
	ports := map[routeKey][]string{}
	addBackend := func(src string, backend networkingv1.IngressBackend, path string, isDefault bool) {
		if backend.Service == nil {
			return
		}
		dst := fmt.Sprintf("%s/service/%s/%s", cluster, ing.Namespace, backend.Service.Name)
		key := routeKey{src, dst}
		i, exists := byRoute[key]
		if !exists {
			i = len(edges)
			byRoute[key] = i
			edges = append(edges, asset.Edge{
				SrcID: src, SrcType: "k8s_ingress", DstID: dst, DstType: "k8s_service",
				EdgeType: "routes_to", Properties: map[string]string{},
			})
		}
		if isDefault {
			edges[i].Properties["default_backend"] = "true"
		} else {
			paths[key] = append(paths[key], path)
		}
		port := backend.Service.Port.Name
		if port == "" && backend.Service.Port.Number > 0 {
			port = strconv.Itoa(int(backend.Service.Port.Number))
		}
		if port != "" {
			ports[key] = append(ports[key], port)
		}
	}
	for _, rule := range ing.Spec.Rules {
		id := ensureHost(rule.Host)
		if rule.HTTP != nil {
			for _, path := range rule.HTTP.Paths {
				addBackend(id, path.Backend, path.Path, false)
			}
		}
		if ing.Spec.DefaultBackend != nil {
			addBackend(id, *ing.Spec.DefaultBackend, "", true)
		}
	}
	if ing.Spec.DefaultBackend != nil {
		addBackend(ensureHost(""), *ing.Spec.DefaultBackend, "", true)
	} else if len(assets) == 0 {
		ensureHost("")
	}
	for key, i := range byRoute {
		p := paths[key]
		slices.Sort(p)
		p = slices.Compact(p)
		if len(p) > 0 {
			edges[i].Properties["path"] = p[0]
			edges[i].Properties["paths"] = strings.Join(p, ",")
		}
		ps := ports[key]
		slices.Sort(ps)
		edges[i].Properties["ports"] = strings.Join(slices.Compact(ps), ",")
	}
	return assets, edges
}
