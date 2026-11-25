package kubernetes

import (
	"fmt"
	"strings"
	"time"

	networkingv1 "k8s.io/api/networking/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// ingressIsInternal reports whether an Ingress is provisioned on an internal
// (non-internet-facing) load balancer: an ingress class containing "internal"
// or the cloud LB scheme annotations that force a private LB.
func ingressIsInternal(ing networkingv1.Ingress) bool {
	class := ""
	if ing.Spec.IngressClassName != nil {
		class = *ing.Spec.IngressClassName
	}
	if class == "" {
		class = ing.Annotations["kubernetes.io/ingress.class"]
	}
	if strings.Contains(strings.ToLower(class), "internal") {
		return true
	}
	if strings.EqualFold(ing.Annotations["alb.ingress.kubernetes.io/scheme"], "internal") {
		return true
	}
	// GCE: the internal ingress class is checked above ("gce-internal").
	return false
}

// ingressAssets maps a Kubernetes Ingress to one k8s_ingress asset per rule
// host. Each host becomes a scan target in ListExternal() via Domain != "".
// TLS presence marks the host as HTTPS (public=true). A routes_to edge links
// each host to its backend Service so the supply-chain → exposure chain works.
func ingressAssets(ing networkingv1.Ingress, cluster string, now time.Time) ([]asset.Asset, []asset.Edge) {
	var assets []asset.Asset
	var edges []asset.Edge

	hasTLS := len(ing.Spec.TLS) > 0
	lbHost := ""
	if len(ing.Status.LoadBalancer.Ingress) > 0 {
		lbHost = ing.Status.LoadBalancer.Ingress[0].Hostname
		if lbHost == "" {
			lbHost = ing.Status.LoadBalancer.Ingress[0].IP
		}
	}
	// Internal ingress classes (internal ALB/NLB, private nginx) never get an
	// internet-reachable endpoint — flagging them public inflated exposure.
	internal := ingressIsInternal(ing)

	for _, rule := range ing.Spec.Rules {
		host := rule.Host
		if host == "" {
			host = lbHost // wildcard rule — use the LB hostname as the target
		}
		if host == "" {
			continue
		}
		id := fmt.Sprintf("%s/ingress/%s/%s/%s", cluster, ing.Namespace, ing.Name, host)
		assets = append(assets, asset.Asset{
			ID:       id,
			Name:     ing.Name + "/" + host,
			Type:     "k8s_ingress",
			Provider: asset.ProviderKubernetes,
			Region:   cluster,
			Domain:   host,
			Endpoint: "https://" + host,
			Tags:     ing.Labels,
			Metadata: map[string]string{
				"namespace":    ing.Namespace,
				"ingress_name": ing.Name,
				"tls":          fmt.Sprintf("%t", hasTLS),
				"lb_hostname":  lbHost,
				"public":       fmt.Sprintf("%t", !internal),
			},
			DiscoveredAt: now,
			LastSeen:     now,
		})

		// Emit routes_to edges for each path's backend service.
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service == nil {
				continue
			}
			svcID := fmt.Sprintf("%s/service/%s/%s", cluster, ing.Namespace, path.Backend.Service.Name)
			edges = append(edges, asset.Edge{
				SrcID: id, SrcType: "k8s_ingress",
				DstID: svcID, DstType: "k8s_service",
				EdgeType: "routes_to",
				Properties: map[string]string{
					"path": path.Path,
				},
			})
		}
	}
	return assets, edges
}
