package kubernetes

import (
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/cidrset"
)

const (
	awsLBSchemeAnnotation   = "service.beta.kubernetes.io/aws-load-balancer-scheme"
	awsLBInternalAnnotation = "service.beta.kubernetes.io/aws-load-balancer-internal"
	awsLBTypeAnnotation     = "service.beta.kubernetes.io/aws-load-balancer-type"
	// sourceRangesAnnotation is the pre-spec form of loadBalancerSourceRanges,
	// still honoured when the spec field is empty.
	sourceRangesAnnotation = "service.beta.kubernetes.io/load-balancer-source-ranges"
	autoModeNLBClass       = "eks.amazonaws.com/nlb"
)

// awsNLBControllerClasses are the loadBalancerClass values of the AWS Load
// Balancer Controller and of EKS Auto Mode, which provision NLBs by their own
// scheme rules (awsNLBControllerScheme).
var awsNLBControllerClasses = map[string]bool{
	"service.k8s.aws/nlb": true,
	autoModeNLBClass:      true,
}

// lbScheme is what the Service's own spec says about its load balancer.
type lbScheme int

const (
	schemeInternetFacing lbScheme = iota
	schemeInternal
	// schemeUnstated: a controller-managed Service with no scheme annotation.
	// The controller then keeps an existing NLB's scheme or applies its own
	// default (internal unless --default-load-balancer-scheme says
	// internet-facing), neither of which the Service records.
	schemeUnstated
)

func serviceAsset(svc corev1.Service, cluster string, now time.Time) asset.Asset {
	id := fmt.Sprintf("%s/service/%s/%s", cluster, svc.Namespace, svc.Name)
	// An internal LoadBalancer publishes a PRIVATE address in the same status
	// field as an internet-facing one, so PublicIP is only set for LBs not
	// observed internal — otherwise a private LB is mistaken for
	// internet-reachable (mirrors the ingressIsInternal guard). An unstated
	// scheme keeps the address and is flagged scheme_assumed: it was not
	// observed private, so it is not taken as private.
	scheme := serviceLBScheme(svc)
	var addresses []string
	for _, endpoint := range svc.Status.LoadBalancer.Ingress {
		addresses = append(addresses, endpoint.IP, endpoint.Hostname)
	}
	publicIP, privateOnly, _ := lbAddress(addresses)
	internal := scheme == schemeInternal || privateOnly
	if internal {
		publicIP = ""
	}
	ranges := lbSourceRanges(svc)
	class := ""
	if svc.Spec.LoadBalancerClass != nil {
		class = *svc.Spec.LoadBalancerClass
	}
	return asset.Asset{
		ID:       id,
		Name:     svc.Name,
		Type:     "k8s_service",
		Provider: asset.ProviderKubernetes,
		Region:   cluster,
		PublicIP: publicIP,
		Tags:     svc.Labels,
		Metadata: map[string]string{
			"namespace":           svc.Namespace,
			"type":                string(svc.Spec.Type),
			"cluster_ip":          svc.Spec.ClusterIP,
			"selector":            joinSelector(svc.Spec.Selector),
			"internal":            fmt.Sprintf("%t", internal),
			"scheme_assumed":      fmt.Sprintf("%t", scheme == schemeUnstated),
			"load_balancer_class": class,
			// "" = no source restriction: the load balancer admits any address.
			"source_ranges":     strings.Join(ranges, ","),
			"source_restricted": fmt.Sprintf("%t", sourceRangesRestricted(ranges)),
		},
		DiscoveredAt: now, LastSeen: now,
	}
}

// serviceLBScheme reads a Service's load balancer scheme from its spec.
// Services the AWS Load Balancer Controller or EKS Auto Mode provision follow
// those controllers' rules; every other Service is internal only when a
// cloud-provider annotation forces a private LB.
func serviceLBScheme(svc corev1.Service) lbScheme {
	a := svc.Annotations
	if awsNLBControllerManaged(svc) {
		return awsNLBControllerScheme(svc)
	}
	switch {
	case strings.EqualFold(a[awsLBInternalAnnotation], "true"),
		a[awsLBInternalAnnotation] == "0.0.0.0/0",
		strings.EqualFold(a[awsLBSchemeAnnotation], "internal"),
		strings.EqualFold(a["service.beta.kubernetes.io/azure-load-balancer-internal"], "true"),
		strings.EqualFold(a["cloud.google.com/load-balancer-type"], "internal"),
		strings.EqualFold(a["networking.gke.io/load-balancer-type"], "internal"):
		return schemeInternal
	}
	return schemeInternetFacing
}

// awsNLBControllerManaged reports whether the AWS Load Balancer Controller or
// EKS Auto Mode provisions this Service's NLB: by loadBalancerClass, or by the
// aws-load-balancer-type values the in-tree AWS provider leaves to the
// controller ("external", and the deprecated "nlb-ip").
func awsNLBControllerManaged(svc corev1.Service) bool {
	if svc.Spec.LoadBalancerClass != nil && awsNLBControllerClasses[*svc.Spec.LoadBalancerClass] {
		return true
	}
	switch strings.ToLower(svc.Annotations[awsLBTypeAnnotation]) {
	case "external", "nlb-ip":
		return true
	}
	return false
}

func isAutoModeNLB(svc corev1.Service) bool {
	return svc.Spec.LoadBalancerClass != nil && *svc.Spec.LoadBalancerClass == autoModeNLBClass
}

// awsNLBControllerScheme applies the controllers' scheme rules: the scheme
// annotation wins, and the deprecated aws-load-balancer-internal annotation is
// read when the scheme is absent (EKS Auto Mode does not support it). A value
// other than the ones that mean internal reads as internet-facing, so an
// unrecognised setting is never taken as private. With neither annotation the
// scheme is unstated.
func awsNLBControllerScheme(svc corev1.Service) lbScheme {
	a := svc.Annotations
	if v, ok := a[awsLBSchemeAnnotation]; ok {
		if strings.EqualFold(strings.TrimSpace(v), "internal") {
			return schemeInternal
		}
		return schemeInternetFacing
	}
	if v, ok := a[awsLBInternalAnnotation]; ok && !isAutoModeNLB(svc) {
		if strings.EqualFold(strings.TrimSpace(v), "true") {
			return schemeInternal
		}
		return schemeInternetFacing
	}
	return schemeUnstated
}

// lbSourceRanges returns the client CIDRs a LoadBalancer Service admits:
// spec.loadBalancerSourceRanges, else the legacy annotation, which EKS Auto
// Mode does not support. Nil means no restriction.
func lbSourceRanges(svc corev1.Service) []string {
	raw := svc.Spec.LoadBalancerSourceRanges
	if len(raw) == 0 && !isAutoModeNLB(svc) {
		if v := strings.TrimSpace(svc.Annotations[sourceRangesAnnotation]); v != "" {
			raw = strings.Split(v, ",")
		}
	}
	var out []string
	for _, r := range raw {
		if r = strings.TrimSpace(r); r != "" {
			out = append(out, r)
		}
	}
	return out
}

// sourceRangesRestricted reports whether the ranges keep the load balancer
// off the open internet: some are set, every one parses, and their union
// covers neither all of IPv4 nor all of IPv6. An entry that does not parse
// could be anything, so it leaves the load balancer world-open.
func sourceRangesRestricted(ranges []string) bool {
	if len(ranges) == 0 || len(cidrset.Parse(ranges)) != len(ranges) {
		return false
	}
	return !cidrset.CoversWorld(ranges)
}
