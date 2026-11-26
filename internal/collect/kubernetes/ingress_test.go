package kubernetes

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/correlate"
	"github.com/vulngraph/vulngraph/internal/app/graphstore"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func serviceBackend(name string) networkingv1.IngressBackend {
	return networkingv1.IngressBackend{Service: &networkingv1.IngressServiceBackend{Name: name, Port: networkingv1.ServiceBackendPort{Number: 80}}}
}

func TestIngressExposure(t *testing.T) {
	tests := []struct {
		name, class, scheme string
		endpoints           []networkingv1.IngressLoadBalancerIngress
		internal            bool
	}{
		{name: "unprovisioned public class", class: "nginx"},
		{name: "nginx private", class: "nginx-private", internal: true},
		{name: "legacy internal", class: "gce-internal", internal: true},
		{name: "ALB internal scheme", scheme: "internal", internal: true},
		{name: "arbitrary class name is not privacy evidence", class: "external-internal-tools"},
		{name: "private IPv4", endpoints: []networkingv1.IngressLoadBalancerIngress{{IP: "10.0.1.2"}}, internal: true},
		{name: "private IPv6", endpoints: []networkingv1.IngressLoadBalancerIngress{{IP: "fd00::1"}}, internal: true},
		{name: "all endpoints matter", endpoints: []networkingv1.IngressLoadBalancerIngress{{IP: "10.0.1.2"}, {IP: "203.0.113.10"}}},
		{name: "hostname is unresolved", endpoints: []networkingv1.IngressLoadBalancerIngress{{Hostname: "lb.example.test"}}},
		{name: "conflicting public address", class: "nginx-private", endpoints: []networkingv1.IngressLoadBalancerIngress{{IP: "203.0.113.10"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ing := networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "app", Annotations: map[string]string{"alb.ingress.kubernetes.io/scheme": tt.scheme}},
				Spec:   networkingv1.IngressSpec{IngressClassName: &tt.class, DefaultBackend: ptrBackend("web")},
				Status: networkingv1.IngressStatus{LoadBalancer: networkingv1.IngressLoadBalancerStatus{Ingress: tt.endpoints}}}
			assets, edges := ingressAssets(ing, "c", time.Now())
			require.Len(t, assets, 1)
			require.Len(t, edges, 1, "private topology must be retained")
			require.Equal(t, "c/ingress/app/web/_default", assets[0].ID)
			if tt.internal {
				require.Equal(t, "false", assets[0].Metadata["public"])
				require.Empty(t, assets[0].Metadata["public_access"])
			} else {
				require.Equal(t, "true", assets[0].Metadata["public"])
				require.Equal(t, asset.PublicAccessPossible, assets[0].Metadata["public_access"])
			}
			ing.Spec.IngressClassName = nil
			ing.Annotations["kubernetes.io/ingress.class"] = tt.class
			legacy, _ := ingressAssets(ing, "c", time.Now())
			require.Equal(t, assets[0].Metadata, legacy[0].Metadata)
		})
	}
}
func ptrBackend(name string) *networkingv1.IngressBackend { b := serviceBackend(name); return &b }

func TestIngressRoutesAndTLS(t *testing.T) {
	ing := networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "app"}, Spec: networkingv1.IngressSpec{
		DefaultBackend: ptrBackend("fallback"),
		TLS:            []networkingv1.IngressTLS{{Hosts: []string{"secure.example.test"}}},
		Rules: []networkingv1.IngressRule{
			{Host: "secure.example.test", IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{
				{Path: "/z", Backend: serviceBackend("web")}, {Path: "/a", Backend: serviceBackend("web")}, {Path: "/a", Backend: serviceBackend("web")},
			}}}},
			{Host: "plain.example.test", IngressRuleValue: networkingv1.IngressRuleValue{HTTP: &networkingv1.HTTPIngressRuleValue{Paths: []networkingv1.HTTPIngressPath{{Path: "/", Backend: serviceBackend("web")}}}}},
		},
	}}
	assets, edges := ingressAssets(ing, "c", time.Now())
	require.Len(t, assets, 3)
	require.Equal(t, "https://secure.example.test", assets[0].Endpoint)
	require.Equal(t, "http://plain.example.test", assets[1].Endpoint)
	require.Empty(t, assets[2].Endpoint)
	require.Len(t, edges, 5)
	require.Equal(t, "/a,/z", edges[0].Properties["paths"])
	require.Equal(t, "80", edges[0].Properties["ports"])
	require.Equal(t, "true", edges[1].Properties["default_backend"])
	original := assets[2].ID
	ing.Status.LoadBalancer.Ingress = []networkingv1.IngressLoadBalancerIngress{{IP: "2001:db8::1"}}
	assets, _ = ingressAssets(ing, "c", time.Now())
	require.Equal(t, original, assets[2].ID, "provisioning an address must not change ingress identity")
	require.Equal(t, "http://[2001:db8::1]", assets[2].Endpoint)
}

func TestServiceAsset_PrivateAddresses(t *testing.T) {
	for _, addresses := range [][]corev1.LoadBalancerIngress{
		{{IP: "10.0.5.5"}}, {{IP: "fd00::1"}}, {{IP: "::ffff:192.168.0.1"}}, {{IP: "127.0.0.1"}}, {{IP: "169.254.1.1"}},
	} {
		svc := lbService(nil)
		svc.Status.LoadBalancer.Ingress = addresses
		a := serviceAsset(svc, "c", time.Now())
		require.Empty(t, a.PublicIP)
		require.Equal(t, "true", a.Metadata["internal"])
	}
	svc := lbService(nil)
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{{IP: "10.0.5.5"}, {Hostname: "lb.example.test"}, {IP: "203.0.113.10"}}
	a := serviceAsset(svc, "c", time.Now())
	require.Equal(t, "203.0.113.10", a.PublicIP)
	require.Equal(t, "false", a.Metadata["internal"])
}

type ingressChainAssets []asset.Asset

func (a ingressChainAssets) ListAll(context.Context, asset.SyncProjection) (asset.AssetSyncResult, error) {
	return asset.AssetSyncResult{Assets: a}, nil
}

type ingressChainEdges []asset.Edge

func (e ingressChainEdges) AllEdges(context.Context, asset.SyncProjection) (asset.EdgeSyncResult, error) {
	return asset.EdgeSyncResult{Edges: e}, nil
}
func (ingressChainEdges) VerifyDepartedAssets(context.Context, []string) (map[string]bool, error) {
	return nil, nil
}

func TestIngressServicePodGraphPath(t *testing.T) {
	for _, class := range []string{"nginx", "nginx-private"} {
		t.Run(class, func(t *testing.T) {
			now := time.Now()
			pod, _, _ := podAsset(corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "app", Labels: map[string]string{"app": "web"}}}, "c", now)
			svc := serviceAsset(corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "app"}, Spec: corev1.ServiceSpec{Type: corev1.ServiceTypeClusterIP, Selector: map[string]string{"app": "web"}}}, "c", now)
			ing := networkingv1.Ingress{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "app"}, Spec: networkingv1.IngressSpec{IngressClassName: &class, DefaultBackend: ptrBackend("web")}}
			ia, edges := ingressAssets(ing, "c", now)
			assets := append([]asset.Asset{pod, svc}, ia...)
			g := correlate.NewGraph(assets)
			edges = append(edges, (correlate.K8sServiceTargets{}).Correlate(g)...)
			edges = append(edges, (correlate.InternetReachability{}).Correlate(g)...)
			store, err := graphstore.Open("", 64, 0, 0, "")
			require.NoError(t, err)
			t.Cleanup(store.Close)
			require.NoError(t, store.SyncFromSources(context.Background(), 0, ingressChainAssets(assets), ingressChainEdges(edges), nil))
			result, err := store.RunCypher(context.Background(), "MATCH (:Asset)-[:Accesses]->(:Asset)-[:AccessesK8sWorkload]->(p:K8sWorkload) RETURN p", 100, 100)
			require.NoError(t, err)
			require.Len(t, result.Nodes, 1, "internal ingress retains its service and pod path")
			sig, err := store.NodeSignals(context.Background(), pod.ID)
			require.NoError(t, err)
			if class == "nginx" {
				require.Equal(t, 3, sig.InternetHops) // possible ingress starts one hop beyond confirmed exposure
			} else {
				require.Equal(t, graphstore.ReachNone, sig.InternetHops)
			}
		})
	}
}
