package gcp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	compute "google.golang.org/api/compute/v1"
)

type fakeLB struct {
	backends   []*compute.BackendService
	https      []*compute.TargetHttpsProxy
	ssl        []*compute.TargetSslProxy
	policies   []*compute.SslPolicy
	policyErr  error
	groups     map[string][]string
	groupErr   error
	httpsUnrch []string
}

func (f fakeLB) BackendServices(context.Context, string) ([]*compute.BackendService, []string, error) {
	return f.backends, nil, nil
}
func (f fakeLB) TargetHTTPSProxies(context.Context, string) ([]*compute.TargetHttpsProxy, []string, error) {
	return f.https, f.httpsUnrch, nil
}
func (f fakeLB) TargetSSLProxies(context.Context, string) ([]*compute.TargetSslProxy, error) {
	return f.ssl, nil
}
func (f fakeLB) SSLPolicies(context.Context, string) ([]*compute.SslPolicy, []string, error) {
	return f.policies, nil, f.policyErr
}
func (f fakeLB) GroupInstances(_ context.Context, _, url string) ([]string, error) {
	return f.groups[url], f.groupErr
}

const (
	modernLink = "https://www.googleapis.com/compute/v1/projects/p/global/sslPolicies/modern"
	weakLink   = "https://www.googleapis.com/compute/v1/projects/p/global/sslPolicies/weak-custom"
	igURL      = "https://www.googleapis.com/compute/v1/projects/p/zones/europe-west4-a/instanceGroups/web"
)

func TestCollectLoadBalancing(t *testing.T) {
	f := fakeLB{
		backends: []*compute.BackendService{
			{Name: "web", Protocol: "HTTPS", LoadBalancingScheme: "EXTERNAL_MANAGED", LogConfig: &compute.BackendServiceLogConfig{Enable: true},
				Iap: &compute.BackendServiceIAP{Enabled: true}, Backends: []*compute.Backend{{Group: igURL}}},
			{Name: "api", Region: "regions/europe-west4", LoadBalancingScheme: "INTERNAL_MANAGED"},
			{Name: "tcp", Protocol: "TCP", LoadBalancingScheme: "INTERNAL"},
			{Name: "neg", Protocol: "HTTP", Iap: &compute.BackendServiceIAP{Enabled: true},
				Backends: []*compute.Backend{{Group: "projects/p/zones/z/networkEndpointGroups/n"}}},
		},
		groups: map[string][]string{igURL: {"https://www.googleapis.com/compute/v1/projects/p/zones/europe-west4-a/instances/web-1"}},
		policies: []*compute.SslPolicy{
			{SelfLink: modernLink, Profile: "MODERN", MinTlsVersion: "TLS_1_2"},
			{SelfLink: weakLink, Profile: "CUSTOM", CustomFeatures: []string{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", "TLS_RSA_WITH_3DES_EDE_CBC_SHA"}},
		},
		https: []*compute.TargetHttpsProxy{
			{Name: "k8s2-ts-abc", SslPolicy: modernLink, SslCertificates: []string{"cert-a"}},
			{Name: "default-policy"},
			{Name: "weak", SslPolicy: weakLink},
		},
		ssl: []*compute.TargetSslProxy{{Name: "tcp-tls", SslPolicy: "https://www.googleapis.com/compute/v1/projects/p/global/sslPolicies/missing"}},
	}
	got, err := collectLoadBalancing(context.Background(), f, "p", time.Now())
	require.NoError(t, err)
	md := byID(got)

	web := md["p/backend-service/global/web"]
	require.Equal(t, "true", web["logging"])
	require.Equal(t, "true", web["iap_enabled"])
	require.Equal(t, "p/europe-west4-a/web-1", web["iap_backend_instances"])
	api := md["p/backend-service/europe-west4/api"]
	require.Equal(t, "HTTP", api["protocol"], "an omitted protocol is the HTTP default")
	require.Equal(t, "false", api["logging"], "an omitted logConfig is logging off")
	require.NotContains(t, md["p/backend-service/global/tcp"], "logging", "a TCP backend is not an HTTP(S) load balancer")
	require.NotContains(t, md["p/backend-service/global/neg"], "iap_backend_instances", "NEG membership is unknown")

	ing := md["p/target-proxy/global/k8s2-ts-abc"]
	require.Equal(t, "false", ing["ssl_policy_weak"])
	require.Equal(t, "true", ing["gke_ingress"])
	require.Equal(t, "cert-a", ing["certificate_links"])
	require.Equal(t, "true", md["p/target-proxy/global/default-policy"]["ssl_policy_weak"], "no policy is the COMPATIBLE default")
	require.Equal(t, "CUSTOM profile enables TLS_RSA_WITH_3DES_EDE_CBC_SHA", md["p/target-proxy/global/weak"]["ssl_policy_weakness"])
	require.NotContains(t, md["p/target-proxy/global/tcp-tls"], "ssl_policy_weak", "an unlisted policy is unknown, never strong")
}

func TestCollectLoadBalancing_FailuresAreUnknown(t *testing.T) {
	f := fakeLB{
		backends:  []*compute.BackendService{{Name: "web", Iap: &compute.BackendServiceIAP{Enabled: true}, Backends: []*compute.Backend{{Group: igURL}}}},
		groupErr:  errors.New("denied"),
		https:     []*compute.TargetHttpsProxy{{Name: "named", SslPolicy: modernLink}, {Name: "default"}},
		policyErr: errors.New("boom"), httpsUnrch: []string{"regions/asia-east1"},
	}
	got, err := collectLoadBalancing(context.Background(), f, "p", time.Now())
	require.Error(t, err)
	md := byID(got)
	require.NotContains(t, md["p/backend-service/global/web"], "iap_backend_instances")
	require.NotContains(t, md["p/target-proxy/global/named"], "ssl_policy_weak")
	require.Equal(t, "true", md["p/target-proxy/global/default"]["ssl_policy_weak"], "the default policy needs no lookup")
}

func TestSSLPolicyWeakness(t *testing.T) {
	pol := func(p compute.SslPolicy) map[string]*compute.SslPolicy {
		p.SelfLink = "l"
		return map[string]*compute.SslPolicy{"l": &p}
	}
	for _, tc := range []struct {
		name string
		p    compute.SslPolicy
		weak bool
	}{
		{"restricted", compute.SslPolicy{Profile: "RESTRICTED"}, false},
		{"modern tls1.2", compute.SslPolicy{Profile: "MODERN", MinTlsVersion: "TLS_1_2"}, false},
		{"modern tls1.0", compute.SslPolicy{Profile: "MODERN"}, true},
		{"compatible", compute.SslPolicy{Profile: "COMPATIBLE", MinTlsVersion: "TLS_1_2"}, true},
		{"unset profile", compute.SslPolicy{}, true},
		{"custom strong", compute.SslPolicy{Profile: "CUSTOM", CustomFeatures: []string{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"}}, false},
		{"custom rsa kex", compute.SslPolicy{Profile: "CUSTOM", CustomFeatures: []string{"TLS_RSA_WITH_AES_128_GCM_SHA256"}}, true},
	} {
		weak, _, ok := sslPolicyWeakness("l", pol(tc.p))
		require.True(t, ok, tc.name)
		require.Equal(t, tc.weak, weak, tc.name)
	}
}
