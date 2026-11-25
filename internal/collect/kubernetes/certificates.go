package kubernetes

import (
	"context"
	"fmt"
	"strings"
	"time"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

// certGVR is the cert-manager Certificate CRD group/version/resource.
var certGVR = schema.GroupVersionResource{
	Group:    "cert-manager.io",
	Version:  "v1",
	Resource: "certificates",
}

// certInfo is a minimal projection of a cert-manager Certificate object.
type certInfo struct {
	Name       string
	Namespace  string
	DNSNames   []string
	Issuer     string
	IssuerKind string
	SecretName string
	NotBefore  time.Time
	NotAfter   time.Time
	Ready      bool
	Message    string
}

// collectCertManagerCerts fetches all cert-manager Certificate resources across
// all namespaces and maps them to assets. Errors from CRD-not-found (cert-manager
// not installed) are silently skipped; other errors are returned.
func collectCertManagerCerts(ctx context.Context, dyn dynamic.Interface, cluster string, now time.Time) ([]asset.Asset, []asset.Edge, error) {
	list, err := dyn.Resource(certGVR).Namespace("").List(ctx, metav1.ListOptions{})
	if err != nil {
		// CRD absent — cert-manager not installed on this cluster. Not an error.
		// apierrors.IsNotFound covers this dynamic-client case: dyn.Resource
		// takes a GVR directly and does no RESTMapper lookup, so the apiserver's
		// "no route for this resource" response comes back as a generic
		// 404/NotFound StatusError, never as a meta.IsNoMatchError (that shape is
		// only produced by RESTMapper-based clients, which this collector does
		// not use). A structured check, not string matching, and it `errors.As`
		// through this function's own %w wrap.
		if apierrors.IsNotFound(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("collectCertManagerCerts: %w", err)
	}

	var assets []asset.Asset
	var edges []asset.Edge
	for _, item := range list.Items {
		c := certInfo{
			Name:      item.GetName(),
			Namespace: item.GetNamespace(),
		}

		spec, _ := item.Object["spec"].(map[string]interface{})
		if spec != nil {
			if dns, ok := spec["dnsNames"].([]interface{}); ok {
				for _, d := range dns {
					if s, ok := d.(string); ok {
						c.DNSNames = append(c.DNSNames, s)
					}
				}
			}
			if ref, ok := spec["issuerRef"].(map[string]interface{}); ok {
				c.Issuer, _ = ref["name"].(string)
				c.IssuerKind, _ = ref["kind"].(string)
			}
			c.SecretName, _ = spec["secretName"].(string)
		}

		status, _ := item.Object["status"].(map[string]interface{})
		if status != nil {
			if v, ok := status["notAfter"].(string); ok {
				if t, err2 := time.Parse(time.RFC3339, v); err2 == nil {
					c.NotAfter = t
				}
			}
			if v, ok := status["notBefore"].(string); ok {
				if t, err2 := time.Parse(time.RFC3339, v); err2 == nil {
					c.NotBefore = t
				}
			}
			if conds, ok := status["conditions"].([]interface{}); ok {
				for _, cond := range conds {
					m, _ := cond.(map[string]interface{})
					if m == nil {
						continue
					}
					if typ, _ := m["type"].(string); typ == "Ready" {
						c.Ready = m["status"] == "True"
						c.Message, _ = m["message"].(string)
					}
				}
			}
		}

		a, e := certManagerAsset(c, cluster, now)
		assets = append(assets, a)
		edges = append(edges, e...)
	}
	return assets, edges, nil
}

func certManagerAsset(c certInfo, cluster string, now time.Time) (asset.Asset, []asset.Edge) {
	id := fmt.Sprintf("%s/certificate/%s/%s", cluster, c.Namespace, c.Name)

	certMeta := map[string]string{
		"namespace":   c.Namespace,
		"issuer":      c.Issuer,
		"issuer_kind": c.IssuerKind,
		"secret_name": c.SecretName,
		"ready":       fmt.Sprintf("%t", c.Ready),
		"dns_names":   strings.Join(c.DNSNames, ","),
		"source":      "cert-manager",
	}
	if !c.NotAfter.IsZero() {
		certMeta["expires_at"] = c.NotAfter.UTC().Format(time.RFC3339)
		days := int(time.Until(c.NotAfter).Hours() / 24)
		certMeta["days_until_expiry"] = fmt.Sprintf("%d", days)
		// Both outcomes recorded, so an absent key means only that NotAfter was
		// unset — a Certificate that has not been issued yet. See the note in
		// collect/aws/acm.go.
		certMeta["expiring_soon"] = fmt.Sprintf("%t", days <= 30)
	}
	if !c.NotBefore.IsZero() {
		certMeta["issued_at"] = c.NotBefore.UTC().Format(time.RFC3339)
	}
	if c.Message != "" {
		certMeta["status_message"] = c.Message
	}

	// Primary domain: first DNS name, fall back to cert name.
	domain := c.Name
	if len(c.DNSNames) > 0 {
		domain = c.DNSNames[0]
	}

	a := asset.Asset{
		ID:           id,
		Name:         c.Name,
		Type:         "k8s_certificate",
		Provider:     asset.ProviderKubernetes,
		Region:       cluster,
		Domain:       domain,
		Tags:         map[string]string{"namespace": c.Namespace, "issuer": c.Issuer},
		Metadata:     certMeta,
		DiscoveredAt: now,
		LastSeen:     now,
	}

	edges := []asset.Edge{{
		SrcID:    id,
		SrcType:  "k8s_certificate",
		DstID:    fmt.Sprintf("%s/namespace/%s", cluster, c.Namespace),
		DstType:  "k8s_namespace",
		EdgeType: "runs_in",
	}}
	return a, edges
}
