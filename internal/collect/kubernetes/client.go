package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// client.go holds the real, in-cluster implementation of k8sAPI; the mappers
// and the collection order live in kubernetes.go.

type realK8s struct {
	cs          *kubernetes.Clientset
	dyn         dynamic.Interface // for CRD access (cert-manager, etc.)
	clusterName string
	// ownNamespace is the namespace Vulngraph runs in (nodeposture_client.go).
	ownNamespace string
}

func (r *realK8s) ListNamespaces(ctx context.Context) ([]corev1.Namespace, error) {
	return listPages(ctx, func(opts metav1.ListOptions) ([]corev1.Namespace, string, string, error) {
		list, err := r.cs.CoreV1().Namespaces().List(ctx, opts)
		if err != nil {
			return nil, "", "", err
		}
		return list.Items, list.Continue, list.ResourceVersion, nil
	})
}

func (r *realK8s) ListPods(ctx context.Context, ns string) ([]corev1.Pod, error) {
	return listPages(ctx, func(opts metav1.ListOptions) ([]corev1.Pod, string, string, error) {
		list, err := r.cs.CoreV1().Pods(ns).List(ctx, opts)
		if err != nil {
			return nil, "", "", err
		}
		for _, pod := range list.Items {
			if ns != "" && pod.Namespace != ns {
				return nil, "", "", fmt.Errorf("pod page contains an object outside namespace %q", ns)
			}
		}
		return list.Items, list.Continue, list.ResourceVersion, nil
	})
}

func (r *realK8s) ListServices(ctx context.Context, ns string) ([]corev1.Service, error) {
	return listPages(ctx, func(opts metav1.ListOptions) ([]corev1.Service, string, string, error) {
		list, err := r.cs.CoreV1().Services(ns).List(ctx, opts)
		if err != nil {
			return nil, "", "", err
		}
		return list.Items, list.Continue, list.ResourceVersion, nil
	})
}

func (r *realK8s) ListDeployments(ctx context.Context, ns string) ([]appsv1.Deployment, error) {
	return listPages(ctx, func(opts metav1.ListOptions) ([]appsv1.Deployment, string, string, error) {
		list, err := r.cs.AppsV1().Deployments(ns).List(ctx, opts)
		if err != nil {
			return nil, "", "", err
		}
		return list.Items, list.Continue, list.ResourceVersion, nil
	})
}

func (r *realK8s) ListStatefulSets(ctx context.Context, ns string) ([]appsv1.StatefulSet, error) {
	return listPages(ctx, func(opts metav1.ListOptions) ([]appsv1.StatefulSet, string, string, error) {
		list, err := r.cs.AppsV1().StatefulSets(ns).List(ctx, opts)
		if err != nil {
			return nil, "", "", err
		}
		return list.Items, list.Continue, list.ResourceVersion, nil
	})
}

func (r *realK8s) ListDaemonSets(ctx context.Context, ns string) ([]appsv1.DaemonSet, error) {
	return listPages(ctx, func(opts metav1.ListOptions) ([]appsv1.DaemonSet, string, string, error) {
		list, err := r.cs.AppsV1().DaemonSets(ns).List(ctx, opts)
		if err != nil {
			return nil, "", "", err
		}
		return list.Items, list.Continue, list.ResourceVersion, nil
	})
}

func (r *realK8s) ListJobs(ctx context.Context, ns string) ([]batchv1.Job, error) {
	return listPages(ctx, func(opts metav1.ListOptions) ([]batchv1.Job, string, string, error) {
		list, err := r.cs.BatchV1().Jobs(ns).List(ctx, opts)
		if err != nil {
			return nil, "", "", err
		}
		return list.Items, list.Continue, list.ResourceVersion, nil
	})
}

func (r *realK8s) ListClusterRoles(ctx context.Context) ([]rbacv1.ClusterRole, error) {
	return listPages(ctx, func(opts metav1.ListOptions) ([]rbacv1.ClusterRole, string, string, error) {
		list, err := r.cs.RbacV1().ClusterRoles().List(ctx, opts)
		if err != nil {
			return nil, "", "", err
		}
		return list.Items, list.Continue, list.ResourceVersion, nil
	})
}

func (r *realK8s) ListClusterRoleBindings(ctx context.Context) ([]rbacv1.ClusterRoleBinding, error) {
	return listPages(ctx, func(opts metav1.ListOptions) ([]rbacv1.ClusterRoleBinding, string, string, error) {
		list, err := r.cs.RbacV1().ClusterRoleBindings().List(ctx, opts)
		if err != nil {
			return nil, "", "", err
		}
		return list.Items, list.Continue, list.ResourceVersion, nil
	})
}

func (r *realK8s) ListRoles(ctx context.Context) ([]rbacv1.Role, error) {
	return listPages(ctx, func(opts metav1.ListOptions) ([]rbacv1.Role, string, string, error) {
		list, err := r.cs.RbacV1().Roles(metav1.NamespaceAll).List(ctx, opts)
		if err != nil {
			return nil, "", "", err
		}
		return list.Items, list.Continue, list.ResourceVersion, nil
	})
}

func (r *realK8s) ListRoleBindings(ctx context.Context) ([]rbacv1.RoleBinding, error) {
	return listPages(ctx, func(opts metav1.ListOptions) ([]rbacv1.RoleBinding, string, string, error) {
		list, err := r.cs.RbacV1().RoleBindings(metav1.NamespaceAll).List(ctx, opts)
		if err != nil {
			return nil, "", "", err
		}
		return list.Items, list.Continue, list.ResourceVersion, nil
	})
}

func (r *realK8s) ListServiceAccounts(ctx context.Context, ns string) ([]corev1.ServiceAccount, error) {
	return listPages(ctx, func(opts metav1.ListOptions) ([]corev1.ServiceAccount, string, string, error) {
		list, err := r.cs.CoreV1().ServiceAccounts(ns).List(ctx, opts)
		if err != nil {
			return nil, "", "", err
		}
		return list.Items, list.Continue, list.ResourceVersion, nil
	})
}

func (r *realK8s) ListIngresses(ctx context.Context, ns string) ([]networkingv1.Ingress, error) {
	return listPages(ctx, func(opts metav1.ListOptions) ([]networkingv1.Ingress, string, string, error) {
		list, err := r.cs.NetworkingV1().Ingresses(ns).List(ctx, opts)
		if err != nil {
			return nil, "", "", err
		}
		return list.Items, list.Continue, list.ResourceVersion, nil
	})
}

func (r *realK8s) ListNetworkPolicies(ctx context.Context, ns string) ([]networkingv1.NetworkPolicy, error) {
	return listPages(ctx, func(opts metav1.ListOptions) ([]networkingv1.NetworkPolicy, string, string, error) {
		list, err := r.cs.NetworkingV1().NetworkPolicies(ns).List(ctx, opts)
		if err != nil {
			return nil, "", "", err
		}
		return list.Items, list.Continue, list.ResourceVersion, nil
	})
}

func (r *realK8s) ListConfigMaps(ctx context.Context, ns string) ([]corev1.ConfigMap, error) {
	return listPages(ctx, func(opts metav1.ListOptions) ([]corev1.ConfigMap, string, string, error) {
		list, err := r.cs.CoreV1().ConfigMaps(ns).List(ctx, opts)
		if err != nil {
			return nil, "", "", err
		}
		return list.Items, list.Continue, list.ResourceVersion, nil
	})
}

// issuerDiscoveryTimeout bounds the single unauthenticated-shaped GET below.
// The API server answers it from memory; a cluster that does not serve it at
// all must not stall the whole sweep waiting for a TCP timeout.
const issuerDiscoveryTimeout = 10 * time.Second

// ServiceAccountIssuer returns the API server's OIDC issuer, read from the
// cluster's own OpenID discovery document. This is the cluster stating which
// cluster it is — see identity.go for why that matters and what the value joins
// to on the cloud side.
func (r *realK8s) ServiceAccountIssuer(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, issuerDiscoveryTimeout)
	defer cancel()
	raw, err := r.cs.Discovery().RESTClient().Get().
		AbsPath(openIDConfigurationPath).DoRaw(ctx)
	if err != nil {
		return "", fmt.Errorf("ServiceAccountIssuer: %w", err)
	}
	var doc struct {
		Issuer string `json:"issuer"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", fmt.Errorf("ServiceAccountIssuer: decode: %w", err)
	}
	return doc.Issuer, nil
}

func defaultClient(_ context.Context, cfg map[string]string) (k8sAPI, string, error) {
	clusterName := cfg["cluster_name"]
	if clusterName == "" {
		clusterName = "in-cluster"
	}
	rc, err := rest.InClusterConfig()
	if err != nil {
		return nil, "", fmt.Errorf("defaultClient: in-cluster config: %w (is the pod running in Kubernetes?)", err)
	}
	// The client-go default rate limiter (QPS 5 / burst 10) throttles the many
	// list calls a full cluster inventory makes across namespaces — a large
	// cluster fails mid-collect with "client rate limiter Wait ... would exceed".
	// These are read-only lists, so raise the ceiling well above the default.
	rc.QPS = 100
	rc.Burst = 200
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, "", fmt.Errorf("defaultClient: build client: %w", err)
	}
	dyn, err := dynamic.NewForConfig(rc)
	if err != nil {
		return nil, "", fmt.Errorf("defaultClient: dynamic client: %w", err)
	}
	return &realK8s{cs: cs, dyn: dyn, clusterName: clusterName, ownNamespace: readOwnNamespace()}, clusterName, nil
}

// isPermissionError reports whether an API error is an authorization refusal
// (Forbidden/Unauthorized) rather than a transient failure.
//
// This distinction gates result.Partial, which disables deletion detection and
// finding auto-resolution for the whole connector (internal/jobs/sync.go). A
// missing RBAC permission is a stable, operator-fixable coverage gap, not
// evidence the cluster's inventory is untrustworthy — only a timeout or 5xx
// should set Partial.
func isPermissionError(err error) bool {
	return apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err)
}
