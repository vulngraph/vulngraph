// Package kubernetes collects pod, service, deployment, namespace, and RBAC
// inventory from the cluster the binary is running in. Authentication is
// in-cluster only: no kubeconfig file is accepted; the pod's service
// account token is the credential. Cross-cluster support can be added later
// via OIDC-issued tokens, following the same no-static-secret principle.
package kubernetes

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strings"
	"time"

	admissionv1 "k8s.io/api/admissionregistration/v1"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/k8sns"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// k8sAPI is the slice of the Kubernetes client used by the collector,
// small enough to fake in tests.
type k8sAPI interface {
	ListNamespaces(ctx context.Context) ([]corev1.Namespace, error)
	ListPods(ctx context.Context, ns string) ([]corev1.Pod, error)
	ListServices(ctx context.Context, ns string) ([]corev1.Service, error)
	ListDeployments(ctx context.Context, ns string) ([]appsv1.Deployment, error)
	ListStatefulSets(ctx context.Context, ns string) ([]appsv1.StatefulSet, error)
	ListDaemonSets(ctx context.Context, ns string) ([]appsv1.DaemonSet, error)
	ListJobs(ctx context.Context, ns string) ([]batchv1.Job, error)
	ListClusterRoles(ctx context.Context) ([]rbacv1.ClusterRole, error)
	ListClusterRoleBindings(ctx context.Context) ([]rbacv1.ClusterRoleBinding, error)
	ListRoles(ctx context.Context) ([]rbacv1.Role, error)
	ListRoleBindings(ctx context.Context) ([]rbacv1.RoleBinding, error)
	ListServiceAccounts(ctx context.Context, ns string) ([]corev1.ServiceAccount, error)
	ListIngresses(ctx context.Context, ns string) ([]networkingv1.Ingress, error)
	ListNetworkPolicies(ctx context.Context, ns string) ([]networkingv1.NetworkPolicy, error)
	ListConfigMaps(ctx context.Context, ns string) ([]corev1.ConfigMap, error)
	// ServiceAccountIssuer returns the API server's own OIDC issuer — the
	// cluster stating which cluster it is (identity.go).
	ServiceAccountIssuer(ctx context.Context) (string, error)
	// PodLogTail and OwnNamespace read the opt-in node-posture reader's
	// reports back from its pods in Vulngraph's own namespace (nodeposture.go).
	PodLogTail(ctx context.Context, ns, pod, container string) (string, error)
	OwnNamespace() string
	// The cluster-wide admission policy mechanisms (admission_engines.go).
	ListValidatingWebhookConfigurations(ctx context.Context) ([]admissionv1.ValidatingWebhookConfiguration, error)
	ListValidatingAdmissionPolicyBindings(ctx context.Context) ([]admissionv1.ValidatingAdmissionPolicyBinding, error)
	// ListCustomResources lists a CRD's objects cluster-wide (Kyverno policies,
	// Gatekeeper constraints: admission_coverage.go).
	ListCustomResources(ctx context.Context, gvr schema.GroupVersionResource) ([]unstructured.Unstructured, error)
}

// Collector implements collect.Collector for Kubernetes.
type Collector struct {
	newClient func(ctx context.Context, cfg map[string]string) (k8sAPI, string, error)
}

func New() *Collector { return &Collector{newClient: defaultClient} }

func (c *Collector) Collect(ctx context.Context, cfg map[string]string) (collect.Result, error) {
	client, clusterName, err := c.newClient(ctx, cfg)
	if err != nil {
		return collect.Result{}, fmt.Errorf("Collect: %w", err)
	}

	now := time.Now()
	var result collect.Result

	namespaces, err := client.ListNamespaces(ctx)
	if err != nil {
		return collect.Result{}, fmt.Errorf("Collect: list namespaces: %w", err)
	}
	// Namespace assets are added after the per-namespace loop so NetworkPolicy
	// presence (checked below) can be folded into the namespace metadata.

	// Cluster identity, published as an asset before anything else (identity.go).
	// A failed issuer read is NOT Partial: it leaves one metadata key unobserved,
	// and Partial would disable deletion reconciliation for the entire connector
	// over it. Absent = unknown is exactly what the omitted key means, and the
	// check reading it stays silent (Check.Evaluable).
	ident := clusterIdentity{Configured: clusterName, KubeSystemUID: kubeSystemUID(namespaces)}
	if issuer, err := client.ServiceAccountIssuer(ctx); err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("cluster_name", clusterName).
			Msg("k8s cluster identity discovery skipped")
	} else {
		ident.Issuer = issuer
	}
	if ident.nameMismatch() {
		log.FromContext(ctx).Warn().
			Str("configured_name", ident.Configured).
			Str("discovered_name", ident.discoveredName()).
			Msg("k8s connector cluster_name does not match the cluster's own identity; " +
				"cloud-cluster joins keyed on the name cannot resolve")
	}
	clusterIdx := len(result.Assets)
	result.Assets = append(result.Assets, ident.asset(now))
	// kube-system's pods, kept for the control-plane flags (controlplane.go),
	// and Vulngraph's own namespace's pods and DaemonSets, for the node-posture
	// reader (nodeposture.go).
	var kubeSystemPods, ownPods []corev1.Pod
	var ownDaemonSets, allDaemonSets []appsv1.DaemonSet

	// Filled in by the namespace loop below and read by the RBAC binding producers
	// after it, so a `binds` edge is never emitted to a ServiceAccount the collector
	// proved does not exist. The loop must therefore run before ListClusterRoleBindings.
	known := newSAInventory(namespaces)
	seenImages := map[[2]string]bool{}

	// Cluster-wide admission policy engines, stamped on every namespace asset.
	// Best effort: an unread list leaves the key off (admission_engines.go).
	engines, enginesErr := admissionPolicyEngines(ctx, client)
	coverage, coverageErr := map[string]string(nil), enginesErr
	if enginesErr != nil {
		log.FromContext(ctx).Warn().Err(enginesErr).Msg("k8s admission policy engine discovery skipped")
	} else {
		nsNames := make([]string, 0, len(namespaces))
		for _, ns := range namespaces {
			nsNames = append(nsNames, ns.Name)
		}
		if coverage, coverageErr = podSecurityCoverage(ctx, client, engines, nsNames); coverageErr != nil {
			log.FromContext(ctx).Warn().Err(coverageErr).Msg("k8s policy engine coverage unread; namespaces graded on their labels")
		}
	}

	// namespacesFullyEnumerated tracks whether every namespace's k8s_namespace
	// asset was actually emitted this sweep. The asset is skipped for a
	// namespace whose NetworkPolicy listing failed (see below), so a single
	// namespace's transient permission gap must drop the k8s_namespace
	// completeness claim for the WHOLE cluster-scoped listing — ListNamespaces
	// itself has no per-namespace granularity to claim against, so "all
	// namespaces got their asset emitted" is the only thing this scope can
	// truthfully mean.
	namespacesFullyEnumerated := true
	var namespaceAssetCount int

	for _, ns := range namespaces {
		nsName := ns.Name

		// Fetch ServiceAccounts first so pods can inherit the IRSA/WIF role
		// annotation that standard setups put on the SA, not the pod. saRoles maps
		// SA name → eks.amazonaws.com/role-arn (or GKE WIF SA email).
		sas, saErr := client.ListServiceAccounts(ctx, nsName)
		if saErr != nil {
			// Best-effort, but an un-fetched SA list means absent ≠ deleted: flag
			// partial so sync skips deletion reconciliation. This must
			// stay unconditional (no isPermissionError carve-out) even though
			// ServiceAccounts currently has the grant. findDeletedAssets
			// (internal/jobs/sync_deletion_scope.go) consumes
			// CompletedEnumerations, so a scope this
			// sweep did not prove complete is not deletable and the claim
			// below is simply withheld on this path. Partial is kept anyway,
			// deliberately — it is the coarser of two independent gates, and
			// the cost of the redundancy is one skipped deletion pass while
			// the cost of being wrong is pruned ServiceAccount assets with
			// their findings auto-resolved. Do not re-widen this.
			log.FromContext(ctx).Warn().Err(saErr).Str("namespace", nsName).
				Msg("k8s serviceaccount collection skipped")
			result.Partial = true
		} else {
			// ListServiceAccounts makes one unpaginated call (no Limit set, see
			// client.go), so a nil error IS the whole namespace's ServiceAccount
			// set. len(sas) is also exactly what gets emitted as
			// k8s_service_account assets below (every SA becomes an asset,
			// unconditionally), so the count claimed here matches what's stored.
			result.MarkComplete(nsName+"/serviceaccounts", []string{"k8s_service_account"}, len(sas))
		}
		saRoles := make(map[string]string, len(sas))
		saAutomount := make(map[string]*bool, len(sas))
		for _, sa := range sas {
			saAutomount[sa.Name] = sa.AutomountServiceAccountToken
			if arn := sa.Annotations["eks.amazonaws.com/role-arn"]; arn != "" {
				saRoles[sa.Name] = arn
			} else if gsa := sa.Annotations["iam.gke.io/gcp-service-account"]; gsa != "" {
				saRoles[sa.Name] = "serviceAccount:" + gsa
			}
		}

		pods, err := client.ListPods(ctx, nsName)
		if err != nil {
			return collect.Result{}, fmt.Errorf("Collect: list pods %s: %w", nsName, err)
		}
		// A nil error here is the whole namespace's Pod set (one unpaginated
		// call, and an error aborts the entire sweep rather than being
		// swallowed) — claim only the k8s_pod type. The "container" and
		// "container_image" assets podAsset also produces below are NOT
		// claimed: their identity is keyed cross-namespace (an image digest is
		// shared by any pod that runs it) and their count here is not a full
		// enumeration of either type, so a claim would misrepresent what this
		// listing actually proved.
		result.MarkComplete(nsName+"/pods", []string{"k8s_pod"}, len(pods))
		if nsName == "kube-system" {
			kubeSystemPods = pods
		}
		// A namespace that explicitly opts into the "privileged" Pod Security
		// Standard is an operator decision that privileged workloads belong here —
		// the label-based successor to the hardcoded system-namespace allowlist.
		nsPSAEnforce := ns.Labels["pod-security.kubernetes.io/enforce"]
		for _, pod := range pods {
			a, extraAssets, edges := podAsset(pod, clusterName, now)
			if nsPSAEnforce != "" {
				a.Metadata["ns_psa_enforce"] = nsPSAEnforce
			}
			resolveAutomount(a.Metadata, saAutomount, saErr == nil)
			// Inherit the SA-level IRSA/WIF role when the pod has no direct annotation.
			if a.Metadata["exec_role"] == "" {
				if role := saRoles[pod.Spec.ServiceAccountName]; role != "" {
					a.Metadata["exec_role"] = role
				}
			}
			result.Assets = append(result.Assets, a)
			for _, extra := range extraAssets {
				// A shared digest/ref has the same cluster metadata for every pod.
				// Keep distinct refs (they may need different registry credentials)
				// and every pod edge, but emit an identical image record once.
				if extra.Type == "container_image" {
					key := [2]string{extra.ID, extra.Metadata["image_ref"]}
					if seenImages[key] {
						continue
					}
					seenImages[key] = true
				}
				result.Assets = append(result.Assets, extra)
			}
			result.Edges = append(result.Edges, edges...)
		}

		// NetworkPolicy presence — used by the k8s-namespace-no-network-policy check.
		// On a list error we cannot know whether policies exist, so the namespace
		// asset is NOT emitted this sweep (emitting has_network_policy=false would
		// fire the check falsely); Partial keeps sync from treating it as deleted.
		// This must stay unconditional (no isPermissionError carve-out): skipping
		// the namespace asset here means every stored k8s_namespace row is at
		// stake. findDeletedAssets (internal/jobs/sync_deletion_scope.go) is
		// scope-aware and consumes CompletedEnumerations, so the
		// cluster-wide k8s_namespace claim being withheld here (via
		// namespacesFullyEnumerated, below the namespace loop) already makes
		// those rows undeletable this sweep. Partial is kept as the second,
		// coarser gate: k8s_namespace has exactly one cluster-wide scope, so
		// a single namespace's failure puts every stored namespace row at
		// stake and there is no finer claim to fall back on. Do not re-widen
		// this.
		netpols, npErr := client.ListNetworkPolicies(ctx, nsName)
		if npErr != nil {
			log.FromContext(ctx).Warn().Err(npErr).Str("namespace", nsName).
				Msg("k8s networkpolicy collection skipped")
			result.Partial = true
			// The k8s_namespace asset for nsName is skipped this sweep (below),
			// so the cluster-wide k8s_namespace enumeration is not
			// provably complete either — see namespacesFullyEnumerated's doc
			// comment above. NetworkPolicy itself has no asset type of its own
			// (it only feeds the has_network_policy boolean here), so there is
			// no separate scope to decline a claim for.
			namespacesFullyEnumerated = false
		} else {
			nsAsset := namespaceAsset(ns, clusterName, netpols, now)
			if enginesErr == nil {
				nsAsset.Metadata["cluster_policy_engines"] = engines
			}
			if coverageErr == nil {
				nsAsset.Metadata["pod_security_engine"] = coverage[nsName]
			}
			result.Assets = append(result.Assets, nsAsset)
			namespaceAssetCount++
		}

		svcs, err := client.ListServices(ctx, nsName)
		if err != nil {
			return collect.Result{}, fmt.Errorf("Collect: list services %s: %w", nsName, err)
		}
		result.MarkComplete(nsName+"/services", []string{"k8s_service"}, len(svcs))
		for _, svc := range svcs {
			result.Assets = append(result.Assets, serviceAsset(svc, clusterName, now))
		}

		deps, err := client.ListDeployments(ctx, nsName)
		if err != nil {
			return collect.Result{}, fmt.Errorf("Collect: list deployments %s: %w", nsName, err)
		}
		result.MarkComplete(nsName+"/deployments", []string{"k8s_deployment"}, len(deps))
		for _, dep := range deps {
			result.Assets = append(result.Assets, deploymentAsset(dep, clusterName, now))
		}

		// StatefulSets, DaemonSets, and Jobs own pods directly (podOwner above) —
		// without an asset for the owner, checks.Registry's workload aggregator has
		// nowhere to re-address a per-pod finding, so it stays unresolvable
		// per-replica noise. Collecting them as first-class assets, keyed exactly
		// like deploymentAsset, lets those findings collapse to one per workload
		// and gives them a graph anchor (attack-path/blast-radius scoring).
		statefulSets, err := client.ListStatefulSets(ctx, nsName)
		if err != nil {
			return collect.Result{}, fmt.Errorf("Collect: list statefulsets %s: %w", nsName, err)
		}
		result.MarkComplete(nsName+"/statefulsets", []string{"k8s_statefulset"}, len(statefulSets))
		for _, sts := range statefulSets {
			result.Assets = append(result.Assets, statefulSetAsset(sts, clusterName, now))
		}

		daemonSets, err := client.ListDaemonSets(ctx, nsName)
		if err != nil {
			return collect.Result{}, fmt.Errorf("Collect: list daemonsets %s: %w", nsName, err)
		}
		result.MarkComplete(nsName+"/daemonsets", []string{"k8s_daemonset"}, len(daemonSets))
		allDaemonSets = append(allDaemonSets, daemonSets...)
		if nsName == client.OwnNamespace() {
			ownPods, ownDaemonSets = pods, daemonSets
		}
		for _, ds := range daemonSets {
			result.Assets = append(result.Assets, daemonSetAsset(ds, clusterName, now))
		}

		jobs, err := client.ListJobs(ctx, nsName)
		if err != nil {
			return collect.Result{}, fmt.Errorf("Collect: list jobs %s: %w", nsName, err)
		}
		result.MarkComplete(nsName+"/jobs", []string{"k8s_job"}, len(jobs))
		for _, job := range jobs {
			result.Assets = append(result.Assets, jobAsset(job, clusterName, now))
		}

		// Retain ingress hosts and default backends, including private topology.
		ingresses, err := client.ListIngresses(ctx, nsName)
		if err != nil {
			return collect.Result{}, fmt.Errorf("Collect: list ingresses %s: %w", nsName, err)
		}
		// One Ingress can produce several host assets and a default route.
		var ingressAssetCount int
		for _, ing := range ingresses {
			assets, edges := ingressAssets(ing, clusterName, now)
			ingressAssetCount += len(assets)
			result.Assets = append(result.Assets, assets...)
			result.Edges = append(result.Edges, edges...)
		}
		result.MarkComplete(nsName+"/ingresses", []string{"k8s_ingress"}, ingressAssetCount)

		// ConfigMaps: surface any that contain plaintext secret-like keys.
		// Platform namespaces are skipped (k8sns.ConfigMapSkipped, named
		// in the check's description and docs/cspm-coverage.md).
		if !k8sns.ConfigMapSkipped(nsName) {
			cms, cmErr := client.ListConfigMaps(ctx, nsName)
			var cmAssetCount int
			if cmErr != nil {
				// Best-effort, but an un-fetched namespace means absent ≠ deleted:
				// flag partial so sync skips deletion reconciliation.
				// This must stay unconditional (no isPermissionError carve-out):
				// stored ConfigMap assets include plaintext-secret findings, and
				// findDeletedAssets (internal/jobs/sync_deletion_scope.go) is
				// scope-aware and consumes CompletedEnumerations, so
				// withholding this namespace's claim already keeps its stored
				// ConfigMap assets undeletable. Partial is kept as the
				// coarser second gate — plaintext-secret findings ride on
				// these assets, so the asymmetry between a skipped deletion
				// pass and a wrongly-pruned finding still favours redundancy.
				// Do not re-widen this. (CompletedEnumerations
				// is populated below for the success path — see
				// MarkComplete's doc comment for what a future scoped-enforce
				// mode would need before it can act on it.)
				log.FromContext(ctx).Warn().Err(cmErr).Str("namespace", nsName).
					Msg("k8s configmap collection skipped")
				result.Partial = true
			}
			for _, cm := range cms {
				if a, ok := configMapAsset(cm, clusterName, now); ok {
					result.Assets = append(result.Assets, a)
					cmAssetCount++
				}
			}
			if cmErr == nil {
				// One unpaginated call; a nil error is the whole namespace's
				// ConfigMap set. cmAssetCount, not len(cms): only ConfigMaps
				// with a plaintext-secret hit become k8s_configmap assets, and
				// that's the type this scope is claimed for.
				result.MarkComplete(nsName+"/configmaps", []string{"k8s_configmap"}, cmAssetCount)
			}
		}

		// ServiceAccounts: collect so ClusterRoleBinding subjects can reference them
		// and WIF/IRSA correlators can match them. Already fetched above (saRoles).
		//
		// System namespaces are NOT skipped. The RBAC producer emits
		// a `binds` edge for every ServiceAccount subject a binding names, in any
		// namespace, so skipping the asset would make the edge unloadable: the
		// dropped `binds` rows would be subjects in kube-system,
		// monitoring or cert-manager whose SAs exist (gke-metrics-agent, the
		// kube-controller-manager controllers, cert-manager-webhook) but were
		// not collected. Those are the highest-privilege identities in the cluster —
		// the ones a compromised pod's token buys — and `binds` is how RBAC privilege
		// reaches the workload that holds it. The noise argument does not apply: the
		// one check on a k8s_service_account asset (k8s-default-sa-automount) exempts
		// system namespaces itself, a few hundred assets is nothing against
		// a graph of hundreds of thousands of nodes, and it also exposes any Workload-Identity
		// annotation on a system-namespace SA from the WIF/IRSA correlators.
		if saErr == nil {
			for _, sa := range sas {
				result.Assets = append(result.Assets, serviceAccountAsset(sa, clusterName, now))
				known.ids[serviceAccountID(clusterName, sa.Namespace, sa.Name)] = true
			}
			known.listedNamespaces[nsName] = true
		}
	}

	// k8s_namespace is a single cluster-wide scope (ListNamespaces has no
	// per-namespace granularity), so it can only be claimed complete when
	// EVERY namespace's asset was actually emitted this sweep — see
	// namespacesFullyEnumerated's doc comment above the loop.
	if namespacesFullyEnumerated {
		result.MarkComplete("cluster/namespaces", []string{"k8s_namespace"}, namespaceAssetCount)
	}
	maps.Copy(result.Assets[clusterIdx].Metadata, controlPlaneSignals(kubeSystemPods))
	if cms, err := client.ListConfigMaps(ctx, "kube-system"); err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("k8s kube-proxy configuration skipped")
	} else {
		maps.Copy(result.Assets[clusterIdx].Metadata, kubeProxySignals(kubeSystemPods, cms))
		maps.Copy(result.Assets[clusterIdx].Metadata, networkPolicyEngines(allDaemonSets, cms))
	}
	maps.Copy(result.Assets[clusterIdx].Metadata, nodePostureSignals(ctx, client, ownPods, ownDaemonSets))

	clusterRoles, err := client.ListClusterRoles(ctx)
	if err != nil {
		return collect.Result{}, fmt.Errorf("Collect: list cluster roles: %w", err)
	}
	result.MarkComplete("cluster/clusterroles", []string{"k8s_cluster_role"}, len(clusterRoles))

	// Namespaced RBAC: Roles and RoleBindings. Best-effort, like the other
	// cluster-wide RBAC lists above — the collector's own ClusterRole may not
	// yet grant `roles`/`rolebindings` list, and a hard error here would kill
	// the entire k8s sync over one RBAC gap. One cluster-wide call each
	// (metav1.NamespaceAll), mirroring ListClusterRoles/ListClusterRoleBindings
	// rather than a per-namespace loop.
	roles, err := client.ListRoles(ctx)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("k8s role collection skipped")
		result.Partial = result.Partial || !isPermissionError(err)
	} else {
		result.MarkComplete("cluster/roles", []string{"k8s_role"}, len(roles))
	}

	crbs, err := client.ListClusterRoleBindings(ctx)
	if err != nil {
		return collect.Result{}, fmt.Errorf("Collect: list cluster role bindings: %w", err)
	}
	result.MarkComplete("cluster/clusterrolebindings", []string{"k8s_cluster_role_binding"}, len(crbs))

	roleBindings, err := client.ListRoleBindings(ctx)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Msg("k8s rolebinding collection skipped")
		result.Partial = result.Partial || !isPermissionError(err)
	} else {
		result.MarkComplete("cluster/rolebindings", []string{"k8s_role_binding"}, len(roleBindings))
	}

	// Roles are graded before any binding asset is built and indexed by asset
	// ID, so each binding can be stamped with what the role it references
	// actually grants. The bindings are listed first all the same: whether a
	// platform-named role is really the platform's depends on who binds it
	// (gradePlatformRole).
	grades := roleGrades{}
	roleAssets := make([]asset.Asset, 0, len(clusterRoles)+len(roles))
	for _, cr := range clusterRoles {
		roleAssets = append(roleAssets, clusterRoleAsset(cr, clusterName, now))
	}
	for _, role := range roles {
		roleAssets = append(roleAssets, roleAsset(role, clusterName, now))
	}
	env := detectDistros(ctx, client, ident)
	orgBound := orgBoundRoles(clusterName, crbs, roleBindings, env)
	for _, a := range roleAssets {
		gradePlatformRole(&a, env, orgBound)
		grades[a.ID] = a
		result.Assets = append(result.Assets, a)
	}

	for _, crb := range crbs {
		a, edges := clusterRoleBindingAsset(crb, clusterName, now, grades, known, env)
		result.Assets = append(result.Assets, a)
		result.Edges = append(result.Edges, edges...)
	}
	for _, rb := range roleBindings {
		a, edges := roleBindingAsset(rb, clusterName, now, grades, known, env)
		result.Assets = append(result.Assets, a)
		result.Edges = append(result.Edges, edges...)
	}

	// cert-manager Certificate CRDs — best-effort. A CRD-absent cluster returns
	// (nil, nil, nil) and is NOT partial (cert-manager simply isn't installed);
	// a transient list error flags the result partial so sync skips deletion
	// reconciliation instead of auto-resolving k8s_certificate findings.
	// A Forbidden/Unauthorized error (the collector's ClusterRole not granting
	// cert-manager.io access — the common case) is a permission gap, not
	// evidence the inventory can't be trusted; see the ServiceAccounts comment
	// above and isPermissionError's doc comment in client.go.
	if real, ok := client.(*realK8s); ok && real.dyn != nil {
		certAssets, certEdges, err := collectCertManagerCerts(ctx, real.dyn, clusterName, now)
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Msg("k8s cert-manager collection skipped")
			result.Partial = result.Partial || !isPermissionError(err)
		} else {
			// A nil error here — including the CRD-absent case, which
			// collectCertManagerCerts turns into (nil, nil, nil) — is a
			// genuinely complete listing: "cert-manager isn't installed" is a
			// proven fact about the cluster, not an unknown, so zero
			// certificates is as claimable as any other count.
			result.MarkComplete("cluster/certmanager", []string{"k8s_certificate"}, len(certAssets))
		}
		result.Assets = append(result.Assets, certAssets...)
		result.Edges = append(result.Edges, certEdges...)
	}

	return result, nil
}

// --- asset mappers ---

// configMapAsset returns a k8s_configmap asset if the ConfigMap contains any
// key whose name suggests a plaintext secret (password, token, key, etc.) AND
// whose value looks like an actual secret (length > 8, not a placeholder).
// Returns (Asset{}, false) when the ConfigMap is clean.
func configMapAsset(cm corev1.ConfigMap, cluster string, now time.Time) (asset.Asset, bool) {
	var hits []string
	for k, v := range cm.Data {
		if secretKeyPattern(k) && len(v) > 8 && !isPlaceholder(v) {
			hits = append(hits, k)
		}
	}
	if len(hits) == 0 {
		return asset.Asset{}, false
	}
	sort.Strings(hits)
	return asset.Asset{
		ID:       fmt.Sprintf("%s/configmap/%s/%s", cluster, cm.Namespace, cm.Name),
		Name:     cm.Name,
		Type:     "k8s_configmap",
		Provider: asset.ProviderKubernetes,
		Region:   cluster,
		Tags:     cm.Labels,
		Metadata: map[string]string{
			"namespace":            cm.Namespace,
			"has_plaintext_secret": "true",
			"secret_keys":          strings.Join(hits, ","),
		},
		DiscoveredAt: now,
		LastSeen:     now,
	}, true
}

func secretKeyPattern(key string) bool {
	lower := strings.ToLower(key)
	for _, pat := range []string{"password", "passwd", "secret", "token", "apikey", "api_key", "private_key", "credential"} {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

func isPlaceholder(v string) bool {
	return strings.HasPrefix(v, "${") || strings.HasPrefix(v, "$(") ||
		strings.HasPrefix(v, "{{") || v == "CHANGEME" || v == "REPLACE_ME"
}

// namespaceAsset is only built once the namespace's NetworkPolicy list has
// succeeded, so netpols is the namespace's complete policy set.
func namespaceAsset(ns corev1.Namespace, cluster string, netpols []networkingv1.NetworkPolicy, now time.Time) asset.Asset {
	return asset.Asset{
		ID:       fmt.Sprintf("%s/namespace/%s", cluster, ns.Name),
		Name:     ns.Name,
		Type:     "k8s_namespace",
		Provider: asset.ProviderKubernetes,
		Region:   cluster,
		Tags:     ns.Labels,
		Metadata: map[string]string{
			"phase":                    string(ns.Status.Phase),
			"has_network_policy":       fmt.Sprintf("%t", len(netpols) > 0),
			"has_default_deny_ingress": fmt.Sprintf("%t", slices.ContainsFunc(netpols, isDefaultDenyIngress)),
			// The Pod Security Admission level this namespace enforces; "" is the
			// observed absence of the label (the namespace object was read whole).
			"psa_enforce": ns.Labels["pod-security.kubernetes.io/enforce"],
		},
		DiscoveredAt: now, LastSeen: now,
	}
}

// isDefaultDenyIngress reports whether a NetworkPolicy denies all ingress to
// every pod in its namespace: it selects all pods (empty podSelector), covers
// Ingress, and allows nothing. policyTypes may be omitted, in which case the
// API server treats the policy as an Ingress policy.
func isDefaultDenyIngress(np networkingv1.NetworkPolicy) bool {
	sel := np.Spec.PodSelector
	if len(sel.MatchLabels) > 0 || len(sel.MatchExpressions) > 0 || len(np.Spec.Ingress) > 0 {
		return false
	}
	return len(np.Spec.PolicyTypes) == 0 || slices.Contains(np.Spec.PolicyTypes, networkingv1.PolicyTypeIngress)
}

// joinSelector renders a service's label selector as a stable, comma-joined
// "k=v" string so the K8sServiceTargets correlation rule can match it
// against workload labels without re-querying the cluster.
func joinSelector(sel map[string]string) string {
	if len(sel) == 0 {
		return ""
	}
	keys := make([]string, 0, len(sel))
	for k := range sel {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+sel[k])
	}
	return strings.Join(parts, ",")
}
