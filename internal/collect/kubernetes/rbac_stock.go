package kubernetes

// rbac_stock.go — the RBAC objects each Kubernetes distribution ships, as exact
// tables. rbac_platform.go decides what they suppress; this file only says what
// exists and where each entry comes from.
//
// Every table is pinned by a test: upstream and kube-up entries both ways
// against the vendored manifests under testdata/ (TestStockTablesMatchVendoredSources),
// kubeadm, EKS and GKE entries against the in-code fixtures in
// rbac_distro_test.go, which carry the public source of each object.
//
// Residual risk, accepted: a role baseline is per CATEGORY, not per rule, so
// a rule added within a category the role already holds (a second Secret for
// a role that reads Secrets by design, workload writes in another API group)
// is not reported. A per-rule superset check would flag every Kubernetes
// version that adds a harmless rule. Scope is the one exception tracked
// below the category: a scoped baseline never explains an unscoped grant.

// distro is the distribution a table entry comes from. Upstream entries apply
// to every cluster; the others only where the collector has positive evidence
// the cluster is that distribution (detectDistros).
type distro string

const (
	distroUpstream distro = "upstream"
	distroKubeadm  distro = "kubeadm"
	distroEKS      distro = "eks"
	distroGKE      distro = "gke"
)

// stockBinding is one binding a distribution ships. subjectSets lists every
// subject set a supported version ships it with (sorted at init).
type stockBinding struct {
	kind, namespace, name, roleKind, roleRef string
	subjectSets                              [][]string
}

func stockCRB(name, role string, subjects ...string) stockBinding {
	return stockBinding{kind: "ClusterRoleBinding", name: name, roleKind: "ClusterRole", roleRef: role, subjectSets: [][]string{subjects}}
}

func stockRB(namespace, name, roleKind, role string, subjects ...string) stockBinding {
	return stockBinding{kind: "RoleBinding", namespace: namespace, name: name, roleKind: roleKind, roleRef: role, subjectSets: [][]string{subjects}}
}

// stockRole is one role a distribution ships, with what its stock rules grant:
// the dangerous_perms_detail entries and the two wildcard flags exactly as
// clusterRoleAsset/roleAsset compute them over the stock rules. namespace is
// "" for a ClusterRole. A collected role granting anything beyond this is
// reclaimed (gradePlatformRole).
type stockRole struct {
	namespace, name          string
	wildVerbs, wildResources bool
	detail                   string
}

// upstreamControllers are the kube-controller-manager controllers that get a
// system:controller:<name> ClusterRole bound to ServiceAccount
// kube-system/<name> (controller-role-bindings.yaml).
var upstreamControllers = []string{
	"attachdetach-controller", "certificate-controller", "clusterrole-aggregation-controller", "cronjob-controller",
	"daemon-set-controller", "deployment-controller", "device-taint-eviction-controller", "disruption-controller",
	"endpoint-controller", "endpointslice-controller", "endpointslicemirroring-controller", "ephemeral-volume-controller",
	"expand-controller", "generic-garbage-collector", "horizontal-pod-autoscaler", "job-controller",
	"kube-apiserver-serving-clustertrustbundle-publisher", "legacy-service-account-token-cleaner",
	"namespace-controller", "node-controller", "persistent-volume-binder", "pod-garbage-collector",
	"podcertificaterequestcleaner", "pv-protection-controller", "pvc-protection-controller", "replicaset-controller",
	"replication-controller", "resource-claim-controller", "resourcequota-controller", "root-ca-cert-publisher",
	"route-controller", "selinux-warning-controller", "service-account-controller", "service-cidrs-controller",
	"service-controller", "statefulset-controller", "storage-version-migrator-controller",
	"ttl-after-finished-controller", "ttl-controller", "validatingadmissionpolicy-status-controller",
	"volumeattributesclass-protection-controller",
}

// Upstream bootstrap policy: kubernetes plugin/pkg/auth/authorizer/rbac/
// bootstrappolicy/testdata (vendored under testdata/bootstrappolicy).
var upstreamBindings = func() []stockBinding {
	t := []stockBinding{
		// cluster-role-bindings.yaml
		stockCRB("cluster-admin", "cluster-admin", subjGroup("system:masters")),
		stockCRB("system:basic-user", "system:basic-user", subjGroup("system:authenticated")),
		stockCRB("system:cluster-trust-bundle-discovery", "system:cluster-trust-bundle-discovery", subjGroup("system:serviceaccounts")),
		stockCRB("system:discovery", "system:discovery", subjGroup("system:authenticated")),
		stockCRB("system:kube-controller-manager", "system:kube-controller-manager", subjUser("system:kube-controller-manager")),
		stockCRB("system:kube-dns", "system:kube-dns", subjSA("kube-system", "kube-dns")),
		stockCRB("system:kube-scheduler", "system:kube-scheduler", subjUser("system:kube-scheduler")),
		stockCRB("system:monitoring", "system:monitoring", subjGroup("system:monitoring")),
		stockCRB("system:node-proxier", "system:node-proxier", subjUser("system:kube-proxy")),
		stockCRB("system:public-info-viewer", "system:public-info-viewer", subjGroup("system:authenticated"), subjGroup("system:unauthenticated")),
		stockCRB("system:service-account-issuer-discovery", "system:service-account-issuer-discovery", subjGroup("system:serviceaccounts")),
		stockCRB("system:volume-scheduler", "system:volume-scheduler", subjUser("system:kube-scheduler")),
		// system:node ships with no subjects (the Node authorizer handles
		// kubelets); clusters upgraded from before 1.8 may still carry the old
		// Group system:nodes subject.
		{kind: "ClusterRoleBinding", name: "system:node", roleKind: "ClusterRole", roleRef: "system:node",
			subjectSets: [][]string{{}, {subjGroup("system:nodes")}}},

		// namespace-role-bindings.yaml
		stockRB("kube-public", "system:controller:bootstrap-signer", "Role", "system:controller:bootstrap-signer", subjSA("kube-system", "bootstrap-signer")),
		stockRB("kube-system", "system::extension-apiserver-authentication-reader", "Role", "extension-apiserver-authentication-reader",
			subjUser("system:kube-controller-manager"), subjUser("system:kube-scheduler")),
		stockRB("kube-system", "system::leader-locking-kube-controller-manager", "Role", "system::leader-locking-kube-controller-manager",
			subjUser("system:kube-controller-manager"), subjSA("kube-system", "kube-controller-manager"),
			subjSA("kube-system", "leader-election-controller")),
		stockRB("kube-system", "system::leader-locking-kube-scheduler", "Role", "system::leader-locking-kube-scheduler",
			subjUser("system:kube-scheduler"), subjSA("kube-system", "kube-scheduler")),
		stockRB("kube-system", "system:controller:bootstrap-signer", "Role", "system:controller:bootstrap-signer", subjSA("kube-system", "bootstrap-signer")),
		stockRB("kube-system", "system:controller:cloud-provider", "Role", "system:controller:cloud-provider", subjSA("kube-system", "cloud-provider")),
		stockRB("kube-system", "system:controller:token-cleaner", "Role", "system:controller:token-cleaner", subjSA("kube-system", "token-cleaner")),
	}
	// controller-role-bindings.yaml
	for _, c := range upstreamControllers {
		t = append(t, stockCRB("system:controller:"+c, "system:controller:"+c, subjSA("kube-system", c)))
	}
	return t
}()

// upstreamRoles: cluster-roles.yaml, controller-roles.yaml (admin, edit and
// view as the aggregation controller fills them), namespace-roles.yaml.
var upstreamRoles = []stockRole{
	{"", "admin", false, false, "pod-create,pod-exec,rbac-escalate,secrets-read,secrets-write,token-mint,workload-create"},
	{"", "cluster-admin", true, true, "admission-webhook,csr-approve,host-mount,node-proxy,pod-create,pod-exec,rbac-escalate,secrets-read,secrets-write,token-mint,workload-create"},
	{"", "edit", false, false, "pod-create,pod-exec,rbac-escalate,secrets-read,secrets-write,token-mint,workload-create"},
	{"", "system:aggregate-to-admin", false, false, "rbac-escalate"},
	{"", "system:aggregate-to-edit", false, false, "pod-create,pod-exec,rbac-escalate,secrets-read,secrets-write,token-mint,workload-create"},
	{"", "system:aggregate-to-view", false, false, ""},
	{"", "system:auth-delegator", false, false, ""},
	{"", "system:basic-user", false, false, ""},
	{"", "system:certificates.k8s.io:certificatesigningrequests:nodeclient", false, false, ""},
	{"", "system:certificates.k8s.io:certificatesigningrequests:selfnodeclient", false, false, ""},
	{"", "system:certificates.k8s.io:kube-apiserver-client-approver", false, false, "csr-approve(scoped)"},
	{"", "system:certificates.k8s.io:kube-apiserver-client-kubelet-approver", false, false, "csr-approve(scoped)"},
	{"", "system:certificates.k8s.io:kubelet-serving-approver", false, false, "csr-approve(scoped)"},
	{"", "system:certificates.k8s.io:legacy-unknown-approver", false, false, "csr-approve(scoped)"},
	{"", "system:cluster-trust-bundle-discovery", false, false, ""},
	{"", "system:controller:attachdetach-controller", false, false, ""},
	{"", "system:controller:certificate-controller", false, false, "csr-approve,csr-approve(scoped)"},
	{"", "system:controller:clusterrole-aggregation-controller", false, false, "rbac-escalate"},
	{"", "system:controller:cronjob-controller", false, false, "workload-create"},
	{"", "system:controller:daemon-set-controller", false, false, "pod-create"},
	{"", "system:controller:deployment-controller", false, false, "workload-create"},
	{"", "system:controller:device-taint-eviction-controller", false, false, ""},
	{"", "system:controller:disruption-controller", false, true, ""},
	{"", "system:controller:endpoint-controller", false, false, ""},
	{"", "system:controller:endpointslice-controller", false, false, ""},
	{"", "system:controller:endpointslicemirroring-controller", false, false, ""},
	{"", "system:controller:ephemeral-volume-controller", false, false, ""},
	{"", "system:controller:expand-controller", false, false, ""},
	{"", "system:controller:generic-garbage-collector", false, true, "admission-webhook,csr-approve,node-proxy,pod-exec,rbac-escalate,secrets-read,secrets-write,workload-create"},
	{"", "system:controller:horizontal-pod-autoscaler", false, true, ""},
	{"", "system:controller:job-controller", false, false, "pod-create,workload-create"},
	{"", "system:controller:kube-apiserver-serving-clustertrustbundle-publisher", false, false, ""},
	{"", "system:controller:legacy-service-account-token-cleaner", false, false, "secrets-write"},
	{"", "system:controller:namespace-controller", false, true, "admission-webhook,csr-approve,node-proxy,pod-exec,rbac-escalate,secrets-read,secrets-write"},
	{"", "system:controller:node-controller", false, false, ""},
	{"", "system:controller:persistent-volume-binder", false, false, "host-mount,pod-create"},
	{"", "system:controller:pod-garbage-collector", false, false, ""},
	{"", "system:controller:podcertificaterequestcleaner", false, false, ""},
	{"", "system:controller:pv-protection-controller", false, false, ""},
	{"", "system:controller:pvc-protection-controller", false, false, ""},
	{"", "system:controller:replicaset-controller", false, false, "pod-create,workload-create"},
	{"", "system:controller:replication-controller", false, false, "pod-create"},
	{"", "system:controller:resource-claim-controller", false, false, ""},
	{"", "system:controller:resourcequota-controller", false, true, "secrets-read"},
	{"", "system:controller:root-ca-cert-publisher", false, false, ""},
	{"", "system:controller:route-controller", false, false, ""},
	{"", "system:controller:selinux-warning-controller", false, false, ""},
	{"", "system:controller:service-account-controller", false, false, ""},
	{"", "system:controller:service-cidrs-controller", false, false, ""},
	{"", "system:controller:service-controller", false, false, ""},
	{"", "system:controller:statefulset-controller", false, false, "pod-create"},
	{"", "system:controller:storage-version-migrator-controller", false, true, "admission-webhook,csr-approve,rbac-escalate,secrets-read,secrets-write,workload-create"},
	{"", "system:controller:ttl-after-finished-controller", false, false, ""},
	{"", "system:controller:ttl-controller", false, false, ""},
	{"", "system:controller:validatingadmissionpolicy-status-controller", false, false, ""},
	{"", "system:controller:volumeattributesclass-protection-controller", false, false, ""},
	{"", "system:discovery", false, false, ""},
	{"", "system:heapster", false, false, ""},
	{"", "system:kube-aggregator", false, false, ""},
	{"", "system:kube-controller-manager", false, true, "secrets-read,secrets-write,token-mint"},
	{"", "system:kube-dns", false, false, ""},
	{"", "system:kube-scheduler", false, false, ""},
	{"", "system:kubelet-api-admin", true, false, "node-proxy"},
	{"", "system:monitoring", false, false, ""},
	{"", "system:node", false, false, "pod-create,secrets-read,token-mint"},
	{"", "system:node-bootstrapper", false, false, ""},
	{"", "system:node-problem-detector", false, false, ""},
	{"", "system:node-proxier", false, false, ""},
	{"", "system:persistent-volume-provisioner", false, false, "host-mount"},
	{"", "system:public-info-viewer", false, false, ""},
	{"", "system:service-account-issuer-discovery", false, false, ""},
	{"", "system:volume-scheduler", false, false, ""},
	{"", "view", false, false, ""},
	{"kube-public", "system:controller:bootstrap-signer", false, false, ""},
	{"kube-system", "extension-apiserver-authentication-reader", false, false, ""},
	{"kube-system", "system::leader-locking-kube-controller-manager", false, false, ""},
	{"kube-system", "system::leader-locking-kube-scheduler", false, false, ""},
	{"kube-system", "system:controller:bootstrap-signer", false, false, "secrets-read"},
	{"kube-system", "system:controller:cloud-provider", false, false, ""},
	{"kube-system", "system:controller:token-cleaner", false, false, "secrets-read,secrets-write"},
}

const kubeadmNodeToken = "system:bootstrappers:kubeadm:default-node-token"

// kubeadm: cmd/kubeadm/app/constants/constants.go and the init phases that
// create these (bootstraptoken/clusterinfo, bootstraptoken/node, kubelet,
// uploadconfig, addons/proxy, addons/dns, kubeconfig).
var kubeadmBindings = []stockBinding{
	stockCRB("kubeadm:cluster-admins", "cluster-admin", subjGroup("kubeadm:cluster-admins")),
	stockCRB("kubeadm:kubelet-bootstrap", "system:node-bootstrapper", subjGroup(kubeadmNodeToken)),
	stockCRB("kubeadm:node-autoapprove-bootstrap", "system:certificates.k8s.io:certificatesigningrequests:nodeclient", subjGroup(kubeadmNodeToken)),
	stockCRB("kubeadm:node-autoapprove-certificate-rotation", "system:certificates.k8s.io:certificatesigningrequests:selfnodeclient", subjGroup("system:nodes")),
	stockCRB("kubeadm:get-nodes", "kubeadm:get-nodes", subjGroup(kubeadmNodeToken)),
	stockCRB("kubeadm:node-proxier", "system:node-proxier", subjSA("kube-system", "kube-proxy")),
	stockCRB("kubeadm:apiserver-kubelet-client", "system:kubelet-api-admin", subjUser("kube-apiserver-kubelet-client")),
	stockCRB("system:coredns", "system:coredns", subjSA("kube-system", "coredns")),
	stockRB("kube-system", "kubeadm:kubelet-config", "Role", "kubeadm:kubelet-config", subjGroup("system:nodes"), subjGroup(kubeadmNodeToken)),
	stockRB("kube-system", "kubeadm:nodes-kubeadm-config", "Role", "kubeadm:nodes-kubeadm-config", subjGroup(kubeadmNodeToken), subjGroup("system:nodes")),
	stockRB("kube-system", "kube-proxy", "Role", "kube-proxy", subjGroup(kubeadmNodeToken)),
	stockRB("kube-system", "kubeadm:kubeadm-certs", "Role", "kubeadm:kubeadm-certs", subjGroup(kubeadmNodeToken)),
	stockRB("kube-public", "kubeadm:bootstrap-signer-clusterinfo", "Role", "kubeadm:bootstrap-signer-clusterinfo", subjUser("system:anonymous")),
}

var kubeadmRoles = []stockRole{
	{"", "kubeadm:get-nodes", false, false, ""},
	{"", "system:coredns", false, false, ""},
	{"kube-public", "kubeadm:bootstrap-signer-clusterinfo", false, false, ""},
	{"kube-system", "kube-proxy", false, false, ""},
	{"kube-system", "kubeadm:kubeadm-certs", false, false, "secrets-read(scoped)"},
	{"kube-system", "kubeadm:kubelet-config", false, false, ""},
	{"kube-system", "kubeadm:nodes-kubeadm-config", false, false, ""},
}

// EKS. Confirmed from public sources:
//   - docs.aws.amazon.com/eks/latest/userguide/default-roles-users.html:
//     eks:k8s-metrics (rules and subjects verbatim), aws-node,
//     vpc-resource-controller-role and vpc-resource-controller-rolebinding;
//   - .../eks-add-ons.html: eks:addon-cluster-admin binds cluster-admin to
//     eks:addon-manager;
//   - AWS knowledge center eks-troubleshoot-kubectl-commands: eks:node-bootstrapper
//     to Groups system:bootstrappers and system:nodes;
//   - the aws-vpc-cni chart (aws-node rules) and the aws-ebs-csi-driver chart
//     (ebs-external-provisioner-role, ServiceAccount ebs-csi-controller-sa).
//
// UNCONFIRMED (observed on a live EKS cluster, no public listing found): the
// exact subject set of vpc-resource-controller-rolebinding (the
// eks:vpc-resource-controller user itself is named in the
// amazon-vpc-resource-controller-k8s docs), every
// eks:certificate-controller*, eks:addon-manager, eks:cloud-controller-manager,
// eks:node-manager and eks:kube-proxy* tuple, and the rules behind the
// baselines of eks:certificate-controller-approver, eks:addon-manager,
// eks:cloud-controller-manager, eks:node-manager and vpc-resource-controller-role.
// A real role granting more than its baseline here reports; that is the safe
// direction to be wrong in.
var eksBindings = []stockBinding{
	stockCRB("eks:k8s-metrics", "eks:k8s-metrics", subjUser("eks:k8s-metrics")),
	stockRB("kube-system", "eks:k8s-metrics", "Role", "eks:k8s-metrics", subjUser("eks:k8s-metrics")),
	stockCRB("aws-node", "aws-node", subjSA("kube-system", "aws-node")),
	stockCRB("vpc-resource-controller-rolebinding", "vpc-resource-controller-role", subjUser("eks:vpc-resource-controller")),
	stockCRB("eks:addon-cluster-admin", "cluster-admin", subjUser("eks:addon-manager")),
	stockCRB("eks:node-bootstrapper", "eks:node-bootstrapper", subjGroup("system:bootstrappers"), subjGroup("system:nodes")),
	stockCRB("ebs-csi-provisioner-binding", "ebs-external-provisioner-role", subjSA("kube-system", "ebs-csi-controller-sa")),
	stockCRB("eks:certificate-controller", "system:controller:certificate-controller", subjUser("eks:certificate-controller")),
	stockCRB("eks:certificate-controller-approver", "eks:certificate-controller-approver", subjUser("eks:certificate-controller-approver")),
	stockCRB("eks:addon-manager", "eks:addon-manager", subjUser("eks:addon-manager")),
	stockCRB("eks:cloud-controller-manager", "eks:cloud-controller-manager", subjUser("eks:cloud-controller-manager")),
	stockCRB("eks:node-manager", "eks:node-manager", subjUser("eks:node-manager")),
	stockCRB("eks:kube-proxy", "system:node-proxier", subjSA("kube-system", "kube-proxy")),
	stockCRB("eks:kube-proxy-fargate", "system:node-proxier", subjGroup("system:node-proxier")),
	stockCRB("eks:kube-proxy-windows", "system:node-proxier", subjGroup("eks:kube-proxy-windows")),
}

var eksRoles = []stockRole{
	{"", "aws-node", false, false, ""},
	{"", "ebs-external-provisioner-role", false, false, "host-mount"},
	{"", "eks:addon-manager", false, false, "rbac-escalate,workload-create"},
	{"", "eks:certificate-controller-approver", false, false, "csr-approve"},
	{"", "eks:cloud-controller-manager", false, false, ""},
	{"", "eks:k8s-metrics", false, false, ""},
	{"", "eks:node-bootstrapper", false, false, ""},
	{"", "eks:node-manager", false, false, ""},
	{"", "vpc-resource-controller-role", false, false, ""},
	{"kube-system", "eks:k8s-metrics", false, false, ""},
}

// GKE lineage, vendored: kubernetes cluster/addons (kube-up) and
// cluster/gce/addons (testdata/kubeup).
var kubeupBindings = []stockBinding{
	stockCRB("system:cloud-controller-manager", "system:cloud-controller-manager", subjUser("system:cloud-controller-manager")),
	stockCRB("system:controller:cloud-node-controller", "system:controller:cloud-node-controller", subjSA("kube-system", "cloud-node-controller")),
	stockRB("kube-system", "system::leader-locking-cloud-controller-manager", "Role", "system::leader-locking-cloud-controller-manager",
		subjSA("kube-system", "cloud-controller-manager")),
	stockCRB("system:controller:glbc", "system:controller:glbc", subjUser("system:controller:glbc")),
	stockRB("kube-system", "system:controller:glbc", "Role", "system:controller:glbc", subjUser("system:controller:glbc")),
	stockCRB("kube-apiserver-kubelet-api-admin", "kubelet-api-admin", subjUser("kube-apiserver")),
	stockCRB("kubelet-cluster-admin", "system:node", subjUser("kubelet")),
	stockCRB("gce:beta:kubelet-certificate-bootstrap", "gce:beta:kubelet-certificate-bootstrap", subjUser("kubelet")),
	stockCRB("gce:beta:kubelet-certificate-rotation", "gce:beta:kubelet-certificate-rotation", subjGroup("system:nodes")),
	stockCRB("stackdriver:metadata-agent", "stackdriver:metadata-agent", subjSA("kube-system", "metadata-agent")),
	stockCRB("event-exporter-rb", "view", subjSA("kube-system", "event-exporter-sa")),
	stockCRB("metrics-server:system:auth-delegator", "system:auth-delegator", subjSA("kube-system", "metrics-server")),
	stockRB("kube-system", "metrics-server-auth-reader", "Role", "extension-apiserver-authentication-reader", subjSA("kube-system", "metrics-server")),
	stockCRB("system:metrics-server", "system:metrics-server", subjSA("kube-system", "metrics-server")),
	stockCRB("system:konnectivity-server", "system:auth-delegator", subjUser("system:konnectivity-server")),
}

var kubeupRoles = []stockRole{
	{"", "gce:beta:kubelet-certificate-bootstrap", false, false, ""},
	{"", "gce:beta:kubelet-certificate-rotation", false, false, ""},
	{"", "kubelet-api-admin", true, false, "node-proxy"},
	{"", "stackdriver:metadata-agent", false, true, "node-proxy,pod-exec,secrets-read"},
	{"", "system:cloud-controller-manager", false, true, "secrets-read,secrets-write,token-mint"},
	{"", "system:controller:cloud-node-controller", false, false, ""},
	{"", "system:controller:glbc", false, false, "secrets-read"},
	{"", "system:controller:pvl-controller", false, false, ""},
	{"", "system:metrics-server", false, false, "workload-create(scoped)"},
	{"kube-system", "system::leader-locking-cloud-controller-manager", false, false, ""},
	{"kube-system", "system:cloud-controller-manager", false, false, ""},
	{"kube-system", "system:controller:glbc", false, false, ""},
}

// GKE objects with no public manifest. UNCONFIRMED: observed on a live GKE
// cluster; the subjects are as observed and the rules behind the
// system:gcp-controller-manager and gke-metadata-server baselines are the
// documented job of each component (CSR approval; minting Workload Identity
// tokens), not a published rule list.
var gkeBindings = []stockBinding{
	stockCRB("system:gcp-controller-manager", "system:gcp-controller-manager", subjUser("system:gcp-controller-manager")),
	stockCRB("gke-metadata-server", "gke-metadata-server", subjSA("kube-system", "gke-metadata-server")),
	stockCRB("kubelet-bootstrap", "system:node-bootstrapper", subjUser("kubelet")),
}

var gkeRoles = []stockRole{
	{"", "gke-metadata-server", false, false, "token-mint"},
	{"", "system:gcp-controller-manager", false, false, "csr-approve"},
}

// stockSource is one table pair and the distribution it belongs to.
type stockSource struct {
	distro   distro
	bindings []stockBinding
	roles    []stockRole
}

var stockSources = []stockSource{
	{distroUpstream, upstreamBindings, upstreamRoles},
	{distroKubeadm, kubeadmBindings, kubeadmRoles},
	{distroEKS, eksBindings, eksRoles},
	{distroGKE, kubeupBindings, kubeupRoles},
	{distroGKE, gkeBindings, gkeRoles},
}
