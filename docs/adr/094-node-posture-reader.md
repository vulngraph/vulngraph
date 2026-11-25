# ADR 094 — Kubernetes control-plane flags from mirror pods, node posture from an opt-in reader

**Status:** accepted (2026-10-12)

## Context

CIS Kubernetes 2.0.1 had 59 missing controls and 35 marked not_applicable. CIS EKS 1.8.0
had 17 missing. Most of them need one of these:

- Control-plane flags (1.2–1.4 and 2.x). These are the command lines of kube-apiserver,
  kube-controller-manager, kube-scheduler and etcd.
- Kubelet configuration (4.2.x and EKS 3.2.x).
- Mode and owner of node files (1.1.x, 4.1.x and EKS/GKE 3.1.x).

The Kubernetes API publishes the kubelet configuration only through
`nodes/proxy/configz`. Vulngraph's own RBAC checks flag a `nodes/proxy` grant as dangerous,
because it gives exec on every node. The API does not publish file stats at all.

## Decision

**1. Use data the API already shows, and grant no new privilege.** A self-managed control
plane (kubeadm, or any distribution built the same way) runs as static pods. The kubelet
mirrors each one into kube-system with the label `component=<name>` (kubeadm's
`staticpod.ComponentPod`) and the annotation `kubernetes.io/config.mirror`. The mirror pod
carries the full command line, and the collector already lists these pods.

- The collector turns each component's flags into **effective** settings and applies the
  upstream v1.30 default when a flag is absent. It also reads `ETCD_*` variables for etcd.
- It records the settings on the cluster's single `k8s_cluster` asset, where one check
  per control evaluates them.
- When replicas disagree, every distinct value is kept, joined with `|`. A check fires if
  any replica fails. A control plane has one configuration, so that is one finding per
  cluster, not one per replica.
- A setting is left **unknown** (key omitted) in four cases: there is no mirror pod
  (managed control planes); a replica's command is not the binary called directly; a
  config file can override the flag (`--authorization-config`, `--authentication-config`,
  etcd `--config-file`, or any scheduler `--config`: the scheduler then ignores
  `--profiling`); or a value does not parse (a non-integer retention value is omitted, not
  skipped). A check never reads unknown as clean. `--audit-log-path -` (stdout) meets
  1.2.16, and the rotation checks step aside for it.
- kube-proxy's metrics bind address (4.3.1), and whether its kubeconfig is a node file at
  all (4.1.3/4.1.4), come from its pods and from the ConfigMap that its `--config` file is
  mounted from. Under `--config` the file wins over `--metrics-bind-address` and
  `--kubeconfig`.
- The managed matrices (EKS, GKE) keep the control-plane rows they never listed.

**2. Node data comes from an opt-in reader, `graph node-posture`.** It runs from the graph
image, so there is no new image supply chain. The Helm chart ships it disabled, as two
DaemonSets: one on every node, and one on control-plane nodes.

- The reader stats, and for a few files reads, exactly the paths that its read-only
  hostPath mounts provide. It prints one JSON document per interval to stdout.
- It runs as its own ServiceAccount (`nodePosture.serviceAccountName`, default
  `graph-node-posture`) with no RBAC and no service-account token
  (`automountServiceAccountToken: false`).
- It has no network. A NetworkPolicy allows no ingress and no egress, which is stricter
  than "egress to graph only".
- The worker reads the document back through **`pods/log` get in graph's own namespace**.
  This is a namespaced Role, and it is the only RBAC the reader adds. RBAC cannot narrow
  it by label, so it covers the logs of every pod in that namespace. It is bound to the
  worker's ServiceAccount only; serve mounts no API token and the scanner runs as its
  own ServiceAccount without one. Install graph in a dedicated namespace when the
  reader is enabled.
- The collector keys each report by the pod's `spec.nodeName`, which is the API server's
  record of where the pod runs, not a claim the pod makes. It reads only pods that the
  graph-labelled DaemonSet owns, in graph's own namespace.

We considered two other ways to get the reports out, and rejected both.

- *Vulngraph's API with a scoped token* would need a new credential type, an endpoint and
  storage. Each reader would also hold a credential and need egress.
- *A ConfigMap the reader writes* would need ConfigMap create in graph's namespace. Create
  cannot be limited by `resourceNames`, so a compromised reader could plant objects there.

The pod-log channel gives the reader nothing at all. Spoofing a report takes pod create in
graph's namespace, and that permission can already mount graph's own token. A compromised
NODE is different: it controls its own reader pod's filesystem view and log, so it can
report anything about itself. Node posture is the node's self-report, like any host agent's;
it grades configuration drift, not a node an attacker already owns.

Reports are decoded leniently (unknown fields ignored, not `DisallowUnknownFields`): a
reader one release ahead may add a field, and rejecting it would blind every node until the
worker is upgraded. The `graph_node_posture` version marker is what gates an incompatible
change, and every role the collector interprets is validated on its own.

**Least privilege inside the pod.** Each mount goes into exactly one container.

- The `kubelet` container runs as uid 0 with **every capability dropped**. A CIS-compliant
  kubelet config is mode 600 root:root, and a non-root reader would see it as unknown on
  exactly the clusters that pass 4.1.9. Without `CAP_DAC_OVERRIDE`, uid 0 is held to mode
  bits like any other user, but it owns every root file it can reach. So this container gets
  only single `type: File` mounts of kubelet configuration and flag files, never a directory
  (a directory such as `/etc/default` also holds root-owned files like docker's proxy
  credentials) and never a credential. A chart test pins its host paths.
- The `files` container runs as uid 65532: it stats, and reads only world-readable files
  (`/etc/default/kubelet`, the kubelet `--config-dir` drop-ins, passwd/group). AKS's
  `azure.json`, which holds the service principal's secret, is only stat'ed. A directory mount, such as
  `/etc/kubernetes`, lets it stat a 600 key without being able to read it. A single-file
  mount lets it stat a file inside a 700 directory, such as the static-pod manifests.
- Both containers use a read-only root filesystem, `allowPrivilegeEscalation: false`, the
  RuntimeDefault seccomp profile, no host namespaces and no `*OrCreate` hostPath types. The
  reader never writes to the host.
- The reader does not mount the EncryptionConfiguration, because it holds the keys. So 1.2.28
  is manual: a review on a control-plane host.
- The release namespace must allow hostPath (Pod Security privileged level). Vulngraph's own
  hostPath and run-as-root checks report the reader, and that is accepted.

**How a report becomes a setting.** For each node the collector derives two things:

- the effective kubelet settings: the config file, merged with its `--config-dir` drop-ins
  (`*.conf`, name order, objects field by field, as the kubelet merges them; bounded, and
  unread drop-ins make the kubelet unknown), with flags from the configured environment and
  unit files layered on top, and the KubeletConfiguration v1beta1 defaults, including the
  kubelet's own defaulting of `0s` durations;
- file stats: the permission union over a directory, and the owner as names resolved
  through the node's passwd and group files.

It merges nodes the same way as replicas. A DaemonSet that does not report from **every**
node it is scheduled on contributes nothing: an unreported node could be the failing one.
The coverage counts land on the cluster asset as evidence. Without the reader, every node
control is unknown and never passes. kube-bench (Apache-2.0) was prior art for the paths
and conditions; none of its code is used.

**3. One check per control, file mode and owner together.** A chmod and a chown on the same
file are one fix. So one check covers both CIS rows for that file. File-mode limits follow
the benchmark that governs the cluster: 600 under CIS Kubernetes, and 644 on EKS and GKE
(`cloud_provider`). Severity follows the posture rule: logging and hygiene are Low, and
credential exposure is Medium or High.

**4. An installed policy engine is not evidence (5.2.1).** Kyverno and Gatekeeper run their
webhooks with zero, Audit-only or unrelated policies. An unlabelled namespace steps aside only
where enforcement is proven: a Kyverno `validate.podSecurity` rule in Enforce, or a
Gatekeeper pod-security-library constraint in deny, matching Pods there. The chart grants a
list-only ClusterRole (`graph-policy-engine-reader`, named resources, no wildcards) for those
reads. An engine without that proof, or a forbidden read, grades the namespace Info; an
explicit privileged label is always Low. ValidatingAdmissionPolicies are not counted: whether
CEL enforces pod security cannot be decided from its text.

**5. Node-role grants are graded on the role.** EKS node-role ECR push is one finding per IAM
role (the collector joins node facts onto the role), not one per instance.

## Consequences

- CIS Kubernetes goes from 13 covered, 17 partial and 59 missing to 119 covered, 2 partial
  and 10 manual, with 81 new checks across CIS Kubernetes, EKS and AKS. The node
  rows are covered only while the reader is deployed. Without it, they are honestly
  unknown.
- The kubelet's live command line is not read, because that needs hostPID. A flag set
  outside the configured flag sources is missed. The chart lists each distribution's
  sources.
- On a cluster that is not kubeadm, the control-plane flags are unknown unless the
  distribution also uses mirror pods. Self-managed control planes that run under systemd
  stay unknown.
