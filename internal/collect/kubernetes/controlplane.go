package kubernetes

import (
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
)

// controlplane.go reads the control-plane configuration a self-managed cluster
// publishes through the API (ADR 094). kubeadm, and distributions built like it,
// run kube-apiserver, kube-controller-manager, kube-scheduler and etcd as static
// pods; the kubelet mirrors each into kube-system, labelled component=<name>
// (kubeadm's staticpod.ComponentPod) and annotated kubernetes.io/config.mirror.
// The mirror pod carries the full command line, so the CIS 1.2-1.4 and 2.x flag
// controls are evaluable from the pod list the collector already makes.
//
// The collector normalises each component's flags into EFFECTIVE settings,
// applying the upstream default when a flag is absent (v1.30 defaults), exactly
// as pods.go resolves allowPrivilegeEscalation's default. Grading stays in the
// checks package.
//
// Keys land on the k8s_cluster asset, one per setting: a cluster has one
// control-plane configuration, so a flag misconfigured on three API-server
// replicas is one root cause and one finding. Replicas that disagree (a rolling
// change) keep every distinct value, sorted and joined with "|", so the checks
// fire when ANY replica fails. A setting is omitted — unknown — when no mirror
// pod exists (managed control planes), when a replica's command line cannot be
// parsed, or when a config file the flags point at can override it.

// controlPlaneComponents maps a static-pod component name to its key prefix.
var controlPlaneComponents = map[string]string{
	"kube-apiserver":          "apiserver",
	"kube-controller-manager": "controller_manager",
	"kube-scheduler":          "scheduler",
	"etcd":                    "etcd",
}

// mirrorPodAnnotation is set by the kubelet on the API object of a static pod.
const mirrorPodAnnotation = "kubernetes.io/config.mirror"

// defaultAdmissionPlugins is kube-apiserver's default-on admission set
// (pkg/kubeapiserver/options/plugins.go DefaultOffAdmissionPlugins, v1.30).
var defaultAdmissionPlugins = []string{
	"CertificateApproval", "CertificateSigning", "CertificateSubjectRestriction",
	"ClusterTrustBundleAttest", "DefaultIngressClass", "DefaultStorageClass",
	"DefaultTolerationSeconds", "LimitRanger", "MutatingAdmissionWebhook",
	"NamespaceLifecycle", "PersistentVolumeClaimResize", "PodSecurity", "Priority",
	"ResourceQuota", "RuntimeClass", "ServiceAccount", "StorageObjectInUseProtection",
	"TaintNodesByCondition", "ValidatingAdmissionPolicy", "ValidatingAdmissionWebhook",
}

// controlPlaneSignals returns the k8s_cluster metadata derived from the
// control-plane mirror pods among kube-system's pods. Empty when there are none.
func controlPlaneSignals(pods []corev1.Pod) map[string]string {
	replicas := map[string][]map[string]string{} // component → per-replica settings
	broken := map[string]bool{}
	for _, pod := range pods {
		component, ok := controlPlaneComponent(pod)
		if !ok {
			continue
		}
		flags, ok := componentFlags(pod, component)
		if !ok {
			broken[component] = true
			continue
		}
		replicas[component] = append(replicas[component], effectiveSettings(component, flags))
	}
	out := map[string]string{}
	for component, sets := range replicas {
		if broken[component] {
			continue // one unreadable replica could be the failing one
		}
		prefix := controlPlaneComponents[component]
		out[prefix+"_replicas"] = strconv.Itoa(len(sets))
		for key, value := range mergeReplicaSettings(sets) {
			out[prefix+"_"+key] = value
		}
	}
	return out
}

// controlPlaneComponent identifies a control-plane mirror pod.
func controlPlaneComponent(pod corev1.Pod) (string, bool) {
	if pod.Namespace != "kube-system" {
		return "", false
	}
	if _, mirror := pod.Annotations[mirrorPodAnnotation]; !mirror {
		return "", false
	}
	component := pod.Labels["component"]
	_, ok := controlPlaneComponents[component]
	return component, ok
}

// componentFlags parses the component container's command line into a
// flag→value map. ok=false when the container is missing or the command is not
// the component binary invoked directly (a shell wrapper hides the flags).
func componentFlags(pod corev1.Pod, component string) (map[string]string, bool) {
	idx := slices.IndexFunc(pod.Spec.Containers, func(c corev1.Container) bool { return c.Name == component })
	if idx < 0 {
		return nil, false
	}
	c := pod.Spec.Containers[idx]
	argv := append(append([]string(nil), c.Command...), c.Args...)
	if len(argv) == 0 || path.Base(argv[0]) != component {
		return nil, false
	}
	flags := map[string]string{}
	if component == "etcd" {
		// etcd also reads ETCD_<FLAG> environment variables; a flag wins.
		for _, e := range c.Env {
			if name, found := strings.CutPrefix(e.Name, "ETCD_"); found && e.ValueFrom == nil {
				flags[strings.ToLower(strings.ReplaceAll(name, "_", "-"))] = e.Value
			}
		}
	}
	rest := argv[1:]
	for i := 0; i < len(rest); i++ {
		name, found := strings.CutPrefix(rest[i], "--")
		if !found {
			return nil, false // a positional argument: not a shape we understand
		}
		if k, v, eq := strings.Cut(name, "="); eq {
			flags[k] = v
			continue
		}
		if i+1 < len(rest) && (!strings.HasPrefix(rest[i+1], "-") || rest[i+1] == "-") {
			flags[name] = rest[i+1]
			i++
			continue
		}
		flags[name] = "true"
	}
	return flags, true
}

// mergeReplicaSettings keeps a setting only when every replica reported it, and
// joins the distinct values.
func mergeReplicaSettings(sets []map[string]string) map[string]string {
	out := map[string]string{}
	for key := range sets[0] {
		var values []string
		known := true
		for _, s := range sets {
			v, ok := s[key]
			if !ok {
				known = false
				break
			}
			if !slices.Contains(values, v) {
				values = append(values, v)
			}
		}
		if known {
			sort.Strings(values)
			out[key] = strings.Join(values, "|")
		}
	}
	return out
}

// settingReader resolves flags to effective values. A key it cannot resolve is
// simply not written.
type settingReader struct {
	flags map[string]string
	out   map[string]string
}

// boolean writes a bool flag's effective value; an unparseable value is unknown.
func (r settingReader) boolean(key, flag string, def bool) {
	v, ok := r.flags[flag]
	if !ok {
		r.out[key] = strconv.FormatBool(def)
		return
	}
	if b, err := strconv.ParseBool(v); err == nil {
		r.out[key] = strconv.FormatBool(b)
	}
}

// value writes a flag's value, or def when absent.
func (r settingReader) value(key, flag, def string) {
	if v, ok := r.flags[flag]; ok {
		r.out[key] = v
		return
	}
	r.out[key] = def
}

// integer writes an integer flag's value, or def when absent. A value that is
// not an integer is unknown: the checks compare numbers, and a garbage value
// they skip would read as compliant.
func (r settingReader) integer(key, flag, def string) {
	v, ok := r.flags[flag]
	if !ok {
		r.out[key] = def
		return
	}
	if _, err := strconv.Atoi(v); err == nil {
		r.out[key] = v
	}
}

// set writes whether every named flag has a non-empty value.
func (r settingReader) set(key string, flags ...string) {
	all := true
	for _, f := range flags {
		if r.flags[f] == "" {
			all = false
		}
	}
	r.out[key] = strconv.FormatBool(all)
}

func effectiveSettings(component string, flags map[string]string) map[string]string {
	r := settingReader{flags: flags, out: map[string]string{}}
	switch component {
	case "kube-apiserver":
		apiserverSettings(r)
	case "kube-controller-manager":
		r.set("terminated_pod_gc_threshold_set", "terminated-pod-gc-threshold")
		r.boolean("profiling", "profiling", true)
		r.boolean("use_service_account_credentials", "use-service-account-credentials", false)
		r.set("service_account_private_key_file_set", "service-account-private-key-file")
		r.set("root_ca_file_set", "root-ca-file")
		r.out["rotate_kubelet_server_certificate"] = strconv.FormatBool(featureGate(flags["feature-gates"], "RotateKubeletServerCertificate") != "false")
		r.value("bind_address", "bind-address", "0.0.0.0")
	case "kube-scheduler":
		// With --config, kube-scheduler ignores --profiling (v1.30 flag docs:
		// "ignored if a config file is specified") and reads enableProfiling
		// from the KubeSchedulerConfiguration file, which the API does not show.
		// --bind-address is a secure-serving flag the file cannot set.
		if _, cfg := flags["config"]; !cfg {
			r.boolean("profiling", "profiling", true)
		}
		r.value("bind_address", "bind-address", "0.0.0.0")
	case "etcd":
		if _, cfg := flags["config-file"]; cfg {
			return r.out // the config file overrides every flag
		}
		r.set("client_tls_set", "cert-file", "key-file")
		r.boolean("client_cert_auth", "client-cert-auth", false)
		r.boolean("auto_tls", "auto-tls", false)
		r.set("peer_tls_set", "peer-cert-file", "peer-key-file")
		r.boolean("peer_client_cert_auth", "peer-client-cert-auth", false)
		r.boolean("peer_auto_tls", "peer-auto-tls", false)
	}
	return r.out
}

func apiserverSettings(r settingReader) {
	flags := r.flags
	// --authentication-config (structured authentication) can enable anonymous
	// access in its file; without the flag the file decides.
	if _, structured := flags["authentication-config"]; !structured || flags["anonymous-auth"] != "" {
		r.boolean("anonymous_auth", "anonymous-auth", true)
	}
	r.set("token_auth_file_set", "token-auth-file")
	// The removed --admission-control flag would change the set in a way this
	// reader does not model: unknown rather than guessed.
	if _, legacy := flags["admission-control"]; !legacy {
		r.out["admission_plugins"] = strings.Join(admissionPlugins(flags["enable-admission-plugins"], flags["disable-admission-plugins"]), ",")
	}
	r.set("kubelet_client_cert_set", "kubelet-client-certificate", "kubelet-client-key")
	r.set("kubelet_ca_set", "kubelet-certificate-authority")
	// --authorization-config (structured authorization) replaces the mode flag.
	if _, structured := flags["authorization-config"]; !structured {
		r.value("authorization_mode", "authorization-mode", "AlwaysAllow")
	}
	r.boolean("profiling", "profiling", true)
	r.value("audit_log_path", "audit-log-path", "")
	r.set("audit_policy_file_set", "audit-policy-file")
	r.integer("audit_log_maxage", "audit-log-maxage", "0")
	r.integer("audit_log_maxbackup", "audit-log-maxbackup", "0")
	r.integer("audit_log_maxsize", "audit-log-maxsize", "0")
	r.boolean("service_account_lookup", "service-account-lookup", true)
	r.set("service_account_key_file_set", "service-account-key-file")
	r.set("etcd_client_cert_set", "etcd-certfile", "etcd-keyfile")
	r.set("tls_cert_set", "tls-cert-file", "tls-private-key-file")
	r.set("client_ca_set", "client-ca-file")
	r.set("etcd_ca_set", "etcd-cafile")
	r.set("encryption_provider_config_set", "encryption-provider-config")
	r.value("tls_cipher_suites", "tls-cipher-suites", "")
	r.boolean("service_account_extend_token_expiration", "service-account-extend-token-expiration", true)
}

// admissionPlugins is the effective admission set: the defaults plus
// --enable-admission-plugins, minus --disable-admission-plugins. Sorted.
func admissionPlugins(enable, disable string) []string {
	set := map[string]bool{}
	for _, p := range defaultAdmissionPlugins {
		set[p] = true
	}
	for _, p := range splitCSV(enable) {
		set[p] = true
	}
	for _, p := range splitCSV(disable) {
		delete(set, p)
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// featureGate returns the value a --feature-gates list gives gate ("" if unset).
func featureGate(gates, gate string) string {
	for _, kv := range splitCSV(gates) {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.TrimSpace(k) == gate {
			return strings.ToLower(strings.TrimSpace(v))
		}
	}
	return ""
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
