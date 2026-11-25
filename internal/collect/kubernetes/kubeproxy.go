package kubernetes

import (
	"encoding/json"
	"path"
	"slices"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

// kubeproxy.go resolves two kube-proxy facts from API objects alone, from each
// kube-proxy pod's flags and the KubeProxyConfiguration its --config file is
// mounted from (kubeadm: ConfigMap kube-system/kube-proxy, EKS:
// kube-system/kube-proxy-config):
//
//   - where it serves metrics (CIS Kubernetes 4.3.1): --metrics-bind-address,
//     else metricsBindAddress, else the upstream default;
//   - whether its kubeconfig is a node file at all (CIS 4.1.3/4.1.4 apply only
//     "if the proxy kubeconfig file exists"): a kubeconfig read from a
//     ConfigMap, Secret or projected volume, or none (in-cluster credentials),
//     is not on the node, so the file controls record it as absent. A
//     hostPath kubeconfig is a node file only the node posture reader can stat.
//
// Each result is omitted when any kube-proxy pod cannot be resolved.

// kubeProxyDefaultMetricsBind is KubeProxyConfiguration's default.
const kubeProxyDefaultMetricsBind = "127.0.0.1:10249"

// kubeProxyFacts is one kube-proxy pod's resolved configuration.
type kubeProxyFacts struct {
	metricsBind  string
	hostFileConf bool // the kubeconfig is a file on the node
}

func kubeProxySignals(pods []corev1.Pod, cms []corev1.ConfigMap) map[string]string {
	var binds []string
	hostFile, seen := false, false
	for _, pod := range pods {
		if pod.Namespace != "kube-system" || pod.Labels["k8s-app"] != "kube-proxy" {
			continue
		}
		f, ok := resolveKubeProxy(pod, cms)
		if !ok {
			return nil
		}
		seen = true
		hostFile = hostFile || f.hostFileConf
		if !slices.Contains(binds, f.metricsBind) {
			binds = append(binds, f.metricsBind)
		}
	}
	if !seen {
		return nil
	}
	sort.Strings(binds)
	out := map[string]string{"kube_proxy_metrics_bind_address": strings.Join(binds, "|")}
	if !hostFile {
		out["node_file_kube_proxy_kubeconfig_mode"] = absentValue
		out["node_file_kube_proxy_kubeconfig_owner"] = absentValue
	}
	return out
}

func resolveKubeProxy(pod corev1.Pod, cms []corev1.ConfigMap) (kubeProxyFacts, bool) {
	flags, ok := componentFlags(pod, "kube-proxy")
	if !ok {
		return kubeProxyFacts{}, false
	}
	var cfg struct {
		MetricsBindAddress string `json:"metricsBindAddress"`
		ClientConnection   struct {
			Kubeconfig string `json:"kubeconfig"`
		} `json:"clientConnection"`
	}
	if cfgPath, hasConfig := flags["config"]; hasConfig {
		raw, ok := mountedConfigMapFile(pod, "kube-proxy", cfgPath, cms)
		if !ok {
			return kubeProxyFacts{}, false
		}
		js, err := utilyaml.ToJSON([]byte(raw))
		if err != nil || json.Unmarshal(js, &cfg) != nil {
			return kubeProxyFacts{}, false
		}
	}
	// With --config the file wins: kube-proxy takes metricsBindAddress and
	// clientConnection.kubeconfig from it and ignores the matching flags.
	bindFlag, kcFlag := flags["metrics-bind-address"], flags["kubeconfig"]
	if _, hasConfig := flags["config"]; hasConfig {
		bindFlag, kcFlag = "", ""
	}
	f := kubeProxyFacts{metricsBind: firstNonEmpty(bindFlag, cfg.MetricsBindAddress, kubeProxyDefaultMetricsBind)}
	if kc := firstNonEmpty(kcFlag, cfg.ClientConnection.Kubeconfig); kc != "" {
		vol, _, ok := mountSource(pod, "kube-proxy", kc)
		if !ok {
			return kubeProxyFacts{}, false // a path on no volume: cannot tell
		}
		f.hostFileConf = vol.HostPath != nil
	}
	return f, true
}

// mountSource finds the volume a container path is mounted from, and the path
// relative to the mount.
func mountSource(pod corev1.Pod, container, file string) (corev1.Volume, string, bool) {
	idx := slices.IndexFunc(pod.Spec.Containers, func(c corev1.Container) bool { return c.Name == container })
	if idx < 0 {
		return corev1.Volume{}, "", false
	}
	for _, m := range pod.Spec.Containers[idx].VolumeMounts {
		rel, found := strings.CutPrefix(path.Clean(file), path.Clean(m.MountPath)+"/")
		if !found || m.SubPath != "" {
			continue
		}
		vi := slices.IndexFunc(pod.Spec.Volumes, func(v corev1.Volume) bool { return v.Name == m.Name })
		if vi < 0 {
			return corev1.Volume{}, "", false
		}
		return pod.Spec.Volumes[vi], rel, true
	}
	return corev1.Volume{}, "", false
}

// mountedConfigMapFile returns the content of file, as the named container
// sees it, when it comes from a ConfigMap volume.
func mountedConfigMapFile(pod corev1.Pod, container, file string, cms []corev1.ConfigMap) (string, bool) {
	vol, rel, ok := mountSource(pod, container, file)
	if !ok || vol.ConfigMap == nil {
		return "", false
	}
	src := vol.ConfigMap
	key := rel
	if len(src.Items) > 0 {
		key = ""
		for _, it := range src.Items {
			if it.Path == rel {
				key = it.Key
			}
		}
	}
	ci := slices.IndexFunc(cms, func(cm corev1.ConfigMap) bool { return cm.Namespace == pod.Namespace && cm.Name == src.Name })
	if ci < 0 || key == "" {
		return "", false
	}
	v, ok := cms[ci].Data[key]
	return v, ok
}
