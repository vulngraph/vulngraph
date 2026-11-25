package kubernetes

import (
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// kubeProxyPod is a kube-proxy DaemonSet pod reading --config from a ConfigMap
// volume, in kubeadm's layout (cmd/kubeadm/app/phases/addons/proxy/manifests.go)
// or EKS's (kube-proxy-config mounted at /var/lib/kube-proxy-config).
func kubeProxyPod(name, cmName, mountPath, cfgFile string, extra ...string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "kube-system", Labels: map[string]string{"k8s-app": "kube-proxy"}},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name:         "kube-proxy",
				Command:      append([]string{"/usr/local/bin/kube-proxy", "--config=" + mountPath + "/" + cfgFile, "--hostname-override=$(NODE_NAME)"}, extra...),
				VolumeMounts: []corev1.VolumeMount{{Name: "kube-proxy", MountPath: mountPath}},
			}},
			Volumes: []corev1.Volume{{Name: "kube-proxy", VolumeSource: corev1.VolumeSource{
				ConfigMap: &corev1.ConfigMapVolumeSource{LocalObjectReference: corev1.LocalObjectReference{Name: cmName}},
			}}},
		},
	}
}

func proxyConfigMap(name, key, cfg string) corev1.ConfigMap {
	return corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "kube-system"}, Data: map[string]string{key: cfg}}
}

func TestKubeProxySignals(t *testing.T) {
	// kubeadm's config.conf names the kubeconfig the same ConfigMap volume carries.
	kubeadmCM := proxyConfigMap("kube-proxy", "config.conf", "apiVersion: kubeproxy.config.k8s.io/v1alpha1\nclientConnection:\n  kubeconfig: /var/lib/kube-proxy/kubeconfig.conf\nkind: KubeProxyConfiguration\nmetricsBindAddress: \"\"\nmode: \"\"\n")
	eksCM := proxyConfigMap("kube-proxy-config", "config", "apiVersion: kubeproxy.config.k8s.io/v1alpha1\nkind: KubeProxyConfiguration\nmetricsBindAddress: 0.0.0.0:10249\n")
	kubeadmPod := kubeProxyPod("kube-proxy-a", "kube-proxy", "/var/lib/kube-proxy", "config.conf")
	eksPod := kubeProxyPod("kube-proxy-b", "kube-proxy-config", "/var/lib/kube-proxy-config", "config")
	// No --config: the flags decide.
	flagsOnly := func(name string, extra ...string) corev1.Pod {
		p := kubeProxyPod(name, "kube-proxy", "/var/lib/kube-proxy", "config.conf")
		p.Spec.Containers[0].Command = append([]string{"/usr/local/bin/kube-proxy"}, extra...)
		return p
	}
	hostPathPod := flagsOnly("kube-proxy-c", "--kubeconfig=/node/kubeconfig")
	hostPathPod.Spec.Containers[0].VolumeMounts = append(hostPathPod.Spec.Containers[0].VolumeMounts, corev1.VolumeMount{Name: "node", MountPath: "/node"})
	hostPathPod.Spec.Volumes = append(hostPathPod.Spec.Volumes, corev1.Volume{Name: "node", VolumeSource: corev1.VolumeSource{
		HostPath: &corev1.HostPathVolumeSource{Path: "/var/lib/kube-proxy"},
	}})
	noNodeFile := func(bind string) map[string]string {
		return map[string]string{"kube_proxy_metrics_bind_address": bind,
			"node_file_kube_proxy_kubeconfig_mode": "absent", "node_file_kube_proxy_kubeconfig_owner": "absent"}
	}

	tests := []struct {
		name string
		pods []corev1.Pod
		cms  []corev1.ConfigMap
		want map[string]string
	}{
		{"kubeadm default is loopback, kubeconfig from the ConfigMap", []corev1.Pod{kubeadmPod}, []corev1.ConfigMap{kubeadmCM},
			noNodeFile("127.0.0.1:10249")},
		{"EKS binds all interfaces", []corev1.Pod{eksPod}, []corev1.ConfigMap{eksCM}, noNodeFile("0.0.0.0:10249")},
		{"with --config the file wins over the flag", []corev1.Pod{kubeProxyPod("p", "kube-proxy", "/var/lib/kube-proxy", "config.conf", "--metrics-bind-address=0.0.0.0:10249")},
			[]corev1.ConfigMap{kubeadmCM}, noNodeFile("127.0.0.1:10249")},
		{"without --config the flag decides", []corev1.Pod{flagsOnly("p", "--metrics-bind-address=0.0.0.0:10249")}, nil, noNodeFile("0.0.0.0:10249")},
		{"a --kubeconfig flag is ignored under --config", []corev1.Pod{kubeProxyPod("p", "kube-proxy", "/var/lib/kube-proxy", "config.conf", "--kubeconfig=/nowhere/kubeconfig")},
			[]corev1.ConfigMap{kubeadmCM}, noNodeFile("127.0.0.1:10249")},
		{"pods disagree", []corev1.Pod{kubeadmPod, eksPod}, []corev1.ConfigMap{kubeadmCM, eksCM},
			noNodeFile("0.0.0.0:10249|127.0.0.1:10249")},
		{"a hostPath kubeconfig is a node file only the reader can stat", []corev1.Pod{kubeadmPod, hostPathPod}, []corev1.ConfigMap{kubeadmCM},
			map[string]string{"kube_proxy_metrics_bind_address": "127.0.0.1:10249"}},
		{"config map unreadable is unknown", []corev1.Pod{kubeadmPod}, nil, nil},
		{"one unresolvable pod makes the cluster unknown", []corev1.Pod{kubeadmPod, eksPod}, []corev1.ConfigMap{kubeadmCM}, nil},
		{"no kube-proxy (Cilium kube-proxy replacement)", nil, nil, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, kubeProxySignals(tt.pods, tt.cms))
		})
	}
}
