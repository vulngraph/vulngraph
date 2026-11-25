package kubernetes

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/vulngraph/vulngraph/internal/nodeposture"
)

func u32(v uint32) *uint32 { return &v }

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/kubeadm/node/" + name)
	require.NoError(t, err)
	return string(b)
}

// kubeadmWorkerFiles is the reader's report from a default kubeadm v1.30 node:
// config.yaml, kubeadm-flags.env and 10-kubeadm.conf are the files kubeadm and
// the pkgs.k8s.io kubelet package write, at their default modes.
func kubeadmWorkerFiles(t *testing.T) []nodeposture.File {
	root := func(role, mode string) nodeposture.File {
		return nodeposture.File{Role: role, Exists: true, Mode: mode, UID: u32(0), GID: u32(0)}
	}
	cfg := root("kubelet_config", "0644")
	cfg.Content = readFixture(t, "config.yaml")
	svc := root("kubelet_service", "0644")
	svc.Content = readFixture(t, "10-kubeadm.conf")
	flags := root("kubelet_flags_kubeadm", "0644")
	flags.Content = readFixture(t, "kubeadm-flags.env")
	return []nodeposture.File{
		svc, flags,
		{Role: "kubelet_flags_defaults"}, // /etc/default/kubelet: optional, absent
		cfg,
		root("kubelet_kubeconfig", "0600"),
		root("client_ca", "0644"),
		{Role: "kube_proxy_kubeconfig"}, // kubeadm runs kube-proxy from a ConfigMap
	}
}

func TestNodeSettings_DefaultKubeadmWorker(t *testing.T) {
	require.Equal(t, map[string]string{
		"kubelet_anonymous_auth":                "false",
		"kubelet_authorization_mode":            "Webhook",
		"kubelet_client_ca_set":                 "true",
		"kubelet_read_only_port":                "0",
		"kubelet_streaming_idle_timeout":        "4h0m0s", // "0s" in the file is defaulted
		"kubelet_make_iptables_util_chains":     "true",
		"kubelet_hostname_override_set":         "false",
		"kubelet_tls_cert_set":                  "false",
		"kubelet_rotate_certificates":           "true",
		"kubelet_rotate_server_certificates":    "true",
		"kubelet_tls_cipher_suites":             "",
		"kubelet_pod_pids_limit":                "-1",
		"kubelet_seccomp_default":               "false",
		"node_file_kubelet_service_mode":        "0644",
		"node_file_kubelet_service_owner":       "root:root",
		"node_file_kubelet_config_mode":         "0644",
		"node_file_kubelet_config_owner":        "root:root",
		"node_file_kubelet_kubeconfig_mode":     "0600",
		"node_file_kubelet_kubeconfig_owner":    "root:root",
		"node_file_client_ca_mode":              "0644",
		"node_file_client_ca_owner":             "root:root",
		"node_file_kube_proxy_kubeconfig_mode":  "absent",
		"node_file_kube_proxy_kubeconfig_owner": "absent",
	}, nodeSettings(kubeadmWorkerFiles(t)))
}

func TestKubeletSettings_FlagsOverrideConfig(t *testing.T) {
	files := kubeadmWorkerFiles(t)
	files[2] = nodeposture.File{Role: "kubelet_flags_defaults", Exists: true, Mode: "0644", UID: u32(0), GID: u32(0),
		Content: "KUBELET_EXTRA_ARGS=\"--anonymous-auth=true --read-only-port=10255 --streaming-connection-idle-timeout=0 --hostname-override=n1 --feature-gates=RotateKubeletServerCertificate=false\"\n"}
	got := kubeletSettings(files)
	require.Equal(t, "true", got["kubelet_anonymous_auth"])
	require.Equal(t, "10255", got["kubelet_read_only_port"])
	require.Equal(t, "0s", got["kubelet_streaming_idle_timeout"], "a zero flag is not defaulted")
	require.Equal(t, "true", got["kubelet_hostname_override_set"])
	require.Equal(t, "false", got["kubelet_rotate_server_certificates"])
}

// Missing data is unknown: no config file, an unreadable flag source, an
// unreadable or absent required file.
func TestNodeSettings_Unknown(t *testing.T) {
	t.Run("config unreadable", func(t *testing.T) {
		files := kubeadmWorkerFiles(t)
		files[3].Content, files[3].Error = "", "permission denied"
		got := nodeSettings(files)
		require.NotContains(t, got, "kubelet_anonymous_auth")
		require.NotContains(t, got, "node_file_kubelet_config_mode", "an errored observation is not a stat")
	})
	t.Run("flag source unreadable", func(t *testing.T) {
		files := kubeadmWorkerFiles(t)
		files[1].Content, files[1].Error = "", "permission denied"
		require.NotContains(t, kubeletSettings(files), "kubelet_anonymous_auth")
	})
	t.Run("required file absent", func(t *testing.T) {
		files := kubeadmWorkerFiles(t)
		files[4] = nodeposture.File{Role: "kubelet_kubeconfig"}
		require.NotContains(t, fileSettings(files), "node_file_kubelet_kubeconfig_mode",
			"a kubeconfig the chart's path does not find is a profile mismatch, not compliance")
	})
	t.Run("truncated config", func(t *testing.T) {
		files := kubeadmWorkerFiles(t)
		files[3].Truncated = true
		require.NotContains(t, kubeletSettings(files), "kubelet_read_only_port")
	})
}

func TestFileSettings_ControlPlaneTrees(t *testing.T) {
	files := []nodeposture.File{
		{Role: "host_passwd", Exists: true, Content: "root:x:0:0:root:/root:/bin/bash\netcd:x:998:998::/var/lib/etcd:/sbin/nologin\n"},
		{Role: "host_group", Exists: true, Content: "root:x:0:\netcd:x:998:\n"},
		{Role: "etcd_data_dir", Exists: true, Dir: true, Mode: "0700", UID: u32(998), GID: u32(998)},
		{Role: "admin_kubeconfig", Exists: true, Mode: "0600", UID: u32(0), GID: u32(0)},
		{Role: "super_admin_kubeconfig", Exists: true, Mode: "0640", UID: u32(0), GID: u32(0)},
		{Role: "pki_dir", Exists: true, Dir: true, Mode: "0755", UID: u32(0), GID: u32(0), Entries: []nodeposture.Entry{
			{Path: "ca.crt", Mode: "0644"}, {Path: "ca.key", Mode: "0600"},
			{Path: "etcd/peer.key", Mode: "0644", UID: 1000, GID: 1000},
		}},
		{Role: "cni_dir"},
	}
	got := fileSettings(files)
	require.Equal(t, "etcd:etcd", got["node_file_etcd_data_dir_owner"], "names come from the node's passwd/group")
	require.Equal(t, "0640", got["node_file_admin_kubeconfig_mode"], "super-admin.conf folds into the admin credential files")
	require.Equal(t, "1000:1000,root:root", got["node_file_pki_owner"])
	require.Equal(t, "0644", got["node_file_pki_cert_mode"])
	require.Equal(t, "0644", got["node_file_pki_key_mode"], "the union exposes the one loose key")
	require.Equal(t, "absent", got["node_file_cni_mode"])
	require.NotContains(t, got, "node_file_pki_mode")

	// Without passwd the etcd owner cannot be named: mode known, owner unknown.
	got = fileSettings(files[2:])
	require.Equal(t, "0700", got["node_file_etcd_data_dir_mode"])
	require.NotContains(t, got, "node_file_etcd_data_dir_owner")
}

func TestLatestDocument(t *testing.T) {
	old, _ := json.Marshal(nodeposture.Document{Version: nodeposture.Marker, Files: []nodeposture.File{{Role: "a"}}})
	newer, _ := json.Marshal(nodeposture.Document{Version: nodeposture.Marker, Files: []nodeposture.File{{Role: "b"}}})
	doc, ok := latestDocument(string(old) + "\n{\"level\":\"info\"}\n" + string(newer) + "\nnot json\n")
	require.True(t, ok)
	require.Equal(t, "b", doc.Files[0].Role)
	_, ok = latestDocument("{\"graph_node_posture\":\"other/v9\",\"files\":[]}\n")
	require.False(t, ok, "a document without the marker is ignored")
}

// readerFixture is graph's namespace with the node DaemonSet scheduled on
// the given nodes, each reader pod logging the kubeadm worker report.
func readerFixture(t *testing.T, nodes []string, desired int32) *fakeK8s {
	t.Helper()
	ctrl := true
	ds := appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "graph-node-posture", Namespace: "graph", UID: types.UID("ds-uid"),
			Labels: map[string]string{"app.kubernetes.io/name": "graph", "app.kubernetes.io/component": nodePostureComponent}},
		Status: appsv1.DaemonSetStatus{DesiredNumberScheduled: desired},
	}
	doc, err := json.Marshal(nodeposture.Document{Version: nodeposture.Marker, Files: kubeadmWorkerFiles(t)})
	require.NoError(t, err)
	f := &fakeK8s{
		namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "graph"}}},
		daemonSets: map[string][]appsv1.DaemonSet{"graph": {ds}},
		pods:       map[string][]corev1.Pod{},
		logs:       map[string]string{},
		ownNS:      "graph",
	}
	for _, n := range nodes {
		name := "graph-node-posture-" + n
		f.pods["graph"] = append(f.pods["graph"], corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "graph",
				OwnerReferences: []metav1.OwnerReference{{Kind: "DaemonSet", Name: ds.Name, UID: ds.UID, Controller: &ctrl}}},
			Spec:   corev1.PodSpec{NodeName: n, Containers: []corev1.Container{{Name: "kubelet"}}},
			Status: corev1.PodStatus{Phase: corev1.PodRunning},
		})
		f.logs[name+"/kubelet"] = string(doc) + "\n"
	}
	return f
}

func clusterMeta(t *testing.T, f *fakeK8s) map[string]string {
	t.Helper()
	res, err := withFakeK8s(f).Collect(context.Background(), nil)
	require.NoError(t, err)
	for _, a := range res.Assets {
		if a.Type == "k8s_cluster" {
			return a.Metadata
		}
	}
	t.Fatal("no k8s_cluster asset")
	return nil
}

func TestCollect_NodePostureOnClusterAsset(t *testing.T) {
	md := clusterMeta(t, readerFixture(t, []string{"n1", "n2"}, 2))
	require.Equal(t, "false", md["kubelet_anonymous_auth"])
	require.Equal(t, "2", md["node_posture_nodes_reported"])
}

// A node the reader did not report could be the failing one: partial coverage
// leaves every node setting unknown.
func TestCollect_NodePosturePartialCoverageIsUnknown(t *testing.T) {
	md := clusterMeta(t, readerFixture(t, []string{"n1"}, 3))
	require.NotContains(t, md, "kubelet_anonymous_auth")
	require.Equal(t, "1", md["node_posture_nodes_reported"])
	require.Equal(t, "3", md["node_posture_nodes_desired"])
}

// Pods that only look like the reader — wrong namespace, not owned by the
// DaemonSet — are never read.
func TestCollect_NodePostureIgnoresImpostors(t *testing.T) {
	f := readerFixture(t, []string{"n1"}, 1)
	f.pods["graph"][0].OwnerReferences[0].UID = "other"
	require.NotContains(t, clusterMeta(t, f), "kubelet_anonymous_auth")

	f = readerFixture(t, []string{"n1"}, 1)
	f.ownNS = ""
	require.NotContains(t, clusterMeta(t, f), "node_posture_nodes_reported", "graph's namespace unknown: nothing is read")
}

// Without the reader deployed no node key exists at all.
func TestCollect_NoReaderNoNodeKeys(t *testing.T) {
	md := clusterMeta(t, &fakeK8s{namespaces: appNamespace(), ownNS: "graph"})
	for k := range md {
		require.NotRegexp(t, `^(kubelet_|node_file_|node_posture)`, k)
	}
}

// --config-dir drop-ins override the config file; when the kubelet uses one
// and the reader did not read it, every kubelet setting is unknown.
func TestKubeletSettings_ConfigDirDropIns(t *testing.T) {
	withDir := func(dropins *nodeposture.File) []nodeposture.File {
		files := kubeadmWorkerFiles(t)
		files[2] = nodeposture.File{Role: "kubelet_flags_defaults", Exists: true, Mode: "0644", UID: u32(0), GID: u32(0),
			Content: "KUBELET_EXTRA_ARGS=--config-dir=/etc/kubernetes/kubelet.conf.d\n"}
		if dropins != nil {
			files = append(files, *dropins)
		}
		return files
	}
	require.NotContains(t, kubeletSettings(withDir(nil)), "kubelet_seccomp_default", "drop-ins unread: unknown")

	dir := &nodeposture.File{Role: "kubelet_config_dropins", Exists: true, Dir: true, Entries: []nodeposture.Entry{
		{Path: "10-hardening.conf", Content: "apiVersion: kubelet.config.k8s.io/v1beta1\nkind: KubeletConfiguration\nseccompDefault: true\nauthentication:\n  anonymous:\n    enabled: true\n"},
		{Path: "20-later.conf", Content: `{"readOnlyPort": 10255}`},
		{Path: "99-ignored.json", Content: `{"seccompDefault": false}`},
	}}
	got := kubeletSettings(withDir(dir))
	require.Equal(t, "true", got["kubelet_seccomp_default"], "a drop-in field overrides the file")
	require.Equal(t, "true", got["kubelet_anonymous_auth"], "nested objects merge field by field")
	require.Equal(t, "true", got["kubelet_client_ca_set"], "fields the drop-in does not name survive")
	require.Equal(t, "10255", got["kubelet_read_only_port"])

	dir.Entries[0].Truncated = true
	require.NotContains(t, kubeletSettings(withDir(dir)), "kubelet_seccomp_default")

	// Without --config-dir the kubelet ignores the directory.
	files := kubeadmWorkerFiles(t)
	files = append(files, nodeposture.File{Role: "kubelet_config_dropins", Exists: true, Entries: []nodeposture.Entry{{Path: "10.conf", Content: `{"seccompDefault": true}`}}})
	require.Equal(t, "false", kubeletSettings(files)["kubelet_seccomp_default"])
}

// A kubelet unit the chart's path does not find is a profile mismatch, never an
// absent-and-passing 4.1.1/4.1.2.
func TestFileSettings_MissingKubeletUnitIsUnknown(t *testing.T) {
	files := kubeadmWorkerFiles(t)
	files[0] = nodeposture.File{Role: "kubelet_service"}
	got := fileSettings(files)
	require.NotContains(t, got, "node_file_kubelet_service_mode")
	require.NotContains(t, got, "node_file_kubelet_service_owner")
}
