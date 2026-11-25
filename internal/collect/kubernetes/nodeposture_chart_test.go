package kubernetes

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
)

const (
	chartValues   = "../../../deploy/helm-chart/graph/values.yaml"
	chartTemplate = "../../../deploy/helm-chart/graph/templates/node-posture.yaml"
)

// knownRole reports whether the collector interprets a reader role. A role the
// chart names but nothing reads would be a report silently dropped.
func knownRole(role string) bool {
	if _, ok := statRoles[role]; ok {
		return true
	}
	switch role {
	case "pki_dir", "cni_dir", "kubelet_service", "kubelet_config_dropins", "host_passwd", "host_group":
		return true
	}
	return strings.HasPrefix(role, "kubelet_flags")
}

// Every role the chart ships is one the collector reads, each volume is mounted
// into a container that exists, and root is only ever given read access to
// kubelet configuration (no credentials).
func TestNodePostureChartRolesAreInterpreted(t *testing.T) {
	raw, err := os.ReadFile(chartValues)
	require.NoError(t, err)
	js, err := utilyaml.ToJSON(raw)
	require.NoError(t, err)
	var values struct {
		ServiceAccount struct {
			Name string `json:"name"`
		} `json:"serviceAccount"`
		NodePosture struct {
			Enabled            bool                            `json:"enabled"`
			ServiceAccountName string                          `json:"serviceAccountName"`
			Node               struct{ Volumes []chartVolume } `json:"node"`
			ControlPlane       struct {
				Enabled bool          `json:"enabled"`
				Volumes []chartVolume `json:"volumes"`
			} `json:"controlPlane"`
		} `json:"nodePosture"`
	}
	require.NoError(t, json.Unmarshal(js, &values))
	require.False(t, values.NodePosture.Enabled, "the reader is opt-in")
	require.False(t, values.NodePosture.ControlPlane.Enabled, "the control-plane reader is opt-in")
	require.NotEmpty(t, values.NodePosture.ServiceAccountName)
	require.NotEqual(t, values.ServiceAccount.Name, values.NodePosture.ServiceAccountName,
		"the host-mounting reader must not run as the worker's ServiceAccount, which holds the collector's RBAC")
	vols := append(values.NodePosture.Node.Volumes, values.NodePosture.ControlPlane.Volumes...)
	require.NotEmpty(t, vols)
	for _, v := range vols {
		require.Contains(t, []string{"kubelet", "files"}, v.Container, v.Name)
		require.Contains(t, []string{"File", "Directory"}, v.Type, "%s: a *OrCreate type writes to the host", v.Name)
		for _, r := range v.Roles {
			require.True(t, knownRole(r.Role), "role %q is not interpreted by the collector", r.Role)
			require.Contains(t, []string{"read", "stat", "tree"}, r.Kind, r.Role)
			if v.Container == "kubelet" {
				require.Equal(t, "File", v.Type, "%s: the uid-0 container gets single files, never a directory", v.Name)
				require.Contains(t, kubeletRootHostPaths, v.HostPath, "%s: not a kubelet configuration file", v.Name)
				require.True(t, r.Role == "kubelet_config" || r.Role == "kubelet_service" || strings.HasPrefix(r.Role, "kubelet_flags"),
					"the uid-0 container may only read kubelet configuration, not %q", r.Role)
			}
		}
	}
}

// kubeletRootHostPaths are the host files the default chart may mount into the
// uid-0 container: kubeadm's kubelet config, flag file and systemd drop-in.
// None holds a credential.
var kubeletRootHostPaths = []string{
	"/var/lib/kubelet/config.yaml",
	"/var/lib/kubelet/kubeadm-flags.env",
	"/usr/lib/systemd/system/kubelet.service.d/10-kubeadm.conf",
}

type chartVolume struct {
	Name      string `json:"name"`
	HostPath  string `json:"hostPath"`
	Type      string `json:"type"`
	Container string `json:"container"`
	Roles     []struct {
		Role string `json:"role"`
		Kind string `json:"kind"`
		File string `json:"file"`
	} `json:"roles"`
}

// The template keeps the reader's security posture and the component labels the
// collector selects on.
func TestNodePostureChartPosture(t *testing.T) {
	raw, err := os.ReadFile(chartTemplate)
	require.NoError(t, err)
	tpl := string(raw)
	for _, want := range []string{
		`"component" "` + nodePostureComponent + `"`,
		`"component" "` + nodePostureCPComponent + `"`,
		"serviceAccountName: {{ $root.Values.nodePosture.serviceAccountName }}",
		"name: {{ .Values.nodePosture.serviceAccountName }}",
		"automountServiceAccountToken: false",
		"hostPID: false",
		"hostNetwork: false",
		"allowPrivilegeEscalation: false",
		"readOnlyRootFilesystem: true",
		`drop: ["ALL"]`,
		"readOnly: true",
		"policyTypes: [Ingress, Egress]",
		`resources: ["pods/log"]`,
		`verbs: ["get"]`,
		"kind: Role\n",
	} {
		require.Contains(t, tpl, want)
	}
	require.Equal(t, 2, strings.Count(tpl, "automountServiceAccountToken: false"),
		"both the reader's pods and its own ServiceAccount must disable the API token")
	require.NotContains(t, tpl, "ClusterRole", "the log grant is namespaced")
	require.NotContains(t, tpl, "nodes/proxy")
	require.NotContains(t, tpl, "privileged: true")
}

// The chart grants list on exactly the resources admission_coverage.go reads,
// and nothing broader.
func TestPolicyEngineChartRBACMatchesReads(t *testing.T) {
	raw, err := os.ReadFile("../../../deploy/helm-chart/graph/templates/policy-engine-rbac.yaml")
	require.NoError(t, err)
	tpl := string(raw)
	for _, kind := range gatekeeperPSPKinds {
		require.Contains(t, tpl, "- "+kind+"\n", "gatekeeper kind %s is read but not granted", kind)
	}
	for _, r := range []string{kyvernoClusterPolicyGVR.Resource, kyvernoPolicyGVR.Resource, "validatingwebhookconfigurations", "validatingadmissionpolicybindings"} {
		require.Contains(t, tpl, `"`+r+`"`)
	}
	require.NotContains(t, tpl, `"*"`)
	require.NotContains(t, tpl, "get", "list is all the collector calls")
	require.NotContains(t, tpl, "watch")
}
