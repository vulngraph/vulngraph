package kubernetes

import (
	"testing"

	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestNetworkPolicyEngines(t *testing.T) {
	ds := func(ns, name string) appsv1.DaemonSet {
		return appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name}}
	}
	vpcCNI := func(v string) corev1.ConfigMap {
		return corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "kube-system", Name: "amazon-vpc-cni"},
			Data: map[string]string{"enable-network-policy-controller": v}}
	}
	tests := []struct {
		name string
		ds   []appsv1.DaemonSet
		cms  []corev1.ConfigMap
		want string
	}{
		{"EKS default: VPC CNI with the controller off", []appsv1.DaemonSet{ds("kube-system", "aws-node"), ds("kube-system", "kube-proxy")},
			[]corev1.ConfigMap{vpcCNI("false")}, ""},
		{"VPC CNI network policy on", []appsv1.DaemonSet{ds("kube-system", "aws-node")}, []corev1.ConfigMap{vpcCNI("true")}, "vpc-cni"},
		{"Calico and Cilium", []appsv1.DaemonSet{ds("calico-system", "calico-node"), ds("kube-system", "cilium")}, nil, "calico,cilium"},
		{"nothing", nil, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, map[string]string{"network_policy_engines": tt.want}, networkPolicyEngines(tt.ds, tt.cms))
		})
	}
}
