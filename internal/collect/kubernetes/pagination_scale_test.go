package kubernetes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/collect"
	"github.com/vulngraph/vulngraph/internal/testutil/collectbench"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type pagedPodClient struct {
	*fakeK8s
	real *realK8s
}

func (c pagedPodClient) ListPods(ctx context.Context, ns string) ([]corev1.Pod, error) {
	return c.real.ListPods(ctx, ns)
}

func testConnectorScalePagedPods(t *testing.T) {
	for _, n := range collectbench.Sizes(t) {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			var calls atomic.Int64
			transport := collectbench.Transport(func(req *http.Request) (*http.Response, error) {
				calls.Add(1)
				if req.URL.Host != "kubernetes.fixture.invalid" || req.URL.Path != "/api/v1/namespaces/workloads/pods" {
					return nil, fmt.Errorf("unexpected pod fixture URL %s", req.URL)
				}
				start, _ := strconv.Atoi(req.URL.Query().Get("continue"))
				limit, _ := strconv.Atoi(req.URL.Query().Get("limit"))
				if limit != 500 {
					return nil, fmt.Errorf("unbounded pod request limit %d", limit)
				}
				page := corev1.PodList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PodList"}, ListMeta: metav1.ListMeta{ResourceVersion: "123"}, Items: []corev1.Pod{}}
				for i := start; i < min(start+limit, n); i++ {
					metadata := "small"
					if i%100 == 0 {
						metadata = strings.Repeat("annotation", 8192)
					}
					page.Items = append(page.Items, corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-" + strconv.Itoa(i), Namespace: "workloads", Annotations: map[string]string{"fixture": metadata}}, Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "app", Image: "example/app:1"}}}})
				}
				if start+limit < n {
					page.Continue = strconv.Itoa(start + limit)
				}
				b, err := json.Marshal(page)
				return collectbench.Response(req, string(b)), err
			})
			cs, err := kubernetes.NewForConfig(&rest.Config{Host: "https://kubernetes.fixture.invalid", Transport: transport, QPS: 1000, Burst: 1000})
			require.NoError(t, err)
			client := pagedPodClient{fakeK8s: &fakeK8s{namespaces: []corev1.Namespace{{ObjectMeta: metav1.ObjectMeta{Name: "workloads"}}}}, real: &realK8s{cs: cs}}
			c := &Collector{newClient: func(context.Context, map[string]string) (k8sAPI, string, error) { return client, "paged-cluster", nil }}
			collectbench.Run(t, "kubernetes_paged", "real Kubernetes SDK pod pagination, with 1% wide annotations", "k8s_pod", n, func() { calls.Store(0) }, func() (collect.Result, int, error) {
				r, err := c.Collect(t.Context(), nil)
				require.EqualValues(t, (n+499)/500, calls.Load())
				return r, int(calls.Load()), err
			})
		})
	}
}
