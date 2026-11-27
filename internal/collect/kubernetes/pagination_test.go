package kubernetes

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func TestPodPagesExhaustOrFailClosed(t *testing.T) {
	for _, mode := range []string{"complete", "forbidden", "expired", "repeated_token", "cancelled", "empty", "missing_snapshot", "missing_items", "changed_snapshot", "missing_identity", "wrong_namespace", "duplicate_identity"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				call := calls.Add(1)
				if r.URL.Query().Get("limit") != "500" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if call > 1 && mode == "forbidden" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				if call > 1 && mode == "expired" {
					w.WriteHeader(http.StatusGone)
					return
				}
				start := 0
				if r.URL.Query().Get("continue") != "" {
					start, _ = strconv.Atoi(r.URL.Query().Get("continue"))
				}
				page := corev1.PodList{TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "PodList"}, ListMeta: metav1.ListMeta{ResourceVersion: "123"}}
				for i := start; i < min(start+500, 1005); i++ {
					page.Items = append(page.Items, corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "pod-" + strconv.Itoa(i), Namespace: "workloads"}})
				}
				if start+500 < 1005 {
					page.Continue = strconv.Itoa(start + 500)
				}
				if mode == "duplicate_identity" && call > 1 {
					page.Items[0].Name = "pod-0"
				}
				if mode == "missing_identity" {
					page.Items[0].Name = ""
				}
				if mode == "wrong_namespace" {
					page.Items[0].Namespace = "other"
				}
				if mode == "empty" {
					page.Items = []corev1.Pod{}
					page.Continue = ""
				}
				if mode == "missing_snapshot" {
					page.ResourceVersion = ""
				}
				if mode == "missing_items" {
					page.Items = nil
				}
				if mode == "changed_snapshot" && call > 1 {
					page.ResourceVersion = "124"
				}
				if mode == "repeated_token" {
					page.Continue = "500"
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(page)
			}))
			defer srv.Close()
			cs, err := kubernetes.NewForConfig(&rest.Config{Host: srv.URL, QPS: 1000, Burst: 1000})
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			got, err := (&realK8s{cs: cs}).ListPods(ctx, "workloads")
			if mode == "empty" {
				require.NoError(t, err)
				require.Empty(t, got)
				return
			}
			if mode != "complete" {
				require.Error(t, err)
				require.Empty(t, got, "partial pages must not look like a complete list")
				return
			}
			require.NoError(t, err)
			require.Len(t, got, 1005)
			require.EqualValues(t, 3, calls.Load())
			for i, pod := range got {
				require.Equal(t, "pod-"+strconv.Itoa(i), pod.Name)
			}
		})
	}
}
