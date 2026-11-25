package kubernetes

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/vulngraph/vulngraph/internal/nodeposture"
	"github.com/vulngraph/vulngraph/pkg/log"
)

// nodeposture.go reads the opt-in node posture reader (ADR 094) back from the
// cluster. The reader DaemonSets run in Vulngraph's own namespace and print one
// nodeposture.Document per interval to stdout; the collector reads each pod's
// log tail (pods/log get, granted by the chart in that namespace only) and
// keys every report by the pod's spec.nodeName — the API server's record of
// where the pod runs, not anything the pod says about itself.
//
// Settings are derived per node (nodeposture_kubelet.go, nodeposture_files.go)
// and merged across nodes exactly like control-plane replicas: every distinct
// value joined with "|" on the k8s_cluster asset, one finding per cluster per
// root cause. A DaemonSet whose reports do not cover every node it is
// scheduled on contributes nothing: an unreported node could be the failing
// one, so partial coverage is unknown, never clean. Without the reader every
// node control is unknown.

// The reader DaemonSets' app.kubernetes.io/component labels
// (deploy/helm-chart/graph/templates/node-posture.yaml).
const (
	nodePostureComponent   = "node-posture"
	nodePostureCPComponent = "node-posture-control-plane"
)

// nodePostureLogConcurrency bounds simultaneous log reads (each is a kubelet
// round trip through the API server).
const nodePostureLogConcurrency = 8

func nodePostureSignals(ctx context.Context, client k8sAPI, pods []corev1.Pod, daemonSets []appsv1.DaemonSet) map[string]string {
	ns := client.OwnNamespace()
	if ns == "" {
		return nil
	}
	out := map[string]string{}
	for _, ds := range daemonSets {
		comp := ds.Labels["app.kubernetes.io/component"]
		if ds.Namespace != ns || ds.Labels["app.kubernetes.io/name"] != "graph" ||
			(comp != nodePostureComponent && comp != nodePostureCPComponent) {
			continue
		}
		prefix := "node_posture"
		if comp == nodePostureCPComponent {
			prefix = "node_posture_cp"
		}
		reports := readDaemonSetReports(ctx, client, ds, pods)
		desired := int(ds.Status.DesiredNumberScheduled)
		out[prefix+"_nodes_reported"] = strconv.Itoa(len(reports))
		out[prefix+"_nodes_desired"] = strconv.Itoa(desired)
		if desired == 0 || len(reports) < desired {
			log.FromContext(ctx).Warn().Str("daemonset", ds.Name).Int("reported", len(reports)).Int("desired", desired).
				Msg("k8s node posture incomplete; node controls stay unknown")
			continue
		}
		perNode := make([]map[string]string, 0, len(reports))
		for _, files := range reports {
			perNode = append(perNode, nodeSettings(files))
		}
		maps.Copy(out, mergeReplicaSettings(perNode))
	}
	return out
}

// readDaemonSetReports returns node → the merged files of every container of
// that node's reader pod. A pod with any container missing a document is left
// out, so it counts against coverage.
func readDaemonSetReports(ctx context.Context, client k8sAPI, ds appsv1.DaemonSet, pods []corev1.Pod) map[string][]nodeposture.File {
	var owned []corev1.Pod
	for _, p := range pods {
		if p.Namespace == ds.Namespace && p.Status.Phase == corev1.PodRunning && p.Spec.NodeName != "" &&
			slices.ContainsFunc(p.OwnerReferences, func(o metav1.OwnerReference) bool { return o.UID == ds.UID && o.Controller != nil && *o.Controller }) {
			owned = append(owned, p)
		}
	}
	var (
		mu  sync.Mutex
		wg  sync.WaitGroup
		out = map[string][]nodeposture.File{}
		sem = make(chan struct{}, nodePostureLogConcurrency)
	)
	for _, p := range owned {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					log.FromContext(ctx).Error().Any("panic", r).Str("pod", p.Name).Msg("k8s node posture read: panic")
				}
			}()
			files, ok := readPodReport(ctx, client, p)
			if !ok {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if _, dup := out[p.Spec.NodeName]; dup {
				// Two reader pods on one node (a rollout): the node is reported
				// either way, and the next sweep sees one pod.
				return
			}
			out[p.Spec.NodeName] = files
		}()
	}
	wg.Wait()
	return out
}

func readPodReport(ctx context.Context, client k8sAPI, p corev1.Pod) ([]nodeposture.File, bool) {
	var files []nodeposture.File
	for _, c := range p.Spec.Containers {
		raw, err := client.PodLogTail(ctx, p.Namespace, p.Name, c.Name)
		if err != nil {
			log.FromContext(ctx).Warn().Err(err).Str("pod", p.Name).Str("container", c.Name).Msg("k8s node posture log read failed")
			return nil, false
		}
		doc, ok := latestDocument(raw)
		if !ok {
			return nil, false
		}
		files = append(files, doc.Files...)
	}
	return files, len(files) > 0
}

// latestDocument returns the newest reader document in a log tail. Decoding is
// lenient on purpose (ADR 094): a newer reader may add fields, and the version
// marker, not DisallowUnknownFields, gates an incompatible change.
func latestDocument(raw string) (nodeposture.Document, bool) {
	lines := strings.Split(raw, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var doc nodeposture.Document
		if err := json.Unmarshal([]byte(line), &doc); err == nil && doc.Version == nodeposture.Marker {
			return doc, true
		}
	}
	return nodeposture.Document{}, false
}

// nodeSettings is one node's effective kubelet settings and file posture.
func nodeSettings(files []nodeposture.File) map[string]string {
	out := kubeletSettings(files)
	maps.Copy(out, fileSettings(files))
	return out
}
