//go:build integration

package jobs

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/connector"
)

type envelopeScope struct {
	Kind        connector.Type `json:"kind"`
	Index       int            `json:"index"`
	CloudTarget int            `json:"cloud_target_scope"`
}

func envelopeScopes(raw string, fallback int) ([]envelopeScope, error) {
	counts := map[connector.Type]int{}
	if raw == "" {
		counts[connector.TypeAWS] = fallback
	} else if err := json.Unmarshal([]byte(raw), &counts); err != nil {
		return nil, err
	}
	var scopes []envelopeScope
	for _, kind := range []connector.Type{connector.TypeAWS, connector.TypeGCP, connector.TypeKubernetes, connector.TypeGitHub} {
		n := counts[kind]
		if n < 0 || n > 10000 {
			return nil, fmt.Errorf("invalid %s scope count", kind)
		}
		for range n {
			scopes = append(scopes, envelopeScope{Kind: kind, Index: len(scopes), CloudTarget: -1})
		}
		delete(counts, kind)
	}
	if len(counts) > 0 || len(scopes) < 2 {
		return nil, fmt.Errorf("unsupported or insufficient connector scopes")
	}
	aws, gcp := -1, -1
	for _, scope := range scopes {
		if scope.Kind == connector.TypeAWS && aws < 0 {
			aws = scope.Index
		}
		if scope.Kind == connector.TypeGCP && gcp < 0 {
			gcp = scope.Index
		}
	}
	for i := range scopes {
		switch scopes[i].Kind {
		case connector.TypeKubernetes:
			scopes[i].CloudTarget = gcp
		case connector.TypeGitHub:
			scopes[i].CloudTarget = aws
		}
		if scopes[i].Kind == connector.TypeGitHub && aws < 0 {
			return nil, fmt.Errorf("repository cloud trust fixture needs an AWS scope")
		}
	}
	return scopes, nil
}

func envelopeScopeSizes(scopes []envelopeScope, resources int) []int {
	sizes := make([]int, len(scopes))
	assigned := 0
	for start := 0; start < len(scopes); {
		end := start + 1
		for end < len(scopes) && scopes[end].Kind == scopes[start].Kind {
			end++
		}
		share := resources * (end - start) / len(scopes)
		if end == len(scopes) {
			share = resources - assigned
		}
		copy(sizes[start:end], envelopeSizes(end-start, share))
		assigned += share
		start = end
	}
	return sizes
}

func (s envelopeScope) parentID() string {
	if s.Kind == connector.TypeKubernetes {
		return fmt.Sprintf("synthetic-cluster-%04d/namespace/workloads/serviceaccount/envelope", s.Index)
	}
	if s.Kind == connector.TypeGCP {
		return fmt.Sprintf("serviceAccount:envelope-%04d@synthetic.invalid", s.Index)
	}
	return envelopeID(s.Index, 0)
}

func (s envelopeScope) types() (string, string) {
	switch s.Kind {
	case connector.TypeGCP:
		return "gcp_service_account", "gce_instance"
	case connector.TypeKubernetes:
		return "k8s_service_account", "k8s_pod"
	case connector.TypeGitHub:
		return "github_repo", "github_repo"
	default:
		return "iam_role", "ec2_instance"
	}
}

func (s envelopeScope) observation(a *asset.Asset, index int) {
	parent, workload := s.types()
	a.Provider = asset.Provider(s.Kind)
	a.Type = workload
	if index == 0 {
		a.ID = s.parentID()
		a.Name = a.ID
		a.Type = parent
	}
	switch s.Kind {
	case connector.TypeAWS:
		if index > 0 {
			a.Metadata["iam_role_arn"] = s.parentID()
		}
	case connector.TypeGCP:
		a.Region = "europe-west1"
		a.AccountID = fmt.Sprintf("synthetic-project-%04d", s.Index)
		if index > 0 {
			a.Metadata["exec_role"] = s.parentID()
		}
	case connector.TypeKubernetes:
		if index > 0 {
			a.ID = fmt.Sprintf("synthetic-cluster-%04d/pod/workloads/%s", s.Index, envelopeID(s.Index, index))
			a.Name = a.ID
		}
		a.Region = fmt.Sprintf("synthetic-cluster-%04d", s.Index)
		a.AccountID = a.Region
		a.Metadata["namespace"] = "workloads"
		a.Metadata["service_account"] = "envelope"
		if index == 0 {
			a.Metadata["name"] = "envelope"
			if s.CloudTarget >= 0 {
				a.Metadata["iam.gke.io/gcp-service-account"] = fmt.Sprintf("envelope-%04d@synthetic.invalid", s.CloudTarget)
			}
		}
	case connector.TypeGitHub:
		a.Region = ""
		a.AccountID = fmt.Sprintf("synthetic-org-%04d", s.Index/2)
		a.Metadata["visibility"] = "private"
	}
}

func (s envelopeScope) enumeration() string {
	switch s.Kind {
	case connector.TypeGCP:
		return "global/compute.instances"
	case connector.TypeKubernetes:
		return fmt.Sprintf("synthetic-cluster-%04d/kubernetes:pods", s.Index)
	case connector.TypeGitHub:
		return "global/github:repos"
	default:
		return "eu-west-1/ec2:instances"
	}
}

func (s envelopeScope) target() (string, string, string) {
	parent, _ := s.types()
	if s.Kind == connector.TypeAWS {
		return s.parentID(), parent, "has_role"
	}
	if s.Kind == connector.TypeGitHub {
		return envelopeID(s.CloudTarget, 0), "iam_role", "federated_access"
	}
	return s.parentID(), parent, "executes_as"
}

func envelopeIdentity(id string) (int, int, error) {
	if strings.HasPrefix(id, "synthetic-cluster-") {
		if _, pod, ok := strings.Cut(id, "/pod/workloads/"); ok {
			return envelopeIdentity(pod)
		}
		cluster, path, ok := strings.Cut(strings.TrimPrefix(id, "synthetic-cluster-"), "/namespace/workloads/")
		if !ok {
			return 0, 0, fmt.Errorf("invalid cluster fixture id %s", id)
		}
		c, err := strconv.Atoi(cluster)
		if err != nil {
			return 0, 0, err
		}
		if path == "serviceaccount/envelope" {
			return c, 0, nil
		}
		id = strings.TrimPrefix(path, "pod/")
	}

	if strings.HasPrefix(id, "serviceAccount:envelope-") {
		part := strings.TrimSuffix(strings.TrimPrefix(id, "serviceAccount:envelope-"), "@synthetic.invalid")
		c, e := strconv.Atoi(part)
		return c, 0, e
	}
	if !strings.HasPrefix(id, "envelope-") {
		return 0, 0, fmt.Errorf("unexpected fixture id %s", id)
	}
	c, i, ok := strings.Cut(strings.TrimPrefix(id, "envelope-"), "-")
	if !ok {
		return 0, 0, fmt.Errorf("invalid fixture id %s", id)
	}
	ci, e := strconv.Atoi(c)
	if e != nil {
		return 0, 0, e
	}
	ri, e := strconv.Atoi(i)
	return ci, ri, e
}

// Interleave providers deterministically so even a partial run reaches every
// provider family before exhausting one cloud's configured scopes.
func envelopeSchedule(scopes []envelopeScope) []int {
	kinds := []connector.Type{connector.TypeAWS, connector.TypeGCP, connector.TypeKubernetes, connector.TypeGitHub}
	queues := map[connector.Type][]int{}
	for i, scope := range scopes {
		queues[scope.Kind] = append(queues[scope.Kind], i)
	}
	order := make([]int, 0, len(scopes))
	for len(order) < len(scopes) {
		for _, kind := range kinds {
			if q := queues[kind]; len(q) > 0 {
				order = append(order, q[0])
				queues[kind] = q[1:]
			}
		}
	}
	return order
}
