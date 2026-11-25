package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/googleapi"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// Boolean policies override their parents. Read the nearest policy verbatim:
// GetEffectivePolicy evaluates tag conditions for the PROJECT, which can differ
// from the bucket. Without bucket-tag evaluation, conditional rules stay unknown.
// https://docs.cloud.google.com/storage/docs/org-policy-constraints#conditionally_allow_or_deny_organization_policy_constraints
func (r *realGCS) projectPublicAccessPrevention(ctx context.Context, projectID string) string {
	state, err := r.inheritedPublicAccessPrevention(ctx, projectID)
	if err != nil {
		log.FromContext(ctx).Warn().Err(err).Str("project", projectID).
			Msg("gcs: inherited public-access prevention unresolved; protection and exposure unknown")
	}
	return state
}

func (r *realGCS) inheritedPublicAccessPrevention(ctx context.Context, projectID string) (string, error) {
	if r.policies == nil {
		return "", fmt.Errorf("inheritedPublicAccessPrevention: policy client unavailable")
	}
	p, err := r.publicAccessPreventionPolicy(ctx, "projects/"+projectID)
	if !gcsPolicyNotFound(err) {
		return gcsPolicyResult(p, err)
	}
	if r.rm == nil {
		return "", fmt.Errorf("inheritedPublicAccessPrevention: ancestry client unavailable")
	}
	ancestry, err := r.rm.Projects.GetAncestry(projectID, &cloudresourcemanager.GetAncestryRequest{}).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("inheritedPublicAccessPrevention: ancestry: %w", err)
	}
	parents, err := gcsPolicyParents(ancestry)
	if err != nil {
		return "", err
	}
	for _, parent := range parents {
		p, err := r.publicAccessPreventionPolicy(ctx, parent)
		if !gcsPolicyNotFound(err) {
			return gcsPolicyResult(p, err)
		}
	}
	// The complete hierarchy contains no policy. This constraint defaults to
	// allowing public grants; the bucket's own setting is applied separately.
	return "not_enforced", nil
}

// The SDK flattens the rule's enforce oneof to bool, losing the distinction
// between explicit false and an empty/unsupported rule. Decode the wire value
// so only an observed boolean can establish either enforcement verdict.
type gcsPreventionPolicy struct {
	Spec *struct {
		InheritFromParent bool                         `json:"inheritFromParent"`
		Reset             bool                         `json:"reset"`
		Rules             []map[string]json.RawMessage `json:"rules"`
	} `json:"spec"`
}

func (r *realGCS) publicAccessPreventionPolicy(ctx context.Context, resource string) (*gcsPreventionPolicy, error) {
	parts := strings.Split(resource, "/")
	if len(parts) != 2 || parts[1] == "" || (parts[0] != "projects" && parts[0] != "folders" && parts[0] != "organizations") {
		return nil, fmt.Errorf("publicAccessPreventionPolicy: invalid resource %q", resource)
	}
	u := "https://orgpolicy.googleapis.com/v2/" + parts[0] + "/" + url.PathEscape(parts[1]) + "/policies/storage.publicAccessPrevention"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("publicAccessPreventionPolicy: %w", err)
	}
	resp, err := r.policies.Do(req)
	if err != nil {
		return nil, fmt.Errorf("publicAccessPreventionPolicy %s: %w", resource, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("publicAccessPreventionPolicy: read: %w", err)
	}
	if err := googleapi.CheckResponseWithBody(resp, body); err != nil {
		return nil, fmt.Errorf("publicAccessPreventionPolicy %s: %w", resource, err)
	}
	var p gcsPreventionPolicy
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("publicAccessPreventionPolicy: decode: %w", err)
	}
	return &p, nil
}

func gcsPolicyNotFound(err error) bool {
	var apiErr *googleapi.Error
	return errors.As(err, &apiErr) && apiErr.Code == http.StatusNotFound
}

func gcsPolicyResult(p *gcsPreventionPolicy, err error) (string, error) {
	if err != nil {
		return "", err
	}
	state := gcsPreventionState(p)
	if state == "" {
		return "", fmt.Errorf("publicAccessPreventionPolicy: conditional or unsupported boolean policy")
	}
	return state, nil
}

func gcsPreventionState(p *gcsPreventionPolicy) string {
	if p == nil || p.Spec == nil || p.Spec.InheritFromParent {
		return ""
	}
	if p.Spec.Reset && len(p.Spec.Rules) == 0 {
		return "not_enforced"
	}
	if p.Spec.Reset || len(p.Spec.Rules) != 1 {
		return ""
	}
	rule := p.Spec.Rules[0]
	if len(rule) != 1 {
		return ""
	}
	var enforce *bool
	if err := json.Unmarshal(rule["enforce"], &enforce); err != nil || enforce == nil {
		return ""
	}
	if *enforce {
		return "enforced"
	}
	return "not_enforced"
}

func gcsPolicyParents(ancestry *cloudresourcemanager.GetAncestryResponse) ([]string, error) {
	if ancestry == nil || len(ancestry.Ancestor) == 0 {
		return nil, fmt.Errorf("gcsPolicyParents: empty ancestry")
	}
	var parents []string
	for i, a := range ancestry.Ancestor {
		if a == nil || a.ResourceId == nil || a.ResourceId.Id == "" {
			return nil, fmt.Errorf("gcsPolicyParents: incomplete ancestor")
		}
		kind := a.ResourceId.Type
		switch {
		case i == 0 && kind == "project":
		case i > 0 && i == len(ancestry.Ancestor)-1 && kind == "organization":
			parents = append(parents, "organizations/"+a.ResourceId.Id)
		case i > 0 && i < len(ancestry.Ancestor)-1 && kind == "folder":
			parents = append(parents, "folders/"+a.ResourceId.Id)
		default:
			return nil, fmt.Errorf("gcsPolicyParents: invalid ancestor order or missing root")
		}
	}
	return parents, nil
}
