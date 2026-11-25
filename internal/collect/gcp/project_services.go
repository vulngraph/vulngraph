package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	accessapproval "google.golang.org/api/accessapproval/v1"
	accesscontextmanager "google.golang.org/api/accesscontextmanager/v1"
	binaryauthorization "google.golang.org/api/binaryauthorization/v1"
	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	essentialcontacts "google.golang.org/api/essentialcontacts/v1"
	"google.golang.org/api/googleapi"
	serviceusage "google.golang.org/api/serviceusage/v1"
)

// projectServicesAPI reads the project-wide settings that each live behind
// their own small API: Essential Contacts, Access Approval, Service Usage,
// VPC Service Controls and the Binary Authorization policy.
type projectServicesAPI interface {
	// ContactCategories returns the notification categories the project's
	// essential contacts (its own and inherited) subscribe to.
	ContactCategories(ctx context.Context, projectID string) ([]string, error)
	// OrgContactCategories is the same for contacts set on the organization.
	OrgContactCategories(ctx context.Context, org string) ([]string, error)
	// AccessApproval returns the project's effective Access Approval
	// settings; a nil settings with a nil error means none are configured.
	AccessApproval(ctx context.Context, projectID string) (*accessapproval.AccessApprovalSettings, error)
	OrgAccessApproval(ctx context.Context, org string) (*accessapproval.AccessApprovalSettings, error)
	ServiceState(ctx context.Context, projectID, service string) (string, error)
	// Perimeters lists the organization's regular service perimeters.
	Perimeters(ctx context.Context, org string) ([]*accesscontextmanager.ServicePerimeter, error)
	ProjectNumber(ctx context.Context, projectID string) (string, error)
	Ancestry(ctx context.Context, projectID string) ([]string, error)
	BinAuthzPolicy(ctx context.Context, projectID string) (*binaryauthorization.Policy, error)
}

// essentialContactCategories are the categories CIS GCP 1.17 requires a
// contact for; a contact subscribed to ALL covers every one.
var essentialContactCategories = []string{"LEGAL", "SECURITY", "SUSPENSION", "TECHNICAL", "TECHNICAL_INCIDENTS"}

// collectProjectServices evaluates CIS GCP 1.17, 2.14, 2.16 and 3.8.
//
// Essential Contacts and Access Approval are organization-inherited: when
// the organization's own setting is readable, it lands once on the
// organization settings asset, and the project records only that it is
// covered (a gap at the project is the organization's gap, reported there).
// When the organization is not readable, the project's effective setting
// (which the APIs resolve through the hierarchy) is graded on the project.
// Organization reads are optional grants: denied is unknown, never partial.
func collectProjectServices(ctx context.Context, client projectServicesAPI, projectID string) (map[string]string, orgSettings, error) {
	md := map[string]string{}
	var errs []error
	ancestors, err := client.Ancestry(ctx, projectID)
	optionalRead(ctx, "gcp project ancestry", err, &errs)
	org := orgSettings{md: map[string]string{}}
	for _, a := range ancestors {
		if strings.HasPrefix(a, "organizations/") {
			org.org = a
		}
	}

	orgContacts := false
	if org.org != "" {
		cats, err := client.OrgContactCategories(ctx, org.org)
		optionalRead(ctx, "gcp organization essential contacts", err, &errs)
		if err == nil {
			org.md["essential_contacts_missing"] = strings.Join(missingContactCategories(cats), ",")
			orgContacts = true
		}
	}
	// The project read resolves inherited contacts itself. With the API
	// disabled in the project, organization contacts are unreadable from
	// here, so the answer stays unknown.
	if cats, err := client.ContactCategories(ctx, projectID); err == nil {
		if missing := missingContactCategories(cats); !orgContacts || len(missing) == 0 {
			md["essential_contacts_missing"] = strings.Join(missing, ",")
		}
	} else if !serviceDisabledErr(ctx, err) {
		errs = append(errs, err)
	}

	orgApproval := false
	if org.org != "" {
		s, err := client.OrgAccessApproval(ctx, org.org)
		optionalRead(ctx, "gcp organization access approval", err, &errs)
		if err == nil {
			org.md["access_approval_enrolled"] = strconv.FormatBool(s != nil && len(s.EnrolledServices) > 0)
			orgApproval = true
		}
	}
	// Enrolled directly or through an ancestor. The API disabled in the
	// project is an explicit off: nothing can be enrolled there.
	s, err := client.AccessApproval(ctx, projectID)
	enrolled := err == nil && s != nil && (len(s.EnrolledServices) > 0 || s.EnrolledAncestor)
	switch {
	case err != nil && !serviceDisabledErr(ctx, err):
		errs = append(errs, err)
	case enrolled || !orgApproval:
		md["access_approval_enrolled"] = strconv.FormatBool(enrolled)
	}

	// Cloud Asset Inventory is "enabled" when its API is.
	if state, err := client.ServiceState(ctx, projectID, "cloudasset.googleapis.com"); err == nil {
		md["cloud_asset_api_enabled"] = strconv.FormatBool(state == "ENABLED")
	} else {
		errs = append(errs, err)
	}

	// Perimeter membership is a per-project fact (the organization's
	// perimeters contain some projects and not others), so it stays on the
	// project.
	if org.org != "" {
		v, err := projectInPerimeter(ctx, client, projectID, org.org)
		optionalRead(ctx, "gcp VPC Service Controls perimeters", err, &errs)
		if err == nil {
			md["vpc_sc_perimeter"] = v
		}
	}

	if err := errors.Join(errs...); err != nil {
		return md, org, fmt.Errorf("collectProjectServices: %w", err)
	}
	return md, org, nil
}

func missingContactCategories(have []string) []string {
	if slices.Contains(have, "ALL") {
		return nil
	}
	var missing []string
	for _, c := range essentialContactCategories {
		if !slices.Contains(have, c) {
			missing = append(missing, c)
		}
	}
	return missing
}

// projectInPerimeter returns the names of the regular, enforced service
// perimeters that contain the project and restrict at least one service
// (CIS GCP 3.8); "" means the project is in none. VPC Service Controls are
// an organization feature: a project outside one is not graded.
func projectInPerimeter(ctx context.Context, client projectServicesAPI, projectID, org string) (string, error) {
	number, err := client.ProjectNumber(ctx, projectID)
	if err != nil {
		return "", fmt.Errorf("projectInPerimeter: %w", err)
	}
	perimeters, err := client.Perimeters(ctx, org)
	if err != nil {
		return "", fmt.Errorf("projectInPerimeter: %w", err)
	}
	var in []string
	for _, p := range perimeters {
		if p == nil || p.Status == nil || p.PerimeterType == "PERIMETER_TYPE_BRIDGE" || len(p.Status.RestrictedServices) == 0 {
			continue
		}
		if slices.Contains(p.Status.Resources, "projects/"+number) {
			in = append(in, lastSegment(p.Name))
		}
	}
	return strings.Join(in, ","), nil
}

// binAuthzRule resolves the admission rule the project policy applies to one
// cluster ("<location>.<name>" overrides the default) and reports whether it
// admits untrusted images: ALWAYS_ALLOW, or a dry-run rule that only logs.
func binAuthzRule(p *binaryauthorization.Policy, location, name string) (mode string, allowsAll bool) {
	rule := p.DefaultAdmissionRule
	if r, ok := p.ClusterAdmissionRules[location+"."+name]; ok {
		rule = &r
	}
	if rule == nil {
		return "ALWAYS_ALLOW", true
	}
	mode = rule.EvaluationMode
	if rule.EnforcementMode == "DRYRUN_AUDIT_LOG_ONLY" {
		return mode + "/DRYRUN", true
	}
	return mode, mode == "ALWAYS_ALLOW"
}

// newProjectServicesClient builds the real projectServicesAPI via ADC.
func newProjectServicesClient(ctx context.Context) (projectServicesAPI, error) {
	ec, err := essentialcontacts.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newProjectServicesClient: %w", err)
	}
	aa, err := accessapproval.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newProjectServicesClient: %w", err)
	}
	su, err := serviceusage.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newProjectServicesClient: %w", err)
	}
	acm, err := accesscontextmanager.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newProjectServicesClient: %w", err)
	}
	rm, err := cloudresourcemanager.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newProjectServicesClient: %w", err)
	}
	ba, err := binaryauthorization.NewService(ctx)
	if err != nil {
		return nil, fmt.Errorf("newProjectServicesClient: %w", err)
	}
	return &realProjectServices{ec: ec, aa: aa, su: su, acm: acm, rm: rm, ba: ba}, nil
}

type realProjectServices struct {
	ec  *essentialcontacts.Service
	aa  *accessapproval.Service
	su  *serviceusage.Service
	acm *accesscontextmanager.Service
	rm  *cloudresourcemanager.Service
	ba  *binaryauthorization.Service
}

// contactSet collects the categories valid contacts subscribe to.
func contactSet(set map[string]bool) func(*essentialcontacts.GoogleCloudEssentialcontactsV1ComputeContactsResponse) error {
	return func(p *essentialcontacts.GoogleCloudEssentialcontactsV1ComputeContactsResponse) error {
		for _, c := range p.Contacts {
			if c == nil || c.ValidationState == "INVALID" {
				continue
			}
			for _, s := range c.NotificationCategorySubscriptions {
				set[s] = true
			}
		}
		return nil
	}
}

func (r *realProjectServices) ContactCategories(ctx context.Context, projectID string) ([]string, error) {
	set := map[string]bool{}
	if err := r.ec.Projects.Contacts.Compute("projects/"+projectID).Pages(ctx, contactSet(set)); err != nil {
		return nil, fmt.Errorf("ContactCategories: %w", err)
	}
	return sortedKeys(set), nil
}

func (r *realProjectServices) OrgContactCategories(ctx context.Context, org string) ([]string, error) {
	set := map[string]bool{}
	if err := r.ec.Organizations.Contacts.Compute(org).Pages(ctx, contactSet(set)); err != nil {
		return nil, fmt.Errorf("OrgContactCategories: %w", err)
	}
	return sortedKeys(set), nil
}

func (r *realProjectServices) OrgAccessApproval(ctx context.Context, org string) (*accessapproval.AccessApprovalSettings, error) {
	return approvalSettings(r.aa.Organizations.GetAccessApprovalSettings(org + "/accessApprovalSettings").Context(ctx).Do())
}

func (r *realProjectServices) AccessApproval(ctx context.Context, projectID string) (*accessapproval.AccessApprovalSettings, error) {
	return approvalSettings(r.aa.Projects.GetAccessApprovalSettings("projects/" + projectID + "/accessApprovalSettings").Context(ctx).Do())
}

// approvalSettings reads "no settings" (404) as none configured.
func approvalSettings(s *accessapproval.AccessApprovalSettings, err error) (*accessapproval.AccessApprovalSettings, error) {
	var apiErr *googleapi.Error
	if errors.As(err, &apiErr) && apiErr.Code == http.StatusNotFound {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("AccessApproval: %w", err)
	}
	return s, nil
}

func (r *realProjectServices) ServiceState(ctx context.Context, projectID, service string) (string, error) {
	s, err := r.su.Services.Get("projects/" + projectID + "/services/" + service).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("ServiceState %s: %w", service, err)
	}
	return s.State, nil
}

func (r *realProjectServices) Perimeters(ctx context.Context, org string) ([]*accesscontextmanager.ServicePerimeter, error) {
	var policies []string
	if err := r.acm.AccessPolicies.List().Parent(org).Pages(ctx, func(p *accesscontextmanager.ListAccessPoliciesResponse) error {
		for _, ap := range p.AccessPolicies {
			if ap != nil {
				policies = append(policies, ap.Name)
			}
		}
		return nil
	}); err != nil {
		return nil, fmt.Errorf("Perimeters: %w", err)
	}
	var out []*accesscontextmanager.ServicePerimeter
	for _, pol := range policies {
		if err := r.acm.AccessPolicies.ServicePerimeters.List(pol).Pages(ctx, func(p *accesscontextmanager.ListServicePerimetersResponse) error {
			out = append(out, p.ServicePerimeters...)
			return nil
		}); err != nil {
			return nil, fmt.Errorf("Perimeters %s: %w", pol, err)
		}
	}
	return out, nil
}

func (r *realProjectServices) ProjectNumber(ctx context.Context, projectID string) (string, error) {
	p, err := r.rm.Projects.Get(projectID).Context(ctx).Do()
	if err != nil {
		return "", fmt.Errorf("ProjectNumber: %w", err)
	}
	return strconv.FormatInt(p.ProjectNumber, 10), nil
}

func (r *realProjectServices) Ancestry(ctx context.Context, projectID string) ([]string, error) {
	return projectAncestry(ctx, r.rm, projectID)
}

func (r *realProjectServices) BinAuthzPolicy(ctx context.Context, projectID string) (*binaryauthorization.Policy, error) {
	p, err := r.ba.Projects.GetPolicy("projects/" + projectID + "/policy").Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("BinAuthzPolicy: %w", err)
	}
	return p, nil
}
