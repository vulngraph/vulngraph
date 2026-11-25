package gcp

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	cloudresourcemanager "google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/googleapi"

	"github.com/vulngraph/vulngraph/pkg/log"
)

// targetKey carries the swept project's identifiers (ID and number) on the
// context, so a SERVICE_DISABLED error can be checked against the project it
// names: an API disabled on the CALLER's quota project fails every call the
// same way, and must read as a failed sweep, not as "this project never
// enabled the API".
type targetKey struct{}

func withTargetProject(ctx context.Context, idents ...string) context.Context {
	return context.WithValue(ctx, targetKey{}, idents)
}

func targetIdents(ctx context.Context) []string {
	v, _ := ctx.Value(targetKey{}).([]string)
	return v
}

// resolveTarget puts the project's ID, and its number when Resource Manager
// can read it, on the context. Error messages name the project by number.
func resolveTarget(ctx context.Context, projectID string) context.Context {
	idents := []string{projectID}
	if rm, err := cloudresourcemanager.NewService(ctx); err == nil {
		if p, err := rm.Projects.Get(projectID).Context(ctx).Do(); err == nil {
			idents = append(idents, strconv.FormatInt(p.ProjectNumber, 10))
		} else {
			log.FromContext(ctx).Warn().Err(err).Msg("gcp project number unreadable; SERVICE_DISABLED errors are matched by project ID only")
		}
	}
	return withTargetProject(ctx, idents...)
}

// errorProjectPattern pulls the project out of GCP's long-standing message
// ("... has not been used in project 123 before or it is disabled").
var errorProjectPattern = regexp.MustCompile(`in project ([a-z0-9-]+)`)

// namedProject returns the project a SERVICE_DISABLED error names, from the
// google.rpc.ErrorInfo consumer ("projects/123") or the message; "" when it
// names none.
func namedProject(apiErr *googleapi.Error) string {
	for _, d := range apiErr.Details {
		m, ok := d.(map[string]any)
		if !ok {
			continue
		}
		if md, ok := m["metadata"].(map[string]any); ok {
			if c, _ := md["consumer"].(string); c != "" {
				return strings.TrimPrefix(c, "projects/")
			}
		}
	}
	if sm := errorProjectPattern.FindStringSubmatch(apiErr.Message); sm != nil {
		return sm[1]
	}
	return ""
}

// deniedErr reports a permission failure (401, or a 403 that is not
// SERVICE_DISABLED) — the answer an optional read gets when the collector's
// identity simply lacks an organization, folder or cross-project grant.
func deniedErr(ctx context.Context, err error) bool {
	var apiErr *googleapi.Error
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.Code == http.StatusUnauthorized || (apiErr.Code == http.StatusForbidden && !serviceDisabledErr(ctx, err))
}

// optionalRead records the error of a read whose grant is optional
// (organization, folder or another project's resources): permission denied
// is logged and dropped — the key it feeds stays absent, unknown — and never
// flags the sweep partial, which would stop deletion reconciliation for
// every asset type on a deployment that simply lacks the grant. Any other
// failure is kept.
func optionalRead(ctx context.Context, what string, err error, errs *[]error) {
	if err == nil {
		return
	}
	if deniedErr(ctx, err) {
		log.FromContext(ctx).Info().Err(err).Msg(what + ": permission denied — left ungraded, not counted as partial")
		return
	}
	*errs = append(*errs, err)
}

// targetMatches reports whether a named project is the swept one; with no
// name, or no known identifiers, it is assumed to be.
func targetMatches(ctx context.Context, named string) bool {
	idents := targetIdents(ctx)
	return named == "" || len(idents) == 0 || slices.Contains(idents, named)
}
