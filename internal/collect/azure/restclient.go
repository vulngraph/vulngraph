package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
)

// Microsoft Graph v1.0. Every call made through it is a GET; the application
// permissions it needs are listed in docs/iam/azure-permissions.md.
const graphBaseURL = "https://graph.microsoft.com/v1.0"

var graphScopes = []string{"https://graph.microsoft.com/.default"}

// restClient issues read-only GETs against a JSON REST API (Microsoft Graph,
// or ARM resource providers that have no SDK module here) through an azcore
// pipeline, so it gets the same bearer-token handling and retry policy —
// including 429 Retry-After — as every ARM SDK client.
type restClient struct {
	pl   runtime.Pipeline
	base string // scheme://host[/prefix]; also the only origin nextLinks may point at
}

// newGraphClient returns a Microsoft Graph client. opts is for tests (a fake
// transport); production passes nil.
func newGraphClient(cred azcore.TokenCredential, opts *policy.ClientOptions) *restClient {
	pl := runtime.NewPipeline("graph-azure-collector", "v1.0.0", runtime.PipelineOptions{
		PerRetry: []policy.Policy{runtime.NewBearerTokenPolicy(cred, graphScopes, nil)},
	}, opts)
	return &restClient{pl: pl, base: graphBaseURL}
}

// newARMRestClient returns a client for raw ARM GETs (each caller pins its own
// api-version in the path).
func newARMRestClient(cred azcore.TokenCredential, opts *arm.ClientOptions) (*restClient, error) {
	c, err := arm.NewClient("graph-azure-collector", "v1.0.0", cred, opts)
	if err != nil {
		return nil, fmt.Errorf("newARMRestClient: %w", err)
	}
	return &restClient{pl: c.Pipeline(), base: strings.TrimSuffix(c.Endpoint(), "/")}, nil
}

// errForeignNextLink rejects a pagination link that leaves the API's origin:
// following it would send the bearer token to another host.
var errForeignNextLink = errors.New("azure rest: nextLink points outside the API origin")

// getJSON GETs path (relative to base, or an absolute nextLink on the same
// origin) and decodes the JSON body into out. Any non-200 is an error, so a
// caller never mistakes a 403 for an empty answer.
func (c *restClient) getJSON(ctx context.Context, path string, header map[string]string, out any) error {
	target := path
	if !strings.HasPrefix(path, "https://") {
		target = c.base + path
	} else if !sameOrigin(path, c.base) {
		return errForeignNextLink
	}
	req, err := runtime.NewRequest(ctx, http.MethodGet, target)
	if err != nil {
		return fmt.Errorf("getJSON: %w", err)
	}
	req.Raw().Header.Set("Accept", "application/json")
	for k, v := range header {
		req.Raw().Header.Set(k, v)
	}
	resp, err := c.pl.Do(req)
	if err != nil {
		return fmt.Errorf("getJSON: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return fmt.Errorf("getJSON: %w", runtime.NewResponseError(resp))
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("getJSON: decode: %w", err)
	}
	return nil
}

// restPage is one page of a Graph (@odata.nextLink) or ARM (nextLink) list.
type restPage[T any] struct {
	Value     []T    `json:"value"`
	ODataNext string `json:"@odata.nextLink"`
	NextLink  string `json:"nextLink"`
}

// maxRestPages bounds a pagination loop against a server that keeps handing
// back links. Hitting it is a failed read, never a short list.
const maxRestPages = 2000

// listAll reads every page of a list endpoint. A failure on any page fails the
// whole read: a partial page sequence must never look like a short list.
func listAll[T any](ctx context.Context, c *restClient, path string, header map[string]string) ([]T, error) {
	var out []T
	next := path
	for range maxRestPages {
		var page restPage[T]
		if err := c.getJSON(ctx, next, header, &page); err != nil {
			return nil, fmt.Errorf("listAll %s: %w", path, err)
		}
		out = append(out, page.Value...)
		next = page.ODataNext
		if next == "" {
			next = page.NextLink
		}
		if next == "" {
			return out, nil
		}
	}
	return nil, fmt.Errorf("listAll %s: more than %d pages", path, maxRestPages)
}

func sameOrigin(raw, base string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	b, err := url.Parse(base)
	if err != nil {
		return false
	}
	return u.Scheme == b.Scheme && strings.EqualFold(u.Host, b.Host)
}

// statusCode is the HTTP status of an Azure/Graph response error, or 0.
func statusCode(err error) int {
	if re, ok := errors.AsType[*azcore.ResponseError](err); ok {
		return re.StatusCode
	}
	return 0
}

// errorCode is the service error code of an Azure/Graph response error
// (e.g. "MissingSubscriptionRegistration"), or "".
func errorCode(err error) string {
	if re, ok := errors.AsType[*azcore.ResponseError](err); ok {
		return re.ErrorCode
	}
	return ""
}
