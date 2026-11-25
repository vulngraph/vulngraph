package azure

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/stretchr/testify/require"
)

type fakeCred struct{}

func (fakeCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "t", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// fakeREST answers by request path (+ raw query when the key has a "?"),
// recording what was asked. Unknown paths are 404s.
type fakeREST struct {
	mu        sync.Mutex
	responses map[string]fakeResponse
	seen      []string
}

type fakeResponse struct {
	status int
	body   string
}

func (f *fakeREST) Do(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := req.URL.Path
	f.seen = append(f.seen, req.URL.String())
	r, ok := f.responses[key+"?"+req.URL.RawQuery]
	if !ok {
		r, ok = f.responses[key]
	}
	if !ok {
		r = fakeResponse{status: http.StatusNotFound, body: `{"error":{"code":"NotFound","message":"no"}}`}
	}
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return &http.Response{
		StatusCode: r.status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(r.body)),
		Request:    req,
	}, nil
}

func fakeGraph(responses map[string]fakeResponse) (*restClient, *fakeREST) {
	f := &fakeREST{responses: responses}
	return newGraphClient(fakeCred{}, &policy.ClientOptions{Transport: f, Retry: policy.RetryOptions{MaxRetries: -1}}), f
}

func TestListAll_FollowsNextLinkAndFailsOnAnyPage(t *testing.T) {
	g, _ := fakeGraph(map[string]fakeResponse{
		"/v1.0/things":        {body: `{"value":[{"id":"a"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/things2"}`},
		"/v1.0/things2":       {body: `{"value":[{"id":"b"}]}`},
		"/v1.0/broken":        {body: `{"value":[{"id":"a"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/denied"}`},
		"/v1.0/denied":        {status: http.StatusForbidden, body: `{"error":{"code":"Authorization_RequestDenied","message":"no"}}`},
		"/v1.0/elsewhere":     {body: `{"value":[],"@odata.nextLink":"https://evil.example.com/v1.0/x"}`},
		"/v1.0/emptyResponse": {body: `{"value":[]}`},
	})
	type row struct {
		ID string `json:"id"`
	}
	ctx := context.Background()

	rows, err := listAll[row](ctx, g, "/things", nil)
	require.NoError(t, err)
	require.Equal(t, []row{{"a"}, {"b"}}, rows)

	_, err = listAll[row](ctx, g, "/broken", nil)
	require.Error(t, err, "a failed later page fails the read, never a short list")
	require.Equal(t, http.StatusForbidden, statusCode(err))
	require.Equal(t, "Authorization_RequestDenied", errorCode(err))

	_, err = listAll[row](ctx, g, "/elsewhere", nil)
	require.ErrorIs(t, err, errForeignNextLink, "the bearer token never follows a link off the API origin")

	rows, err = listAll[row](ctx, g, "/emptyResponse", nil)
	require.NoError(t, err)
	require.Empty(t, rows)
}
