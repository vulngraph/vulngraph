// Package censyssdkgo is an inert, API-compatible stand-in for
// github.com/censys/censys-sdk-go, substituted via a `replace` directive in
// the root go.mod. Written from scratch against the single call site in
// github.com/projectdiscovery/uncover/sources/agent/censys (MIT); it contains
// no code from the upstream module.
//
// Why: the upstream module ships no LICENSE file (only a README badge), so
// redistributing it in this project's binaries has no clear grant. It reaches
// this project only through nuclei → uncover's Censys search agent, which
// Vulngraph never invokes (it scans its own inventory, not internet-search
// results). Every call fails with ErrDisabled. See README.md.
package censyssdkgo

import (
	"context"
	"errors"
	"net/http"

	"github.com/censys/censys-sdk-go/models/operations"
)

// ErrDisabled is returned by every API call.
var ErrDisabled = errors.New("censys-sdk-go: Censys integration is not compiled into this build")

// HTTPClient is the transport the upstream SDK accepts.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// SDKOption configures an SDK.
type SDKOption func(*SDK)

// SDK is the client root.
type SDK struct {
	GlobalData *GlobalData
}

// GlobalData groups the global-data search endpoints.
type GlobalData struct{}

// Search always fails with ErrDisabled.
func (*GlobalData) Search(context.Context, operations.V3GlobaldataSearchQueryRequest, ...any) (*operations.V3GlobaldataSearchQueryResponse, error) {
	return nil, ErrDisabled
}

func New(opts ...SDKOption) *SDK {
	s := &SDK{GlobalData: &GlobalData{}}
	for _, o := range opts {
		o(s)
	}
	return s
}

func WithOrganizationID(string) SDKOption { return func(*SDK) {} }
func WithSecurity(string) SDKOption       { return func(*SDK) {} }
func WithClient(HTTPClient) SDKOption     { return func(*SDK) {} }

// Int64 returns a pointer to v.
func Int64(v int64) *int64 { return &v }
