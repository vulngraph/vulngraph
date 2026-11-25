package azure

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
)

// readOnlyARM are the ARM client options every Azure collector client uses.
//
// The ARM pipeline's default registration policy answers a
// MissingSubscriptionRegistration error by REGISTERING the resource provider —
// a write no person approved. It is disabled, and in its place a GET of a
// resource collection under an unregistered provider is answered as an empty
// list: a subscription that never registered a provider cannot hold a
// resource of its types, so "none" is the observation, not a failure.
func readOnlyARM() *arm.ClientOptions {
	return &arm.ClientOptions{
		DisableRPRegistration: true,
		ClientOptions: policy.ClientOptions{
			PerCallPolicies: []policy.Policy{unregisteredProviderAsEmpty{}},
		},
	}
}

// unregisteredProviderAsEmpty rewrites a MissingSubscriptionRegistration
// error on a collection GET into an empty ARM list page. Anything else —
// another error code, a single-resource GET, a write — passes through.
type unregisteredProviderAsEmpty struct{}

func (unregisteredProviderAsEmpty) Do(req *policy.Request) (*http.Response, error) {
	resp, err := req.Next()
	if err != nil || resp.StatusCode < http.StatusBadRequest || req.Raw().Method != http.MethodGet ||
		!isCollectionPath(req.Raw().URL.Path) {
		return resp, err
	}
	body, readErr := runtime.Payload(resp)
	if readErr != nil {
		return resp, err
	}
	var e struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &e) != nil || !unregisteredProviderCodes[e.Error.Code] {
		return resp, nil
	}
	const empty = `{"value":[]}`
	resp.StatusCode = http.StatusOK
	resp.Status = "200 OK"
	resp.Header.Set("Content-Type", "application/json")
	resp.ContentLength = int64(len(empty))
	resp.Body = io.NopCloser(strings.NewReader(empty))
	return resp, nil
}

// unregisteredProviderCodes are the ARM error codes for a resource provider
// the subscription never registered.
var unregisteredProviderCodes = map[string]bool{
	"MissingSubscriptionRegistration":        true,
	"MissingRegistrationForResourceProvider": true,
	"SubscriptionNotRegistered":              true,
}

// isCollectionPath reports whether an ARM path names a resource collection:
// an odd number of segments after /providers/{namespace} ("vaults",
// "vaults/kv/keys"), as opposed to one resource ("vaults/kv").
func isCollectionPath(path string) bool {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	for i := len(parts) - 2; i >= 0; i-- {
		if strings.EqualFold(parts[i], "providers") {
			return (len(parts)-i-2)%2 == 1
		}
	}
	return false
}
