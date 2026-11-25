package azure

import (
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

// isUnregisteredProvider reports an ARM MissingSubscriptionRegistration error
// (a backstop to readOnlyARM's rewrite, for clients built with other options):
// the subscription has never registered the resource provider, so it holds no
// resource of that type. A listing that gets it on its first page is an
// observed empty listing, not a failed read.
func isUnregisteredProvider(err error) bool {
	re, ok := errors.AsType[*azcore.ResponseError](err)
	return ok && re.ErrorCode == "MissingSubscriptionRegistration"
}
