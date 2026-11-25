package aws

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"
)

func TestIsPermanentAWSErr(t *testing.T) {
	// A denied assume-role / access surfaces as one of these codes and will fail
	// identically on every retry — permanent.
	for _, code := range []string{"AccessDenied", "UnauthorizedOperation", "AuthFailure", "InvalidClientTokenId", "ExpiredToken", "ExpiredTokenException", "UnrecognizedClientException", "SignatureDoesNotMatch"} {
		err := fmt.Errorf("Collect: %w", &smithy.GenericAPIError{Code: code, Message: "denied"})
		require.True(t, isPermanentAWSErr(err), "code %s should be permanent", code)
	}

	// Transient conditions must stay retryable.
	require.False(t, isPermanentAWSErr(&smithy.GenericAPIError{Code: "Throttling"}))
	require.False(t, isPermanentAWSErr(&smithy.GenericAPIError{Code: "InternalError"}))
	require.False(t, isPermanentAWSErr(errors.New("dial tcp: i/o timeout")))
}
