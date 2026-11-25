package awsdisk

import (
	"errors"
	"strings"

	ebstypes "github.com/aws/aws-sdk-go-v2/service/ebs/types"
	"github.com/aws/smithy-go"
)

var (
	// ErrEncryptedNoKey means an encrypted snapshot could not be read because the
	// role lacks KMS access to its key. The service reports it as encrypted_no_key.
	ErrEncryptedNoKey = errors.New("awsdisk: encrypted snapshot, no KMS access")
	// ErrPermissionDenied means the role lacks an EBS or EC2 read permission.
	ErrPermissionDenied = errors.New("awsdisk: permission denied")
)

func isAccessDenied(err error) bool {
	var ebsDenied *ebstypes.AccessDeniedException
	if errors.As(err, &ebsDenied) {
		return true
	}
	var api smithy.APIError
	if !errors.As(err, &api) {
		return false
	}
	switch api.ErrorCode() {
	case "AccessDenied", "AccessDeniedException", "UnauthorizedOperation":
		return true
	}
	return false
}

// isKMSDenied reports whether the API named the snapshot's KMS key as the problem.
func isKMSDenied(err error) bool {
	var denied *ebstypes.AccessDeniedException
	if errors.As(err, &denied) && denied.Reason == ebstypes.AccessDeniedExceptionReasonDependencyAccessDenied {
		return true
	}
	var invalid *ebstypes.ValidationException
	if errors.As(err, &invalid) {
		switch invalid.Reason {
		case ebstypes.ValidationExceptionReasonInvalidCustomerKey, ebstypes.ValidationExceptionReasonInvalidGrantToken:
			return true
		}
	}
	var api smithy.APIError
	return errors.As(err, &api) && strings.Contains(strings.ToUpper(api.ErrorCode()), "KMS")
}

// classifyRead maps a block-read failure to the distinct error the service
// acts on, or returns nil when the failure is an ordinary unreadable block.
func classifyRead(err error, encrypted bool) error {
	switch {
	case isKMSDenied(err), encrypted && isAccessDenied(err):
		return ErrEncryptedNoKey
	case isAccessDenied(err):
		return ErrPermissionDenied
	}
	return nil
}
