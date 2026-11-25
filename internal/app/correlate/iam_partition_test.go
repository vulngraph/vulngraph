package correlate

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// GovCloud and China trust principals name graph nodes like commercial ones;
// a commercial-only prefix silently dropped their trust edges.
func TestIsIAMPrincipalARN_AllPartitions(t *testing.T) {
	for _, arn := range []string{
		"arn:aws:iam::111122223333:role/r",
		"arn:aws-us-gov:iam::111122223333:role/r",
		"arn:aws-cn:iam::111122223333:user/u",
		"arn:aws-us-gov:iam::111122223333:root",
	} {
		require.True(t, isIAMPrincipalARN(arn), arn)
	}
	for _, s := range []string{"ec2.amazonaws.com", "arn:aws:iam::111122223333:oidc-provider/x", "arn:aws-iso:iam::1:role/r"} {
		require.False(t, isIAMPrincipalARN(s), s)
	}
}
