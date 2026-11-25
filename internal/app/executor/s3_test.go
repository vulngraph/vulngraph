package executor

import (
	"errors"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"
)

// s3_block_public is ungated because its audit row restores the bucket
// exactly (plan.go never): that holds only if the earlier bucket-level block
// is read and recorded, and a failed read must stop the call rather than
// record "none".
func TestPublicAccessBlockBefore(t *testing.T) {
	partial := &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: &s3types.PublicAccessBlockConfiguration{
		BlockPublicAcls: awssdk.Bool(true), BlockPublicPolicy: awssdk.Bool(false),
	}}
	cases := []struct {
		name    string
		out     *s3.GetPublicAccessBlockOutput
		err     error
		want    string
		wantErr bool
	}{
		{"no block on the bucket", nil, &smithy.GenericAPIError{Code: "NoSuchPublicAccessBlockConfiguration"}, "none", false},
		{"partial block, unset flags are false", partial, nil,
			"BlockPublicAcls=true,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false", false},
		{"access denied is not none", nil, &smithy.GenericAPIError{Code: "AccessDenied"}, "", true},
		{"transport error is not none", nil, errors.New("dial tcp: i/o timeout"), "", true},
		{"empty response is not none", &s3.GetPublicAccessBlockOutput{}, nil, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := publicAccessBlockBefore(tc.out, tc.err)
			if tc.wantErr {
				require.Error(t, err)
				require.Empty(t, got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}
