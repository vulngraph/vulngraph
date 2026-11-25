package aws

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	ecrtypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeECRAuth struct {
	out *ecr.GetAuthorizationTokenOutput
	err error
}

func (f fakeECRAuth) GetAuthorizationToken(context.Context, *ecr.GetAuthorizationTokenInput, ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error) {
	return f.out, f.err
}

func tokenOut(token string, expires *time.Time) *ecr.GetAuthorizationTokenOutput {
	return &ecr.GetAuthorizationTokenOutput{AuthorizationData: []ecrtypes.AuthorizationData{{
		AuthorizationToken: awssdk.String(token), ExpiresAt: expires,
	}}}
}

func TestECRToken(t *testing.T) {
	exp := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	good := base64.StdEncoding.EncodeToString([]byte("AWS:secret:with:colons"))

	user, pass, got, err := ecrToken(t.Context(), fakeECRAuth{out: tokenOut(good, &exp)})
	require.NoError(t, err)
	assert.Equal(t, "AWS", user)
	assert.Equal(t, "secret:with:colons", pass, "only the first colon separates user from password")
	assert.Equal(t, exp, got)

	for name, client := range map[string]fakeECRAuth{
		"api error":  {err: errors.New("AccessDenied")},
		"no data":    {out: &ecr.GetAuthorizationTokenOutput{}},
		"not base64": {out: tokenOut("%%%", &exp)},
		"no colon":   {out: tokenOut(base64.StdEncoding.EncodeToString([]byte("AWS")), &exp)},
		"empty pass": {out: tokenOut(base64.StdEncoding.EncodeToString([]byte("AWS:")), &exp)},
		"no expiry":  {out: tokenOut(good, nil)},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := ecrToken(t.Context(), client)
			require.Error(t, err)
		})
	}
}
