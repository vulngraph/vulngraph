package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/connector"
)

type fakeConnectorLister struct {
	conns map[string]connector.Connector
	order []string
}

func (f fakeConnectorLister) List(context.Context, bool) ([]connector.Connector, error) {
	out := make([]connector.Connector, 0, len(f.order))
	for _, id := range f.order {
		c := f.conns[id]
		c.Config = nil // List never decrypts
		out = append(out, c)
	}
	return out, nil
}

func (f fakeConnectorLister) Get(_ context.Context, id string) (connector.Connector, error) {
	return f.conns[id], nil
}

func TestConnectorAccount(t *testing.T) {
	assert.Equal(t, "111111111111", connectorAccount(map[string]string{"account_id": "111111111111", "role_arn": "arn:aws:iam::222222222222:role/x"}))
	assert.Equal(t, "222222222222", connectorAccount(map[string]string{"role_arn": "arn:aws:iam::222222222222:role/GraphReadOnly"}))
	assert.Equal(t, "333333333333", connectorAccount(map[string]string{"role_arn": "arn:aws-cn:iam::333333333333:role/r"}))
	assert.Empty(t, connectorAccount(map[string]string{"aws_access_key_id": "AKIA"}))
	assert.Empty(t, connectorAccount(map[string]string{"role_arn": "not-an-arn"}))
}

func TestECRTokenSource(t *testing.T) {
	lister := fakeConnectorLister{
		order: []string{"gh", "a", "b"},
		conns: map[string]connector.Connector{
			"gh": {ID: "gh", Type: connector.TypeGitHub, Config: map[string]string{"account_id": "222222222222"}},
			"a":  {ID: "a", Type: connector.TypeAWS, Config: map[string]string{"role_arn": "arn:aws:iam::111111111111:role/r", "region": "us-east-1"}},
			"b":  {ID: "b", Type: connector.TypeAWS, Config: map[string]string{"role_arn": "arn:aws:iam::222222222222:role/r", "region": "us-east-1"}},
		},
	}
	exp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var gotRole, gotRegion string
	src := &ecrTokenSource{connectors: lister, mint: func(_ context.Context, cfg map[string]string, region string) (string, string, time.Time, error) {
		gotRole, gotRegion = cfg["role_arn"], region
		return "AWS", "pw", exp, nil
	}}

	tok, err := src.Token(t.Context(), "222222222222", "eu-west-1")
	require.NoError(t, err)
	assert.Equal(t, "arn:aws:iam::222222222222:role/r", gotRole, "the registry account's AWS connector mints the token, never a GitHub connector")
	assert.Equal(t, "eu-west-1", gotRegion, "minted in the registry's region")
	assert.Equal(t, "pw", tok.Password)
	assert.Equal(t, exp, tok.ExpiresAt)

	_, err = src.Token(t.Context(), "999999999999", "eu-west-1")
	require.ErrorContains(t, err, "no enabled AWS connector for account 999999999999")

	src.mint = func(context.Context, map[string]string, string) (string, string, time.Time, error) {
		return "", "", time.Time{}, errors.New("AccessDenied: ecr:GetAuthorizationToken")
	}
	_, err = src.Token(t.Context(), "111111111111", "eu-west-1")
	require.ErrorContains(t, err, "AccessDenied")
}
