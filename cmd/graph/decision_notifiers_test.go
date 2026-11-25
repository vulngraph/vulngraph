package main

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/govern"
)

func TestDecisionNotifiers(t *testing.T) {
	secret := strings.Repeat("s", govern.MinTokenSecretBytes)
	cases := []struct {
		name    string
		env     map[string]string
		want    int
		wantErr error
	}{
		{name: "slack only", env: map[string]string{}, want: 1},
		{name: "webhook and slack", env: map[string]string{
			"DECISION_WEBHOOK_URL": "https://hooks.example.com/d", "DECISION_WEBHOOK_SECRET": "whsec",
		}, want: 2},
		{name: "smtp adds email", env: map[string]string{
			"SMTP_HOST": "smtp.example.com", "SMTP_FROM": "a@example.com", "SMTP_TO": "b@example.com",
			"APPROVAL_BASE_URL": "https://graph.example.com", "APPROVAL_TOKEN_SECRET": secret,
		}, want: 2},
		// A configured-but-broken SMTP channel fails the worker rather than
		// silently dropping approval emails.
		{name: "smtp with short secret", env: map[string]string{
			"SMTP_HOST": "smtp.example.com", "APPROVAL_TOKEN_SECRET": "short",
		}, wantErr: govern.ErrTokenSecretShort},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decisionNotifiers(context.Background(), func(k string) string { return tc.env[k] }, &capturedDispatch{})
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Len(t, got, tc.want)
		})
	}
}
