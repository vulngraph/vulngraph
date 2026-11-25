package aws

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSQSEncryption(t *testing.T) {
	tests := []struct {
		name  string
		attrs map[string]string
		want  string
		ok    bool
	}{
		{"sse-kms", map[string]string{"KmsMasterKeyId": "alias/aws/sqs", "SqsManagedSseEnabled": "false"}, "kms", true},
		{"sse-sqs", map[string]string{"SqsManagedSseEnabled": "true"}, "sqs", true},
		{"unencrypted", map[string]string{"SqsManagedSseEnabled": "false"}, "none", true},
		// Neither attribute came back: nothing was observed.
		{"not returned", map[string]string{}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sqsEncryption(tt.attrs)
			require.Equal(t, tt.ok, ok)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestSQSQueueCarriesEncryption(t *testing.T) {
	now := time.Now()
	q, err := collectSQSQueues(context.Background(), &fakeSQS{
		urls:  []string{"https://sqs.eu-west-1.amazonaws.com/1/orders"},
		extra: map[string]string{"SqsManagedSseEnabled": "false"},
	}, "eu-west-1", "1", now)
	require.NoError(t, err)
	require.Equal(t, "none", q[0].Metadata["sse"])

	// A failed attribute read leaves the queue's encryption unknown.
	q, err = collectSQSQueues(context.Background(), &fakeSQS{
		urls:      []string{"https://sqs.eu-west-1.amazonaws.com/1/orders"},
		policyErr: errors.New("AccessDenied"),
	}, "eu-west-1", "1", now)
	require.NoError(t, err)
	require.NotContains(t, q[0].Metadata, "sse")
}
