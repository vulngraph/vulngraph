package ciem

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrust_ConditionProofRequiresFixedCaller(t *testing.T) {
	for _, tt := range []struct {
		name, positive, negative, key, value string
		public                               bool
	}{
		{"self account", "StringEquals", "StringNotEquals", "aws:PrincipalAccount", "${aws:PrincipalAccount}", true},
		{"self ARN", "ArnEquals", "ArnNotEquals", "aws:PrincipalArn", "${aws:PrincipalArn}", true},
		{"wildcard account ARN", "ArnEquals", "ArnNotEquals", "aws:PrincipalArn", "arn:aws:iam::*:role/deploy", true},
		{"fixed account ARN wildcard role", "ArnEquals", "ArnNotEquals", "aws:PrincipalArn", "arn:aws:iam::111122223333:role/*", false},
		{"fixed exact ARN", "ArnEquals", "ArnNotEquals", "aws:PrincipalArn", "arn:aws:iam::111122223333:role/deploy", false},
		{"fixed exact account", "StringEquals", "StringNotEquals", "aws:PrincipalAccount", "111122223333", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			allowCondition := fmt.Sprintf(`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole","Condition":{%q:{%q:%q}}}}`, tt.positive, tt.key, tt.value)
			denyCondition := fmt.Sprintf(`{"Version":"2012-10-17","Statement":[
				{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"},
				{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole","Condition":{%q:{%q:%q}}}]}`, tt.negative, tt.key, tt.value)
			for _, doc := range []string{allowCondition, denyCondition} {
				eval := EvaluateTrustPolicy(doc)
				require.Equal(t, tt.public, eval.PublicEntry, doc)
				if tt.public {
					require.Equal(t, TrustEntryPublic, eval.EntryClass(selfAccount))
					require.Empty(t, eval.ConfinedBy)
				} else {
					require.Equal(t, TrustEntryCrossAcct, eval.EntryClass(selfAccount))
				}
			}
		})
	}
}

func TestTrust_ComplementaryNetworkDenyDoesNotConfine(t *testing.T) {
	eval := EvaluateTrustPolicy(`{"Statement":[
		{"Effect":"Allow","Principal":"*","Action":"sts:AssumeRole"},
		{"Effect":"Deny","Principal":"*","Action":"sts:AssumeRole","Condition":{
			"NotIpAddress":{"aws:SourceIp":["0.0.0.0/1","::/1"]},
			"NotIpAddressIfExists":{"aws:SourceIp":["128.0.0.0/1","8000::/1"]}}}]}`)
	require.True(t, eval.PublicEntry)
	require.Empty(t, eval.ConfinedBy)
}
