package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseINI_ProfilesKeysSecretsRegions(t *testing.T) {
	in := `[example]
aws_access_key_id = AKIA111
aws_secret_access_key = secret111
region = eu-west-1

[secondary]
aws_access_key_id = AKIA222
aws_secret_access_key = secret222
`
	m := parseINI(in)

	require.Equal(t, "AKIA111", m["example"])
	require.Equal(t, "secret111", m["__secret__example"])
	require.Equal(t, "eu-west-1", m["__region__example"])

	require.Equal(t, "AKIA222", m["secondary"])
	require.Equal(t, "secret222", m["__secret__secondary"])
	require.Empty(t, m["__region__secondary"]) // no region line for secondary
}

func TestParseINI_IgnoresJunkAndBlankLines(t *testing.T) {
	m := parseINI("\n\n  \n[only]\naws_access_key_id=AKIA\nnonsense line without equals\n")
	require.Equal(t, "AKIA", m["only"])
	require.Len(t, m, 1)
}

func TestParseINI_Empty(t *testing.T) {
	require.Empty(t, parseINI(""))
}

func TestSplitCSV(t *testing.T) {
	require.Equal(t, []string{"a", "b", "c"}, splitCSV("a, b ,c"))
	require.Nil(t, splitCSV(""))
	require.Equal(t, []string{"one"}, splitCSV(" one "))
}

func TestBootstrapScope_EmptyEnablesAll(t *testing.T) {
	scope := bootstrapScope("")
	require.Equal(t, []string{"azure", "aws", "github", "gcp", "kubernetes"}, scopeList(scope))
}

func TestBootstrapScope_RestrictsAndNormalizes(t *testing.T) {
	scope := bootstrapScope("AWS, github")
	require.Equal(t, []string{"aws", "github"}, scopeList(scope))
	require.False(t, scope["gcp"])
	require.False(t, scope["kubernetes"])
}

func TestOrDefault(t *testing.T) {
	require.Equal(t, "x", orDefault("x", "fallback"))
	require.Equal(t, "fallback", orDefault("", "fallback"))
}

func envMap(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func TestOrgConnectorPayload_UnsetSkips(t *testing.T) {
	_, ok, err := orgConnectorPayload(envMap(nil), nil)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestOrgConnectorPayload_RequiresExternalID(t *testing.T) {
	_, _, err := orgConnectorPayload(envMap(map[string]string{
		"AWS_ORG_MANAGEMENT_ROLE_ARN": "arn:aws:iam::111111111111:role/GraphOrgDiscovery",
	}), nil)
	require.Error(t, err)
}

// The default hub is graph's ambient identity: no key leaves the pod.
func TestOrgConnectorPayload_AmbientByDefault(t *testing.T) {
	p, ok, err := orgConnectorPayload(envMap(map[string]string{
		"AWS_ORG_MANAGEMENT_ROLE_ARN": "arn:aws:iam::111111111111:role/GraphOrgDiscovery",
		"AWS_ORG_EXTERNAL_ID":         "ext-123",
	}), map[string]string{"hub": "AKIA", "__secret__hub": "s"})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "aws_org", p.Type)
	require.Equal(t, "ambient", p.Config["hub_auth"])
	require.NotContains(t, p.Config, "aws_access_key_id")
	require.Equal(t, "GraphReadOnly", p.Config["member_role_name"])
}

// A named hub profile's keys go onto the ONE org connector, never per account.
func TestOrgConnectorPayload_HubProfile(t *testing.T) {
	env := envMap(map[string]string{
		"AWS_ORG_MANAGEMENT_ROLE_ARN": "arn:aws:iam::111111111111:role/GraphOrgDiscovery",
		"AWS_ORG_EXTERNAL_ID":         "ext-123",
		"AWS_ORG_HUB_PROFILE":         "hub",
		"AWS_ORG_HUB_ROLE_ARN":        "arn:aws:iam::333333333333:role/GraphHub",
	})
	p, ok, err := orgConnectorPayload(env, map[string]string{"hub": "AKIAHUB", "__secret__hub": "s"})
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, "access_key", p.Config["hub_auth"])
	require.Equal(t, "AKIAHUB", p.Config["aws_access_key_id"])
	require.Equal(t, "arn:aws:iam::333333333333:role/GraphHub", p.Config["hub_role_arn"])

	_, _, err = orgConnectorPayload(env, map[string]string{})
	require.Error(t, err, "a named profile with no keys fails rather than falling back to ambient")
}

// A stored IAM user key is only the principal the hub role trusts: without the
// hub role to assume, every role in the chain would refuse it.
func TestOrgConnectorPayload_HubProfileRequiresHubRole(t *testing.T) {
	_, _, err := orgConnectorPayload(envMap(map[string]string{
		"AWS_ORG_MANAGEMENT_ROLE_ARN": "arn:aws:iam::111111111111:role/GraphOrgDiscovery",
		"AWS_ORG_EXTERNAL_ID":         "ext-123",
		"AWS_ORG_HUB_PROFILE":         "hub",
	}), map[string]string{"hub": "AKIAHUB", "__secret__hub": "s"})
	require.ErrorContains(t, err, "AWS_ORG_HUB_ROLE_ARN")
}
