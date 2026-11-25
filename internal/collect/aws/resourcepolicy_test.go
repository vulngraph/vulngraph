package aws

import (
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestPublicResourceAccess(t *testing.T) {
	sensitive := []string{"kms:decrypt"}

	tests := []struct {
		name string
		doc  string
		want string
	}{
		{
			// publicResourceAccess itself has no special case for an empty doc —
			// resourcePolicyMetadata is what short-circuits before ever calling it
			// (see the dedicated test below). Called directly, an empty doc has zero
			// statements, which is the same "grants nothing" case as a closed policy.
			name: "no policy",
			doc:  "",
			want: asset.PublicAccessNone,
		},
		{
			name: "closed policy — scoped to one account, no wildcard",
			doc: `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},
				"Action":"kms:Decrypt","Resource":"*"}]}`,
			want: asset.PublicAccessNone,
		},
		{
			name: "genuinely public — wildcard principal, sensitive action, no condition",
			doc:  `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:Decrypt","Resource":"*"}]}`,
			want: asset.PublicAccessConfirmed,
		},
		{
			name: "wildcard principal scoped by Condition — standard cross-account pattern, NOT public",
			doc: `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:Decrypt","Resource":"*",
				"Condition":{"StringEquals":{"aws:SourceAccount":"111122223333"}}}]}`,
			want: asset.PublicAccessNone,
		},
		{
			name: "explicit Deny overrides the wildcard Allow on the same action",
			doc: `{"Statement":[
				{"Effect":"Allow","Principal":"*","Action":"kms:Decrypt","Resource":"*"},
				{"Effect":"Deny","Principal":"*","Action":"kms:Decrypt","Resource":"*"}
			]}`,
			want: asset.PublicAccessNone,
		},
		{
			name: "single-object Statement (not an array) — must still parse",
			doc:  `{"Statement":{"Effect":"Allow","Principal":"*","Action":"kms:Decrypt","Resource":"*"}}`,
			want: asset.PublicAccessConfirmed,
		},
		{
			name: "public grant of a non-sensitive action — must NOT be graded public",
			doc:  `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:DescribeKey","Resource":"*"}]}`,
			want: asset.PublicAccessNone,
		},
		{
			name: "wildcard AWS principal as a list containing '*'",
			doc:  `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["*"]},"Action":"kms:Decrypt","Resource":"*"}]}`,
			want: asset.PublicAccessConfirmed,
		},
		{
			name: "Deny only covers a different action — Allow on the sensitive one survives",
			doc: `{"Statement":[
				{"Effect":"Allow","Principal":"*","Action":"kms:Decrypt","Resource":"*"},
				{"Effect":"Deny","Principal":"*","Action":"kms:PutKeyPolicy","Resource":"*"}
			]}`,
			want: asset.PublicAccessConfirmed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := publicResourceAccess(tt.doc, sensitive)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestResourcePolicyMetadata(t *testing.T) {
	// Every call site gates this function on its own API call having SUCCEEDED,
	// so reaching it with doc=="" always means "asked, and there is nothing to
	// grant" — a real observation. This is what closes the gap for SQS, SNS and
	// Secrets Manager: all three answer a missing policy with a successful
	// response carrying an empty/absent policy, not a typed exception, so their
	// "no policy" case reaches exactly this branch.
	t.Run("empty doc from a successful call is graded PublicAccessNone, not absent", func(t *testing.T) {
		pub, policies := resourcePolicyMetadata("", "key1-resource", []string{"kms:decrypt"})
		require.Equal(t, asset.PublicAccessNone, pub)
		require.Empty(t, policies, "no document exists to store, only the observation")
	})

	// A policy that EXISTS but grants nothing to the public is still an
	// OBSERVATION — PublicAccessNone, not absent. Before this, "read the policy,
	// it's closed" and "there is no policy" were the identical missing key, which
	// is why aws-ecr-repository-policy-public could not tell a closed repository
	// from an unread one: every closed policy vanished as completely as an unread one.
	t.Run("closed policy is stored and graded PublicAccessNone", func(t *testing.T) {
		doc := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"kms:Decrypt","Resource":"*"}]}`
		pub, policies := resourcePolicyMetadata(doc, "key1-resource", []string{"kms:decrypt"})
		require.Equal(t, asset.PublicAccessNone, pub)
		require.Contains(t, policies, `"type":"resource"`)
		require.Contains(t, policies, "key1-resource")
	})

	t.Run("public policy is stored and graded confirmed", func(t *testing.T) {
		doc := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"kms:Decrypt","Resource":"*"}]}`
		pub, policies := resourcePolicyMetadata(doc, "key1-resource", []string{"kms:decrypt"})
		require.Equal(t, asset.PublicAccessConfirmed, pub)
		require.Contains(t, policies, `"type":"resource"`)
	})
}

// An empty Condition object restricts nothing, so a wildcard-principal grant
// carrying one is genuinely public. Testing `len(raw) > 0` read it as scoped and
// graded a public resource closed — a false negative on the exact thing these
// checks exist to catch.
func TestPublicResourceAccess_EmptyConditionDoesNotShield(t *testing.T) {
	doc := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:ReceiveMessage","Condition":{}}]}`
	require.Equal(t, asset.PublicAccessConfirmed,
		publicResourceAccess(doc, []string{"sqs:receivemessage"}),
		"an empty Condition narrows nothing — this queue is open")

	// A real Condition still shields.
	scoped := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:ReceiveMessage",` +
		`"Condition":{"StringEquals":{"aws:SourceAccount":"111122223333"}}}]}`
	require.Equal(t, asset.PublicAccessNone, publicResourceAccess(scoped, []string{"sqs:receivemessage"}))

	// Unparseable Condition is treated as restricting: a malformed document must
	// not manufacture a critical finding.
	broken := `{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:ReceiveMessage","Condition":"nonsense"}]}`
	require.Equal(t, asset.PublicAccessNone, publicResourceAccess(broken, []string{"sqs:receivemessage"}))
}

// Every service grades through publicResourceAccess, so one principal and
// condition reading holds for all of them. An Allow with NotPrincipal reaches
// everyone but the listed principals; a condition on transport alone admits
// anyone over TLS; an organization condition pins the caller.
func TestPublicResourceAccessAcrossServices(t *testing.T) {
	services := []struct {
		name      string
		action    string
		sensitive []string
	}{
		{"kms", "kms:Decrypt", kmsSensitiveActions},
		{"sqs", "sqs:ReceiveMessage", sqsSensitiveActions},
		{"sns", "sns:Subscribe", snsSensitiveActions},
		{"ecr", "ecr:BatchGetImage", ecrSensitiveActions},
		{"secretsmanager", "secretsmanager:GetSecretValue", secretsManagerSensitiveActions},
		{"lambda", "lambda:InvokeFunction", lambdaInvokeActions},
	}
	shapes := []struct {
		name string
		stmt string
		want string
	}{
		{"NotPrincipal allow", `"NotPrincipal":{"AWS":"arn:aws:iam::111122223333:role/admin"}`, asset.PublicAccessConfirmed},
		{"NotPrincipal allow, org-conditioned", `"NotPrincipal":{"AWS":"arn:aws:iam::111122223333:role/admin"},"Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-abc123"}}`, asset.PublicAccessNone},
		{"SecureTransport only", `"Principal":"*","Condition":{"Bool":{"aws:SecureTransport":"true"}}`, asset.PublicAccessConfirmed},
		{"UserAgent only", `"Principal":{"AWS":"*"},"Condition":{"StringLike":{"aws:UserAgent":"*"}}`, asset.PublicAccessConfirmed},
		{"PrincipalOrgID", `"Principal":"*","Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-abc123"}}`, asset.PublicAccessNone},
		{"PrincipalOrgID beside SecureTransport", `"Principal":"*","Condition":{"Bool":{"aws:SecureTransport":"true"},"StringEquals":{"aws:PrincipalOrgID":"o-abc123"}}`, asset.PublicAccessNone},
		{"SourceArn, key case-insensitive", `"Principal":"*","Condition":{"ArnLike":{"AWS:SourceArn":"arn:aws:s3:::b"}}`, asset.PublicAccessNone},
		{"named principal", `"Principal":{"AWS":"arn:aws:iam::111122223333:root"}`, asset.PublicAccessNone},
	}
	for _, svc := range services {
		for _, sh := range shapes {
			t.Run(svc.name+"/"+sh.name, func(t *testing.T) {
				doc := `{"Statement":[{"Effect":"Allow","Action":"` + svc.action + `","Resource":"*",` + sh.stmt + `}]}`
				require.Equal(t, sh.want, publicResourceAccess(doc, svc.sensitive))
			})
		}
	}
}

func TestPublicResourceAccessServiceConditionKeys(t *testing.T) {
	tests := []struct {
		name      string
		doc       string
		sensitive []string
		want      string
	}{
		{"KMS caller account pins the caller",
			`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"kms:Decrypt","Resource":"*","Condition":{"StringEquals":{"kms:CallerAccount":"111122223333","kms:ViaService":"ec2.eu-west-1.amazonaws.com"}}}]}`,
			kmsSensitiveActions, asset.PublicAccessNone},
		{"KMS via-service alone does not",
			`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"kms:Decrypt","Resource":"*","Condition":{"StringEquals":{"kms:ViaService":"ec2.eu-west-1.amazonaws.com"}}}]}`,
			kmsSensitiveActions, asset.PublicAccessConfirmed},
		{"EFS mount-target access stays in the VPC",
			`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":["elasticfilesystem:ClientMount","elasticfilesystem:ClientWrite"],"Condition":{"Bool":{"elasticfilesystem:AccessedViaMountTarget":"true"}}}]}`,
			efsSensitiveActions, asset.PublicAccessNone},
		{"Lambda function URL with auth NONE",
			`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"lambda:InvokeFunctionUrl","Resource":"*","Condition":{"StringEquals":{"lambda:FunctionUrlAuthType":"NONE"}}}]}`,
			lambdaInvokeActions, asset.PublicAccessConfirmed},
		{"NotPrincipal Deny on another action leaves the grant",
			`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:ReceiveMessage"},{"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":"sqs:SendMessage"}]}`,
			sqsSensitiveActions, asset.PublicAccessConfirmed},
		{"NotPrincipal Deny on the granted actions takes them back from the public",
			`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:*"},{"Effect":"Deny","NotPrincipal":{"AWS":"arn:aws:iam::111122223333:root"},"Action":["sqs:ReceiveMessage","sqs:SendMessage"]}]}`,
			sqsSensitiveActions, asset.PublicAccessNone},
		{"wildcard NotPrincipal Allow reaches no one",
			`{"Statement":[{"Effect":"Allow","NotPrincipal":"*","Action":"sqs:ReceiveMessage"}]}`,
			sqsSensitiveActions, asset.PublicAccessNone},
		{"null NotPrincipal reaches no one",
			`{"Statement":[{"Effect":"Allow","NotPrincipal":null,"Action":"sqs:ReceiveMessage"}]}`,
			sqsSensitiveActions, asset.PublicAccessNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, publicResourceAccess(tt.doc, tt.sensitive))
		})
	}
}

// A restricting key pins the caller only under an operator that requires a
// match, and a source-IP key only with ranges short of the internet; a
// service key pins only when it names the caller or the destination.
func TestPublicResourceAccessConditionForms(t *testing.T) {
	tests := []struct {
		name      string
		principal string
		action    string
		cond      string
		sensitive []string
		want      string
	}{
		{"source IP 0.0.0.0/0", `"*"`, "sqs:ReceiveMessage", `{"IpAddress":{"aws:SourceIp":"0.0.0.0/0"}}`, sqsSensitiveActions, asset.PublicAccessConfirmed},
		{"source IP split halves", `"*"`, "sqs:ReceiveMessage", `{"IpAddress":{"aws:SourceIp":["0.0.0.0/1","128.0.0.0/1"]}}`, sqsSensitiveActions, asset.PublicAccessConfirmed},
		{"source IP ::/0", `"*"`, "sqs:ReceiveMessage", `{"IpAddress":{"aws:SourceIp":["203.0.113.0/24","::/0"]}}`, sqsSensitiveActions, asset.PublicAccessConfirmed},
		{"source IP one range", `"*"`, "sqs:ReceiveMessage", `{"IpAddress":{"aws:SourceIp":"203.0.113.0/24"}}`, sqsSensitiveActions, asset.PublicAccessNone},
		{"any org", `"*"`, "kms:Decrypt", `{"StringLike":{"aws:PrincipalOrgID":["o-abc123","*"]}}`, kmsSensitiveActions, asset.PublicAccessConfirmed},
		{"negated org", `"*"`, "kms:Decrypt", `{"StringNotEquals":{"aws:PrincipalOrgID":"o-abc123"}}`, kmsSensitiveActions, asset.PublicAccessConfirmed},
		{"negated IP", `"*"`, "kms:Decrypt", `{"NotIpAddress":{"aws:SourceIp":"203.0.113.0/24"}}`, kmsSensitiveActions, asset.PublicAccessConfirmed},
		{"IfExists VPC endpoint", `"*"`, "secretsmanager:GetSecretValue", `{"StringEqualsIfExists":{"aws:SourceVpce":"vpce-1"}}`, secretsManagerSensitiveActions, asset.PublicAccessConfirmed},
		{"ForAllValues org path", `"*"`, "ecr:BatchGetImage", `{"ForAllValues:StringLike":{"aws:PrincipalOrgPaths":"o-abc123/*"}}`, ecrSensitiveActions, asset.PublicAccessConfirmed},
		{"ForAnyValue org path", `"*"`, "ecr:BatchGetImage", `{"ForAnyValue:StringLike":{"aws:PrincipalOrgPaths":"o-abc123/*"}}`, ecrSensitiveActions, asset.PublicAccessNone},
		{"Null org", `"*"`, "lambda:InvokeFunction", `{"Null":{"aws:PrincipalOrgID":"false"}}`, lambdaInvokeActions, asset.PublicAccessConfirmed},
		{"EFS mount target as a JSON boolean", `{"AWS":"*"}`, "elasticfilesystem:ClientMount", `{"Bool":{"elasticfilesystem:AccessedViaMountTarget":true}}`, efsSensitiveActions, asset.PublicAccessNone},
		{"EFS mount target false", `{"AWS":"*"}`, "elasticfilesystem:ClientMount", `{"Bool":{"elasticfilesystem:AccessedViaMountTarget":"false"}}`, efsSensitiveActions, asset.PublicAccessConfirmed},
		{"SNS endpoint", `"*"`, "sns:Subscribe", `{"StringEquals":{"sns:Endpoint":"https://hooks.example.com/in"}}`, snsSensitiveActions, asset.PublicAccessNone},
		{"SNS protocol", `"*"`, "sns:Subscribe", `{"StringEquals":{"sns:Protocol":"email"}}`, snsSensitiveActions, asset.PublicAccessConfirmed},
		{"called via", `"*"`, "kms:Decrypt", `{"ForAnyValue:StringEquals":{"aws:CalledVia":"cloudformation.amazonaws.com"}}`, kmsSensitiveActions, asset.PublicAccessConfirmed},
		{"any AWS service principal", `"*"`, "sqs:SendMessage", `{"Bool":{"aws:PrincipalIsAWSService":"true"}}`, sqsSensitiveActions, asset.PublicAccessConfirmed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := `{"Statement":[{"Effect":"Allow","Principal":` + tt.principal + `,"Action":"` + tt.action +
				`","Resource":"*","Condition":` + tt.cond + `}]}`
			require.Equal(t, tt.want, publicResourceAccess(doc, tt.sensitive))
		})
	}
}

// NotAction applies a statement to every action it does not list, on an
// Allow and on a Deny alike.
func TestPublicResourceAccessNotAction(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"Allow NotAction leaves the sensitive action granted",
			`{"Statement":[{"Effect":"Allow","Principal":"*","NotAction":"sqs:DeleteMessage","Resource":"*"}]}`, asset.PublicAccessConfirmed},
		{"Allow NotAction excluding every sensitive action",
			`{"Statement":[{"Effect":"Allow","Principal":"*","NotAction":["sqs:ReceiveMessage","sqs:SendMessage"],"Resource":"*"}]}`, asset.PublicAccessNone},
		{"Deny NotAction sparing the granted action does not take it back",
			`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:ReceiveMessage"},{"Effect":"Deny","Principal":"*","NotAction":"sqs:ReceiveMessage"}]}`, asset.PublicAccessConfirmed},
		{"Deny NotAction covering the granted action takes it back",
			`{"Statement":[{"Effect":"Allow","Principal":"*","Action":"sqs:ReceiveMessage"},{"Effect":"Deny","Principal":"*","NotAction":"sqs:GetQueueAttributes"}]}`, asset.PublicAccessNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, publicResourceAccess(tt.doc, sqsSensitiveActions))
		})
	}
}
