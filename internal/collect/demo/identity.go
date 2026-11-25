package demo

import (
	"encoding/json"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/ciem"
)

// Role ARNs the other files refer to.
var (
	roleWeb        = iamARN("role/acme-web")
	roleAdmin      = iamARN("role/acme-ec2-admin")
	roleBatch      = iamARN("role/acme-batch")
	roleGateway    = iamARN("role/acme-ai-gateway-task")
	roleSupportBot = iamARN("role/acme-support-bot-task")
)

// policy is the collector's stored form of one policy document.
type policy struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Managed  bool   `json:"managed"`
	Document string `json:"document"`
}

func statement(effect string, actions []string, resource string) map[string]any {
	return map[string]any{"Effect": effect, "Action": actions, "Resource": resource}
}

func document(statements ...map[string]any) string {
	out, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": statements})
	if err != nil {
		panic("demo: policy document: " + err.Error()) // static input
	}
	return string(out)
}

func trust(service string) string {
	out, err := json.Marshal(map[string]any{"Version": "2012-10-17", "Statement": []map[string]any{{
		"Effect": "Allow", "Principal": map[string]string{"Service": service}, "Action": "sts:AssumeRole",
		"Condition": map[string]any{"StringEquals": map[string]string{"aws:SourceAccount": accountID}},
	}}})
	if err != nil {
		panic("demo: trust document: " + err.Error()) // static input
	}
	return string(out)
}

func encode(policies ...policy) string {
	out, err := json.Marshal(policies)
	if err != nil {
		panic("demo: policies: " + err.Error()) // static input
	}
	return string(out)
}

// identity adds the roles and users. The web role may pass any role to EC2 and
// start instances, which lets whoever controls the web server launch an
// instance as the admin role: the escalation path the demo is built around.
func (b *builder) identity() {
	// Acme is a standalone AWS account. Its IAM inventory includes the
	// membership observation and confirms that its principals have no boundary.
	observation, err := json.Marshal(ciem.AWSOrganizationEvidence{
		AccountID: accountID, Applicability: "exempt", Reason: "standalone", Complete: true, ObservedAt: b.now,
	})
	if err != nil {
		panic("demo: organization evidence: " + err.Error())
	}
	membership := string(observation)
	b.add(asset.Asset{
		ID: "aws_scp:" + accountID, Name: "SCPs for " + accountID, Type: "aws_scp_set", Provider: asset.ProviderAWS, Region: "global",
		Metadata: map[string]string{
			ciem.MetaAWSOrganization: membership, "policies": "[]", "policy_count": "0", "policies_complete": "true",
		},
	})
	for _, r := range []struct {
		arn, name, service string
		admin              bool
		policies           []policy
	}{
		{roleWeb, "acme-web", "ec2.amazonaws.com", false, []policy{{
			Name: "web-app", Type: "identity",
			Document: document(
				statement("Allow", []string{"iam:PassRole"}, roleAdmin),
				statement("Allow", []string{"ec2:RunInstances", "ec2:DescribeInstances"}, "*"),
				statement("Allow", []string{"s3:GetObject", "s3:PutObject"}, "arn:aws:s3:::acme-customer-exports/*"),
				statement("Allow", []string{"secretsmanager:GetSecretValue"}, arn("secretsmanager", "secret:prod/orders-db-*")),
			),
		}}},
		{roleAdmin, "acme-ec2-admin", "ec2.amazonaws.com", true, []policy{{
			Name: "AdministratorAccess", Type: "identity", Managed: true,
			Document: document(statement("Allow", []string{"*"}, "*")),
		}}},
		{roleBatch, "acme-batch", "ec2.amazonaws.com", false, []policy{{
			Name: "batch-read", Type: "identity",
			Document: document(statement("Allow", []string{"s3:GetObject"}, "arn:aws:s3:::acme-batch-input/*")),
		}}},
		{roleGateway, "acme-ai-gateway-task", "ecs-tasks.amazonaws.com", false, []policy{{
			Name: "ai-gateway", Type: "identity",
			Document: document(
				statement("Allow", []string{"bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"}, "*"),
				statement("Allow", []string{"secretsmanager:GetSecretValue"}, arn("secretsmanager", "secret:prod/llm-provider-keys-*")),
			),
		}}},
		{roleSupportBot, "acme-support-bot-task", "ecs-tasks.amazonaws.com", false, []policy{{
			Name: "support-bot", Type: "identity",
			Document: document(statement("Allow", []string{"dynamodb:GetItem", "dynamodb:Query"}, arn("dynamodb", "table/tickets"))),
		}}},
	} {
		meta := map[string]string{
			ciem.MetaAWSOrganizationMembership: membership,
			"permission_boundary_complete":     "true",
			"policies":                         encode(append(r.policies, policy{Name: "trust", Type: "trust", Document: trust(r.service)})...),
			"public_trust":                     "false",
			"mfa_required_to_assume":           "false",
			"trust_entry":                      "service",
			"last_used_days":                   "1",
			"last_used_observed":               "true",
		}
		if r.admin {
			meta["admin"] = "true"
		}
		b.add(asset.Asset{
			ID: r.arn, Name: r.name, Type: "iam_role", Provider: asset.ProviderAWS, Region: "global",
			Metadata: meta,
		})
	}

	b.add(asset.Asset{
		ID: iamARN("user/dana.ops"), Name: "dana.ops", Type: "iam_user", Provider: asset.ProviderAWS, Region: "global",
		Metadata: map[string]string{
			ciem.MetaAWSOrganizationMembership: membership,
			"permission_boundary_complete":     "true",
			"console_access":                   "true", "mfa_enabled": "false", "password_last_used_days": "3",
			"policies": encode(policy{
				Name: "ops", Type: "identity", Document: document(statement("Allow", []string{"ec2:*", "s3:*"}, "*")),
			}),
		},
	})
}
