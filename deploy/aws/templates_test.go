package awsdeploy

import (
	"io/fs"
	"regexp"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// actions returns every IAM action granted in a template, at any depth. The
// CloudFormation short-form tags (!If, !Sub) decode as ordinary nodes.
func actions(t *testing.T, name string) []string {
	t.Helper()
	body, err := fs.ReadFile(Templates, name)
	require.NoError(t, err)
	var root yaml.Node
	require.NoError(t, yaml.Unmarshal(body, &root))
	seen := map[string]bool{}
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				k, v := n.Content[i], n.Content[i+1]
				if k.Value == "Action" {
					if v.Kind == yaml.ScalarNode {
						seen[v.Value] = true
					}
					for _, c := range v.Content {
						seen[c.Value] = true
					}
				}
				walk(v)
			}
			return
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(&root)
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

var readAction = regexp.MustCompile(`^[a-z0-9-]+:(Get|List|Describe|BatchGet)[A-Za-z]*$`)

// The member role is read-only: beyond the managed policies, every action it
// grants is a read, and the set is exactly the documented extras. Adding one
// means adding it to the template's header and docs/onboarding-aws-org.md.
func TestReadOnlyRoleGrantsOnlyReads(t *testing.T) {
	got := actions(t, "graph-readonly-role.yaml")
	for _, a := range got {
		if a == "sts:AssumeRole" { // the trust policy's own action
			continue
		}
		require.Regexp(t, readAction, a, "the read-only role must not grant %s", a)
	}
	require.Equal(t, []string{
		"ce:GetCostAndUsage",
		"codebuild:BatchGetReportGroups", "codebuild:ListReportGroups",
		"ebs:GetSnapshotBlock", "ebs:ListChangedBlocks", "ebs:ListSnapshotBlocks", "ec2:DescribeSnapshots",
		"ecr:BatchGetImage", "ecr:GetAuthorizationToken", "ecr:GetDownloadUrlForLayer",
		"glue:GetMLTransforms",
		"identitystore:DescribeGroup", "identitystore:DescribeUser",
		"macie2:GetAutomatedDiscoveryConfiguration", "macie2:GetMacieSession",
		"s3:GetObject", "s3express:GetLifecycleConfiguration", "sts:AssumeRole",
		"waf-regional:GetRule", "waf:GetRule", "wafv2:GetRuleGroup",
	}, got)
}

// The discovery role grants exactly the four calls collect/aws/org.go makes
// (ListAccounts, and the OU walk), nothing else.
func TestOrgDiscoveryRoleGrantsOnlyOrganizationReads(t *testing.T) {
	require.Equal(t, []string{
		"organizations:ListAccounts", "organizations:ListAccountsForParent",
		"organizations:ListOrganizationalUnitsForParent", "organizations:ListRoots",
		"sts:AssumeRole",
	}, actions(t, "graph-org-stackset.yaml"))
}

// The hub holds no permission but assuming graph's own roles.
func TestHubRoleOnlyAssumes(t *testing.T) {
	for _, a := range actions(t, "graph-hub-role.yaml") {
		require.Contains(t, []string{"sts:AssumeRole", "sts:TagSession", "sts:AssumeRoleWithWebIdentity"}, a)
	}
}

// The execution role is exactly the executor's action list (ADR 087) — a new
// executor action must be added here on purpose, not by widening a wildcard.
func TestExecutionRoleIsTheExecutorActionList(t *testing.T) {
	require.Equal(t, []string{
		"ec2:RevokeSecurityGroupIngress", "ec2:StartInstances", "ec2:StopInstances",
		"iam:DeleteAccessKey", "iam:UpdateAccessKey",
		"kms:CreateGrant",
		"s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock", "sts:AssumeRole",
	}, actions(t, "graph-execution-role.yaml"))
}

// Terraform state routinely holds plaintext secrets, so the member role reads
// it only when the operator opts in: GrantTerraformStateRead defaults to
// "false" in both templates that declare it (docs/onboarding-aws-org.md).
func TestTerraformStateReadIsOptIn(t *testing.T) {
	for _, name := range []string{"graph-readonly-role.yaml", "graph-org-stackset.yaml"} {
		body, err := fs.ReadFile(Templates, name)
		require.NoError(t, err)
		var tpl struct {
			Parameters map[string]struct {
				Default string `yaml:"Default"`
			} `yaml:"Parameters"`
		}
		require.NoError(t, yaml.Unmarshal(body, &tpl), name)
		p, ok := tpl.Parameters["GrantTerraformStateRead"]
		require.True(t, ok, "%s declares GrantTerraformStateRead", name)
		require.Equal(t, "false", p.Default, "%s must leave the Terraform-state read off by default", name)
	}
}

// A snapshot is a whole disk, secrets included, so the member role reads
// snapshots only when the operator opts in: GrantDiskScanRead defaults to
// "false", and the grant sits behind that condition (docs/iam/disk-scan-aws.md).
func TestDiskScanReadIsOptIn(t *testing.T) {
	body, err := fs.ReadFile(Templates, "graph-readonly-role.yaml")
	require.NoError(t, err)
	var tpl struct {
		Parameters map[string]struct {
			Default string `yaml:"Default"`
		} `yaml:"Parameters"`
	}
	require.NoError(t, yaml.Unmarshal(body, &tpl))
	p, ok := tpl.Parameters["GrantDiskScanRead"]
	require.True(t, ok, "graph-readonly-role.yaml declares GrantDiskScanRead")
	require.Equal(t, "false", p.Default)

	root := parse(t, "graph-readonly-role.yaml")
	stmts := mappings(root, "Sid", is("GraphReadSnapshotBlocks"))
	require.Len(t, stmts, 1)
	var granted []string
	for _, a := range value(stmts[0], "Action").Content {
		granted = append(granted, a.Value)
	}
	require.ElementsMatch(t, []string{
		"ebs:GetSnapshotBlock", "ebs:ListSnapshotBlocks", "ebs:ListChangedBlocks", "ec2:DescribeSnapshots",
	}, granted)

	var conditionalOn string
	walkIf(root, stmts[0], &conditionalOn)
	require.Equal(t, "DiskScanRead", conditionalOn, "the snapshot read must sit behind the DiskScanRead condition")
	cond := value(value(root.Content[0], "Conditions"), "DiskScanRead")
	require.NotNil(t, cond)
	require.Equal(t, "!Equals", cond.Tag)
	require.Equal(t, "true", cond.Content[1].Value)
}

// walkIf records the condition name of the !If whose first branch is target.
func walkIf(n, target *yaml.Node, out *string) {
	if n.Tag == "!If" && len(n.Content) >= 2 && n.Content[1] == target {
		*out = n.Content[0].Value
	}
	for _, c := range n.Content {
		walkIf(c, target, out)
	}
}

// The disk-scan role is exactly the snapshot action list: it may create a
// snapshot only if tagged vulngraph-disk-scan, tag only during creation, and
// delete only snapshots already carrying the tag. It grants no read.
func TestDiskScanRoleIsTheSnapshotActionList(t *testing.T) {
	require.Equal(t, []string{
		"ec2:CreateSnapshot", "ec2:CreateTags", "ec2:DeleteSnapshot", "sts:AssumeRole",
	}, actions(t, "graph-diskscan-role.yaml"))

	root := parse(t, "graph-diskscan-role.yaml")
	cond := func(sid string) *yaml.Node {
		stmts := mappings(root, "Sid", is(sid))
		require.Len(t, stmts, 1, sid)
		c := value(stmts[0], "Condition")
		require.NotNil(t, c, "%s must carry a condition", sid)
		return c
	}
	create := cond("GraphCreateTaggedSnapshots")
	require.Equal(t, "false", value(value(create, "Null"), "aws:RequestTag/vulngraph-disk-scan").Value)
	keys := value(value(create, "ForAllValues:StringEquals"), "aws:TagKeys")
	require.Len(t, keys.Content, 1)
	require.Equal(t, "vulngraph-disk-scan", keys.Content[0].Value)

	require.Equal(t, "CreateSnapshot", value(value(cond("GraphTagOnCreateOnly"), "StringEquals"), "ec2:CreateAction").Value)
	require.Equal(t, "false", value(value(cond("GraphDeleteTaggedSnapshots"), "Null"), "aws:ResourceTag/vulngraph-disk-scan").Value)

	for _, sid := range []string{"GraphSnapshotVolumes", "GraphCreateTaggedSnapshots", "GraphTagOnCreateOnly", "GraphDeleteTaggedSnapshots"} {
		stmts := mappings(root, "Sid", is(sid))
		require.Len(t, stmts, 1)
		require.Equal(t, "Allow", value(stmts[0], "Effect").Value)
		require.NotEqual(t, "*", value(stmts[0], "Resource").Value, "%s must name its resource", sid)
	}

	body, err := fs.ReadFile(Templates, "graph-diskscan-role.yaml")
	require.NoError(t, err)
	var tpl struct {
		Parameters map[string]struct {
			Default string `yaml:"Default"`
		} `yaml:"Parameters"`
	}
	require.NoError(t, yaml.Unmarshal(body, &tpl))
	for _, name := range []string{"HubRoleArn", "ExternalId"} {
		_, ok := tpl.Parameters[name]
		require.True(t, ok, "trust uses the %s parameter", name)
	}
	require.NotEqual(t, "GraphReadOnly", tpl.Parameters["RoleName"].Default)
	require.NotEqual(t, "GraphExecute", tpl.Parameters["RoleName"].Default)
}

// parse returns a template's document node.
func parse(t *testing.T, name string) *yaml.Node {
	t.Helper()
	body, err := fs.ReadFile(Templates, name)
	require.NoError(t, err)
	var root yaml.Node
	require.NoError(t, yaml.Unmarshal(body, &root))
	return &root
}

// mappings returns every mapping node, at any depth, that has key k with a
// value satisfying match.
func mappings(n *yaml.Node, k string, match func(*yaml.Node) bool) []*yaml.Node {
	var out []*yaml.Node
	if n.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == k && match(n.Content[i+1]) {
				out = append(out, n)
			}
		}
	}
	for _, c := range n.Content {
		out = append(out, mappings(c, k, match)...)
	}
	return out
}

// value returns the value node for key k in mapping m, or nil.
func value(m *yaml.Node, k string) *yaml.Node {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == k {
			return m.Content[i+1]
		}
	}
	return nil
}

func keys(m *yaml.Node) []string {
	var out []string
	for i := 0; i+1 < len(m.Content); i += 2 {
		out = append(out, m.Content[i].Value)
	}
	return out
}

func is(v string) func(*yaml.Node) bool { return func(n *yaml.Node) bool { return n.Value == v } }

// The default trust (EKS Pod Identity) is pinned like the IRSA one: graph's
// namespace and ServiceAccount, optionally its cluster. Account alone let any
// association in the account — the scanner's ServiceAccount included — obtain
// the hub.
func TestHubPodIdentityTrustIsPinnedToGraphsServiceAccount(t *testing.T) {
	root := parse(t, "graph-hub-role.yaml")
	principals := mappings(root, "Service", is("pods.eks.amazonaws.com"))
	require.Len(t, principals, 1)
	stmts := mappings(root, "Principal", func(n *yaml.Node) bool { return n == principals[0] })
	require.Len(t, stmts, 1)
	eq := value(value(stmts[0], "Condition"), "StringEquals")
	require.NotNil(t, eq)
	require.ElementsMatch(t, []string{
		"aws:SourceAccount",
		"aws:RequestTag/kubernetes-namespace",
		"aws:RequestTag/kubernetes-service-account",
		"aws:RequestTag/eks-cluster-arn",
	}, keys(eq))

	body, err := fs.ReadFile(Templates, "graph-hub-role.yaml")
	require.NoError(t, err)
	require.Contains(t, string(body), `"${OIDCProviderHost}:sub": "${ServiceAccount}"`, "the IRSA trust pins the subject")
}

// serve's own ServiceAccount (chart serviceAccount.serveName) is trusted
// whenever ExecutorServiceAccount is set, with or without an execution role:
// tying it to ExecutionRoleName left a split serve with no cloud identity at all.
func TestHubTrustsServeServiceAccountWithoutExecutionRole(t *testing.T) {
	root := parse(t, "graph-hub-role.yaml")
	tagged := mappings(root, "aws:RequestTag/kubernetes-service-account", func(*yaml.Node) bool { return true })
	require.Len(t, tagged, 1)
	sa := value(tagged[0], "aws:RequestTag/kubernetes-service-account")
	require.Equal(t, "!If", sa.Tag)
	require.NotEmpty(t, sa.Content)
	cond := sa.Content[0].Value

	conditions := value(root.Content[0], "Conditions")
	require.NotNil(t, conditions)
	def := value(conditions, cond)
	require.NotNil(t, def, "condition %s is defined", cond)
	var refs []string
	for _, c := range def.Content {
		refs = append(refs, c.Value)
	}
	require.ElementsMatch(t, []string{"IsPodIdentity", "HasExecutorServiceAccount"}, refs,
		"the trust of serve's ServiceAccount must not depend on ExecutionRoleName")
}

// The read path and the Approve & run path are separate statements, so the
// execution role can be held to serve's ServiceAccount; the member statement
// never names the execution role.
func TestHubExecutionPathIsItsOwnStatement(t *testing.T) {
	root := parse(t, "graph-hub-role.yaml")
	member := mappings(root, "Sid", is("GraphAssumeMemberRoles"))
	require.Len(t, member, 1)
	require.NotContains(t, value(member[0], "Resource").Value, "ExecutionRoleName")

	exec := mappings(root, "Sid", is("GraphAssumeExecutionRoles"))
	require.Len(t, exec, 1)
	require.Contains(t, value(exec[0], "Resource").Value, "${ExecutionRoleName}")
	pinned := mappings(exec[0], "aws:PrincipalTag/kubernetes-service-account", func(*yaml.Node) bool { return true })
	require.Len(t, pinned, 1, "the execution statement must be able to require serve's ServiceAccount")

	trust := mappings(parse(t, "graph-execution-role.yaml"), "sts:ExternalId", func(*yaml.Node) bool { return true })
	require.Len(t, trust, 1)
	require.Contains(t, keys(trust[0]), "aws:PrincipalTag/kubernetes-service-account",
		"the execution role's own trust can require serve's ServiceAccount too")
}

// S3 ARNs carry no account id, so a wildcard bucket grant without
// s3:ResourceAccount also reaches buckets in other accounts whose bucket
// policy admits the role. The Terraform-state read and the Block Public Access
// write are both held to the role's own account.
func TestS3GrantsAreHeldToTheOwnAccount(t *testing.T) {
	for name, sid := range map[string]string{
		"graph-readonly-role.yaml":  "GraphReadTfStateObjects",
		"graph-execution-role.yaml": "GraphBucketPublicAccessBlock",
	} {
		stmts := mappings(parse(t, name), "Sid", is(sid))
		require.Len(t, stmts, 1, "%s: %s", name, sid)
		eq := value(value(stmts[0], "Condition"), "StringEquals")
		require.NotNil(t, eq, "%s: %s has no StringEquals condition", name, sid)
		acct := value(eq, "s3:ResourceAccount")
		require.NotNil(t, acct, "%s: %s must pin s3:ResourceAccount", name, sid)
		require.Equal(t, "!Ref", acct.Tag)
		require.Equal(t, "AWS::AccountId", acct.Value)
	}
}

// Resources tagged vulngraph-protected are out of the execution role's reach
// for every action whose resource AWS evaluates tags on.
func TestExecutionRoleSkipsProtectedResources(t *testing.T) {
	stmts := mappings(parse(t, "graph-execution-role.yaml"), "Sid", is("GraphSkipProtectedResources"))
	require.Len(t, stmts, 1)
	require.Equal(t, "Deny", value(stmts[0], "Effect").Value)
	var denied []string
	for _, a := range value(stmts[0], "Action").Content {
		denied = append(denied, a.Value)
	}
	require.ElementsMatch(t, []string{
		"ec2:RevokeSecurityGroupIngress", "ec2:StopInstances", "ec2:StartInstances",
		"iam:UpdateAccessKey", "iam:DeleteAccessKey",
	}, denied)
	null := value(value(stmts[0], "Condition"), "Null")
	require.NotNil(t, null)
	require.Equal(t, "false", value(null, "aws:ResourceTag/vulngraph-protected").Value)
}

// The hub reaches the disk scan role only when DiskScanRoleName is set, only
// that role, and with the member statement's org pin: the opt-in stays opt-in.
func TestHubDiskScanRoleIsOptIn(t *testing.T) {
	root := parse(t, "graph-hub-role.yaml")
	params := value(root.Content[0], "Parameters")
	require.NotNil(t, params)
	param := value(params, "DiskScanRoleName")
	require.NotNil(t, param)
	require.Equal(t, "", value(param, "Default").Value, "no grant by default")

	stmts := mappings(root, "Sid", is("GraphAssumeDiskScanRoles"))
	require.Len(t, stmts, 1)
	require.Equal(t, "sts:AssumeRole", value(stmts[0], "Action").Value)
	require.Contains(t, value(stmts[0], "Resource").Value, "role/${DiskScanRoleName}")
	require.NotContains(t, value(stmts[0], "Resource").Value, "MemberRoleName")
	require.Equal(t, "!If", value(stmts[0], "Condition").Tag)
	require.Len(t, mappings(stmts[0], "aws:ResourceOrgID", func(*yaml.Node) bool { return true }), 1)

	body, err := fs.ReadFile(Templates, "graph-hub-role.yaml")
	require.NoError(t, err)
	require.Contains(t, string(body), "HasDiskScanRole: !Not [!Equals [!Ref DiskScanRoleName, \"\"]]",
		"the statement exists only when the parameter is set")
	// The only roles the hub may assume: discovery, member, execution, disk scan.
	for _, sid := range []string{"GraphAssumeOrgDiscovery", "GraphAssumeMemberRoles", "GraphAssumeExecutionRoles", "GraphAssumeDiskScanRoles"} {
		require.Len(t, mappings(root, "Sid", is(sid)), 1, sid)
	}
}
