# AWS application, ML, identity and Organizations reads

These reads feed the CIS AWS Foundations 7.0.0 and AWS FSBP checks for
application, ML and identity services. Every one is a `List*`, `Describe*`,
`Get*` or `BatchGet*` call. Each service collector lives in its own file under
`internal/collect/aws/` and is registered in `regionalServices`
(`regional_services.go`); the IAM and Organizations reads are global.

## Granted by the managed policies

The AWS-managed `SecurityAudit` (and, where noted, `ViewOnlyAccess`) policy
that `GraphReadOnly` attaches already grants these:

| Service | Calls | Feeds |
|---|---|---|
| SageMaker | `sagemaker:ListNotebookInstances`, `DescribeNotebookInstance`, `ListModels`, `DescribeModel`, `ListEndpointConfigs`, `DescribeEndpointConfig`, `List`/`Describe{DataQuality,ModelBias,ModelQuality,ModelExplainability}JobDefinition(s)`, `ListMonitoringSchedules`, `DescribeMonitoringSchedule`, `ListFeatureGroups`, `DescribeFeatureGroup` | SageMaker.1–5, 8–17, 19 |
| Bedrock AgentCore | `bedrock-agentcore:ListAgentRuntimes`, `GetAgentRuntime`, `ListGateways`, `ListBrowsers`, `GetBrowser` | BedrockAgentCore.1, 2, 5, 6 |
| CodeBuild | `codebuild:ListProjects`, `BatchGetProjects` | CodeBuild.1–4 |
| Cognito | `cognito-idp:ListUserPools`, `DescribeUserPool`; `cognito-identity:ListIdentityPools`, `DescribeIdentityPool` | Cognito.2–6 |
| EMR | `elasticmapreduce:ListClusters`, `DescribeCluster`, `ListInstances`, `GetBlockPublicAccessConfiguration`, `ListSecurityConfigurations`, `DescribeSecurityConfiguration` | EMR.1–4 |
| AppSync | `appsync:ListGraphqlApis`, `GetApiCache` | AppSync.1, 2, 5, 6 |
| Elastic Beanstalk | `elasticbeanstalk:DescribeEnvironments`, `DescribeConfigurationSettings` | ElasticBeanstalk.1–3 |
| WorkSpaces | `workspaces:DescribeWorkspaces` | WorkSpaces.1, 2 |
| Transfer Family | `transfer:ListServers`, `DescribeServer`, `ListConnectors`, `DescribeConnector` | Transfer.2, 3 |
| CloudFormation | `cloudformation:DescribeStacks` | CloudFormation.3, 4 |
| Step Functions | `states:ListStateMachines`, `DescribeStateMachine` | StepFunctions.1 |
| EventBridge | `events:ListEventBuses`, `DescribeEventBus` | EventBridge.3, CIS 2.21 |
| Amazon MQ | `mq:ListBrokers`, `DescribeBroker` | MQ.2 |
| SES | `ses:ListConfigurationSets`, `GetConfigurationSet` (SES v2 API) | SES.3 |
| Service Catalog | `servicecatalog:ListPortfolios`, `ListPortfolioAccess` (`ViewOnlyAccess`) | ServiceCatalog.1 |
| Connect | `connect:ListInstances`, `ListInstanceAttributes` | Connect.2 |
| DataSync | `datasync:ListTasks`, `DescribeTask` | DataSync.1 |
| Private CA | `acm-pca:ListCertificateAuthorities` | PCA.1 |
| ECS | `ecs:ListTaskDefinitionFamilies`, `DescribeTaskDefinition`, `DescribeCapacityProviders` (plus the existing service reads) | ECS.3–5, 8–10, 16, 18–21 |
| EKS | `eks:ListNodegroups`, `DescribeNodegroup` | EKS.9 |
| ECR | `ecr:GetLifecyclePolicy` | ECR.3 |
| IAM | `iam:GetAccountAuthorizationDetails` (groups, customer-managed policies), `GetGroup`, `ListServerCertificates`, `ListEntitiesForPolicy` | CIS 2.11, 2.14, 2.15, 2.17, 2.20; FSBP IAM.1, IAM.21, KMS.1, KMS.2 |
| Organizations | `organizations:ListRoots`, `DescribeOrganization`, `ListAccounts`, `ListParents`, `ListPoliciesForTarget`, `DescribeResourcePolicy`, `ListAWSServiceAccessForOrganization`, `ListDelegatedAdministrators`, `ListDelegatedServicesForAccount`; `iam:ListOrganizationsFeatures` | CIS 2.1.1, 2.1.2, 2.1.5, 2.1.6 |

## Not granted by the managed policies

| Permission | Read | Feeds |
|---|---|---|
| `codebuild:ListReportGroups`, `codebuild:BatchGetReportGroups` | report-group export encryption | `aws-codebuild-report-export-unencrypted` (CodeBuild.7) |

`deploy/aws/graph-readonly-role.yaml` carries them in its supplemental
read-only statement. A hand-written least-privilege policy needs:

```json
{
  "Sid": "GraphCodeBuildReportGroups",
  "Effect": "Allow",
  "Action": ["codebuild:ListReportGroups", "codebuild:BatchGetReportGroups"],
  "Resource": "*"
}
```

## Organizations: only the management or delegated-admin account

The Organizations reads succeed only for the management account or the
Organizations delegated administrator. Every AWS connector tries them; on any
other account `ListRoots` is denied and nothing is emitted, so CIS 2.1.x stays
**unknown** (no asset, no finding) until the management or delegated-admin
account is connected — it is never read as passing. With an `aws_org`
connector that means the `GraphReadOnly` role in the management account (the
template is deployed there separately from the StackSet). Centralized root
access (`iam:ListOrganizationsFeatures`) additionally needs the management
account or IAM's delegated administrator; from any other account those two
keys are unknown.

## Without the permissions

Nothing is guessed. A denied listing marks that collector skipped and the
sweep partial, so no stored asset is read as deleted; a denied per-resource
read leaves that resource's keys absent and its checks unevaluable, so an open
finding is held open. A service AWS does not run in a region is neither: an
NXDOMAIN for a region-limited service's own standard endpoint reads as "not offered there"
only when no FIPS, dual-stack or custom endpoint is configured and the
region's EC2 listing succeeded in the same sweep (regional_offered.go); any
other DNS failure is a failed read.
