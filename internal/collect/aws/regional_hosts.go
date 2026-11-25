package aws

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/aws/aws-sdk-go-v2/service/apigatewayv2"
	"github.com/aws/aws-sdk-go-v2/service/appsync"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	"github.com/aws/aws-sdk-go-v2/service/backup"
	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	"github.com/aws/aws-sdk-go-v2/service/codebuild"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentity"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/connect"
	"github.com/aws/aws-sdk-go-v2/service/databasemigrationservice"
	"github.com/aws/aws-sdk-go-v2/service/datasync"
	"github.com/aws/aws-sdk-go-v2/service/dax"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/efs"
	"github.com/aws/aws-sdk-go-v2/service/elasticache"
	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/emr"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	"github.com/aws/aws-sdk-go-v2/service/firehose"
	"github.com/aws/aws-sdk-go-v2/service/fsx"
	"github.com/aws/aws-sdk-go-v2/service/glue"
	"github.com/aws/aws-sdk-go-v2/service/kafka"
	"github.com/aws/aws-sdk-go-v2/service/kafkaconnect"
	"github.com/aws/aws-sdk-go-v2/service/kinesis"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/mq"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	"github.com/aws/aws-sdk-go-v2/service/opensearch"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	"github.com/aws/aws-sdk-go-v2/service/redshift"
	"github.com/aws/aws-sdk-go-v2/service/redshiftserverless"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3control"
	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/servicecatalog"
	"github.com/aws/aws-sdk-go-v2/service/sesv2"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/aws/aws-sdk-go-v2/service/sns"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/transfer"
	"github.com/aws/aws-sdk-go-v2/service/wafregional"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	"github.com/aws/aws-sdk-go-v2/service/workspaces"
)

// Each regional service's standard endpoint host for a region, read from
// the SDK's own endpoint rules (regional_offered.go, rule 1) rather than a
// hand-kept table, so a service that moves its endpoint cannot drift from it.
//
// Two hosts are never the one a client dials, so an NXDOMAIN never matches
// them and always reads as a failed read: s3ControlHost (access-point calls
// go to <account>.s3-control.<region>) and dynamoDBHost when the credentials
// carry an account ID (account-based endpoints). Both services run in every
// region, so nothing is lost.

func kmsHost(r string) string {
	return standardHost(kms.NewDefaultEndpointResolverV2(), kms.EndpointParameters{Region: &r})
}

func ecrHost(r string) string {
	return standardHost(ecr.NewDefaultEndpointResolverV2(), ecr.EndpointParameters{Region: &r})
}

func sqsHost(r string) string {
	return standardHost(sqs.NewDefaultEndpointResolverV2(), sqs.EndpointParameters{Region: &r})
}

func snsHost(r string) string {
	return standardHost(sns.NewDefaultEndpointResolverV2(), sns.EndpointParameters{Region: &r})
}

func apiGatewayHost(r string) string {
	return standardHost(apigateway.NewDefaultEndpointResolverV2(), apigateway.EndpointParameters{Region: &r})
}

func apiGatewayV2Host(r string) string {
	return standardHost(apigatewayv2.NewDefaultEndpointResolverV2(), apigatewayv2.EndpointParameters{Region: &r})
}

func acmHost(r string) string {
	return standardHost(acm.NewDefaultEndpointResolverV2(), acm.EndpointParameters{Region: &r})
}

func secretsManagerHost(r string) string {
	return standardHost(secretsmanager.NewDefaultEndpointResolverV2(), secretsmanager.EndpointParameters{Region: &r})
}

func ssmHost(r string) string {
	return standardHost(ssm.NewDefaultEndpointResolverV2(), ssm.EndpointParameters{Region: &r})
}

func ec2Host(r string) string {
	return standardHost(ec2.NewDefaultEndpointResolverV2(), ec2.EndpointParameters{Region: &r})
}

func rdsHost(r string) string {
	return standardHost(rds.NewDefaultEndpointResolverV2(), rds.EndpointParameters{Region: &r})
}

func redshiftHost(r string) string {
	return standardHost(redshift.NewDefaultEndpointResolverV2(), redshift.EndpointParameters{Region: &r})
}

func redshiftServerlessHost(r string) string {
	return standardHost(redshiftserverless.NewDefaultEndpointResolverV2(), redshiftserverless.EndpointParameters{Region: &r})
}

func openSearchHost(r string) string {
	return standardHost(opensearch.NewDefaultEndpointResolverV2(), opensearch.EndpointParameters{Region: &r})
}

func dmsHost(r string) string {
	return standardHost(databasemigrationservice.NewDefaultEndpointResolverV2(), databasemigrationservice.EndpointParameters{Region: &r})
}

func elastiCacheHost(r string) string {
	return standardHost(elasticache.NewDefaultEndpointResolverV2(), elasticache.EndpointParameters{Region: &r})
}

func mskHost(r string) string {
	return standardHost(kafka.NewDefaultEndpointResolverV2(), kafka.EndpointParameters{Region: &r})
}

func mskConnectHost(r string) string {
	return standardHost(kafkaconnect.NewDefaultEndpointResolverV2(), kafkaconnect.EndpointParameters{Region: &r})
}

func efsHost(r string) string {
	return standardHost(efs.NewDefaultEndpointResolverV2(), efs.EndpointParameters{Region: &r})
}

func fsxHost(r string) string {
	return standardHost(fsx.NewDefaultEndpointResolverV2(), fsx.EndpointParameters{Region: &r})
}

func backupHost(r string) string {
	return standardHost(backup.NewDefaultEndpointResolverV2(), backup.EndpointParameters{Region: &r})
}

func dynamoDBHost(r string) string {
	return standardHost(dynamodb.NewDefaultEndpointResolverV2(), dynamodb.EndpointParameters{Region: &r})
}

func daxHost(r string) string {
	return standardHost(dax.NewDefaultEndpointResolverV2(), dax.EndpointParameters{Region: &r})
}

func kinesisHost(r string) string {
	return standardHost(kinesis.NewDefaultEndpointResolverV2(), kinesis.EndpointParameters{Region: &r})
}

func firehoseHost(r string) string {
	return standardHost(firehose.NewDefaultEndpointResolverV2(), firehose.EndpointParameters{Region: &r})
}

func glueHost(r string) string {
	return standardHost(glue.NewDefaultEndpointResolverV2(), glue.EndpointParameters{Region: &r})
}

func athenaHost(r string) string {
	return standardHost(athena.NewDefaultEndpointResolverV2(), athena.EndpointParameters{Region: &r})
}

func s3ControlHost(r string) string {
	return standardHost(s3control.NewDefaultEndpointResolverV2(), s3control.EndpointParameters{Region: &r})
}

func s3ExpressControlHost(r string) string {
	return standardHost(s3.NewDefaultEndpointResolverV2(), s3.EndpointParameters{Region: &r, UseS3ExpressControlEndpoint: awssdk.Bool(true)})
}

func autoScalingHost(r string) string {
	return standardHost(autoscaling.NewDefaultEndpointResolverV2(), autoscaling.EndpointParameters{Region: &r})
}

func elbv2Host(r string) string {
	return standardHost(elasticloadbalancingv2.NewDefaultEndpointResolverV2(), elasticloadbalancingv2.EndpointParameters{Region: &r})
}

func classicELBHost(r string) string {
	return standardHost(elasticloadbalancing.NewDefaultEndpointResolverV2(), elasticloadbalancing.EndpointParameters{Region: &r})
}

func wafv2Host(r string) string {
	return standardHost(wafv2.NewDefaultEndpointResolverV2(), wafv2.EndpointParameters{Region: &r})
}

func wafRegionalHost(r string) string {
	return standardHost(wafregional.NewDefaultEndpointResolverV2(), wafregional.EndpointParameters{Region: &r})
}

func networkFirewallHost(r string) string {
	return standardHost(networkfirewall.NewDefaultEndpointResolverV2(), networkfirewall.EndpointParameters{Region: &r})
}

func sagemakerHost(r string) string {
	return standardHost(sagemaker.NewDefaultEndpointResolverV2(), sagemaker.EndpointParameters{Region: &r})
}

func agentCoreHost(r string) string {
	return standardHost(bedrockagentcorecontrol.NewDefaultEndpointResolverV2(), bedrockagentcorecontrol.EndpointParameters{Region: &r})
}

func workSpacesHost(r string) string {
	return standardHost(workspaces.NewDefaultEndpointResolverV2(), workspaces.EndpointParameters{Region: &r})
}

func transferHost(r string) string {
	return standardHost(transfer.NewDefaultEndpointResolverV2(), transfer.EndpointParameters{Region: &r})
}

func cloudFormationHost(r string) string {
	return standardHost(cloudformation.NewDefaultEndpointResolverV2(), cloudformation.EndpointParameters{Region: &r})
}

func stepFunctionsHost(r string) string {
	return standardHost(sfn.NewDefaultEndpointResolverV2(), sfn.EndpointParameters{Region: &r})
}

func eventBridgeHost(r string) string {
	return standardHost(eventbridge.NewDefaultEndpointResolverV2(), eventbridge.EndpointParameters{Region: &r})
}

func mqHost(r string) string {
	return standardHost(mq.NewDefaultEndpointResolverV2(), mq.EndpointParameters{Region: &r})
}

func sesHost(r string) string {
	return standardHost(sesv2.NewDefaultEndpointResolverV2(), sesv2.EndpointParameters{Region: &r})
}

func serviceCatalogHost(r string) string {
	return standardHost(servicecatalog.NewDefaultEndpointResolverV2(), servicecatalog.EndpointParameters{Region: &r})
}

func connectHost(r string) string {
	return standardHost(connect.NewDefaultEndpointResolverV2(), connect.EndpointParameters{Region: &r})
}

func dataSyncHost(r string) string {
	return standardHost(datasync.NewDefaultEndpointResolverV2(), datasync.EndpointParameters{Region: &r})
}

func privateCAHost(r string) string {
	return standardHost(acmpca.NewDefaultEndpointResolverV2(), acmpca.EndpointParameters{Region: &r})
}

func codeBuildHost(r string) string {
	return standardHost(codebuild.NewDefaultEndpointResolverV2(), codebuild.EndpointParameters{Region: &r})
}

func cognitoUserPoolsHost(r string) string {
	return standardHost(cognitoidentityprovider.NewDefaultEndpointResolverV2(), cognitoidentityprovider.EndpointParameters{Region: &r})
}

func cognitoIdentityPoolsHost(r string) string {
	return standardHost(cognitoidentity.NewDefaultEndpointResolverV2(), cognitoidentity.EndpointParameters{Region: &r})
}

func emrHost(r string) string {
	return standardHost(emr.NewDefaultEndpointResolverV2(), emr.EndpointParameters{Region: &r})
}

func appSyncHost(r string) string {
	return standardHost(appsync.NewDefaultEndpointResolverV2(), appsync.EndpointParameters{Region: &r})
}

func elasticBeanstalkHost(r string) string {
	return standardHost(elasticbeanstalk.NewDefaultEndpointResolverV2(), elasticbeanstalk.EndpointParameters{Region: &r})
}
