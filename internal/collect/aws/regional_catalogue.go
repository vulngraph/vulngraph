package aws

// regionalServices is the catalogue appended to every region's fan-out
// (regionalServiceTasks): one entry per list-and-emit regional collector.
// Every entry names its endpoint host so the region ledger alone judges an
// NXDOMAIN (regional_offered.go). family/types are set only where the
// listing is proven complete. regionLimited is set only for services AWS does
// not run in every commercial region (its regional-services list): newer
// services, and older ones that skip newer regions. Unsure means unset, so an
// NXDOMAIN fails closed as a skipped collector.
//
// Glue jobs and ML transforms are separate tasks because glue:GetMLTransforms
// is outside the managed read-only policies: a role without it loses the
// transforms only.
var regionalServices = []regionalService{
	// Core and simple services (services.go, apigateway.go, acm.go,
	// region_settings.go).
	{name: "kms", host: kmsHost, fn: whole(collectKMS)},
	{name: "ecr", host: ecrHost, fn: whole(collectECR)},
	{name: "sqs", host: sqsHost, fn: whole(collectSQS)},
	{name: "sns", host: snsHost, fn: whole(collectSNS)},
	{name: "apigateway", host: apiGatewayHost, fn: whole(collectAPIGateway)},
	{name: "acm", host: acmHost, fn: whole(collectACM)},
	{name: "secretsmanager", host: secretsManagerHost, fn: whole(collectSecretsManager)},
	{name: "ssm", host: ssmHost, fn: whole(collectSSMParameters)},
	{name: "region settings", host: ec2Host, fn: whole(collectRegionSettings)},

	// Data stores and analytics (CIS AWS storage, FSBP data services).
	{name: "rds", host: rdsHost, fn: collectRDS},
	{name: "redshift", host: redshiftHost, fn: whole(collectRedshift)},
	{name: "redshift serverless", regionLimited: true, host: redshiftServerlessHost, fn: collectRedshiftServerless},
	{name: "opensearch", host: openSearchHost, fn: whole(collectOpenSearch)},
	{name: "dms", host: dmsHost, fn: whole(collectDMS)},
	{name: "elasticache", host: elastiCacheHost, fn: whole(collectElastiCache)},
	{name: "msk", host: mskHost, fn: whole(collectMSK)},
	{name: "msk connect", regionLimited: true, host: mskConnectHost, fn: whole(collectMSKConnect)},
	{name: "efs", host: efsHost, fn: whole(collectEFS)},
	{name: "fsx", host: fsxHost, fn: whole(collectFSx)},
	{name: "backup", host: backupHost, fn: whole(collectBackup)},
	{name: "dynamodb", host: dynamoDBHost, fn: whole(collectDynamoDB)},
	{name: "dax", regionLimited: true, host: daxHost, fn: whole(collectDAX)},
	{name: "kinesis", host: kinesisHost, fn: whole(collectKinesis)},
	{name: "firehose", host: firehoseHost, fn: whole(collectFirehose)},
	{name: "glue jobs", host: glueHost, fn: whole(collectGlueJobs)},
	{name: "glue ml transforms", host: glueHost, fn: collectGlueMLTransforms, proves: capabilityGlueMLTransforms},
	{name: "athena", host: athenaHost, fn: whole(collectAthena)},
	{name: "s3 access points", host: s3ControlHost, fn: whole(collectS3AccessPoints)},
	{name: "s3 directory buckets", regionLimited: true, host: s3ExpressControlHost, fn: whole(collectS3DirectoryBuckets)},

	// Network, edge and compute posture (CIS AWS 6.x, FSBP EC2/ELB/WAF/API
	// Gateway/Network Firewall/Auto Scaling/SSM).
	{name: "network acl", host: ec2Host, fn: whole(collectNetworkACLs)},
	{name: "transit gateway", host: ec2Host, fn: whole(collectTransitGateways)},
	{name: "vpn connection", host: ec2Host, fn: whole(collectVPNConnections)},
	{name: "client vpn", host: ec2Host, fn: whole(collectClientVPNEndpoints)},
	{name: "launch template", host: ec2Host, fn: whole(collectLaunchTemplates)},
	{name: "spot fleet", host: ec2Host, fn: whole(collectSpotFleetRequests)},
	{name: "auto scaling", host: autoScalingHost, fn: whole(collectAutoScaling)},
	{name: "elbv2 target groups", host: elbv2Host, fn: whole(collectTargetGroups)},
	{name: "classic elb", host: classicELBHost, fn: whole(collectClassicELBs)},
	{name: "wafv2 regional", host: wafv2Host, fn: whole(collectWAFv2Regional)},
	{name: "waf classic regional", regionLimited: true, host: wafRegionalHost, fn: whole(collectWAFClassicRegional)},
	{name: "apigateway stages", host: apiGatewayHost, fn: whole(collectAPIGatewayStages)},
	{name: "apigatewayv2", regionLimited: true, host: apiGatewayV2Host, fn: whole(collectAPIGatewayV2)},
	{name: "apigateway domains", host: apiGatewayHost, fn: whole(collectAPIGatewayDomains)},
	{name: "network firewall", regionLimited: true, host: networkFirewallHost, fn: whole(collectNetworkFirewall)},
	{name: "ssm documents", host: ssmHost, fn: whole(collectSSMDocuments)},

	// Application, ML and identity services most accounts never use.
	{name: "sagemaker", regionLimited: true, host: sagemakerHost, fn: whole(collectSageMaker), family: "sagemaker:inference", types: []string{"sagemaker_notebook", "sagemaker_model", "sagemaker_endpoint_config"}},
	{name: "sagemaker monitoring", regionLimited: true, host: sagemakerHost, fn: whole(collectSageMakerMonitoring), family: "sagemaker:monitoring", types: []string{"sagemaker_monitoring_job_definition", "sagemaker_monitoring_schedule", "sagemaker_feature_group"}},
	{name: "bedrock agentcore", regionLimited: true, host: agentCoreHost, fn: whole(collectAgentCore), family: "bedrock-agentcore:resources", types: []string{"agentcore_runtime", "agentcore_gateway", "agentcore_browser"}},
	{name: "workspaces", regionLimited: true, host: workSpacesHost, fn: whole(collectWorkSpaces), family: "workspaces:workspaces", types: []string{workspacesType}},
	{name: "transfer", regionLimited: true, host: transferHost, fn: whole(collectTransfer), family: "transfer:servers-connectors", types: []string{transferServerType, transferConnectorType}},
	{name: "cloudformation", host: cloudFormationHost, fn: whole(collectCloudFormation), family: "cloudformation:stacks", types: []string{cloudFormationStackType}},
	{name: "stepfunctions", host: stepFunctionsHost, fn: whole(collectStepFunctions), family: "states:state-machines", types: []string{stateMachineType}},
	{name: "eventbridge", host: eventBridgeHost, fn: whole(collectEventBridge), family: "events:event-buses", types: []string{eventBusType}},
	{name: "mq", regionLimited: true, host: mqHost, fn: whole(collectMQ), family: "mq:brokers", types: []string{mqBrokerType}},
	{name: "ses", regionLimited: true, host: sesHost, fn: whole(collectSES), family: "ses:configuration-sets", types: []string{sesConfigurationSetType}},
	{name: "servicecatalog", host: serviceCatalogHost, fn: whole(collectServiceCatalog), family: "servicecatalog:portfolios", types: []string{serviceCatalogPortfolioType}},
	{name: "connect", regionLimited: true, host: connectHost, fn: whole(collectConnect), family: "connect:instances", types: []string{connectInstanceType}},
	{name: "datasync", regionLimited: true, host: dataSyncHost, fn: whole(collectDataSync), family: "datasync:tasks", types: []string{dataSyncTaskType}},
	{name: "acm-pca", host: privateCAHost, fn: whole(collectPrivateCA), family: "acm-pca:certificate-authorities", types: []string{privateCAType}},
	{name: "codebuild", host: codeBuildHost, fn: whole(collectCodeBuild), family: "codebuild:projects", types: []string{"codebuild_project"}},
	{name: "codebuild report groups", host: codeBuildHost, fn: whole(collectCodeBuildReportGroups), family: "codebuild:report-groups", types: []string{"codebuild_report_group"}},
	{name: "cognito user pools", regionLimited: true, host: cognitoUserPoolsHost, fn: whole(collectCognitoUserPools), family: "cognito-idp:user-pools", types: []string{"cognito_user_pool"}},
	{name: "cognito identity pools", regionLimited: true, host: cognitoIdentityPoolsHost, fn: whole(collectCognitoIdentityPools), family: "cognito-identity:identity-pools", types: []string{"cognito_identity_pool"}},
	{name: "emr", regionLimited: true, host: emrHost, fn: whole(collectEMR), family: "emr:clusters", types: []string{"emr_cluster", "emr_security_configuration"}},
	{name: "appsync", regionLimited: true, host: appSyncHost, fn: whole(collectAppSync), family: "appsync:graphql-apis", types: []string{"appsync_graphql_api"}},
	{name: "elasticbeanstalk", host: elasticBeanstalkHost, fn: whole(collectElasticBeanstalk), family: "elasticbeanstalk:environments", types: []string{"elasticbeanstalk_environment"}},
}
