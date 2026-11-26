# Third-party dependency licenses

License metadata originally generated with `go-licenses/v2@v2.0.1`. On 2026-11-26,
the Go rows were filtered against `go list -deps ./cmd/graph` after retiring the
external scanner. The counts below describe the retained report rows. This is
not a fresh license classification of every dependency. Container builds also
collect the license files of linked Go modules and bundled frontend packages
with `scripts/collect-licenses.sh`; LadybugDB notices remain in `NOTICE`.

The removed Nuclei dependency tree no longer requires the Censys or LDAP-server
replacement modules. There are currently no govulncheck exceptions.

## Summary by license

| License | Report rows |
|---|---|
| Apache-2.0 | 147 |
| BSD-2-Clause | 1 |
| BSD-3-Clause | 39 |
| ISC | 1 |
| MIT | 70 |
| MIT (first-party; `internal/graphdb/ladybug/LICENSE`) | 1 |
| MIT-0 (LICENSE verified in module) | 6 |
| MPL-2.0 | 6 |
| Unicode-DFS-2016 | 1 |

## Full report

| Package | License | License URL |
|---|---|---|
| cloud.google.com/go/auth | Apache-2.0 | https://github.com/googleapis/google-cloud-go/blob/auth/v0.20.0/auth/LICENSE |
| cloud.google.com/go/auth/oauth2adapt | Apache-2.0 | https://github.com/googleapis/google-cloud-go/blob/auth/oauth2adapt/v0.2.8/auth/oauth2adapt/LICENSE |
| cloud.google.com/go/compute/metadata | Apache-2.0 | https://github.com/googleapis/google-cloud-go/blob/compute/metadata/v0.9.0/compute/metadata/LICENSE |
| github.com/Azure/azure-sdk-for-go/sdk/azcore | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/azcore/v1.22.0/sdk/azcore/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/azidentity | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/azidentity/v1.14.0/sdk/azidentity/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/internal | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/internal/v1.12.0/sdk/internal/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/applicationinsights/armapplicationinsights | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/resourcemanager/applicationinsights/armapplicationinsights/v1.2.0/sdk/resourcemanager/applicationinsights/armapplicationinsights/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appservice/armappservice/v4 | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/resourcemanager/appservice/armappservice/v4.1.0/sdk/resourcemanager/appservice/armappservice/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2 | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/resourcemanager/authorization/armauthorization/v2.2.0/sdk/resourcemanager/authorization/armauthorization/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6 | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/resourcemanager/compute/armcompute/v6.4.0/sdk/resourcemanager/compute/armcompute/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v8 | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/resourcemanager/containerservice/armcontainerservice/v8.2.0/sdk/resourcemanager/containerservice/armcontainerservice/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/databricks/armdatabricks | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/resourcemanager/databricks/armdatabricks/v1.1.0/sdk/resourcemanager/databricks/armdatabricks/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/keyvault/armkeyvault | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/resourcemanager/keyvault/armkeyvault/v1.5.0/sdk/resourcemanager/keyvault/armkeyvault/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/monitor/armmonitor | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/resourcemanager/monitor/armmonitor/v0.13.0/sdk/resourcemanager/monitor/armmonitor/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v6 | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/resourcemanager/network/armnetwork/v6.2.0/sdk/resourcemanager/network/armnetwork/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/operationalinsights/armoperationalinsights/v2 | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/resourcemanager/operationalinsights/armoperationalinsights/v2.0.2/sdk/resourcemanager/operationalinsights/armoperationalinsights/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armlocks | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/resourcemanager/resources/armlocks/v1.2.0/sdk/resourcemanager/resources/armlocks/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armpolicy | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/resourcemanager/resources/armpolicy/v1.0.0/sdk/resourcemanager/resources/armpolicy/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources/v2 | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/resourcemanager/resources/armresources/v2.1.0/sdk/resourcemanager/resources/armresources/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/resourcemanager/resources/armsubscriptions/v1.3.0/sdk/resourcemanager/resources/armsubscriptions/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/resourcemanager/security/armsecurity/v0.15.0/sdk/resourcemanager/security/armsecurity/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/sql/armsql | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/resourcemanager/sql/armsql/v1.2.0/sdk/resourcemanager/sql/armsql/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/resourcemanager/storage/armstorage/v1.8.1/sdk/resourcemanager/storage/armstorage/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/subscription/armsubscription | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/resourcemanager/subscription/armsubscription/v1.2.0/sdk/resourcemanager/subscription/armsubscription/LICENSE.txt |
| github.com/Azure/azure-sdk-for-go/sdk/storage/azblob | MIT | https://github.com/Azure/azure-sdk-for-go/blob/sdk/storage/azblob/v1.1.0/sdk/storage/azblob/LICENSE.txt |
| github.com/AzureAD/microsoft-authentication-library-for-go/apps | MIT | https://github.com/AzureAD/microsoft-authentication-library-for-go/blob/v1.7.2/LICENSE |
| github.com/ClickHouse/ch-go | Apache-2.0 | https://github.com/ClickHouse/ch-go/blob/v0.71.0/LICENSE |
| github.com/ClickHouse/clickhouse-go/v2 | Apache-2.0 | https://github.com/ClickHouse/clickhouse-go/blob/v2.46.0/LICENSE |
| github.com/agext/levenshtein | Apache-2.0 | https://github.com/agext/levenshtein/blob/v1.2.1/LICENSE |
| github.com/andybalholm/brotli | MIT | https://github.com/andybalholm/brotli/blob/v1.2.1/LICENSE |
| github.com/anthropics/anthropic-sdk-go | MIT | https://github.com/anthropics/anthropic-sdk-go/blob/v1.50.1/LICENSE |
| github.com/apparentlymart/go-textseg/v15/textseg | MIT | https://github.com/apparentlymart/go-textseg/blob/v15.0.0/LICENSE |
| github.com/apparentlymart/go-textseg/v15/textseg | Unicode-DFS-2016 | https://github.com/apparentlymart/go-textseg/blob/v15.0.0/LICENSE |
| github.com/aws/aws-sdk-go-v2 | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/v1.47.3/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/aws/protocol/eventstream/v1.7.22/aws/protocol/eventstream/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/config | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/config/v1.33.9/config/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/credentials | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/credentials/v1.20.9/credentials/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/feature/ec2/imds | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/feature/ec2/imds/v1.20.3/feature/ec2/imds/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/internal/configsources | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/internal/configsources/v1.5.6/internal/configsources/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/internal/endpoints/v2.8.6/internal/endpoints/v2/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/internal/sync/singleflight | BSD-3-Clause | https://github.com/aws/aws-sdk-go-v2/blob/v1.47.3/internal/sync/singleflight/LICENSE |
| github.com/aws/aws-sdk-go-v2/internal/v4a | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/internal/v4a/v1.5.6/internal/v4a/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/accessanalyzer | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/accessanalyzer/v1.57.4/service/accessanalyzer/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/account | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/account/v1.30.0/service/account/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/acm | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/acm/v1.40.0/service/acm/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/acmpca | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/acmpca/v1.56.4/service/acmpca/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/apigateway | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/apigateway/v1.40.6/service/apigateway/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/apigatewayv2 | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/apigatewayv2/v1.46.1/service/apigatewayv2/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/applicationautoscaling | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/applicationautoscaling/v1.51.4/service/applicationautoscaling/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/appsync | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/appsync/v1.62.4/service/appsync/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/athena | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/athena/v1.66.4/service/athena/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/autoscaling | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/autoscaling/v1.69.1/service/autoscaling/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/backup | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/backup/v1.69.1/service/backup/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/bedrockagentcorecontrol/v1.72.3/service/bedrockagentcorecontrol/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/cloudformation | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/cloudformation/v1.82.1/service/cloudformation/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/cloudfront | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/cloudfront/v1.66.1/service/cloudfront/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/cloudtrail | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/cloudtrail/v1.56.4/service/cloudtrail/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/cloudwatch | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/cloudwatch/v1.73.3/service/cloudwatch/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/cloudwatchlogs/v1.89.3/service/cloudwatchlogs/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/codebuild | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/codebuild/v1.78.4/service/codebuild/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/cognitoidentity | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/cognitoidentity/v1.42.4/service/cognitoidentity/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/cognitoidentityprovider/v1.75.3/service/cognitoidentityprovider/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/configservice | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/configservice/v1.74.4/service/configservice/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/connect | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/connect/v1.204.3/service/connect/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/costexplorer | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/costexplorer/v1.65.1/service/costexplorer/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/databasemigrationservice | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/databasemigrationservice/v1.75.1/service/databasemigrationservice/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/datasync | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/datasync/v1.67.4/service/datasync/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/dax | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/dax/v1.38.7/service/dax/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/dynamodb | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/dynamodb/v1.70.3/service/dynamodb/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/ec2 | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/ec2/v1.307.0/service/ec2/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/ecr | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/ecr/v1.58.4/service/ecr/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/ecs | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/ecs/v1.83.0/service/ecs/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/efs | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/efs/v1.49.4/service/efs/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/eks | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/eks/v1.86.0/service/eks/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/elasticache | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/elasticache/v1.63.3/service/elasticache/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/elasticbeanstalk/v1.43.4/service/elasticbeanstalk/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/elasticloadbalancing/v1.35.1/service/elasticloadbalancing/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/elasticloadbalancingv2/v1.55.4/service/elasticloadbalancingv2/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/emr | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/emr/v1.70.4/service/emr/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/eventbridge | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/eventbridge/v1.55.3/service/eventbridge/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/firehose | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/firehose/v1.52.4/service/firehose/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/fsx | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/fsx/v1.74.4/service/fsx/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/glue | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/glue/v1.169.1/service/glue/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/guardduty | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/guardduty/v1.79.3/service/guardduty/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/iam | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/iam/v1.54.4/service/iam/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/identitystore | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/identitystore/v1.38.1/service/identitystore/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/inspector2 | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/inspector2/v1.61.3/service/inspector2/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/internal/accept-encoding/v1.13.21/service/internal/accept-encoding/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/internal/checksum | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/internal/checksum/v1.9.13/service/internal/checksum/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/internal/endpoint-discovery/v1.13.6/service/internal/endpoint-discovery/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/internal/presigned-url | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/internal/presigned-url/v1.14.6/service/internal/presigned-url/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/internal/s3shared | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/internal/s3shared/v1.19.31/service/internal/s3shared/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/kafka | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/kafka/v1.65.4/service/kafka/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/kafkaconnect | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/kafkaconnect/v1.39.4/service/kafkaconnect/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/kinesis | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/kinesis/v1.56.4/service/kinesis/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/kms | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/kms/v1.53.4/service/kms/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/lambda | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/lambda/v1.92.3/service/lambda/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/macie2 | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/macie2/v1.59.4/service/macie2/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/mq | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/mq/v1.45.4/service/mq/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/networkfirewall | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/networkfirewall/v1.76.1/service/networkfirewall/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/opensearch | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/opensearch/v1.85.1/service/opensearch/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/organizations | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/organizations/v1.51.10/service/organizations/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/rds | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/rds/v1.119.2/service/rds/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/redshift | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/redshift/v1.71.4/service/redshift/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/redshiftserverless | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/redshiftserverless/v1.44.4/service/redshiftserverless/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/route53 | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/route53/v1.63.3/service/route53/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/s3 | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/s3/v1.99.0/service/s3/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/s3control | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/s3control/v1.72.0/service/s3control/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/sagemaker | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/sagemaker/v1.282.3/service/sagemaker/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/secretsmanager | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/secretsmanager/v1.42.3/service/secretsmanager/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/securityhub | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/securityhub/v1.84.1/service/securityhub/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/servicecatalog | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/servicecatalog/v1.47.4/service/servicecatalog/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/sesv2 | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/sesv2/v1.79.1/service/sesv2/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/sfn | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/sfn/v1.51.4/service/sfn/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/signin | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/signin/v1.10.4/service/signin/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/sns | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/sns/v1.40.1/service/sns/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/sqs | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/sqs/v1.44.0/service/sqs/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/ssm | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/ssm/v1.69.3/service/ssm/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/sso | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/sso/v1.38.4/service/sso/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/ssoadmin | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/ssoadmin/v1.41.1/service/ssoadmin/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/ssooidc | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/ssooidc/v1.43.4/service/ssooidc/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/sts | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/sts/v1.51.4/service/sts/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/transfer | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/transfer/v1.85.3/service/transfer/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/waf | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/waf/v1.32.1/service/waf/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/wafregional | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/wafregional/v1.32.1/service/wafregional/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/wafv2 | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/wafv2/v1.75.1/service/wafv2/LICENSE.txt |
| github.com/aws/aws-sdk-go-v2/service/workspaces | Apache-2.0 | https://github.com/aws/aws-sdk-go-v2/blob/service/workspaces/v1.81.4/service/workspaces/LICENSE.txt |
| github.com/aws/smithy-go | Apache-2.0 | https://github.com/aws/smithy-go/blob/v1.28.5/LICENSE |
| github.com/aws/smithy-go/internal/sync/singleflight | BSD-3-Clause | https://github.com/aws/smithy-go/blob/v1.28.5/internal/sync/singleflight/LICENSE |
| github.com/aws/smithy-go/transport/http/protocol/internal/json/internal/stdlib | BSD-3-Clause | https://github.com/aws/smithy-go/blob/v1.28.5/transport/http/protocol/internal/json/internal/stdlib/LICENSE |
| github.com/bahlo/generic-list-go | BSD-3-Clause | https://github.com/bahlo/generic-list-go/blob/v0.2.0/LICENSE |
| github.com/beorn7/perks/quantile | MIT | https://github.com/beorn7/perks/blob/v1.0.1/LICENSE |
| github.com/boombuler/barcode | MIT | https://github.com/boombuler/barcode/blob/v1.0.1/LICENSE |
| github.com/buger/jsonparser | MIT | https://github.com/buger/jsonparser/blob/v1.1.2/LICENSE |
| github.com/cenkalti/backoff/v5 | MIT | https://github.com/cenkalti/backoff/blob/v5.0.3/LICENSE |
| github.com/cespare/xxhash | MIT | https://github.com/cespare/xxhash/blob/v1.1.0/LICENSE.txt |
| github.com/cespare/xxhash/v2 | MIT | https://github.com/cespare/xxhash/blob/v2.3.0/LICENSE.txt |
| github.com/davecgh/go-spew/spew | ISC | https://github.com/davecgh/go-spew/blob/d8f796af33cc/LICENSE |
| github.com/docker/cli/cli/config | Apache-2.0 | https://github.com/docker/cli/blob/v29.5.3/LICENSE |
| github.com/docker/docker-credential-helpers | MIT | https://github.com/docker/docker-credential-helpers/blob/v0.9.5/LICENSE |
| github.com/emicklei/go-restful/v3 | MIT | https://github.com/emicklei/go-restful/blob/v3.13.0/LICENSE |
| github.com/felixge/httpsnoop | MIT | https://github.com/felixge/httpsnoop/blob/v1.0.4/LICENSE.txt |
| github.com/fxamacker/cbor/v2 | MIT | https://github.com/fxamacker/cbor/blob/v2.9.0/LICENSE |
| github.com/go-faster/city | MIT | https://github.com/go-faster/city/blob/v1.0.1/LICENSE |
| github.com/go-faster/errors | BSD-3-Clause | https://github.com/go-faster/errors/blob/v0.7.1/LICENSE |
| github.com/go-logr/logr | Apache-2.0 | https://github.com/go-logr/logr/blob/v1.4.4/LICENSE |
| github.com/go-logr/stdr | Apache-2.0 | https://github.com/go-logr/stdr/blob/v1.2.2/LICENSE |
| github.com/go-openapi/jsonpointer | Apache-2.0 | https://github.com/go-openapi/jsonpointer/blob/v0.22.5/LICENSE |
| github.com/go-openapi/jsonreference | Apache-2.0 | https://github.com/go-openapi/jsonreference/blob/v0.20.2/LICENSE |
| github.com/go-openapi/swag | Apache-2.0 | https://github.com/go-openapi/swag/blob/v0.23.0/LICENSE |
| github.com/golang-jwt/jwt/v5 | MIT | https://github.com/golang-jwt/jwt/blob/v5.3.1/LICENSE |
| github.com/google/gnostic-models | Apache-2.0 | https://github.com/google/gnostic-models/blob/v0.7.0/LICENSE |
| github.com/google/go-containerregistry | Apache-2.0 | https://github.com/google/go-containerregistry/blob/v0.21.7/LICENSE |
| github.com/google/s2a-go | Apache-2.0 | https://github.com/google/s2a-go/blob/v0.1.9/LICENSE.md |
| github.com/google/uuid | BSD-3-Clause | https://github.com/google/uuid/blob/v1.6.0/LICENSE |
| github.com/googleapis/enterprise-certificate-proxy/client | Apache-2.0 | https://github.com/googleapis/enterprise-certificate-proxy/blob/v0.3.16/LICENSE |
| github.com/googleapis/gax-go/v2 | BSD-3-Clause | https://github.com/googleapis/gax-go/blob/v2.22.0/v2/LICENSE |
| github.com/grpc-ecosystem/grpc-gateway/v2 | BSD-3-Clause | https://github.com/grpc-ecosystem/grpc-gateway/blob/v2.29.0/LICENSE |
| github.com/hashicorp/hcl/v2 | MPL-2.0 | https://github.com/hashicorp/hcl/blob/v2.24.0/LICENSE |
| github.com/invopop/jsonschema | MIT | https://github.com/invopop/jsonschema/blob/v0.14.0/COPYING |
| github.com/jackc/pgpassfile | MIT | https://github.com/jackc/pgpassfile/blob/v1.0.0/LICENSE |
| github.com/jackc/pgservicefile | MIT | https://github.com/jackc/pgservicefile/blob/5a60cdf6a761/LICENSE |
| github.com/jackc/pgx/v5 | MIT | https://github.com/jackc/pgx/blob/v5.10.0/LICENSE |
| github.com/jackc/puddle/v2 | MIT | https://github.com/jackc/puddle/blob/v2.2.2/LICENSE |
| github.com/json-iterator/go | MIT | https://github.com/json-iterator/go/blob/v1.1.12/LICENSE |
| github.com/klauspost/compress | MIT | https://github.com/klauspost/compress/blob/v1.18.7/LICENSE |
| github.com/klauspost/compress | Apache-2.0 | https://github.com/klauspost/compress/blob/v1.18.7/LICENSE |
| github.com/klauspost/compress | BSD-3-Clause | https://github.com/klauspost/compress/blob/v1.18.7/LICENSE |
| github.com/klauspost/compress/internal/snapref | BSD-3-Clause | https://github.com/klauspost/compress/blob/v1.18.7/internal/snapref/LICENSE |
| github.com/klauspost/compress/zstd/internal/xxhash | MIT | https://github.com/klauspost/compress/blob/v1.18.7/zstd/internal/xxhash/LICENSE.txt |
| github.com/kylelemons/godebug | Apache-2.0 | https://github.com/kylelemons/godebug/blob/v1.1.0/LICENSE |
| github.com/mattn/go-colorable | MIT | https://github.com/mattn/go-colorable/blob/v0.1.14/LICENSE |
| github.com/mattn/go-isatty | MIT | https://github.com/mattn/go-isatty/blob/v0.0.22/LICENSE |
| github.com/mfridman/interpolate | MIT | https://github.com/mfridman/interpolate/blob/v0.0.2/LICENSE.txt |
| github.com/mitchellh/go-wordwrap | MIT | https://github.com/mitchellh/go-wordwrap/blob/v1.0.1/LICENSE.md |
| github.com/modern-go/concurrent | Apache-2.0 | https://github.com/modern-go/concurrent/blob/bacd9c7ef1dd/LICENSE |
| github.com/modern-go/reflect2 | Apache-2.0 | https://github.com/modern-go/reflect2/blob/35a7c28c31ee/LICENSE |
| github.com/munnerz/goautoneg | BSD-3-Clause | https://github.com/munnerz/goautoneg/blob/a7dc8b61c822/LICENSE |
| github.com/opencontainers/go-digest | Apache-2.0 | https://github.com/opencontainers/go-digest/blob/v1.0.0/LICENSE |
| github.com/opencontainers/image-spec/specs-go | Apache-2.0 | https://github.com/opencontainers/image-spec/blob/v1.1.1/LICENSE |
| github.com/paulmach/orb | MIT | https://github.com/paulmach/orb/blob/v0.13.0/LICENSE.md |
| github.com/pb33f/ordered-map/v2 | Apache-2.0 | https://github.com/pb33f/ordered-map/blob/v2.3.1/LICENSE |
| github.com/pierrec/lz4/v4 | BSD-3-Clause | https://github.com/pierrec/lz4/blob/v4.1.26/LICENSE |
| github.com/pkg/browser | BSD-2-Clause | https://github.com/pkg/browser/blob/5ac0b6a4141c/LICENSE |
| github.com/pquerna/otp | Apache-2.0 | https://github.com/pquerna/otp/blob/v1.5.0/LICENSE |
| github.com/pressly/goose/v3 | MIT | https://github.com/pressly/goose/blob/v3.27.1/LICENSE |
| github.com/prometheus/client_golang/internal/github.com/golang/gddo/httputil | BSD-3-Clause | https://github.com/prometheus/client_golang/blob/v1.23.2/internal/github.com/golang/gddo/LICENSE |
| github.com/prometheus/client_golang/prometheus | Apache-2.0 | https://github.com/prometheus/client_golang/blob/v1.23.2/LICENSE |
| github.com/prometheus/client_model/go | Apache-2.0 | https://github.com/prometheus/client_model/blob/v0.6.2/LICENSE |
| github.com/prometheus/common | Apache-2.0 | https://github.com/prometheus/common/blob/v0.67.5/LICENSE |
| github.com/riverqueue/river | MPL-2.0 | https://github.com/riverqueue/river/blob/v0.39.0/LICENSE |
| github.com/riverqueue/river/riverdriver | MPL-2.0 | https://github.com/riverqueue/river/blob/riverdriver/v0.39.0/riverdriver/LICENSE |
| github.com/riverqueue/river/riverdriver/riverpgxv5 | MPL-2.0 | https://github.com/riverqueue/river/blob/riverdriver/riverpgxv5/v0.39.0/riverdriver/riverpgxv5/LICENSE |
| github.com/riverqueue/river/rivershared | MPL-2.0 | https://github.com/riverqueue/river/blob/rivershared/v0.39.0/rivershared/LICENSE |
| github.com/riverqueue/river/rivershared/levenshtein | MIT | https://github.com/riverqueue/river/blob/rivershared/v0.39.0/rivershared/levenshtein/License.txt |
| github.com/riverqueue/river/rivertype | MPL-2.0 | https://github.com/riverqueue/river/blob/rivertype/v0.39.0/rivertype/LICENSE |
| github.com/rs/zerolog | MIT | https://github.com/rs/zerolog/blob/v1.35.1/LICENSE |
| github.com/segmentio/asm/bswap | MIT-0 (LICENSE verified in module) |  |
| github.com/segmentio/asm/cpu | MIT-0 (LICENSE verified in module) |  |
| github.com/segmentio/asm/cpu/arm | MIT-0 (LICENSE verified in module) |  |
| github.com/segmentio/asm/cpu/arm64 | MIT-0 (LICENSE verified in module) |  |
| github.com/segmentio/asm/cpu/cpuid | MIT-0 (LICENSE verified in module) |  |
| github.com/segmentio/asm/cpu/x86 | MIT-0 (LICENSE verified in module) |  |
| github.com/sethvargo/go-retry | Apache-2.0 | https://github.com/sethvargo/go-retry/blob/v0.3.0/LICENSE |
| github.com/shopspring/decimal | MIT | https://github.com/shopspring/decimal/blob/v1.4.0/LICENSE |
| github.com/sirupsen/logrus | MIT | https://github.com/sirupsen/logrus/blob/v1.9.4/LICENSE |
| github.com/standard-webhooks/standard-webhooks/libraries/go | MIT | https://github.com/standard-webhooks/standard-webhooks/blob/libraries/v0.0.1/libraries/LICENSE |
| github.com/stretchr/testify | MIT | https://github.com/stretchr/testify/blob/v1.11.1/LICENSE |
| github.com/tidwall/gjson | MIT | https://github.com/tidwall/gjson/blob/v1.19.0/LICENSE |
| github.com/tidwall/match | MIT | https://github.com/tidwall/match/blob/v1.2.0/LICENSE |
| github.com/tidwall/pretty | MIT | https://github.com/tidwall/pretty/blob/v1.2.1/LICENSE |
| github.com/tidwall/sjson | MIT | https://github.com/tidwall/sjson/blob/v1.2.5/LICENSE |
| github.com/vulngraph/vulngraph | Apache-2.0 | https://github.com/vulngraph/vulngraph/blob/HEAD/LICENSE |
| github.com/vulngraph/vulngraph/internal/graphdb/ladybug | MIT (first-party; `internal/graphdb/ladybug/LICENSE`) |  |
| github.com/x448/float16 | MIT | https://github.com/x448/float16/blob/v0.8.4/LICENSE |
| github.com/zclconf/go-cty/cty | MIT | https://github.com/zclconf/go-cty/blob/v1.16.3/LICENSE |
| go.opentelemetry.io/auto/sdk | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go-instrumentation/blob/sdk/v1.2.1/sdk/LICENSE |
| go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go-contrib/blob/instrumentation/net/http/otelhttp/v0.68.0/instrumentation/net/http/otelhttp/LICENSE |
| go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp | BSD-3-Clause | https://github.com/open-telemetry/opentelemetry-go-contrib/blob/instrumentation/net/http/otelhttp/v0.68.0/instrumentation/net/http/otelhttp/LICENSE |
| go.opentelemetry.io/otel | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go/blob/v1.45.0/LICENSE |
| go.opentelemetry.io/otel | BSD-3-Clause | https://github.com/open-telemetry/opentelemetry-go/blob/v1.45.0/LICENSE |
| go.opentelemetry.io/otel/exporters/otlp/otlptrace | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go/blob/exporters/otlp/otlptrace/v1.45.0/exporters/otlp/otlptrace/LICENSE |
| go.opentelemetry.io/otel/exporters/otlp/otlptrace | BSD-3-Clause | https://github.com/open-telemetry/opentelemetry-go/blob/exporters/otlp/otlptrace/v1.45.0/exporters/otlp/otlptrace/LICENSE |
| go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go/blob/exporters/otlp/otlptrace/otlptracehttp/v1.45.0/exporters/otlp/otlptrace/otlptracehttp/LICENSE |
| go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp | BSD-3-Clause | https://github.com/open-telemetry/opentelemetry-go/blob/exporters/otlp/otlptrace/otlptracehttp/v1.45.0/exporters/otlp/otlptrace/otlptracehttp/LICENSE |
| go.opentelemetry.io/otel/metric | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go/blob/metric/v1.45.0/metric/LICENSE |
| go.opentelemetry.io/otel/metric | BSD-3-Clause | https://github.com/open-telemetry/opentelemetry-go/blob/metric/v1.45.0/metric/LICENSE |
| go.opentelemetry.io/otel/sdk | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go/blob/sdk/v1.45.0/sdk/LICENSE |
| go.opentelemetry.io/otel/sdk | BSD-3-Clause | https://github.com/open-telemetry/opentelemetry-go/blob/sdk/v1.45.0/sdk/LICENSE |
| go.opentelemetry.io/otel/trace | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-go/blob/trace/v1.45.0/trace/LICENSE |
| go.opentelemetry.io/otel/trace | BSD-3-Clause | https://github.com/open-telemetry/opentelemetry-go/blob/trace/v1.45.0/trace/LICENSE |
| go.opentelemetry.io/proto/otlp | Apache-2.0 | https://github.com/open-telemetry/opentelemetry-proto-go/blob/otlp/v1.11.0/otlp/LICENSE |
| go.uber.org/goleak | MIT | https://github.com/uber-go/goleak/blob/v1.3.0/LICENSE |
| go.uber.org/multierr | MIT | https://github.com/uber-go/multierr/blob/v1.11.0/LICENSE.txt |
| go.yaml.in/yaml/v2 | Apache-2.0 | https://github.com/yaml/go-yaml/blob/v2.4.4/LICENSE |
| go.yaml.in/yaml/v3 | MIT | https://github.com/yaml/go-yaml/blob/v3.0.4/LICENSE |
| go.yaml.in/yaml/v4 | MIT | https://github.com/yaml/go-yaml/blob/v4.0.0-rc.2/LICENSE |
| golang.org/x/crypto | BSD-3-Clause | https://cs.opensource.google/go/x/crypto/+/v0.57.0:LICENSE |
| golang.org/x/mod | BSD-3-Clause | https://cs.opensource.google/go/x/mod/+/v0.41.0:LICENSE |
| golang.org/x/net | BSD-3-Clause | https://cs.opensource.google/go/x/net/+/v0.60.0:LICENSE |
| golang.org/x/oauth2 | BSD-3-Clause | https://cs.opensource.google/go/x/oauth2/+/v0.36.0:LICENSE |
| golang.org/x/sync | BSD-3-Clause | https://cs.opensource.google/go/x/sync/+/v0.23.0:LICENSE |
| golang.org/x/sys | BSD-3-Clause | https://cs.opensource.google/go/x/sys/+/v0.48.0:LICENSE |
| golang.org/x/term | BSD-3-Clause | https://cs.opensource.google/go/x/term/+/v0.46.0:LICENSE |
| golang.org/x/text | BSD-3-Clause | https://cs.opensource.google/go/x/text/+/v0.42.0:LICENSE |
| golang.org/x/time/rate | BSD-3-Clause | https://cs.opensource.google/go/x/time/+/v0.15.0:LICENSE |
| google.golang.org/api | BSD-3-Clause | https://github.com/googleapis/google-api-go-client/blob/v0.284.0/LICENSE |
| google.golang.org/api/internal/third_party/uritemplates | BSD-3-Clause | https://github.com/googleapis/google-api-go-client/blob/v0.284.0/internal/third_party/uritemplates/LICENSE |
| google.golang.org/genproto/googleapis/api/httpbody | Apache-2.0 | https://github.com/googleapis/go-genproto/blob/6ac0973c030d/googleapis/api/LICENSE |
| google.golang.org/genproto/googleapis/rpc | Apache-2.0 | https://github.com/googleapis/go-genproto/blob/6ac0973c030d/googleapis/rpc/LICENSE |
| google.golang.org/grpc | Apache-2.0 | https://github.com/grpc/grpc-go/blob/v1.83.2/LICENSE |
| google.golang.org/protobuf | BSD-3-Clause | https://github.com/protocolbuffers/protobuf-go/blob/f2248ac996af/LICENSE |
| gopkg.in/evanphx/json-patch.v4 | BSD-3-Clause | https://github.com/evanphx/json-patch/blob/v4.13.0/LICENSE |
| gopkg.in/inf.v0 | BSD-3-Clause | https://github.com/go-inf/inf/blob/v0.9.1/LICENSE |
| gopkg.in/yaml.v3 | MIT | https://github.com/go-yaml/yaml/blob/v3.0.1/LICENSE |
| k8s.io/api | Apache-2.0 | https://github.com/kubernetes/api/blob/v0.36.2/LICENSE |
| k8s.io/apimachinery/pkg | Apache-2.0 | https://github.com/kubernetes/apimachinery/blob/v0.36.2/LICENSE |
| k8s.io/apimachinery/third_party/forked/golang | BSD-3-Clause | https://github.com/kubernetes/apimachinery/blob/v0.36.2/third_party/forked/golang/LICENSE |
| k8s.io/client-go | Apache-2.0 | https://github.com/kubernetes/client-go/blob/v0.36.2/LICENSE |
| k8s.io/klog/v2 | Apache-2.0 | https://github.com/kubernetes/klog/blob/v2.140.0/LICENSE |
| k8s.io/kube-openapi/pkg | Apache-2.0 | https://github.com/kubernetes/kube-openapi/blob/43fb72c5454a/LICENSE |
| k8s.io/kube-openapi/pkg/internal/third_party/go-json-experiment/json | BSD-3-Clause | https://github.com/kubernetes/kube-openapi/blob/43fb72c5454a/pkg/internal/third_party/go-json-experiment/json/LICENSE |
| k8s.io/kube-openapi/pkg/validation/spec | Apache-2.0 | https://github.com/kubernetes/kube-openapi/blob/43fb72c5454a/pkg/validation/spec/LICENSE |
| k8s.io/utils | Apache-2.0 | https://github.com/kubernetes/utils/blob/b8788abfbbc2/LICENSE |
| k8s.io/utils/internal/third_party/forked/golang/net | BSD-3-Clause | https://github.com/kubernetes/utils/blob/b8788abfbbc2/internal/third_party/forked/golang/LICENSE |
| sigs.k8s.io/json | Apache-2.0 | https://github.com/kubernetes-sigs/json/blob/2d320260d730/LICENSE |
| sigs.k8s.io/json | BSD-3-Clause | https://github.com/kubernetes-sigs/json/blob/2d320260d730/LICENSE |
| sigs.k8s.io/randfill | Apache-2.0 | https://github.com/kubernetes-sigs/randfill/blob/v1.0.0/LICENSE |
| sigs.k8s.io/structured-merge-diff/v6 | Apache-2.0 | https://github.com/kubernetes-sigs/structured-merge-diff/blob/v6.3.2/LICENSE |
| sigs.k8s.io/yaml | MIT | https://github.com/kubernetes-sigs/yaml/blob/v1.6.0/LICENSE |
| sigs.k8s.io/yaml | Apache-2.0 | https://github.com/kubernetes-sigs/yaml/blob/v1.6.0/LICENSE |
| sigs.k8s.io/yaml | BSD-3-Clause | https://github.com/kubernetes-sigs/yaml/blob/v1.6.0/LICENSE |

## Frontend (npm) — production dependencies bundled into web/dist

Transitive closure of `frontend/package.json` `dependencies` (dev-only build
tooling is not shipped). Regenerate by walking `frontend/node_modules`.

| Package | Version | License |
|---|---|---|
| @fontsource-variable/instrument-sans | 5.3.0 | OFL-1.1 |
| @fontsource-variable/jetbrains-mono | 5.3.0 | OFL-1.1 |
| @tanstack/history | 1.162.0 | MIT |
| @tanstack/query-core | 5.101.0 | MIT |
| @tanstack/react-query | 5.101.0 | MIT |
| @tanstack/react-router | 1.170.15 | MIT |
| @tanstack/react-store | 0.9.3 | MIT |
| @tanstack/router-core | 1.171.13 | MIT |
| @tanstack/store | 0.9.3 | MIT |
| @types/d3-color | 3.1.3 | MIT |
| @types/d3-drag | 3.0.7 | MIT |
| @types/d3-force | 3.0.10 | MIT |
| @types/d3-interpolate | 3.0.4 | MIT |
| @types/d3-selection | 3.0.11 | MIT |
| @types/d3-transition | 3.0.9 | MIT |
| @types/d3-zoom | 3.0.8 | MIT |
| @xyflow/react | 12.11.0 | MIT |
| @xyflow/system | 0.0.77 | MIT |
| classcat | 5.0.5 | MIT |
| cookie-es | 3.1.1 | MIT |
| d3-color | 3.1.0 | ISC |
| d3-dispatch | 3.0.1 | ISC |
| d3-drag | 3.0.0 | ISC |
| d3-ease | 3.0.1 | BSD-3-Clause |
| d3-force | 3.0.0 | ISC |
| d3-interpolate | 3.0.1 | ISC |
| d3-quadtree | 3.0.1 | ISC |
| d3-selection | 3.0.0 | ISC |
| d3-timer | 3.0.1 | ISC |
| d3-transition | 3.0.1 | ISC |
| d3-zoom | 3.0.0 | ISC |
| isbot | 5.1.42 | Unlicense |
| lucide-react | 1.18.0 | ISC |
| react | 19.2.7 | MIT |
| react-dom | 19.2.7 | MIT |
| scheduler | 0.27.0 | MIT |
| seroval | 1.5.4 | MIT |
| seroval-plugins | 1.5.4 | MIT |
| use-sync-external-store | 1.6.0 | MIT |
| zustand | 4.5.7 | MIT |
