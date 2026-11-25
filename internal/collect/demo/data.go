package demo

import "github.com/vulngraph/vulngraph/internal/app/asset"

// data adds the stores the web tier reaches: the orders database and a bucket
// of customer exports.
func (b *builder) data() {
	b.add(asset.Asset{
		ID: arn("rds", "db:acme-orders"), Name: "acme-orders", Type: "rds_instance", Provider: asset.ProviderAWS, Region: region,
		Endpoint: "acme-orders.c9akciq32.us-east-1.rds.amazonaws.com",
		Tags:     map[string]string{"env": "prod", "data": "pii"},
		Metadata: map[string]string{
			"engine": "postgres", "engine_version": "15.4", "storage_encrypted": "false", "multi_az": "false",
			"security_groups": sgDB, "db_cluster_id": "", "read_replica_source": "",
			"backup_retention_days": "1", "deletion_protection": "false", "port": "5432",
		},
	})
	b.add(asset.Asset{
		ID: "acme-customer-exports", Name: "acme-customer-exports", Type: "s3_bucket", Provider: asset.ProviderAWS, Region: region,
		Domain: "acme-customer-exports.s3.amazonaws.com",
		Tags:   map[string]string{"env": "prod", "data": "pii"},
		Metadata: map[string]string{
			"public": "false", "bpa_all_enabled": "true", "encryption": "", "logging": "disabled",
			"versioning": "disabled", "mfa_delete": "disabled",
		},
	})
	for _, name := range []string{"orders-db", "llm-provider-keys"} {
		b.add(asset.Asset{
			ID: arn("secretsmanager", "secret:prod/"+name+"-AbCdEf"), Name: "prod/" + name, Type: "secretsmanager_secret",
			Provider: asset.ProviderAWS, Region: region,
			Metadata: map[string]string{"rotation_enabled": "false", "public_access": "none"},
		})
	}
	b.edges = append(b.edges, asset.Edge{
		SrcID: arn("rds", "db:acme-orders"), SrcType: "rds_instance", DstID: sgDB, DstType: "security_group", EdgeType: "protected_by",
	})
}
