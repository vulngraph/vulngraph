package checks

// azure_defender_plans.go — one check per Microsoft Defender for Cloud plan
// CIS Azure Foundations 6 requires (8.1.x.1), on the azure_subscription
// settings asset. One check per plan, not one rollup, because each CIS control
// is one plan: compliance is per control, and a control must not fail because
// a different plan is off. Each reads defender_plan_<plan>, written only for a
// plan the pricings response returned and did not mark deprecated, so a plan
// it omitted is unknown, never on. "Enable service X" hygiene: Low.

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func azureDefenderPlanChecks() []Check {
	return []Check{
		azureDefenderPlanServers,
		azureDefenderPlanCSPM,
		azureDefenderPlanAPIs,
		azureDefenderPlanContainers,
		azureDefenderPlanStorage,
		azureDefenderPlanAppServices,
		azureDefenderPlanCosmosDB,
		azureDefenderPlanOSSDatabases,
		azureDefenderPlanSQL,
		azureDefenderPlanSQLVMs,
		azureDefenderPlanKeyVault,
		azureDefenderPlanARM,
	}
}

// defenderPlanOff reports whether the pricings response returned the plan on
// a tier other than Standard.
func defenderPlanOff(a asset.Asset, key string) bool {
	tier, ok := a.Metadata[key]
	return ok && tier != "Standard"
}

var azureDefenderPlanServers = Check{
	ID:          "azure-defender-servers-off",
	Title:       "Microsoft Defender for Servers is off",
	Description: "The Defender for Cloud Servers plan (pricings resource VirtualMachines) is not on the Standard tier (CIS 8.1.3.1), so threats against those resources raise no Defender alerts.",
	Remediation: "Defender for Cloud → Environment settings → the subscription → Defender plans: turn Servers On. CLI: `az security pricing create -n VirtualMachines --tier standard`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return defenderPlanOff(a, "defender_plan_virtualmachines") },
}

var azureDefenderPlanCSPM = Check{
	ID:          "azure-defender-cspm-off",
	Title:       "Microsoft Defender for Defender CSPM is off",
	Description: "The Defender for Cloud Defender CSPM plan (pricings resource CloudPosture) is not on the Standard tier (CIS 8.1.1.1), so threats against those resources raise no Defender alerts.",
	Remediation: "Defender for Cloud → Environment settings → the subscription → Defender plans: turn Defender CSPM On. CLI: `az security pricing create -n CloudPosture --tier standard`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return defenderPlanOff(a, "defender_plan_cloudposture") },
}

var azureDefenderPlanAPIs = Check{
	ID:          "azure-defender-apis-off",
	Title:       "Microsoft Defender for APIs is off",
	Description: "The Defender for Cloud APIs plan (pricings resource Api) is not on the Standard tier (CIS 8.1.2.1), so threats against those resources raise no Defender alerts.",
	Remediation: "Defender for Cloud → Environment settings → the subscription → Defender plans: turn APIs On. CLI: `az security pricing create -n Api --tier standard`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return defenderPlanOff(a, "defender_plan_api") },
}

var azureDefenderPlanContainers = Check{
	ID:          "azure-defender-containers-off",
	Title:       "Microsoft Defender for Containers is off",
	Description: "The Defender for Cloud Containers plan (pricings resource Containers) is not on the Standard tier (CIS 8.1.4.1), so threats against those resources raise no Defender alerts.",
	Remediation: "Defender for Cloud → Environment settings → the subscription → Defender plans: turn Containers On. CLI: `az security pricing create -n Containers --tier standard`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return defenderPlanOff(a, "defender_plan_containers") },
}

var azureDefenderPlanStorage = Check{
	ID:          "azure-defender-storage-off",
	Title:       "Microsoft Defender for Storage is off",
	Description: "The Defender for Cloud Storage plan (pricings resource StorageAccounts) is not on the Standard tier (CIS 8.1.5.1), so threats against those resources raise no Defender alerts.",
	Remediation: "Defender for Cloud → Environment settings → the subscription → Defender plans: turn Storage On. CLI: `az security pricing create -n StorageAccounts --tier standard`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return defenderPlanOff(a, "defender_plan_storageaccounts") },
}

var azureDefenderPlanAppServices = Check{
	ID:          "azure-defender-appservice-off",
	Title:       "Microsoft Defender for App Service is off",
	Description: "The Defender for Cloud App Service plan (pricings resource AppServices) is not on the Standard tier (CIS 8.1.6.1), so threats against those resources raise no Defender alerts.",
	Remediation: "Defender for Cloud → Environment settings → the subscription → Defender plans: turn App Service On. CLI: `az security pricing create -n AppServices --tier standard`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return defenderPlanOff(a, "defender_plan_appservices") },
}

var azureDefenderPlanCosmosDB = Check{
	ID:          "azure-defender-cosmosdb-off",
	Title:       "Microsoft Defender for Azure Cosmos DB is off",
	Description: "The Defender for Cloud Azure Cosmos DB plan (pricings resource CosmosDbs) is not on the Standard tier (CIS 8.1.7.1), so threats against those resources raise no Defender alerts.",
	Remediation: "Defender for Cloud → Environment settings → the subscription → Defender plans: turn Azure Cosmos DB On. CLI: `az security pricing create -n CosmosDbs --tier standard`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return defenderPlanOff(a, "defender_plan_cosmosdbs") },
}

var azureDefenderPlanOSSDatabases = Check{
	ID:          "azure-defender-oss-db-off",
	Title:       "Microsoft Defender for open-source relational databases is off",
	Description: "The Defender for Cloud open-source relational databases plan (pricings resource OpenSourceRelationalDatabases) is not on the Standard tier (CIS 8.1.7.2), so threats against those resources raise no Defender alerts.",
	Remediation: "Defender for Cloud → Environment settings → the subscription → Defender plans: turn open-source relational databases On. CLI: `az security pricing create -n OpenSourceRelationalDatabases --tier standard`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return defenderPlanOff(a, "defender_plan_opensourcerelationaldatabases") },
}

var azureDefenderPlanSQL = Check{
	ID:          "azure-defender-sql-off",
	Title:       "Microsoft Defender for Azure SQL databases is off",
	Description: "The Defender for Cloud Azure SQL databases plan (pricings resource SqlServers) is not on the Standard tier (CIS 8.1.7.3), so threats against those resources raise no Defender alerts.",
	Remediation: "Defender for Cloud → Environment settings → the subscription → Defender plans: turn Azure SQL databases On. CLI: `az security pricing create -n SqlServers --tier standard`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return defenderPlanOff(a, "defender_plan_sqlservers") },
}

var azureDefenderPlanSQLVMs = Check{
	ID:          "azure-defender-sql-vm-off",
	Title:       "Microsoft Defender for SQL servers on machines is off",
	Description: "The Defender for Cloud SQL servers on machines plan (pricings resource SqlServerVirtualMachines) is not on the Standard tier (CIS 8.1.7.4), so threats against those resources raise no Defender alerts.",
	Remediation: "Defender for Cloud → Environment settings → the subscription → Defender plans: turn SQL servers on machines On. CLI: `az security pricing create -n SqlServerVirtualMachines --tier standard`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return defenderPlanOff(a, "defender_plan_sqlservervirtualmachines") },
}

var azureDefenderPlanKeyVault = Check{
	ID:          "azure-defender-keyvault-off",
	Title:       "Microsoft Defender for Key Vault is off",
	Description: "The Defender for Cloud Key Vault plan (pricings resource KeyVaults) is not on the Standard tier (CIS 8.1.8.1), so threats against those resources raise no Defender alerts.",
	Remediation: "Defender for Cloud → Environment settings → the subscription → Defender plans: turn Key Vault On. CLI: `az security pricing create -n KeyVaults --tier standard`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return defenderPlanOff(a, "defender_plan_keyvaults") },
}

var azureDefenderPlanARM = Check{
	ID:          "azure-defender-arm-off",
	Title:       "Microsoft Defender for Resource Manager is off",
	Description: "The Defender for Cloud Resource Manager plan (pricings resource Arm) is not on the Standard tier (CIS 8.1.9.1), so threats against those resources raise no Defender alerts.",
	Remediation: "Defender for Cloud → Environment settings → the subscription → Defender plans: turn Resource Manager On. CLI: `az security pricing create -n Arm --tier standard`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityLow,
	Provider:    asset.ProviderAzure,
	AssetType:   subscriptionType,
	Violates:    func(a asset.Asset) bool { return defenderPlanOff(a, "defender_plan_arm") },
}
