package upstream

// FrameworkSource is where one compliance framework's requirement mapping
// comes from. Prowler maps requirement → Prowler check; graph joins those
// checks to its own benchmark controls through Prowler's CIS and FSBP files
// (the same check named under a CIS recommendation or an FSBP control).
// SecurityHubPrefix, when set, adds the requirements AWS itself publishes
// for each FSBP control ("Related requirements").
type FrameworkSource struct {
	ID                string
	Prowler           map[string]string // provider → compliance JSON
	SecurityHubPrefix string
}

const (
	prowlerFSBPFile = "aws_foundational_security_best_practices_aws.json"
	shNISTPrefix    = "NIST.800-53.r5 "
	shPCIPrefix     = "PCI DSS v4.0.1/"
)

// FrameworkSources lists the mapped frameworks. CIS Controls v8 is absent:
// no license-clean public mapping exists (ADR 093).
var FrameworkSources = []FrameworkSource{
	{ID: "nist-800-53-r5", Prowler: map[string]string{"aws": "nist_800_53_revision_5_aws.json"}, SecurityHubPrefix: shNISTPrefix},
	{ID: "pci-dss-4.0", Prowler: map[string]string{
		"aws": "pci_4.0_aws.json", "azure": "pci_4.0_azure.json", "gcp": "pci_4.0_gcp.json", "kubernetes": "pci_4.0_kubernetes.json",
	}, SecurityHubPrefix: shPCIPrefix},
	{ID: "soc2-2017", Prowler: map[string]string{"aws": "soc2_aws.json", "azure": "soc2_azure.json", "gcp": "soc2_gcp.json"}},
	{ID: "iso-27001-2022", Prowler: map[string]string{
		"aws": "iso27001_2022_aws.json", "azure": "iso27001_2022_azure.json", "gcp": "iso27001_2022_gcp.json", "kubernetes": "iso27001_2022_kubernetes.json",
	}},
	{ID: "hipaa-security-rule", Prowler: map[string]string{"aws": "hipaa_aws.json", "azure": "hipaa_azure.json", "gcp": "hipaa_gcp.json"}},
}
