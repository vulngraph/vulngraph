package checks

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// azureNSGWinRMOpenInternet is the WinRM sibling of the RDP/SSH NSG checks.
// WinRM (5985 HTTP, 5986 HTTPS) is remote PowerShell: a management plane as
// direct as RDP, and the one password-spraying tooling targets once RDP is
// closed. The AWS security-group check covers it through adminPorts.
var azureNSGWinRMOpenInternet = Check{
	ID:          "azure-nsg-winrm-not-open-internet",
	Title:       "Azure NSG allows WinRM (5985/5986) from the internet",
	Description: "An inbound NSG rule permits TCP/5985 or TCP/5986 from 0.0.0.0/0 or ::/0, exposing Windows Remote Management (remote PowerShell) to the whole internet. WinRM accepts the same credentials as RDP and is a common password-spraying and lateral-movement target.",
	Remediation: "Remove or restrict the NSG inbound rule. Reach WinRM through Azure Bastion, a VPN, or a jump host on a private network, and restrict the source to known management CIDRs.",
	Type:        "exposure",
	Severity:    finding.SeverityHigh,
	Provider:    asset.ProviderAzure,
	AssetType:   "security_group",
	Violates: func(a asset.Asset) bool {
		return nsgAllowsWorldPort(a, 5985) || nsgAllowsWorldPort(a, 5986)
	},
}
