package checks

import (
	"strconv"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/distro"
)

// End-of-life operating systems on VMs. The OS identity is the VM's
// package_ecosystem ("CentOS:7", "Amazon Linux:2"), which the inventory
// collectors stamp only when they actually read the host's package list, so a
// VM without an inventory is never graded. The dates are the hand-maintained
// lifecycle table in internal/distro.
//
// Severity is High on a VM with a public IP, Medium otherwise: an unpatched OS
// is exploitable through whatever CVE lands next, and reachability is what makes
// that a near-term problem. The must-fix classifier still weighs the host's real
// exposure and blast radius on top.

const vmEOLDescription = "This VM runs an operating system release past the end of its vendor's standard support. " +
	"Where the vendor publishes nothing further (CentOS Linux, Amazon Linux 1 and 2, Debian past LTS, interim Ubuntu releases), " +
	"no advisory will ever be issued for a vulnerability disclosed after that date, so the absence of CVE findings on this host proves nothing. " +
	"Where a paid extended tier exists (RHEL ELS, Ubuntu Pro ESM, Oracle Extended Support) fixes reach only subscribed hosts."

const vmEOLRemediation = "Move the workload to a supported release: Amazon Linux 2023 for Amazon Linux 1/2; RHEL 9, Rocky Linux 9, AlmaLinux 9 or " +
	"CentOS Stream for CentOS Linux; the current LTS for Ubuntu and Debian. Rebuild the image or launch template rather than upgrading in place. " +
	"If a migration is not possible yet, confirm the host is enrolled in the vendor's extended-support programme and restrict its network exposure."

var awsEC2OSEndOfLife = Check{
	ID:          "aws-ec2-os-end-of-life",
	Title:       "EC2 instance runs an end-of-life operating system",
	Description: vmEOLDescription,
	Remediation: vmEOLRemediation,
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderAWS,
	AssetType:   "ec2_instance",
	Violates:    vmOSPastEndOfLife,
	SeverityFor: vmEOLSeverity,
	EvidenceFor: vmEOLEvidence,
	TableProbes: distro.LifecycleEcosystems(),
}

var gcpGCEOSEndOfLife = Check{
	ID:          "gcp-gce-os-end-of-life",
	Title:       "Compute Engine VM runs an end-of-life operating system",
	Description: vmEOLDescription,
	Remediation: vmEOLRemediation,
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "gce_instance",
	Violates:    vmOSPastEndOfLife,
	SeverityFor: vmEOLSeverity,
	EvidenceFor: vmEOLEvidence,
	TableProbes: distro.LifecycleEcosystems(),
}

// vmOSPastEndOfLife fires on a release the lifecycle table lists as past its
// end of standard support. An absent ecosystem (no inventory) or an unlisted
// release is unknown and stays silent.
func vmOSPastEndOfLife(a asset.Asset) bool {
	l, ok := distro.EndOfLife(a.Metadata["package_ecosystem"])
	return ok && l.Past(time.Now())
}

func vmEOLSeverity(a asset.Asset) finding.Severity {
	if a.PublicIP != "" {
		return finding.SeverityHigh
	}
	return finding.SeverityMedium
}

func vmEOLEvidence(a asset.Asset) map[string]string {
	eco := a.Metadata[asset.MetaPackageEcosystem]
	l, _ := distro.EndOfLife(eco)
	ev := map[string]string{
		"os_release":  eco,
		"end_of_life": l.End.Format(time.DateOnly),
		"final":       strconv.FormatBool(l.Final),
	}
	if l.Note != "" {
		ev["support_note"] = l.Note
	}
	return ev
}
