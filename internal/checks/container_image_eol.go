package checks

import (
	"strconv"
	"time"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/distro"
)

// End-of-life base operating systems in running container images (ADR 088).
//
// The OS identity is base_os ("Debian:11", "Alpine:v3.18"), the release the
// image-vuln sweep read off the image's os-release and package database. It is
// not collector metadata: the collectors rewrite a container_image row whole on
// every sync and never know what is inside the image, so the sync-time check
// run never sees base_os. The base-image job (internal/jobs/baseimage.go)
// evaluates this check instead, on a copy of each running image's asset
// carrying the recorded identity. That is why it is not in Default(): there it
// would be permanently blind and drag graph_check_evaluable_ratio down for
// nothing.
//
// An image whose release is unknown (no os-release, a scratch image, an
// unlisted release) is never graded. Severity is High when a workload running
// the image is directly internet-exposed, Medium otherwise — the same rule as
// the VM end-of-life checks, with the workload's exposure standing in for the
// VM's public IP.

const containerImageEOLDescription = "A running container image is built on an operating system release past the end of its vendor's standard support. " +
	"Where the vendor publishes nothing further (Debian past LTS, Alpine branches, interim Ubuntu releases, CentOS Linux, Amazon Linux 1 and 2, openSUSE Leap), " +
	"no advisory will ever be issued for a vulnerability disclosed after that date, so the absence of CVE findings on this image proves nothing. " +
	"Where a paid extended tier exists (RHEL ELS, Ubuntu Pro ESM, SUSE LTSS, Oracle Extended Support) fixes reach only subscribed images."

const containerImageEOLRemediation = "Rebuild the image on a supported base: change the FROM line of its Dockerfile to a supported release " +
	"of the same distribution, or to a minimal/hardened base (the base-image root-cause finding for this image's base lists concrete " +
	"replacements), then redeploy the workloads running it. Patching a running container is undone by the next restart."

var containerImageOSEndOfLife = Check{
	ID:          "container-image-os-end-of-life",
	Title:       "Running container image is built on an end-of-life operating system",
	Description: containerImageEOLDescription,
	Remediation: containerImageEOLRemediation,
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	AssetType:   "container_image",
	Violates:    imageOSPastEndOfLife,
	SeverityFor: imageEOLSeverity,
	EvidenceFor: imageEOLEvidence,
	TableProbes: distro.LifecycleEcosystems(),
}

// ContainerImageChecks returns the checks evaluated on running container images
// by the base-image job, stamped with their derived required keys like every
// registry check. Provider-agnostic: a container_image is collected by the
// kubernetes, ECS and Cloud Run collectors alike, and the job calls Evaluate
// directly rather than Run.
func ContainerImageChecks() *Registry {
	r := NewRegistry()
	r.Register(containerImageOSEndOfLife)
	return r
}

// Evaluate returns the finding c raises on a, ignoring provider applicability —
// for a caller that has already chosen the assets c grades.
func (c Check) Evaluate(a asset.Asset, now time.Time) (finding.Finding, bool) {
	return c.eval(a, now)
}

// imageOSPastEndOfLife fires on a base release the lifecycle table lists as
// past its end of standard support. An absent base_os (not scanned, or
// scanned and unidentified) or an unlisted release is unknown and stays silent.
func imageOSPastEndOfLife(a asset.Asset) bool {
	l, ok := distro.EndOfLife(a.Metadata["base_os"])
	return ok && l.Past(time.Now())
}

func imageEOLSeverity(a asset.Asset) finding.Severity {
	if a.Metadata[asset.MetaWorkloadExposed] == "true" {
		return finding.SeverityHigh
	}
	return finding.SeverityMedium
}

func imageEOLEvidence(a asset.Asset) map[string]string {
	eco := a.Metadata[asset.MetaBaseOS]
	l, _ := distro.EndOfLife(eco)
	ev := map[string]string{
		"os_release":              eco,
		"end_of_life":             l.End.Format(time.DateOnly),
		"final":                   strconv.FormatBool(l.Final),
		asset.MetaBaseImageSource: a.Metadata[asset.MetaBaseImageSource],
		asset.MetaWorkloadExposed: a.Metadata[asset.MetaWorkloadExposed],
	}
	if b := a.Metadata[asset.MetaBaseImage]; b != "" {
		ev[asset.MetaBaseImage] = b
	}
	if l.Note != "" {
		ev["support_note"] = l.Note
	}
	return ev
}
