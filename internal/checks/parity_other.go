package checks

import (
	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

var gcpLoggingComputeChangeAlertMissing = Check{
	ID:          "gcp-logging-compute-change-alert-missing",
	Title:       "Project does not alert on Compute Engine configuration changes",
	Description: "No enabled Cloud Monitoring alert policy with a notification channel fires on Compute Engine configuration changes (instances, disks, networks, firewall rules and routes). An alert is in place when such a policy watches a log-based metric, or a log-match condition, whose filter matches the audit entries of all of those changes. Without it, changes that open access or weaken a workload go unnoticed. Severity is medium.",
	Remediation: "Console: Logging > Logs-based metrics > Create metric with filter `protoPayload.serviceName=\"compute.googleapis.com\"`, then Monitoring > Alerting > Create policy on that metric with a notification channel. CLI: `gcloud logging metrics create compute_config_changes --log-filter='protoPayload.serviceName=\"compute.googleapis.com\"'`, then `gcloud alpha monitoring policies create --display-name=\"Compute config changes\" --notification-channels=CHANNEL_ID --condition-filter='metric.type=\"logging.googleapis.com/user/compute_config_changes\"' --condition-threshold-value=0 --condition-threshold-comparison=COMPARISON_GT --condition-threshold-duration=0s`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGCP,
	AssetType:   "cloud_account",
	Violates:    func(a asset.Asset) bool { return a.Metadata["log_compute_alert_missing"] == "true" },
}

var githubNoCodeowners = Check{
	ID:          "github-no-codeowners-file",
	Title:       "GitHub repository has no CODEOWNERS file",
	Description: "The repository's default branch has no CODEOWNERS file in the root, .github/ or docs/. Without it no team is automatically requested to review changes to sensitive paths, and branch protection cannot require code-owner approval. Archived repositories and repositories the sweep could not read are not evaluated. Severity is medium.",
	Remediation: "Console: open the repository, Add file > Create new file, name it `.github/CODEOWNERS`, add a line such as `* @org/team`, and commit to the default branch. CLI: `gh api -X PUT repos/ORG/REPO/contents/.github/CODEOWNERS -f message='add CODEOWNERS' -f content=\"$(printf '* @org/team\\n' | base64)\"`.",
	Type:        "misconfiguration",
	Severity:    finding.SeverityMedium,
	Provider:    asset.ProviderGitHub,
	AssetType:   "github_repo",
	Violates: func(a asset.Asset) bool {
		return a.Metadata["codeowners_file"] == "absent" && a.Metadata["archived"] != "true"
	},
}
