package checks

import (
	"testing"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

var otherChecksAbsentRows = []absentDataRow{
	{name: "gcp-logging-compute-change-alert-missing", check: gcpLoggingComputeChangeAlertMissing,
		violating: map[string]string{"log_compute_alert_missing": "true"},
		compliant: map[string]string{"log_compute_alert_missing": "false"}, unknown: map[string]string{}},
	{name: "github-no-codeowners-file", check: githubNoCodeowners,
		violating: map[string]string{asset.MetaCodeownersFile: "absent"},
		compliant: map[string]string{asset.MetaCodeowners: "* @org/a"}, unknown: map[string]string{}},
}

func TestOtherChecksAbsentData(t *testing.T) {
	runAbsentDataRows(t, otherChecksAbsentRows)
}

func TestGitHubNoCodeownersSkipsArchived(t *testing.T) {
	a := asset.Asset{Type: "github_repo", Metadata: map[string]string{asset.MetaCodeownersFile: "absent", "archived": "true"}}
	if githubNoCodeowners.Violates(a) {
		t.Fatal("archived repo must not fire")
	}
}

// A finding can only close when the check stays evaluable on the compliant
// state the collector now writes; Violates alone does not prove that.
func TestGitHubNoCodeownersClosesWhenFileAppears(t *testing.T) {
	repo := func(md map[string]string) asset.Asset {
		return asset.Asset{ID: "org/r", Type: "github_repo", Provider: asset.ProviderGitHub, Metadata: md}
	}
	c, ok := Default().ByID("github-no-codeowners-file")
	if !ok {
		t.Fatal("check not registered")
	}
	present := repo(map[string]string{"archived": "false", asset.MetaCodeownersFile: "present"})
	if c.Violates(present) || !c.Evaluable(present) {
		t.Fatal("a repo with a CODEOWNERS file must be evaluable and compliant so the open finding closes")
	}
	unread := repo(map[string]string{"archived": "false"})
	if c.Evaluable(unread) {
		t.Fatal("a repo the sweep could not read must not close the finding")
	}
}
