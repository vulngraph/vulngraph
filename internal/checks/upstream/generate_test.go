package upstream

import (
	"encoding/json"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/checks/benchmarks"
	"github.com/vulngraph/vulngraph/internal/checks/frameworks"
)

func jsonFile(t *testing.T, v any) *fstest.MapFile {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	return &fstest.MapFile{Data: raw}
}

type preq struct {
	ID, Name, Section string
	Checks            []string
}

func prowlerFile(t *testing.T, reqs ...preq) *fstest.MapFile {
	t.Helper()
	var out []map[string]any
	for _, r := range reqs {
		out = append(out, map[string]any{"Id": r.ID, "Name": r.Name, "Checks": r.Checks,
			"Attributes": []map[string]any{{"Section": r.Section}}})
	}
	return jsonFile(t, map[string]any{"Framework": "f", "Requirements": out})
}

func genMatrices() []benchmarks.Benchmark {
	return []benchmarks.Benchmark{
		{ID: "aws-fsbp", Version: "1.0.0", Providers: []string{"aws"}, Controls: []benchmarks.Control{{ID: "ACM.1"}, {ID: "IAM.6"}}},
		{ID: "cis-aws-foundations", Version: "7.0.0", Providers: []string{"aws"}, Controls: []benchmarks.Control{{ID: "2.3"}}},
		{ID: "cis-gcp-foundation", Version: "5.0.0", Providers: []string{"gcp"}, Controls: []benchmarks.Control{{ID: "1.1"}}},
	}
}

func genBundle(t *testing.T) fstest.MapFS {
	listingOf := func(names ...string) *fstest.MapFile {
		var l []map[string]string
		for _, n := range names {
			l = append(l, map[string]string{"name": n})
		}
		return jsonFile(t, l)
	}
	return fstest.MapFS{
		ProwlerIndexPath("aws"): listingOf("cis_7.0_aws.json", prowlerFSBPFile),
		ProwlerIndexPath("gcp"): listingOf("cis_4.0_gcp.json"),
		ProwlerFilePath("aws", "cis_7.0_aws.json"): prowlerFile(t,
			preq{ID: "2.3", Checks: []string{"iam_root_mfa_enabled"}},
			preq{ID: "9.9", Checks: []string{"iam_root_mfa_enabled"}}, // no matrix row: dropped
		),
		ProwlerFilePath("aws", prowlerFSBPFile): prowlerFile(t,
			preq{ID: "IAM.6", Checks: []string{"iam_root_mfa_enabled"}},
		),
		// CIS GCP 4.0 is not the pinned 5.0.0; its IDs renumber, so it must not be joined.
		ProwlerFilePath("gcp", "cis_4.0_gcp.json"): prowlerFile(t, preq{ID: "1.1", Checks: []string{"gcp_check"}}),
		// ACM.1 and ACM.3 are FSBP (ACM.3 has no matrix row); Account.2 is
		// NIST-only, so its related requirements are not a source at all.
		PathSecurityHubReference: {Data: []byte(refRow("acm-controls.html", "ACM.1", "AWS Foundational Security Best Practices v1.0.0") +
			refRow("acm-controls.html", "ACM.3", "AWS Foundational Security Best Practices") +
			refRow("account-controls.html", "Account.2", "NIST SP 800-53 Rev. 5"))},
		SecurityHubPagePath("acm-controls.html"): {Data: []byte(`<h2 id="acm-1">[ACM.1] Certs renewed</h2>
  <p><b>Related requirements:</b> NIST.800-53.r5 SC-28(3),
            NIST.800-53.r5 SC-7(16), PCI DSS v4.0.1/4.2.1</p>
   <h2 id="acm-3">[ACM.3] Certs tagged</h2>
  <p><b>Related requirements:</b> NIST.800-53.r5 SC-28(3)</p>`)},
		SecurityHubPagePath("account-controls.html"): {Data: []byte(`<h2 id="account-2">[Account.2] In an organization</h2>
  <p><b>Related requirements:</b> NIST.800-53.r5 SC-7(16)</p>`)},
	}
}

func refRow(page, id, standards string) string {
	return `<tr><td><a href="./` + page + `">` + id + `</a></td><td>title</td><td>` + standards + `</td><td>MEDIUM</td></tr>`
}

func TestProwlerCheckRefsJoinsPinnedCISAndFSBPOnly(t *testing.T) {
	bs := genMatrices()
	refs, err := prowlerCheckRefs(genBundle(t), bs, frameworks.NewIndex(bs))
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"cis-aws-foundations/2.3", "aws-fsbp/IAM.6"}, refs["aws"]["iam_root_mfa_enabled"],
		"CIS 9.9 has no matrix row and is dropped")
	require.Empty(t, refs["gcp"], "a non-pinned CIS version is never joined: CIS renumbers between versions")
}

func TestGenerateNISTFoldsItemsAndAddsSecurityHub(t *testing.T) {
	bs := genMatrices()
	b := genBundle(t)
	ix := frameworks.NewIndex(bs)
	b[ProwlerFilePath("aws", "nist.json")] = prowlerFile(t,
		preq{Name: "AC-2(3)(a)", Checks: []string{"iam_root_mfa_enabled"}},
		preq{Name: "CP-1(2)", Checks: []string{"iam_root_mfa_enabled"}}, // a CP-1 item, not an enhancement
		preq{Name: "AC-2(d)(1)", Checks: []string{"unmapped_check"}},
	)
	byCheck, err := prowlerCheckRefs(b, bs, ix)
	require.NoError(t, err)
	related, err := securityHubRelatedAll(b)
	require.NoError(t, err)
	nist := map[string]string{"AC-2": "Account Management", "AC-2(3)": "Disable Accounts", "CP-1": "Policy and Procedures",
		"SC-28(3)": "Cryptographic Keys", "SC-7(16)": "Prevent Discovery of System Components"}
	src := FrameworkSource{ID: "nist-800-53-r5", Prowler: map[string]string{"aws": "nist.json"}, SecurityHubPrefix: shNISTPrefix}
	fw, err := generateOne(b, src, frameworkMetas[src.ID], byCheck, related, ix, nil, nist)
	require.NoError(t, err)

	got := map[string]frameworks.Requirement{}
	var order []string
	for _, r := range fw.Requirements {
		got[r.ID] = r
		order = append(order, r.ID)
	}
	require.Equal(t, []string{"AC-2", "AC-2(3)", "CP-1", "SC-7(16)", "SC-28(3)"}, order)
	require.Equal(t, []string{"aws-fsbp/IAM.6", "cis-aws-foundations/2.3"}, got["AC-2(3)"].Controls)
	require.Equal(t, []string{"aws-fsbp/IAM.6", "cis-aws-foundations/2.3"}, got["CP-1"].Controls)
	require.Empty(t, got["AC-2"].Controls, "a Prowler check with no benchmark equivalent maps nothing")
	require.Equal(t, []string{"aws-fsbp/ACM.1"}, got["SC-28(3)"].Controls, "from AWS's related requirements")
	require.Equal(t, "Cryptographic Keys", got["SC-28(3)"].Title)

	// Unjoined source evidence is counted, never silently dropped.
	require.Equal(t, 1, got["AC-2"].Unjoined, "unmapped_check reaches no graph control")
	require.Zero(t, got["AC-2(3)"].Unjoined)
	require.Equal(t, 1, got["SC-28(3)"].Unjoined, "FSBP ACM.3 has no matrix row")
	require.Zero(t, got["SC-7(16)"].Unjoined, "Account.2 is not FSBP, so it is not a source mapping")
}

func TestGenerateHandTitledNeedsCommittedTitles(t *testing.T) {
	bs := genMatrices()
	b := genBundle(t)
	b[ProwlerFilePath("aws", "pci.json")] = prowlerFile(t,
		preq{ID: "4.2.1.7", Section: "4.2.1: PAN is protected in transit.", Checks: []string{"iam_root_mfa_enabled"}})
	ix := frameworks.NewIndex(bs)
	byCheck, err := prowlerCheckRefs(b, bs, ix)
	require.NoError(t, err)
	related, err := securityHubRelatedAll(b)
	require.NoError(t, err)
	src := FrameworkSource{ID: "pci-dss-4.0", Prowler: map[string]string{"aws": "pci.json"}, SecurityHubPrefix: shPCIPrefix}

	_, err = generateOne(b, src, frameworkMetas[src.ID], byCheck, related, ix, map[string]string{}, nil)
	require.ErrorContains(t, err, "4.2.1", "an untitled requirement is an error, never a placeholder or copied text")

	fw, err := generateOne(b, src, frameworkMetas[src.ID], byCheck, related, ix, map[string]string{"4.2.1": "Strong cryptography in transit"}, nil)
	require.NoError(t, err)
	require.Len(t, fw.Requirements, 1, "Prowler's sub-items roll up to the PCI requirement in their section")
	require.Equal(t, []string{"aws-fsbp/ACM.1", "aws-fsbp/IAM.6", "cis-aws-foundations/2.3"}, fw.Requirements[0].Controls)
}

func TestGenerateKeepsCommittedCatalogue(t *testing.T) {
	bs := genMatrices()
	b := genBundle(t)
	b[ProwlerFilePath("aws", "soc2.json")] = prowlerFile(t, preq{Name: "CC6.1 long AICPA text", Checks: []string{"iam_root_mfa_enabled"}})
	ix := frameworks.NewIndex(bs)
	byCheck, err := prowlerCheckRefs(b, bs, ix)
	require.NoError(t, err)
	src := FrameworkSource{ID: "soc2-2017", Prowler: map[string]string{"aws": "soc2.json"}}
	fw, err := generateOne(b, src, frameworkMetas[src.ID], byCheck, nil, ix,
		map[string]string{"CC6.1": "Logical access security", "CC1.1": "Integrity and ethics"}, nil)
	require.NoError(t, err)
	require.Len(t, fw.Requirements, 2, "CC1.1 has no mapping but stays in the catalogue, so coverage counts it")
	require.Equal(t, "CC1.1", fw.Requirements[0].ID)
	require.Empty(t, fw.Requirements[0].Controls)
	require.Equal(t, "Logical access security", fw.Requirements[1].Title, "the hand title, never Prowler's copied criterion text")
}
