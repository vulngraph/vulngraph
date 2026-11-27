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
)

// FrameworkSources lists the built-in mapped frameworks. NIST SP 800-53 is the
// only one shipped; an operator's own frameworks load from FRAMEWORKS_DIR.
var FrameworkSources = []FrameworkSource{
	{ID: "nist-800-53-r5", Prowler: map[string]string{"aws": "nist_800_53_revision_5_aws.json"}, SecurityHubPrefix: shNISTPrefix},
}
