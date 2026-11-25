package checks

import (
	"strings"

	"github.com/vulngraph/vulngraph/internal/app/asset"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

// acmCertNonPQC is cryptographic inventory, not a misconfiguration: it records
// which issued certificates use a classical public-key algorithm, so a
// post-quantum migration has a list to work from. Info severity on purpose —
// every RSA/ECDSA certificate in use today fires, and none of them is a defect
// anyone should be woken for.
//
// Only the known classical families (ACM's RSA_* and EC_*) count. An algorithm
// the check does not recognise — a post-quantum one, or anything newer — stays
// silent rather than being misfiled as classical, and an unreadable certificate
// (no key_algorithm) is unknown.
var acmCertNonPQC = Check{
	ID:          "acm-cert-non-pqc",
	Title:       "ACM certificate uses a classical (non-post-quantum) key algorithm",
	Description: "This issued ACM certificate's key is RSA or elliptic-curve. Both are expected to be breakable by a large quantum computer, and traffic recorded today can be decrypted later if the key exchange is classical too. This is an inventory entry for post-quantum migration planning, not a vulnerability: no action is needed until a post-quantum certificate type is available and supported by the clients this certificate serves.",
	Remediation: "No immediate action. Track these certificates for post-quantum migration; when replacing them, prefer a post-quantum or hybrid algorithm where ACM, the attached service and its clients support one, and enable hybrid post-quantum key exchange in the TLS policy of the load balancer or CloudFront distribution where offered.",
	Type:        "hygiene",
	Severity:    finding.SeverityInfo,
	Provider:    asset.ProviderAWS,
	AssetType:   "acm_certificate",
	Violates: func(a asset.Asset) bool {
		if a.Metadata["status"] != "ISSUED" {
			return false
		}
		alg := a.Metadata["key_algorithm"]
		return strings.HasPrefix(alg, "RSA_") || strings.HasPrefix(alg, "EC_")
	},
	EvidenceFor: func(a asset.Asset) map[string]string {
		return map[string]string{"key_algorithm": a.Metadata["key_algorithm"]}
	},
}
