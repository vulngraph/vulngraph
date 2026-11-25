package nuclei

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestGPLLdapserverIsReplaced guards the licensing fix in
// third_party/ldapserver-stub: nuclei → interactsh/pkg/server pulls in the
// GPL-2.0 github.com/projectdiscovery/ldapserver, which must never be linked
// into this project's binaries. Dropping the go.mod replace (e.g. a
// `go mod tidy` with edits, or a dependency bump that rewrites go.mod) would
// silently relink it; this fails instead.
func TestGPLLdapserverIsReplaced(t *testing.T) {
	requireReplaced(t, `github\.com/projectdiscovery/ldapserver => \./third_party/ldapserver-stub`)
}

// TestUnlicensedCensysSDKIsReplaced: same guard for
// github.com/censys/censys-sdk-go, which ships no LICENSE file (no clear
// redistribution grant) and reaches us only via nuclei → uncover's Censys
// search agent, which Vulngraph never invokes. See third_party/censys-sdk-stub.
func TestUnlicensedCensysSDKIsReplaced(t *testing.T) {
	requireReplaced(t, `github\.com/censys/censys-sdk-go => \./third_party/censys-sdk-stub`)
}

func requireReplaced(t *testing.T, replace string) {
	t.Helper()
	gomod, err := os.ReadFile(filepath.Join("..", "..", "..", "go.mod"))
	require.NoError(t, err)
	require.Regexp(t, regexp.MustCompile(`(?m)^replace `+replace+`\s*$`), string(gomod),
		"go.mod must keep this replace — see the stub's README under third_party/")
}
