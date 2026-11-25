package intel

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeDomain(t *testing.T) {
	valid := map[string]string{
		"example.com":               "example.com",
		"  Example.COM ":            "example.com",
		"https://www.example.com/x": "www.example.com",
		"*.zeta.test":               "zeta.test",
		"api.zeta.test:443":         "api.zeta.test",
		"zeta-fixture.co.uk.":       "zeta-fixture.co.uk",
		"xn--80ak6aa92e.test":       "xn--80ak6aa92e.test", // punycode
		"a-b.example-site.test":     "a-b.example-site.test",
	}
	for in, want := range valid {
		got, err := NormalizeDomain(in)
		require.NoErrorf(t, err, "input %q", in)
		require.Equalf(t, want, got, "input %q", in)
	}

	invalid := []string{
		"",
		"   ",
		"zeta,cin",         // comma typo
		"zeta",             // no TLD
		"zeta.",            // trailing dot only, no TLD
		"-bad.example.com", // leading hyphen label
		"bad-.example.com", // trailing hyphen label
		"example..com",     // empty label
		"exam ple.com",     // space in label
		"http://",          // scheme only
		"192.168.1.1",      // IP, not a domain name (numeric TLD)
	}
	for _, in := range invalid {
		_, err := NormalizeDomain(in)
		require.ErrorIsf(t, err, ErrInvalidDomain, "input %q should be rejected", in)
	}
}
