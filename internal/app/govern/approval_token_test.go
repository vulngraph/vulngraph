package govern

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var testSecret = strings.Repeat("k", 32)

func testClaims() LinkClaims {
	return LinkClaims{
		FindingIDs: []string{"f1"}, SetHash: "hash", ActionClass: "remediate",
		Verdict: VerdictApproved, Nonce: "nonce-1", Recipient: "sec@example.com",
	}
}

func TestApprovalToken_RoundTrip(t *testing.T) {
	token, err := GenerateApprovalToken(testClaims(), testSecret)
	require.NoError(t, err)

	got, err := ValidateApprovalToken(token, testSecret)
	require.NoError(t, err)
	require.Equal(t, []string{"f1"}, got.FindingIDs)
	require.Equal(t, "hash", got.SetHash)
	require.Equal(t, "remediate", got.ActionClass)
	require.Equal(t, VerdictApproved, got.Verdict)
	require.Equal(t, "nonce-1", got.Nonce)
	require.Equal(t, "sec@example.com", got.Recipient)
	require.WithinDuration(t, time.Now().Add(approvalTokenTTL), got.ExpiresAt, time.Minute)
}

func TestApprovalToken_WrongSecret(t *testing.T) {
	token, err := GenerateApprovalToken(testClaims(), testSecret)
	require.NoError(t, err)
	_, err = ValidateApprovalToken(token, strings.Repeat("x", 32))
	require.ErrorIs(t, err, ErrTokenInvalid)
}

func TestApprovalToken_Tampered(t *testing.T) {
	token, err := GenerateApprovalToken(testClaims(), testSecret)
	require.NoError(t, err)
	tampered := token[:3] + "X" + token[4:]
	_, err = ValidateApprovalToken(tampered, testSecret)
	require.ErrorIs(t, err, ErrTokenInvalid)
}

func TestApprovalToken_Expired(t *testing.T) {
	c := testClaims()
	c.ExpiresAt = time.Now().Add(-time.Second)
	token, err := GenerateApprovalToken(c, testSecret)
	require.NoError(t, err)
	_, err = ValidateApprovalToken(token, testSecret)
	require.ErrorIs(t, err, ErrTokenExpired)
}

func TestApprovalToken_Malformed(t *testing.T) {
	for _, tok := range []string{"", "nodottoken", "a.b.c"} {
		_, err := ValidateApprovalToken(tok, testSecret)
		require.ErrorIs(t, err, ErrTokenInvalid, tok)
	}
}

// A link must name exactly what it authorises: a token without the decision
// set, action class or nonce cannot be minted, so nothing unbound is emailed.
func TestApprovalToken_RequiresBindingClaims(t *testing.T) {
	for name, mutate := range map[string]func(*LinkClaims){
		"no findings":     func(c *LinkClaims) { c.FindingIDs = nil },
		"no set hash":     func(c *LinkClaims) { c.SetHash = "" },
		"no action class": func(c *LinkClaims) { c.ActionClass = "" },
		"no nonce":        func(c *LinkClaims) { c.Nonce = "" },
		"bad verdict":     func(c *LinkClaims) { c.Verdict = "maybe" },
	} {
		c := testClaims()
		mutate(&c)
		_, err := GenerateApprovalToken(c, testSecret)
		require.ErrorIs(t, err, ErrTokenInvalid, name)
	}
}

func TestApprovalToken_ShortSecretIsRefused(t *testing.T) {
	require.ErrorIs(t, ValidateTokenSecret("short"), ErrTokenSecretShort)
	require.NoError(t, ValidateTokenSecret(testSecret))

	_, err := GenerateApprovalToken(testClaims(), "short")
	require.ErrorIs(t, err, ErrTokenSecretShort)
	_, err = ValidateApprovalToken("a.b", "short")
	require.ErrorIs(t, err, ErrTokenInvalid)
}
