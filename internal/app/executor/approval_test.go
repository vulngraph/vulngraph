package executor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/auth"
	"github.com/vulngraph/vulngraph/internal/app/connector"
)

func testApprover(t *testing.T) *Approver {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	a, err := NewApprover(base64.StdEncoding.EncodeToString(key))
	require.NoError(t, err)
	return a.WithLedger(&memLedger{spent: map[string]bool{}})
}

// memLedger is an in-memory GrantLedger.
type memLedger struct {
	spent     map[string]bool
	err       error
	authority map[string]int64
}

func (m *memLedger) Redeem(_ context.Context, grantHash, _, approverID string, version int64, _ time.Time) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	if m.authority != nil && m.authority[approverID] != version {
		return false, nil
	}
	if m.spent[grantHash] {
		return false, nil
	}
	m.spent[grantHash] = true
	return true, nil
}

func TestNewApprover_RejectsBadKey(t *testing.T) {
	_, err := NewApprover("not-base64!!!")
	require.Error(t, err)
	_, err = NewApprover(base64.StdEncoding.EncodeToString([]byte("short")))
	require.ErrorContains(t, err, "32 bytes")
}

// The grant-signing key must not BE the credential-encryption key: an oracle on
// one must not yield the other.
func TestNewApprover_DerivesAKeyDistinctFromTheSecret(t *testing.T) {
	raw := make([]byte, 32)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	a, err := NewApprover(base64.StdEncoding.EncodeToString(raw))
	require.NoError(t, err)
	require.NotEqual(t, raw, a.key, "the approval key is the raw secret — HKDF domain separation is gone")
}

func TestApproval_RoundTrip(t *testing.T) {
	a := testApprover(t)
	g, err := a.Mint("conn-1", ActionEC2Stop, "stop EC2 instance i-abc in eu-west-1", alice)
	require.NoError(t, err)
	require.NoError(t, verifyErr(a, g.Token, "conn-1", ActionEC2Stop, "stop EC2 instance i-abc in eu-west-1", bob))
}

func TestApproval_SelfApprovalIsRefused(t *testing.T) {
	a := testApprover(t)
	g, err := a.Mint("conn-1", ActionEC2Stop, "plan", alice)
	require.NoError(t, err)

	err = verifyErr(a, g.Token, "conn-1", ActionEC2Stop, "plan", alice)
	require.ErrorIs(t, err, ErrApprovalInvalid)
	require.Contains(t, err.Error(), "cannot also execute")

	// Case must not be a bypass — an IdP that hands back a differently-cased
	// address would otherwise let one person hold both halves.
	err = verifyErr(a, g.Token, "conn-1", ActionEC2Stop, "plan", Principal{ID: "u-alice-2", Name: "Alice@example.com"})
	require.ErrorIs(t, err, ErrApprovalInvalid)
}

func TestApproval_UnattributedExecutorIsRefused(t *testing.T) {
	a := testApprover(t)
	g, err := a.Mint("conn-1", ActionEC2Stop, "plan", alice)
	require.NoError(t, err)
	require.ErrorIs(t, verifyErr(a, g.Token, "conn-1", ActionEC2Stop, "plan", Principal{ID: "u-x", Name: AuditActorUnknown}), ErrApprovalInvalid)
	require.ErrorIs(t, verifyErr(a, g.Token, "conn-1", ActionEC2Stop, "plan", Principal{}), ErrApprovalInvalid)
}

var (
	alice = Principal{ID: "u-alice", Name: "alice@example.com", AuthorityVersion: 1}
	bob   = Principal{ID: "u-bob", Name: "bob@example.com", AuthorityVersion: 1}
)

// The same user under a different display name (their API key) is still the
// same person: the check is on the stable user id.
func TestApproval_SameUserIDUnderAnotherNameIsRefused(t *testing.T) {
	a := testApprover(t)
	g, err := a.Mint("conn-1", ActionEC2Stop, "plan", alice)
	require.NoError(t, err)

	err = verifyErr(a, g.Token, "conn-1", ActionEC2Stop, "plan", Principal{ID: alice.ID, Name: "ci-bot (api-key)"})
	require.ErrorIs(t, err, ErrApprovalInvalid)
	require.Contains(t, err.Error(), "cannot also execute")

	require.ErrorIs(t, verifyErr(a, g.Token, "conn-1", ActionEC2Stop, "plan", Principal{Name: "ci-bot (api-key)"}), ErrApprovalInvalid,
		"an executor with no user id cannot be compared and must be refused")
}

func TestApproval_UnattributedApproverCannotMint(t *testing.T) {
	a := testApprover(t)
	_, err := a.Mint("conn-1", ActionEC2Stop, "plan", Principal{Name: "alice@example.com"})
	require.ErrorIs(t, err, ErrApprovalInvalid, "an approver without a user id must not mint")
}

func TestApproval_UnattributedApproverCannotMintNamed(t *testing.T) {
	a := testApprover(t)
	_, err := a.Mint("conn-1", ActionEC2Stop, "plan", Principal{ID: "u-x", Name: AuditActorUnknown})
	require.ErrorIs(t, err, ErrApprovalInvalid)
	_, err = a.Mint("conn-1", ActionEC2Stop, "plan", Principal{})
	require.ErrorIs(t, err, ErrApprovalInvalid)
}

// The grant is bound to the PLAN, not just the action: approving "stop i-abc"
// must not authorise "stop i-def".
func TestApproval_IsBoundToTheExactPlan(t *testing.T) {
	a := testApprover(t)
	g, err := a.Mint("conn-1", ActionEC2Stop, "stop EC2 instance i-abc in eu-west-1", alice)
	require.NoError(t, err)

	err = verifyErr(a, g.Token, "conn-1", ActionEC2Stop, "stop EC2 instance i-def in eu-west-1", bob)
	require.ErrorIs(t, err, ErrApprovalInvalid)
	require.Contains(t, err.Error(), "different change")
}

func TestApproval_IsBoundToConnectorAndAction(t *testing.T) {
	a := testApprover(t)
	g, err := a.Mint("conn-1", ActionEC2Stop, "plan", alice)
	require.NoError(t, err)

	require.ErrorIs(t, verifyErr(a, g.Token, "conn-2", ActionEC2Stop, "plan", bob), ErrApprovalInvalid)
	require.ErrorIs(t, verifyErr(a, g.Token, "conn-1", ActionGCPFirewallRemove, "plan", bob), ErrApprovalInvalid)
}

func TestApproval_ExpiredGrantIsRefused(t *testing.T) {
	a := testApprover(t)
	now := time.Now()
	a.now = func() time.Time { return now }
	g, err := a.Mint("conn-1", ActionEC2Stop, "plan", alice)
	require.NoError(t, err)

	a.now = func() time.Time { return now.Add(ApprovalTTL + time.Second) }
	err = verifyErr(a, g.Token, "conn-1", ActionEC2Stop, "plan", bob)
	require.ErrorIs(t, err, ErrApprovalInvalid)
	require.Contains(t, err.Error(), "expired")
}

func TestApproval_ForgedOrTamperedGrantIsRefused(t *testing.T) {
	a := testApprover(t)
	g, err := a.Mint("conn-1", ActionEC2Stop, "plan", alice)
	require.NoError(t, err)

	// Tamper with the FIRST character of the signature, not the last.
	//
	// base64.RawURLEncoding ignores non-zero trailing bits, so the final character
	// of a token is partly redundant: several distinct characters decode to the
	// same bytes. Flipping it therefore produces a token that is textually
	// different and cryptographically identical, and Verify correctly returns nil
	// — a "tampered" grant that was never tampered with. That made this test pass
	// or fail on the random key, and it failed in CI while passing locally.
	//
	// A security test that is flaky in the direction of PASSING is worse than one
	// that fails: it reports a control as working on the runs where it did not
	// exercise it. The first signature character carries full bits.
	dot := strings.LastIndex(g.Token, ".")
	require.Positive(t, dot, "token must be payload.signature")
	tampered := g.Token[:dot+1] + string(flipChar(g.Token[dot+1])) + g.Token[dot+2:]
	require.NotEqual(t, g.Token, tampered)
	require.ErrorIs(t, verifyErr(a, tampered, "conn-1", ActionEC2Stop, "plan", bob), ErrApprovalInvalid)

	// A grant minted under a different key must not verify here.
	other := testApprover(t)
	og, err := other.Mint("conn-1", ActionEC2Stop, "plan", alice)
	require.NoError(t, err)
	require.ErrorIs(t, verifyErr(a, og.Token, "conn-1", ActionEC2Stop, "plan", bob), ErrApprovalInvalid)

	// An unsigned payload must be rejected before it is ever parsed.
	require.ErrorIs(t, verifyErr(a, "nodot", "conn-1", ActionEC2Stop, "plan", bob), ErrApprovalInvalid)
	require.ErrorIs(t, verifyErr(a, ".", "conn-1", ActionEC2Stop, "plan", bob), ErrApprovalInvalid)
}

func flipChar(b byte) byte {
	if b == 'A' {
		return 'B'
	}
	return 'A'
}

// ---- service-level enforcement ----

// Fail closed: an unwired approval seam must block destructive actions, not
// wave them through. This is the difference between a control and an accident.
func TestExecute_DestructiveActionRefusedWhenNoApproverIsWired(t *testing.T) {
	svc := NewService(&fakeConnectors{c: rwConnector(connector.TypeAWS, map[string]string{
		"region": "eu-west-1", ConfigExecuteRoleARN: "arn:aws:iam::1:role/exec",
	})})

	_, err := svc.Execute(adminCtx("ops@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionEC2Stop,
		Params: map[string]string{ParamInstanceID: "i-abc"},
	})
	require.ErrorIs(t, err, ErrApprovalRequired)
}

func TestExecute_DestructiveActionRefusedWithoutAGrant(t *testing.T) {
	svc := NewService(&fakeConnectors{c: rwConnector(connector.TypeAWS, map[string]string{
		"region": "eu-west-1", ConfigExecuteRoleARN: "arn:aws:iam::1:role/exec",
	})}).WithApprovals(testApprover(t))

	_, err := svc.Execute(adminCtx("ops@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionEC2Stop,
		Params: map[string]string{ParamInstanceID: "i-abc"},
	})
	require.ErrorIs(t, err, ErrApprovalRequired)
	require.Contains(t, err.Error(), "stop EC2 instance i-abc", "the refusal must name what needs approving")
}

// A grant minted for the params an approver saw must not spend on different
// params — the end-to-end version of TestApproval_IsBoundToTheExactPlan.
func TestExecute_GrantDoesNotTransferToDifferentParams(t *testing.T) {
	approver := testApprover(t)
	conns := &fakeConnectors{c: rwConnector(connector.TypeAWS, map[string]string{
		"region": "eu-west-1", ConfigExecuteRoleARN: "arn:aws:iam::1:role/exec",
	})}
	svc := NewService(conns).WithApprovals(approver)

	grant, err := svc.Approve(adminCtx("alice@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionEC2Stop,
		Params: map[string]string{ParamInstanceID: "i-abc"},
	})
	require.NoError(t, err)

	_, err = svc.Execute(adminCtx("bob@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionEC2Stop,
		Params:        map[string]string{ParamInstanceID: "i-PRODUCTION"},
		ApprovalToken: grant.Token,
	})
	require.ErrorIs(t, err, ErrApprovalInvalid)
}

// A valid grant must get PAST the approval gate. It then fails on credentials,
// which is the next control — that ordering is the assertion.
func TestExecute_ValidGrantPassesTheApprovalGate(t *testing.T) {
	approver := testApprover(t)
	svc := NewService(&fakeConnectors{c: rwConnector(connector.TypeAWS, map[string]string{
		"region": "eu-west-1", // no execute_role_arn on purpose
	})}).WithApprovals(approver)

	grant, err := svc.Approve(adminCtx("alice@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionEC2Stop,
		Params: map[string]string{ParamInstanceID: "i-abc"},
	})
	require.NoError(t, err)

	_, err = svc.Execute(adminCtx("bob@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionEC2Stop,
		Params:        map[string]string{ParamInstanceID: "i-abc"},
		ApprovalToken: grant.Token,
	})
	require.ErrorIs(t, err, ErrNoExecutionRole)
	require.NotErrorIs(t, err, ErrApprovalRequired)
	require.NotErrorIs(t, err, ErrApprovalInvalid)
}

// A grant runs one execution: presenting it again inside its TTL — from the
// same replica or another sharing the ledger — is refused before the intent
// row, so a captured grant cannot be replayed.
func TestExecute_GrantIsSingleUse(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	ledger := &memLedger{spent: map[string]bool{}}
	replica := func() *Service {
		a, err := NewApprover(base64.StdEncoding.EncodeToString(key))
		require.NoError(t, err)
		return NewService(&fakeConnectors{c: rwConnector(connector.TypeAWS, map[string]string{"region": "eu-west-1"})}).
			WithApprovals(a.WithLedger(ledger))
	}
	one, two := replica(), replica()
	req := ExecutionRequest{ConnectorID: "conn-1", Action: ActionEC2Stop, Params: map[string]string{ParamInstanceID: "i-abc"}}

	grant, err := one.Approve(adminCtx("alice@example.com"), req)
	require.NoError(t, err)
	req.ApprovalToken = grant.Token

	_, err = one.Execute(adminCtx("bob@example.com"), req)
	require.ErrorIs(t, err, ErrNoExecutionRole, "the first use passes the approval gate")

	for name, svc := range map[string]*Service{"same replica": one, "other replica": two} {
		_, err = svc.Execute(adminCtx("bob@example.com"), req)
		require.ErrorIs(t, err, ErrApprovalInvalid, name)
		require.ErrorContains(t, err, "already used", name)
	}

	again, err := one.Approve(adminCtx("alice@example.com"), ExecutionRequest{ConnectorID: "conn-1", Action: ActionEC2Stop, Params: map[string]string{ParamInstanceID: "i-abc"}})
	require.NoError(t, err)
	require.NotEqual(t, grant.Token, again.Token, "a re-approval is a new grant, not the spent one")
}

// A grant has exactly one spelling. The base64 decoder skips CR/LF and accepts
// nonzero trailing bits, so before the canonical check every variant below
// decoded to the same grant under a fresh ledger key and replayed it.
func TestRedeem_NonCanonicalSpellingsCannotReplay(t *testing.T) {
	a := testApprover(t)
	g, err := a.Mint("conn-1", ActionEC2Stop, "plan", alice)
	require.NoError(t, err)
	body, sig, ok := strings.Cut(g.Token, ".")
	require.True(t, ok)

	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	last := strings.IndexByte(alphabet, sig[len(sig)-1])
	require.GreaterOrEqual(t, last, 0)
	trailingBits := func(n int) string {
		// A 32-byte HMAC ends in a 4-bit character; the low 2 bits are padding.
		return body + "." + sig[:len(sig)-1] + string(alphabet[last^n])
	}
	variants := map[string]string{
		"trailing LF":         g.Token + "\n",
		"trailing CRLF":       g.Token + "\r\n",
		"LF inside signature": body + "." + sig[:10] + "\n" + sig[10:],
		"CR inside signature": body + "." + sig[:10] + "\r" + sig[10:],
		"LF inside payload":   body[:10] + "\n" + body[10:] + "." + sig,
		"leading space":       " " + g.Token,
		"trailing bits 01":    trailingBits(1),
		"trailing bits 10":    trailingBits(2),
		"trailing bits 11":    trailingBits(3),
		"padded signature":    g.Token + "=",
	}

	_, err = a.Redeem(context.Background(), g.Token, "conn-1", ActionEC2Stop, "plan", bob)
	require.NoError(t, err, "the canonical token redeems once")
	_, err = a.Redeem(context.Background(), g.Token, "conn-1", ActionEC2Stop, "plan", bob)
	require.ErrorIs(t, err, ErrApprovalInvalid, "the canonical token redeems only once")

	for name, tok := range variants {
		t.Run(name, func(t *testing.T) {
			require.NotEqual(t, g.Token, tok)
			_, err := a.Redeem(context.Background(), tok, "conn-1", ActionEC2Stop, "plan", bob)
			require.ErrorIs(t, err, ErrApprovalInvalid)
			_, err = a.Verify(tok, "conn-1", ActionEC2Stop, "plan", bob)
			require.ErrorIs(t, err, ErrApprovalInvalid, "a non-canonical spelling must not even verify")
		})
	}
}

// The ledger key is the signed payload, not the token string: two spellings
// of one grant share a key, so the ledger alone would stop a replay even if a
// variant ever got past decoding.
func TestGrantKey_IsTheDecodedPayload(t *testing.T) {
	a := testApprover(t)
	g1, err := a.Mint("conn-1", ActionEC2Stop, "plan", alice)
	require.NoError(t, err)
	g2, err := a.Mint("conn-1", ActionEC2Stop, "plan", alice)
	require.NoError(t, err)

	_, p1, err := a.verify(g1.Token, "conn-1", ActionEC2Stop, "plan", bob)
	require.NoError(t, err)
	_, p2, err := a.verify(g2.Token, "conn-1", ActionEC2Stop, "plan", bob)
	require.NoError(t, err)
	body, _, _ := strings.Cut(g1.Token, ".")
	raw, err := base64.RawURLEncoding.DecodeString(body)
	require.NoError(t, err)
	require.Equal(t, raw, p1)
	require.NotEqual(t, grantKey(p1), grantKey(p2), "the nonce makes each mint its own ledger entry")
}

// Without a ledger, or when it cannot be written, a grant is not spendable:
// the fail-closed direction.
func TestRedeem_RefusesWithoutAWorkingLedger(t *testing.T) {
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	a, err := NewApprover(base64.StdEncoding.EncodeToString(key))
	require.NoError(t, err)
	g, err := a.Mint("conn-1", ActionEC2Stop, "plan", alice)
	require.NoError(t, err)

	_, err = a.Redeem(context.Background(), g.Token, "conn-1", ActionEC2Stop, "plan", bob)
	require.ErrorIs(t, err, ErrApprovalRequired)

	a.WithLedger(&memLedger{err: errors.New("postgres down")})
	_, err = a.Redeem(context.Background(), g.Token, "conn-1", ActionEC2Stop, "plan", bob)
	require.ErrorContains(t, err, "postgres down")
}

// The counter-assertion to the destructive tests: a non-destructive action must
// NOT need a grant, or the gate is just "everything".
func TestExecute_NonDestructiveActionNeedsNoGrant(t *testing.T) {
	svc := NewService(&fakeConnectors{c: rwConnector(connector.TypeAWS, map[string]string{
		"region": "eu-west-1", // no execute_role_arn — proves we reached the credential step
	})}).WithApprovals(testApprover(t))

	_, err := svc.Execute(adminCtx("ops@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionS3BlockPublic,
		Params: map[string]string{ParamBucketName: "logs-bucket"},
	})
	require.ErrorIs(t, err, ErrNoExecutionRole)
	require.NotErrorIs(t, err, ErrApprovalRequired)
}

// Restarting a stopped instance can undo a containment that took two admins,
// so one admin alone cannot run it.
func TestExecute_EC2StartNeedsASecondAdmin(t *testing.T) {
	svc := NewService(&fakeConnectors{c: rwConnector(connector.TypeAWS, map[string]string{"region": "eu-west-1"})}).
		WithApprovals(testApprover(t))

	_, err := svc.Execute(adminCtx("ops@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionEC2Start,
		Params: map[string]string{ParamInstanceID: "i-abc"},
	})
	require.ErrorIs(t, err, ErrApprovalRequired)
}

func TestApprove_RefusesActionsThatDoNotNeedApproval(t *testing.T) {
	svc := NewService(&fakeConnectors{c: rwConnector(connector.TypeAWS, map[string]string{"region": "eu-west-1"})}).
		WithApprovals(testApprover(t))

	_, err := svc.Approve(adminCtx("alice@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionS3BlockPublic,
		Params: map[string]string{ParamBucketName: "logs-bucket"},
	})
	require.ErrorIs(t, err, ErrApprovalNotRequired)
}

func TestApprove_IsAudited(t *testing.T) {
	audit := &fakeAuditor{}
	svc := NewService(&fakeConnectors{c: rwConnector(connector.TypeAWS, map[string]string{"region": "eu-west-1"})}).
		WithAudit(audit).WithApprovals(testApprover(t))

	_, err := svc.Approve(adminCtx("alice@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionEC2Stop,
		Params: map[string]string{ParamInstanceID: "i-abc"},
	})
	require.NoError(t, err)
	require.Len(t, audit.events, 1)
	require.Equal(t, AuditActionApprove, audit.events[0].Action)
	require.Equal(t, "alice@example.com", audit.events[0].Actor)
}

// The bypass the id check closes: one admin approves in the UI (session, email
// name) and executes with their own API key (same user id, "<key> (api-key)"
// name). The MCP execute_action tool goes through the same Execute path.
func TestExecute_SessionApproveThenOwnAPIKeyExecuteIsRefused(t *testing.T) {
	svc := NewService(&fakeConnectors{c: rwConnector(connector.TypeAWS, map[string]string{
		"region": "eu-west-1",
	})}).WithApprovals(testApprover(t))
	req := ExecutionRequest{ConnectorID: "conn-1", Action: ActionEC2Stop, Params: map[string]string{ParamInstanceID: "i-abc"}}

	session := auth.ContextWithUser(context.Background(), auth.User{ID: "u-alice", Email: "alice@example.com",
		Role: auth.RoleAdmin, CreatedAt: time.Now().Add(-48 * time.Hour), AdminSince: adminTime(time.Now().Add(-48 * time.Hour)), AuthorityVersion: 1})
	grant, err := svc.Approve(session, req)
	require.NoError(t, err)

	apiKey := auth.ContextWithUser(context.Background(), auth.User{ID: "u-alice", Email: "automation (api-key)", Role: auth.RoleAdmin})
	req.ApprovalToken = grant.Token
	_, err = svc.Execute(apiKey, req)
	require.ErrorIs(t, err, ErrApprovalInvalid)

	// A different user's API key passes the approval gate (and then fails on
	// the missing execution role — the next control).
	otherKey := auth.ContextWithUser(context.Background(), auth.User{ID: "u-bob", Email: "automation (api-key)", Role: auth.RoleAdmin,
		CreatedAt: time.Now().Add(-48 * time.Hour), AdminSince: adminTime(time.Now().Add(-48 * time.Hour)), AuthorityVersion: 1})
	_, err = svc.Execute(otherKey, req)
	require.ErrorIs(t, err, ErrNoExecutionRole)
}

// The approver comes from the session, never the body — a caller who could name
// their own approver would have defeated the whole control.
func TestApprove_ApproverIsTakenFromTheSession(t *testing.T) {
	svc := NewService(&fakeConnectors{c: rwConnector(connector.TypeAWS, map[string]string{"region": "eu-west-1"})}).
		WithApprovals(testApprover(t))

	g, err := svc.Approve(adminCtx("alice@example.com"), ExecutionRequest{
		ConnectorID: "conn-1", Action: ActionEC2Stop,
		Params: map[string]string{ParamInstanceID: "i-abc"},
	})
	require.NoError(t, err)
	require.Equal(t, "alice@example.com", g.Approver)
}

// The approver's address travels inside a readable token, so its hash must be
// keyed: the same address hashes differently under another server's key, and
// is not the plain SHA-256 anyone could brute-force over the IPv4 space.
func TestHashIP_IsKeyed(t *testing.T) {
	a, b := testApprover(t), testApprover(t)
	const ip = "203.0.113.7"
	require.Equal(t, a.hashIP(ip), a.hashIP(ip))
	require.NotEqual(t, a.hashIP(ip), b.hashIP(ip))
	plain := sha256.Sum256([]byte("graph/executor/approver-ip/v1:" + ip))
	require.NotEqual(t, base64.RawURLEncoding.EncodeToString(plain[:12]), a.hashIP(ip))
	require.Empty(t, a.hashIP(""))
}
