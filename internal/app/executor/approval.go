package executor

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

// ApprovalTTL bounds how long a grant stays usable. Long enough for a human to
// read a plan and run the command, short enough that a leaked grant is dead
// before it is useful. Inside the TTL a grant still runs at most one execution
// (GrantLedger).
const ApprovalTTL = 10 * time.Minute

// approvalKeyInfo domain-separates the grant-signing key from the credential
// encryption key. Both are derived from GRAPH_SECRET_KEY today; deriving rather
// than reusing means a future split of the two is a wiring change, not a format
// change, and an oracle on one never yields the other.
const approvalKeyInfo = "graph/executor/approval-grant/v1"

// Approver mints and verifies two-person approval grants, required for
// destructive actions (actionSpec.destructive) and for any change asked for
// over an API key or the MCP seam (see Execute's needsGrant).
//
// A grant is a signed, expiring assertion that a NAMED admin read a SPECIFIC
// plan and approved it. Verification is stateless (HMAC) so a grant minted on
// one replica verifies on any other with no lookup; only redemption touches
// Postgres: Redeem records each grant's first use in the GrantLedger shared by
// every replica, so a grant presented a second time inside its TTL is refused.
// The guarantee is "a second admin approved this exact change, and it ran at
// most once".
type Approver struct {
	key []byte
	now func() time.Time
	// ledger spends grants. nil refuses every redemption — an unwired ledger
	// must not read as "grants are reusable".
	ledger GrantLedger
}

// GrantLedger records grant redemptions across replicas. PGGrantLedger
// implements it.
type GrantLedger interface {
	// Redeem records the first use of the grant with this hash; ok is false
	// when the grant was already redeemed.
	Redeem(ctx context.Context, grantHash, byID string, expiresAt time.Time) (ok bool, err error)
}

// WithLedger attaches the ledger that makes grants single-use.
func (a *Approver) WithLedger(l GrantLedger) *Approver {
	a.ledger = l
	return a
}

// NewApprover derives the grant-signing key from the same base64 32-byte secret
// the rest of the platform is configured with, via HKDF domain separation.
func NewApprover(base64Key string) (*Approver, error) {
	raw, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return nil, fmt.Errorf("NewApprover: decode key: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("NewApprover: key must be 32 bytes, got %d", len(raw))
	}
	key := make([]byte, 32)
	if _, err := hkdf.New(sha256.New, raw, nil, []byte(approvalKeyInfo)).Read(key); err != nil {
		return nil, fmt.Errorf("NewApprover: derive: %w", err)
	}
	return &Approver{key: key, now: time.Now}, nil
}

// Principal identifies a human on either side of a two-person check. ID is the
// stable user id and is what the control compares. Name is the user's email
// (for an API key, its owner's), kept for messages and the audit trail only.
type Principal struct {
	ID   string
	Name string
	// IP is the client address auth.RequireAuth resolved (CLIENT_IP_HEADER
	// behind a proxy). Never compared by the two-person check (NAT and shared
	// egress make it unreliable); only used to flag a shared address in the
	// audit trail.
	IP string
	// CreatedAt is when the principal's account was created; zero = unknown,
	// which the approver account-age check refuses.
	CreatedAt time.Time
	// AdminSince is when the principal's role last became admin; zero =
	// unknown (an admin that predates the column), which counts from CreatedAt.
	AdminSince time.Time
}

// adminTenureStart is when the principal's two-person eligibility clock
// starts: the later of account creation and becoming admin. A zero CreatedAt
// stays zero, so an unknown account age is still refused.
func (p Principal) adminTenureStart() time.Time {
	if p.CreatedAt.IsZero() {
		return time.Time{}
	}
	return later(p.CreatedAt, p.AdminSince)
}

func later(a, b time.Time) time.Time {
	if b.After(a) {
		return b
	}
	return a
}

func (p Principal) attributed() bool {
	return p.ID != "" && p.Name != "" && p.Name != AuditActorUnknown
}

// Approval is a minted grant handed back to the approving admin.
type Approval struct {
	Token     string
	Plan      string
	Approver  string
	ExpiresAt time.Time
}

// grantClaims is the signed payload. PlanHash — not the plan text — binds the
// grant to the change: an approver who read "stop i-abc" cannot have their grant
// spent on "stop i-def", because a different plan hashes differently and the
// signature covers the hash.
type grantClaims struct {
	ConnectorID string `json:"c"`
	Action      string `json:"a"`
	PlanHash    string `json:"p"`
	Approver    string `json:"by"`
	ApproverID  string `json:"uid"`
	// ApproverIP is a hash of the approver's client address ("" if unknown),
	// so an execution from the same address can be flagged for review.
	ApproverIP string `json:"iph,omitempty"`
	ExpiresAt  int64  `json:"exp"`
	// Nonce makes every mint a distinct grant, so re-approving the same plan
	// within one second never hands back a token the ledger already spent.
	Nonce string `json:"n"`
}

// Grant is what a verified approval token asserts about its approver.
type Grant struct {
	Approver   string
	ApproverID string
	// SameIP is true when the executor's client address matches the
	// approver's — one human holding two accounts is the likeliest cause.
	SameIP bool
	// ExpiresAt is when the grant stops verifying.
	ExpiresAt time.Time
}

// Mint signs a grant for one resolved plan.
func (a *Approver) Mint(connectorID string, action Action, plan string, approver Principal) (Approval, error) {
	if !approver.attributed() {
		return Approval{}, fmt.Errorf("%w: an approval must name the approving admin", ErrApprovalInvalid)
	}
	exp := a.now().UTC().Add(ApprovalTTL)
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return Approval{}, fmt.Errorf("Mint: nonce: %w", err)
	}
	claims := grantClaims{
		ConnectorID: connectorID,
		Action:      string(action),
		PlanHash:    hashPlan(plan),
		Approver:    approver.Name,
		ApproverID:  approver.ID,
		ApproverIP:  a.hashIP(approver.IP),
		ExpiresAt:   exp.Unix(),
		Nonce:       base64.RawURLEncoding.EncodeToString(nonce),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return Approval{}, fmt.Errorf("Mint: %w", err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	token := body + "." + base64.RawURLEncoding.EncodeToString(a.sign([]byte(body)))
	return Approval{Token: token, Plan: plan, Approver: approver.Name, ExpiresAt: exp}, nil
}

// Verify checks that token is a valid, unexpired grant for exactly this
// connector, action and plan, approved by an admin OTHER than the executor.
func (a *Approver) Verify(token, connectorID string, action Action, plan string, executor Principal) (Grant, error) {
	claims, _, err := a.verify(token, connectorID, action, plan, executor)
	if err != nil {
		return Grant{}, err
	}
	return claims.grant(a.hashIP(executor.IP)), nil
}

// grant builds the verified Grant; executorIPHash is a.hashIP(executor.IP).
func (c grantClaims) grant(executorIPHash string) Grant {
	return Grant{
		Approver:   c.Approver,
		ApproverID: c.ApproverID,
		SameIP:     executorIPHash != "" && executorIPHash == c.ApproverIP,
		ExpiresAt:  time.Unix(c.ExpiresAt, 0).UTC(),
	}
}

// Redeem verifies token exactly as Verify does and then spends it: the first
// redemption of a grant succeeds, every later one is refused with
// ErrApprovalInvalid, on whichever replica it lands. Execute redeems through
// here, so one approval runs one execution.
func (a *Approver) Redeem(ctx context.Context, token, connectorID string, action Action, plan string, executor Principal) (Grant, error) {
	claims, payload, err := a.verify(token, connectorID, action, plan, executor)
	if err != nil {
		return Grant{}, err
	}
	g := claims.grant(a.hashIP(executor.IP))
	if a.ledger == nil {
		return Grant{}, fmt.Errorf("%w: no grant ledger is configured, so a grant cannot be spent", ErrApprovalRequired)
	}
	ok, err := a.ledger.Redeem(ctx, grantKey(payload), executor.ID, g.ExpiresAt)
	if err != nil {
		return Grant{}, fmt.Errorf("Redeem: %w", err)
	}
	if !ok {
		return Grant{}, fmt.Errorf("%w: this approval grant was already used; ask for a new one", ErrApprovalInvalid)
	}
	return g, nil
}

// grantKey keys a grant in the ledger by its decoded, signed payload — never
// the token string, which has more than one spelling that decodes to the same
// grant — without storing a usable token. The payload carries the mint nonce,
// so every mint has its own key.
func grantKey(payload []byte) string {
	sum := sha256.Sum256(append([]byte("graph/executor/grant-redemption/v2:"), payload...))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// decodeCanonical decodes one token segment and refuses any spelling Mint
// would not have produced: the decoder skips CR/LF and accepts nonzero
// trailing bits, so without the re-encode check one grant has many spellings.
func decodeCanonical(seg string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.Strict().DecodeString(seg)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != seg {
		return nil, false
	}
	return raw, true
}

// verify returns the claims and the decoded signed payload Redeem keys the
// ledger on.
func (a *Approver) verify(token, connectorID string, action Action, plan string, executor Principal) (grantClaims, []byte, error) {
	body, sig, ok := strings.Cut(token, ".")
	if !ok {
		return grantClaims{}, nil, fmt.Errorf("%w: malformed approval token", ErrApprovalInvalid)
	}
	gotSig, ok := decodeCanonical(sig)
	if !ok {
		return grantClaims{}, nil, fmt.Errorf("%w: malformed approval signature", ErrApprovalInvalid)
	}
	// Constant-time, and BEFORE the payload is parsed — an attacker must not be
	// able to steer parsing with an unsigned payload.
	if subtle.ConstantTimeCompare(gotSig, a.sign([]byte(body))) != 1 {
		return grantClaims{}, nil, fmt.Errorf("%w: approval signature does not verify", ErrApprovalInvalid)
	}
	payload, ok := decodeCanonical(body)
	if !ok {
		return grantClaims{}, nil, fmt.Errorf("%w: malformed approval payload", ErrApprovalInvalid)
	}
	var claims grantClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return grantClaims{}, nil, fmt.Errorf("%w: malformed approval claims", ErrApprovalInvalid)
	}

	if a.now().UTC().Unix() > claims.ExpiresAt {
		return grantClaims{}, nil, fmt.Errorf("%w: approval expired", ErrApprovalInvalid)
	}
	if claims.ConnectorID != connectorID || claims.Action != string(action) {
		return grantClaims{}, nil, fmt.Errorf("%w: approval is for a different connector or action", ErrApprovalInvalid)
	}
	if subtle.ConstantTimeCompare([]byte(claims.PlanHash), []byte(hashPlan(plan))) != 1 {
		return grantClaims{}, nil, fmt.Errorf("%w: approval was granted for a different change", ErrApprovalInvalid)
	}
	// Two-person control requires a named executor too, refused explicitly here
	// so the error names the real reason rather than failing the equality check below.
	if !executor.attributed() {
		return grantClaims{}, nil, fmt.Errorf("%w: a destructive action needs an attributed executor", ErrApprovalInvalid)
	}
	// A grant without an approver id (minted before ids were carried) cannot be
	// checked against the executor, so it is refused rather than trusted.
	if claims.ApproverID == "" {
		return grantClaims{}, nil, fmt.Errorf("%w: approval does not identify the approving user", ErrApprovalInvalid)
	}
	// The user id is the control; the name check is belt-and-braces.
	if claims.ApproverID == executor.ID || strings.EqualFold(claims.Approver, executor.Name) {
		return grantClaims{}, nil, fmt.Errorf("%w: %s approved this change and cannot also execute it", ErrApprovalInvalid, executor.Name)
	}
	return claims, payload, nil
}

func (a *Approver) sign(body []byte) []byte {
	m := hmac.New(sha256.New, a.key)
	m.Write(body)
	return m.Sum(nil)
}

// hashIP hides the client address inside the token: the grant is handed to
// the executor, who has no business learning the approver's address. The
// token payload is readable base64 JSON, so the hash is keyed (HMAC under the
// grant-signing key): an unkeyed hash of an IPv4 address is reversed by
// trying all 2^32 of them. The signed body is base64url and never contains
// ':', so this input cannot collide with a grant signature's.
func (a *Approver) hashIP(ip string) string {
	if ip == "" {
		return ""
	}
	m := hmac.New(sha256.New, a.key)
	m.Write([]byte("graph/executor/approver-ip/v2:" + ip))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)[:12])
}

// hashPlan binds a grant to the exact rendered plan. The plan comes from the
// action registry, so approver and executor hash identical text.
func hashPlan(plan string) string {
	sum := sha256.Sum256([]byte(plan))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
