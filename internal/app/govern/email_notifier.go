package govern

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/respond"
)

// emailTemplate is the HTML body sent for each parked decision. Placeholders
// are replaced with strings.NewReplacer before sending — no template engine,
// no external dependencies.
const emailTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vulngraph — Decision requires approval</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         background: #f4f6f9; margin: 0; padding: 32px 16px; color: #1a1d23; }
  .card { background: #ffffff; border-radius: 8px; box-shadow: 0 1px 4px rgba(0,0,0,0.10);
          max-width: 560px; margin: 0 auto; padding: 32px; }
  h1 { font-size: 18px; font-weight: 600; margin: 0 0 4px; color: #1a1d23; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 12px;
           font-weight: 600; background: #fef3c7; color: #92400e; margin-bottom: 20px; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 24px; }
  td { padding: 8px 0; font-size: 14px; vertical-align: top; }
  td:first-child { color: #6b7280; width: 140px; }
  td:last-child { font-weight: 500; }
  .summary { background: #f8fafc; border-left: 3px solid #3b82f6; padding: 12px 14px;
             border-radius: 0 4px 4px 0; font-size: 14px; margin-bottom: 24px; line-height: 1.5; }
  .actions { display: flex; gap: 12px; }
  .btn { display: inline-block; padding: 12px 28px; border-radius: 6px; font-size: 15px;
         font-weight: 600; text-decoration: none; text-align: center; }
  .btn-approve { background: #16a34a; color: #ffffff; }
  .btn-deny    { background: #dc2626; color: #ffffff; }
  .footer { text-align: center; font-size: 12px; color: #9ca3af; margin-top: 24px; }
</style>
</head>
<body>
<div class="card">
  <h1>{{TITLE}}</h1>
  <span class="badge">Requires approval</span>
  <table>
    <tr><td>Action class</td><td>{{ACTION_CLASS}}</td></tr>
    <tr><td>Confidence</td><td>{{CONFIDENCE_BAND}}</td></tr>
    <tr><td>Blast radius</td><td>{{BLAST_RADIUS}}</td></tr>
    <tr><td>Worst score</td><td>{{WORST_SCORE}}</td></tr>
    <tr><td>Findings</td><td>{{COUNT}}</td></tr>
  </table>
  <div class="summary">{{SUMMARY}}</div>
  <div class="actions">
    <a class="btn btn-approve" href="{{APPROVE_URL}}">{{APPROVE_LABEL}}</a>
    <a class="btn btn-deny"    href="{{DENY_URL}}">{{DENY_LABEL}}</a>
  </div>
  <div class="footer">Vulngraph &middot; These links expire in 48 hours and work once.</div>
</div>
</body>
</html>`

// EmailApprovalNotifier emails an approval request when the agent PARKS a
// decision for human approval. It implements respond.DecisionNotifier and is
// wired on the worker, where decisions are made: the request goes out when a
// human is needed, not after one already approved. Each email signs its
// links to the exact decision (finding id + context fingerprint) and action
// class, and carries a nonce that makes the pair of links single-use.
type EmailApprovalNotifier struct {
	host    string
	port    int
	from    string
	to      string
	baseURL string // e.g. https://graph.example.com
	secret  string // HMAC secret for approval tokens
	// implicitTLS is true on the submissions port 465 (RFC 8314): TLS from
	// the first byte instead of STARTTLS.
	implicitTLS bool
	// allowPlaintext lets deliver send without TLS when the server offers no
	// STARTTLS. Dangerous: the approve/deny links are bearer credentials.
	allowPlaintext bool
	// tlsConfig is nil in production (system roots, ServerName = host); tests
	// set one that trusts their own server.
	tlsConfig *tls.Config
	// send delivers one message; deliver in production.
	send func(ctx context.Context, from string, to []string, msg []byte) error
}

// EmailApprovalNotifierConfig holds the fields needed to build the notifier.
type EmailApprovalNotifierConfig struct {
	Host    string
	Port    int // defaults to 587 (STARTTLS); 465 is implicit TLS
	From    string
	To      string
	BaseURL string
	Secret  string
	// AllowPlaintext (SMTP_ALLOW_PLAINTEXT) sends over an unencrypted
	// connection when the server offers no STARTTLS. Dangerous: anyone on the
	// path can read the single-use approve/deny links and use them first.
	AllowPlaintext bool
}

// NewEmailApprovalNotifier builds a notifier that emails approval requests.
// The secret must satisfy ValidateTokenSecret.
func NewEmailApprovalNotifier(cfg EmailApprovalNotifierConfig) (*EmailApprovalNotifier, error) {
	if err := ValidateTokenSecret(cfg.Secret); err != nil {
		return nil, fmt.Errorf("NewEmailApprovalNotifier: %w", err)
	}
	port := cfg.Port
	if port == 0 {
		port = 587
	}
	n := &EmailApprovalNotifier{
		host:           cfg.Host,
		port:           port,
		from:           headerText(cfg.From),
		to:             headerText(cfg.To),
		baseURL:        strings.TrimRight(cfg.BaseURL, "/"),
		secret:         cfg.Secret,
		implicitTLS:    port == implicitTLSPort,
		allowPlaintext: cfg.AllowPlaintext,
	}
	n.send = n.deliver
	return n, nil
}

// Notify sends the approval request for a parked decision; every other
// outcome is ignored.
func (n *EmailApprovalNotifier) Notify(ctx context.Context, f finding.Finding, d respond.Decision, _ respond.ContextPack) error {
	if d.Outcome != respond.OutcomeParked {
		return nil
	}
	if d.Fingerprint == "" {
		return fmt.Errorf("Notify: decision for %s has no fingerprint to bind the approval link to", f.ID)
	}
	nonce, err := newLinkNonce()
	if err != nil {
		return fmt.Errorf("Notify: %w", err)
	}
	ids := []string{f.ID}
	claims := LinkClaims{
		FindingIDs:  ids,
		SetHash:     decisionSetHash(ids, map[string]string{f.ID: d.Fingerprint}),
		ActionClass: string(d.Plan.ActionClass),
		Nonce:       nonce,
		Recipient:   n.to,
	}
	// Classes a link cannot approve get a button into the signed-in queue
	// instead of an approve token nobody could use.
	approveURL, approveLabel := n.baseURL+"/decisions", "Review and approve in Vulngraph"
	if LinkCanApprove(claims.ActionClass) {
		claims.Verdict = VerdictApproved
		approveToken, err := GenerateApprovalToken(claims, n.secret)
		if err != nil {
			return fmt.Errorf("Notify: approve token: %w", err)
		}
		approveURL, approveLabel = n.baseURL+"/api/queue/approve-link/"+approveToken, "&#x2713; Approve"
	}
	// An urgent or unscored finding cannot be denied from a link (linkDenyBlocker):
	// its deny button leads to the signed-in queue instead.
	denyURL, denyLabel := n.baseURL+"/decisions", "Review and deny in Vulngraph"
	if linkDenyBlocker(f) == "" {
		claims.Verdict = VerdictDenied
		denyToken, err := GenerateApprovalToken(claims, n.secret)
		if err != nil {
			return fmt.Errorf("Notify: deny token: %w", err)
		}
		denyURL, denyLabel = n.baseURL+"/api/queue/deny-link/"+denyToken, "&#x2717; Deny"
	}

	title := f.Title
	if title == "" {
		title = d.Plan.Summary
	}
	req := approvalRequest{
		Title: title, ActionClass: string(d.Plan.ActionClass), ConfidenceBand: d.ConfidenceBand,
		BlastRadius: d.BlastRadius, BlastRadiusKnown: d.BlastRadiusKnown, WorstScore: f.Score,
		Count: 1, Summary: d.Plan.Summary,
	}
	body := buildEmailBody(req, emailButtons{approveURL, approveLabel, denyURL, denyLabel})
	msg := buildMIMEMessage(n.from, n.to, "[Vulngraph] Decision requires approval: "+title, body)

	if err := n.send(ctx, n.from, []string{n.to}, msg); err != nil {
		return fmt.Errorf("Notify: %w", err)
	}
	return nil
}

// smtpTimeout bounds one delivery, dial to QUIT.
const smtpTimeout = 30 * time.Second

// implicitTLSPort is the submissions port (RFC 8314): TLS from the first byte.
const implicitTLSPort = 465

// deliver sends msg over TLS: implicit TLS on port 465 (implicitTLS), otherwise a mandatory
// STARTTLS. smtp.SendMail upgrades only when the server advertises STARTTLS
// and silently sends in the clear when it does not (or when a man in the
// middle strips the advertisement); the links in this message are bearer
// credentials, so a server without TLS is refused with ErrSMTPNoTLS unless
// allowPlaintext. A failed TLS handshake is never retried in the clear.
func (n *EmailApprovalNotifier) deliver(ctx context.Context, from string, to []string, msg []byte) error {
	ctx, cancel := context.WithTimeout(ctx, smtpTimeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(n.host, strconv.Itoa(n.port)))
	if err != nil {
		return fmt.Errorf("deliver: dial: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline) // a fresh TCP conn; SetDeadline cannot fail on it
	}
	cfg := n.tlsConfig
	if cfg == nil {
		cfg = &tls.Config{ServerName: n.host, MinVersion: tls.VersionTLS12}
	}
	if n.implicitTLS {
		tc := tls.Client(conn, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return fmt.Errorf("deliver: TLS handshake: %w", err)
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, n.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("deliver: %w", err)
	}
	defer c.Close() //nolint:errcheck // Quit below reports the real outcome
	if !n.implicitTLS {
		if ok, _ := c.Extension("STARTTLS"); ok {
			if err := c.StartTLS(cfg); err != nil {
				return fmt.Errorf("deliver: STARTTLS: %w", err)
			}
		} else if !n.allowPlaintext {
			return fmt.Errorf("deliver: %w", ErrSMTPNoTLS)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("deliver: MAIL: %w", err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("deliver: RCPT: %w", err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("deliver: DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("deliver: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("deliver: end of data: %w", err)
	}
	if err := c.Quit(); err != nil {
		return fmt.Errorf("deliver: QUIT: %w", err)
	}
	return nil
}

// approvalRequest is what the approval email shows.
type approvalRequest struct {
	Title            string
	ActionClass      string
	ConfidenceBand   string
	BlastRadius      int
	BlastRadiusKnown bool
	WorstScore       uint8
	Count            int
	Summary          string
}

// blastRadiusText renders the human-facing blast radius, with an explicit
// caveat when the walk failed — this is the human-authorization surface for
// a real cloud mutation, so an unmeasured value must never render as a
// confident number.
func blastRadiusText(r approvalRequest) string {
	if !r.BlastRadiusKnown {
		return strconv.Itoa(r.BlastRadius) + " (blast-radius walk failed — unmeasured)"
	}
	return strconv.Itoa(r.BlastRadius)
}

// emailButtons are the two action buttons. The labels are trusted markup
// (fixed strings chosen in Notify); the URLs are escaped.
type emailButtons struct {
	approveURL, approveLabel, denyURL, denyLabel string
}

// buildEmailBody fills the template; everything but the button labels is
// escaped.
func buildEmailBody(r approvalRequest, b emailButtons) string {
	rep := strings.NewReplacer(
		"{{TITLE}}", htmlEscape(r.Title),
		"{{ACTION_CLASS}}", htmlEscape(r.ActionClass),
		"{{CONFIDENCE_BAND}}", htmlEscape(r.ConfidenceBand),
		"{{BLAST_RADIUS}}", htmlEscape(blastRadiusText(r)),
		"{{WORST_SCORE}}", strconv.Itoa(int(r.WorstScore)),
		"{{COUNT}}", strconv.Itoa(r.Count),
		"{{SUMMARY}}", htmlEscape(r.Summary),
		"{{APPROVE_URL}}", htmlEscape(b.approveURL),
		"{{APPROVE_LABEL}}", b.approveLabel,
		"{{DENY_LABEL}}", b.denyLabel,
		"{{DENY_URL}}", htmlEscape(b.denyURL),
	)
	return rep.Replace(emailTemplate)
}

// buildMIMEMessage assembles the raw RFC 5322 / MIME message bytes. Every
// header value is reduced to one line of printable text first: a finding
// title is attacker-influenceable (anyone who can name a resource chooses
// it), and a CR/LF in it would end the Subject header and let the title
// inject headers (Bcc:) or a body of its own. The subject is then RFC 2047
// encoded so non-ASCII titles survive.
func buildMIMEMessage(from, to, subject, htmlBody string) []byte {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n",
		headerText(from), headerText(to), mime.QEncoding.Encode("utf-8", headerText(subject)))
	buf.WriteString(htmlBody)
	return buf.Bytes()
}

// headerText collapses s to a single header-safe line: CR, LF and every
// other control character become a space.
func headerText(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

// htmlEscape escapes the five XML/HTML characters that must be safe inside
// attribute values and element content.
func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&#34;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
