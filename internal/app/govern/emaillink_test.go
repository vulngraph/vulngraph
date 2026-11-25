package govern

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/reasoncache"
	"github.com/vulngraph/vulngraph/internal/app/respond"
)

type fakeNonces struct{ spent map[string]bool }

func (f *fakeNonces) Consume(_ context.Context, nonce string, _ time.Time) (bool, error) {
	if f.spent[nonce] {
		return false, nil
	}
	f.spent[nonce] = true
	return true, nil
}

func (f *fakeNonces) Spent(_ context.Context, nonce string) (bool, error) { return f.spent[nonce], nil }

// linkFixture: f1 and f2 are both pending in the same cluster; the link signs f1 only.
func linkFixture() (*Service, *statefulVerdicts, *fakeOutcomes, *fakeNonces, *fakeAudit, LinkClaims) {
	return linkFixtureFor("remediate")
}

func linkFixtureFor(class string) (*Service, *statefulVerdicts, *fakeOutcomes, *fakeNonces, *fakeAudit, LinkClaims) {
	pending := fakePending{entries: []reasoncache.Entry{
		{FindingID: "f1", ActionClass: class, Fingerprint: "fp1"},
		{FindingID: "f2", ActionClass: class, Fingerprint: "fp2"},
	}}
	verdicts := &statefulVerdicts{resolved: map[string]string{}}
	outcomes := &fakeOutcomes{}
	nonces := &fakeNonces{spent: map[string]bool{}}
	audit := &fakeAudit{}
	s := svc(verdicts, pending, s3Findings("f1", "f2"), outcomes, audit).WithLinkNonces(nonces)
	claims := LinkClaims{
		FindingIDs: []string{"f1"}, SetHash: decisionSetHash([]string{"f1"}, map[string]string{"f1": "fp1"}),
		ActionClass: class, Verdict: VerdictApproved, Nonce: "n1", Recipient: "sec@example.com",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	return s, verdicts, outcomes, nonces, audit, claims
}

// A link acts on exactly the decision set it signed — not the whole
// cluster-wide set of same-check findings — and names its recipient.
func TestResolveByLink_ActsOnlyOnTheSignedSet(t *testing.T) {
	s, verdicts, outcomes, _, audit, claims := linkFixture()

	require.NoError(t, s.ResolveByLink(context.Background(), claims))
	require.Equal(t, map[string]string{"f1": "fp1"}, verdicts.resolved, "f2 is in the same cluster but was not signed")
	require.Empty(t, outcomes.recorded, "an approval is a yes to try the fix, not an outcome")
	require.Len(t, audit.events, 1)
	require.Equal(t, "email-link:sec@example.com", audit.events[0].Actor)
}

func TestResolveByLink_IsSingleUse(t *testing.T) {
	s, _, outcomes, _, _, claims := linkFixture()
	claims.Verdict = VerdictDenied
	require.NoError(t, s.ResolveByLink(context.Background(), claims))

	require.ErrorIs(t, s.ResolveByLink(context.Background(), claims), ErrAlreadyResolved)
	approve := claims
	approve.Verdict = VerdictApproved
	require.ErrorIs(t, s.ResolveByLink(context.Background(), approve), ErrAlreadyResolved,
		"the approve link of the same email shares the nonce")
	require.Len(t, outcomes.recorded, 1, "a replay never adds a memory outcome")
}

// The nonce is shared by both links, so a replay is refused even after the
// verdict store would otherwise allow a new verdict (a changed fingerprint).
func TestResolveByLink_SpentNonceIsRefusedOnItsOwn(t *testing.T) {
	s, _, _, nonces, _, claims := linkFixture()
	nonces.spent["n1"] = true
	require.ErrorIs(t, s.ResolveByLink(context.Background(), claims), ErrAlreadyResolved)
	require.ErrorIs(t, s.LinkUsable(context.Background(), claims), ErrAlreadyResolved)
}

func TestResolveByLink_RefusesChangedOrMismatchedDecisions(t *testing.T) {
	for name, mutate := range map[string]func(*LinkClaims){
		"context changed": func(c *LinkClaims) {
			c.SetHash = decisionSetHash([]string{"f1"}, map[string]string{"f1": "fp-old"})
		},
		"different set":         func(c *LinkClaims) { c.FindingIDs = []string{"f1", "f2"} },
		"different class":       func(c *LinkClaims) { c.ActionClass = "observe" },
		"finding no longer due": func(c *LinkClaims) { c.FindingIDs = []string{"gone"} },
	} {
		t.Run(name, func(t *testing.T) {
			s, verdicts, _, nonces, _, claims := linkFixture()
			mutate(&claims)
			err := s.ResolveByLink(context.Background(), claims)
			require.Error(t, err)
			require.True(t, errorsIsAny(err, ErrTargetMismatch, ErrNotPending), err.Error())
			require.Empty(t, verdicts.resolved)
			require.Empty(t, nonces.spent, "a refused link is not spent")
		})
	}
}

// A mailbox bearer link can say yes to a fix that can be undone, never to
// isolating or destroying a resource; it can always say no.
func TestResolveByLink_ApprovesOnlyNonDestructiveClasses(t *testing.T) {
	for _, class := range []string{"isolate", "destroy"} {
		t.Run(class, func(t *testing.T) {
			s, verdicts, _, nonces, _, claims := linkFixtureFor(class)
			require.ErrorIs(t, s.ResolveByLink(context.Background(), claims), ErrLinkCannotApprove)
			require.ErrorIs(t, s.LinkUsable(context.Background(), claims), ErrLinkCannotApprove,
				"the confirmation page does not offer it either")
			require.Empty(t, verdicts.resolved)
			require.Empty(t, nonces.spent, "a refused link is not spent")

			claims.Verdict = VerdictDenied
			require.NoError(t, s.ResolveByLink(context.Background(), claims), "denying is always allowed")
			require.Len(t, verdicts.resolved, 1)
		})
	}
	for _, class := range []string{"observe", "remediate", "modify"} {
		require.True(t, LinkCanApprove(class), class)
	}
}

// Denying is not free (it keeps the finding out of the queue until its
// context changes), so a mailbox link cannot deny an urgent finding.
func TestResolveByLink_CannotDenyAnUrgentFinding(t *testing.T) {
	s, verdicts, _, nonces, _, claims := linkFixture()
	s.findings = fakeFindings{byID: map[string]finding.Finding{
		"f1": {ID: "f1", CheckID: "c", ScoreBand: string(enrich.BandPage), Score: 95},
	}}
	claims.Verdict = VerdictDenied
	require.ErrorIs(t, s.ResolveByLink(context.Background(), claims), ErrLinkCannotDeny)
	require.ErrorIs(t, s.LinkUsable(context.Background(), claims), ErrLinkCannotDeny)
	require.Empty(t, verdicts.resolved)
	require.Empty(t, nonces.spent)

	s.findings = fakeFindings{byID: map[string]finding.Finding{}}
	require.ErrorIs(t, s.ResolveByLink(context.Background(), claims), ErrLinkCannotDeny, "an unreadable finding counts as urgent")

	s.findings = fakeFindings{byID: map[string]finding.Finding{"f1": {ID: "f1", CheckID: "c"}}}
	require.ErrorIs(t, s.ResolveByLink(context.Background(), claims), ErrLinkCannotDeny, "an unscored finding counts as urgent")
}

func TestResolveByLink_RefusedWithoutNonceStore(t *testing.T) {
	s, _, _, _, _, claims := linkFixture()
	s.nonces = nil
	require.ErrorIs(t, s.ResolveByLink(context.Background(), claims), ErrLinksDisabled)
}

func errorsIsAny(err error, targets ...error) bool {
	for _, t := range targets {
		if errors.Is(err, t) {
			return true
		}
	}
	return false
}

// End to end through the handler: the confirm POST records once, a replay is
// a 409 page, never a second verdict.
func TestApproveLinkConfirm_ReplayIs409(t *testing.T) {
	s, verdicts, _, _, _, claims := linkFixture()
	h := NewHandler(s).WithTokenSecret(testSecret)
	token, err := GenerateApprovalToken(claims, testSecret)
	require.NoError(t, err)

	do := func(method string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/queue/approve-link/"+token, nil)
		req.SetPathValue("token", token)
		rec := httptest.NewRecorder()
		if method == http.MethodGet {
			h.ApproveLink(rec, req)
		} else {
			h.ApproveLinkConfirm(rec, req)
		}
		return rec
	}
	require.Equal(t, http.StatusOK, do(http.MethodGet).Code, "the GET only renders a confirmation")
	require.Empty(t, verdicts.resolved)
	require.Equal(t, http.StatusSeeOther, do(http.MethodPost).Code)
	require.Len(t, verdicts.resolved, 1)
	require.Equal(t, http.StatusConflict, do(http.MethodPost).Code)
	require.Equal(t, http.StatusConflict, do(http.MethodGet).Code, "a spent link no longer offers a confirm button")

	deny := httptest.NewRequest(http.MethodPost, "/api/queue/deny-link/"+token, nil)
	deny.SetPathValue("token", token)
	rec := httptest.NewRecorder()
	h.DenyLinkConfirm(rec, deny)
	require.Equal(t, http.StatusBadRequest, rec.Code, "an approve token cannot be used on the deny route")
}

// A mail gateway or link scanner that fetches an approve or deny link (GET,
// HEAD, any number of times) only gets the confirmation page: nothing is
// recorded and the link stays usable until the form is POSTed.
func TestLinkGET_OnlyRendersAConfirmation(t *testing.T) {
	for _, verdict := range []Verdict{VerdictApproved, VerdictDenied} {
		t.Run(string(verdict), func(t *testing.T) {
			s, verdicts, outcomes, nonces, audit, claims := linkFixture()
			claims.Verdict = verdict
			h := NewHandler(s).WithTokenSecret(testSecret)
			token, err := GenerateApprovalToken(claims, testSecret)
			require.NoError(t, err)
			segment, get, post := "approve-link", h.ApproveLink, h.ApproveLinkConfirm
			if verdict == VerdictDenied {
				segment, get, post = "deny-link", h.DenyLink, h.DenyLinkConfirm
			}
			path := "/api/queue/" + segment + "/" + token

			for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodGet} {
				req := httptest.NewRequest(method, path, nil)
				req.SetPathValue("token", token)
				rec := httptest.NewRecorder()
				get(rec, req)
				require.Equal(t, http.StatusOK, rec.Code, method)
				if method == http.MethodGet {
					require.Contains(t, rec.Body.String(), `<form method="POST" action="`+path+`">`)
				}
			}
			require.Empty(t, verdicts.resolved, "a fetch records no verdict")
			require.Empty(t, outcomes.recorded)
			require.Empty(t, nonces.spent, "a fetch does not spend the link")
			require.Empty(t, audit.events)

			req := httptest.NewRequest(http.MethodPost, path, nil)
			req.SetPathValue("token", token)
			rec := httptest.NewRecorder()
			post(rec, req)
			require.Equal(t, http.StatusSeeOther, rec.Code)
			require.Len(t, verdicts.resolved, 1, "only the POST records")
			require.True(t, nonces.spent["n1"])
		})
	}
}

// Without APPROVAL_TOKEN_SECRET the link routes are a 503, not a 500: the
// feature is off, nothing failed.
func TestLinkRoutes_WithoutSecretAre503(t *testing.T) {
	s, verdicts, _, _, _, _ := linkFixture()
	h := NewHandler(s)
	for name, route := range map[string]http.HandlerFunc{
		"approve GET": h.ApproveLink, "deny GET": h.DenyLink,
		"approve POST": h.ApproveLinkConfirm, "deny POST": h.DenyLinkConfirm,
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/queue/approve-link/x.y", nil)
		req.SetPathValue("token", "x.y")
		rec := httptest.NewRecorder()
		route(rec, req)
		require.Equal(t, http.StatusServiceUnavailable, rec.Code, name)
	}
	require.Empty(t, verdicts.resolved)
}

type capturedMail struct {
	to  []string
	msg string
}

func testEmailNotifier(t *testing.T, sent *[]capturedMail) *EmailApprovalNotifier {
	t.Helper()
	n, err := NewEmailApprovalNotifier(EmailApprovalNotifierConfig{
		Host: "smtp.invalid", From: "graph@example.com", To: "sec@example.com",
		BaseURL: "https://graph.example.com/", Secret: testSecret,
	})
	require.NoError(t, err)
	n.send = func(_ context.Context, _ string, to []string, msg []byte) error {
		*sent = append(*sent, capturedMail{to: to, msg: string(msg)})
		return nil
	}
	return n
}

var tokenRe = regexp.MustCompile(`/api/queue/(approve|deny)-link/([A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)`)

// The request goes out when a decision is PARKED, with links bound to that
// decision's fingerprint and action class and sharing one nonce.
func TestEmailNotifier_SendsBoundLinksForParkedDecisions(t *testing.T) {
	var sent []capturedMail
	n := testEmailNotifier(t, &sent)
	f := finding.Finding{ID: "f1", Title: "Public bucket", Score: 60, ScoreBand: "pipeline"}
	d := respond.Decision{FindingID: "f1", Outcome: respond.OutcomeParked, Fingerprint: "fp1",
		Plan: respond.Plan{ActionClass: respond.ClassRemediate, Summary: "block public access"}}

	require.NoError(t, n.Notify(context.Background(), f, d, respond.ContextPack{}))
	require.Len(t, sent, 1)

	matches := tokenRe.FindAllStringSubmatch(sent[0].msg, -1)
	require.Len(t, matches, 2)
	approve, err := ValidateApprovalToken(matches[0][2], testSecret)
	require.NoError(t, err)
	deny, err := ValidateApprovalToken(matches[1][2], testSecret)
	require.NoError(t, err)
	require.Equal(t, VerdictApproved, approve.Verdict)
	require.Equal(t, VerdictDenied, deny.Verdict)
	require.Equal(t, approve.Nonce, deny.Nonce, "one email, one nonce")
	require.Equal(t, []string{"f1"}, approve.FindingIDs)
	require.Equal(t, "remediate", approve.ActionClass)
	require.Equal(t, decisionSetHash([]string{"f1"}, map[string]string{"f1": "fp1"}), approve.SetHash)
	require.Equal(t, "sec@example.com", approve.Recipient)
}

// An isolate/destroy email carries only the deny token; its approve button
// leads to the signed-in queue.
func TestEmailNotifier_NoApproveLinkForDestructiveClasses(t *testing.T) {
	var sent []capturedMail
	n := testEmailNotifier(t, &sent)
	d := respond.Decision{FindingID: "f1", Outcome: respond.OutcomeParked, Fingerprint: "fp1",
		Plan: respond.Plan{ActionClass: respond.ClassIsolate, Summary: "stop the instance"}}
	require.NoError(t, n.Notify(context.Background(), finding.Finding{ID: "f1", Title: "Compromised host", ScoreBand: "pipeline"}, d, respond.ContextPack{}))
	require.Len(t, sent, 1)

	matches := tokenRe.FindAllStringSubmatch(sent[0].msg, -1)
	require.Len(t, matches, 1)
	require.Equal(t, "deny", matches[0][1])
	require.Contains(t, sent[0].msg, `href="https://graph.example.com/decisions"`)
	require.Contains(t, sent[0].msg, "Review and approve in Vulngraph")
}

// An urgent finding's email carries no deny token either: its deny button
// leads to the signed-in queue.
func TestEmailNotifier_NoDenyLinkForUrgentFindings(t *testing.T) {
	var sent []capturedMail
	n := testEmailNotifier(t, &sent)
	d := respond.Decision{FindingID: "f1", Outcome: respond.OutcomeParked, Fingerprint: "fp1",
		Plan: respond.Plan{ActionClass: respond.ClassRemediate, Summary: "patch"}}
	require.NoError(t, n.Notify(context.Background(), finding.Finding{ID: "f1", Title: "KEV", MustFixClass: enrich.MustFix}, d, respond.ContextPack{}))
	require.Len(t, sent, 1)
	matches := tokenRe.FindAllStringSubmatch(sent[0].msg, -1)
	require.Len(t, matches, 1)
	require.Equal(t, "approve", matches[0][1])
	require.Contains(t, sent[0].msg, "Review and deny in Vulngraph")
}

func TestEmailNotifier_IgnoresDecisionsThatNeedNoApproval(t *testing.T) {
	var sent []capturedMail
	n := testEmailNotifier(t, &sent)
	for _, o := range []respond.Outcome{respond.OutcomeObserved, respond.OutcomeEscalated, respond.OutcomeSuppressedByVerdict} {
		require.NoError(t, n.Notify(context.Background(), finding.Finding{ID: "f1"},
			respond.Decision{Outcome: o, Fingerprint: "fp1"}, respond.ContextPack{}))
	}
	require.Empty(t, sent)
}

// A finding title is attacker-influenceable; a CRLF in it must not end the
// Subject header and inject headers or a body.
func TestEmailNotifier_CRLFTitleCannotInjectHeaders(t *testing.T) {
	var sent []capturedMail
	n := testEmailNotifier(t, &sent)
	f := finding.Finding{ID: "f1", Title: "bucket\r\nBcc: attacker@evil.example\r\n\r\n<h1>pwned</h1>"}
	d := respond.Decision{Outcome: respond.OutcomeParked, Fingerprint: "fp1", Plan: respond.Plan{ActionClass: respond.ClassRemediate}}
	require.NoError(t, n.Notify(context.Background(), f, d, respond.ContextPack{}))
	require.Len(t, sent, 1)

	headers, _, ok := strings.Cut(sent[0].msg, "\r\n\r\n")
	require.True(t, ok)
	lines := strings.Split(headers, "\r\n")
	require.Len(t, lines, 5, "From, To, Subject, MIME-Version, Content-Type — nothing injected")
	for _, l := range lines {
		require.False(t, strings.HasPrefix(strings.ToLower(l), "bcc:"), l)
	}
	require.Equal(t, []string{"sec@example.com"}, sent[0].to)
}

func TestBuildMIMEMessage_EncodesAndSanitisesEveryHeader(t *testing.T) {
	msg := string(buildMIMEMessage("a@x\r\nBcc: e@x", "b@x\n", "héllo\r\nX-Evil: 1", "<p>body</p>"))
	headers, body, _ := strings.Cut(msg, "\r\n\r\n")
	require.Equal(t, "<p>body</p>", body)
	require.Len(t, strings.Split(headers, "\r\n"), 5)
	require.Contains(t, headers, "Subject: =?utf-8?q?")
	require.NotContains(t, headers, "\r\nX-Evil")
	require.NotContains(t, headers, "\r\nBcc")
}

func TestNewEmailApprovalNotifier_RequiresStrongSecret(t *testing.T) {
	_, err := NewEmailApprovalNotifier(EmailApprovalNotifierConfig{Host: "h", Secret: "short"})
	require.ErrorIs(t, err, ErrTokenSecretShort)
}
