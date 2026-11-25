package reason

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/belief"
	"github.com/vulngraph/vulngraph/internal/app/finding"
)

func adjIn() belief.AdjudicationInput {
	return belief.AdjudicationInput{
		FindingID:  "f1",
		ResourceID: "role/admin",
		Title:      "IAM role allows privilege escalation",
		RawScore:   92,
		RawBand:    "page",
		Context:    "reachability: unreachable (no internet path)\ntrust_entry: contained (Okta SSO + MFA)",
	}
}

func TestBuildAdjudicationPrompt_FencesUntrustedTitleAndContext(t *testing.T) {
	p := buildAdjudicationPrompt(adjIn())
	require.Contains(t, p, "Raw score: 92 (page)")
	require.Contains(t, p, "role/admin")
	// Title and context are attacker-influenced → must be inside fences.
	title := p[strings.Index(p, "Finding:"):strings.Index(p, "Resource:")]
	require.Contains(t, title, "<<<UNTRUSTED>>>IAM role allows privilege escalation<<<END UNTRUSTED>>>")
	require.Contains(t, p, "reachability: unreachable")
}

func TestSample_ParsesGroundedVerdict(t *testing.T) {
	doer := &fakeDoer{reply: `{"severity":"low","evidence":[
		{"clause":"unreachable from the internet","source":"reachability","fact":"no internet path"},
		{"clause":"contained behind SSO+MFA","source":"trust_entry","fact":"contained"}]}`}
	r := &Reasoner{doer: doer}

	v, err := r.Sample(context.Background(), adjIn())
	require.NoError(t, err)
	require.Equal(t, finding.SeverityLow, v.Severity)
	require.Len(t, v.Evidence, 2)
	require.Equal(t, "reachability", v.Evidence[0].Source)
	// The adversarial system prompt + the fenced context reached the model.
	require.Contains(t, doer.gotUser, "<<<UNTRUSTED>>>")
}

// A trailing sentence after the verdict JSON that itself contains a brace
// pair must not corrupt the parse: json.Decoder (decodeJSONReply, reason.go)
// reads exactly one JSON value and ignores everything after it, unlike a
// naive Index("{")/LastIndex("}") splice which would grab the brace from
// inside the trailing prose.
func TestSample_TolerantOfTrailingProseContainingBraces(t *testing.T) {
	reply := `{"severity":"high","evidence":[{"clause":"reachable","source":"reachability","fact":"0 hops"}]}
Why this matters: {the identity} is directly internet-facing.`
	r := &Reasoner{doer: &fakeDoer{reply: reply}}
	v, err := r.Sample(context.Background(), adjIn())
	require.NoError(t, err)
	require.Equal(t, finding.SeverityHigh, v.Severity)
}

func TestSample_ToleratesJSONFence(t *testing.T) {
	r := &Reasoner{doer: &fakeDoer{reply: "```json\n{\"severity\":\"high\",\"evidence\":[{\"clause\":\"reachable and privileged\",\"source\":\"reachability\",\"fact\":\"0 hops\"}]}\n```"}}
	v, err := r.Sample(context.Background(), adjIn())
	require.NoError(t, err)
	require.Equal(t, finding.SeverityHigh, v.Severity)
}

func TestSample_UngroundedVerdictRejected(t *testing.T) {
	// No evidence → not a valid vote; the sampler errors so it doesn't count.
	r := &Reasoner{doer: &fakeDoer{reply: `{"severity":"low","evidence":[]}`}}
	_, err := r.Sample(context.Background(), adjIn())
	require.Error(t, err)
	require.Contains(t, err.Error(), "no grounded evidence")
}

func TestSample_HalfCitedEvidenceDropped(t *testing.T) {
	// Clause with no source/fact is not grounding — dropped; nothing left → error.
	r := &Reasoner{doer: &fakeDoer{reply: `{"severity":"medium","evidence":[{"clause":"seems fine","source":"","fact":""}]}`}}
	_, err := r.Sample(context.Background(), adjIn())
	require.Error(t, err)
}

func TestSample_RetriesOnceAfterUngroundedEvidenceThenSucceeds(t *testing.T) {
	doer := &fakeDoer{replies: []string{
		`{"severity":"low","evidence":[]}`,
		`{"severity":"low","evidence":[{"clause":"unreachable","source":"reachability","fact":"no internet path"}]}`,
	}}
	r := &Reasoner{doer: doer}

	v, err := r.Sample(context.Background(), adjIn())
	require.NoError(t, err)
	require.Equal(t, finding.SeverityLow, v.Severity)
	require.Equal(t, 2, doer.calls, "one ungrounded reply must cost exactly one retry, not more")
}

func TestSample_TwoConsecutiveUngroundedRepliesFailsOnce(t *testing.T) {
	doer := &fakeDoer{replies: []string{
		`{"severity":"low","evidence":[]}`,
		`{"severity":"low","evidence":[]}`,
	}}
	r := &Reasoner{doer: doer}

	_, err := r.Sample(context.Background(), adjIn())
	require.Error(t, err)
	require.Contains(t, err.Error(), "no grounded evidence")
	require.Equal(t, 2, doer.calls, "the retry itself must not retry again — one failure, counted once")
}

func TestSample_UnknownSeverityRejected(t *testing.T) {
	doer := &fakeDoer{reply: `{"severity":"scary","evidence":[{"clause":"x","source":"y","fact":"z"}]}`}
	r := &Reasoner{doer: doer}
	_, err := r.Sample(context.Background(), adjIn())
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown severity")
	require.Equal(t, 1, doer.calls, "an unknown-severity reply is not errNoGroundedEvidence — must not be retried")
}

func TestSample_DoerErrorPropagates(t *testing.T) {
	doer := &fakeDoer{err: errors.New("rate limited")}
	r := &Reasoner{doer: doer}
	_, err := r.Sample(context.Background(), adjIn())
	require.Error(t, err)
	require.Equal(t, 1, doer.calls, "a transport error is not errNoGroundedEvidence — must not be retried")
}
