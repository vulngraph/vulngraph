package reason

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
	"github.com/vulngraph/vulngraph/internal/app/finding"
	"github.com/vulngraph/vulngraph/internal/app/respond"
	"github.com/vulngraph/vulngraph/internal/llm"
)

type fakeDoer struct {
	reply     string
	err       error
	gotUser   string
	gotSchema map[string]any

	// replies, when non-empty, queues successive doJSON replies — one popped
	// per call — for tests asserting retry behavior (Sample's ungrounded-
	// evidence retry, adjudicate_test.go). Once exhausted, doJSON falls back
	// to the plain reply/err fields above, so existing single-reply tests are
	// unaffected. calls counts every doJSON invocation.
	replies []string
	calls   int
}

func (f *fakeDoer) do(_ context.Context, _, user string) (string, error) {
	f.gotUser = user
	return f.reply, f.err
}

func (f *fakeDoer) doJSON(_ context.Context, _, user string, schema map[string]any) (string, error) {
	f.gotUser, f.gotSchema = user, schema
	f.calls++
	if len(f.replies) > 0 {
		reply := f.replies[0]
		f.replies = f.replies[1:]
		return reply, f.err
	}
	return f.reply, f.err
}

func TestBuildPrompt_IncludesFindingAndGraphContext(t *testing.T) {
	p := buildPrompt(respond.ContextPack{
		Finding: finding.Finding{
			Title: "Public bucket", Severity: finding.SeverityHigh, Type: "exposure",
			ResourceID: "arn:s3", ResourceType: "s3_bucket", CheckID: "aws-s3-public",
			Score: 82, ScoreBand: "page",
		},
		Blast:    respond.BlastSummary{Count: 12, Known: true, ByType: map[string]int{"ec2_instance": 5}, CanAssume: []string{"u -> r"}},
		Peers:    []respond.PeerSummary{{Type: "ciem_privesc", CheckID: "aws-privesc-1", ScoreBand: "high"}},
		Exposure: respond.ExposureFlags{InternetFacing: true, Privileged: true},
	})
	// finding fields
	require.Contains(t, p, "Public bucket")
	require.Contains(t, p, "arn:s3")
	require.Contains(t, p, "aws-s3-public")
	require.Contains(t, p, "82 (page)")
	// graph context — the whole point
	require.Contains(t, p, "internet_facing=true")
	require.Contains(t, p, "privileged=true")
	require.Contains(t, p, "12 reachable")
	require.Contains(t, p, "ec2_instance:5")
	require.Contains(t, p, "u -> r")
	require.Contains(t, p, "ciem_privesc")
}

func TestBuildPrompt_NothingBurger(t *testing.T) {
	p := buildPrompt(respond.ContextPack{
		Finding:      finding.Finding{Title: "low-risk", ResourceID: "arn:x"},
		Blast:        respond.BlastSummary{Count: 0, Known: true},
		Exposure:     respond.ExposureFlags{PeersKnown: true},
		Impact:       respond.ImpactAssessment{DependentsKnown: true},
		FactorsKnown: true,
	})
	require.Contains(t, p, "internet_facing=false")
	require.Contains(t, p, "Blast radius: 0 reachable asset(s)")
	require.Contains(t, p, "No other findings on this resource")
	require.NotContains(t, p, "unknown")
	require.NotContains(t, p, "Provenance:", "no provenance known => no provenance line")
}

// A failed lookup must never render as a measured empty: the system prompt
// treats "empty blast radius, not internet-facing, no peers" as observe, so a
// zero rendered from a failed read would steer the model to observe on
// evidence nobody gathered.
func TestBuildPrompt_UnknownSignalsRenderAsUnknown(t *testing.T) {
	p := buildPrompt(respond.ContextPack{
		Finding: finding.Finding{Title: "x", ResourceID: "arn:x"},
		// Blast.Known, Exposure.PeersKnown, FactorsKnown, Impact.DependentsKnown all false.
	})
	require.Contains(t, p, "Blast radius: unknown (lookup failed")
	require.NotContains(t, p, "0 reachable asset(s)")
	require.Contains(t, p, "Exposure: unknown (peer-findings lookup failed")
	require.NotContains(t, p, "internet_facing=false")
	require.Contains(t, p, "Other findings on this resource: unknown (lookup failed)")
	require.NotContains(t, p, "No other findings on this resource")
	require.Contains(t, p, "Score breakdown: unknown (lookup failed")
	require.Contains(t, p, "dependents=unknown")
	require.NotContains(t, p, "dependents=0")

	require.Contains(t, systemPrompt, "UNKNOWN IS NOT CLEAN")
	require.Contains(t, systemPrompt, "MEASURED empty blast radius")
}

// The CVE context bullet sits in the context list, and the unknown rule is its
// own paragraph after the list rather than a list item.
func TestSystemPrompt_ContextListAndUnknownRule(t *testing.T) {
	require.Contains(t, systemPrompt,
		"\n- For CVE findings: EPSS exploitation probability, KEV status, fix version, and OSV advisory\n- For workload assets:")
	require.Contains(t, systemPrompt, "\n\nUNKNOWN IS NOT CLEAN: ")
	require.NotContains(t, systemPrompt, "- UNKNOWN IS NOT CLEAN")
	list := systemPrompt[:strings.Index(systemPrompt, "Reason over the WHOLE context")]
	require.NotContains(t, list, "UNKNOWN IS NOT CLEAN", "the rule must follow the context list")
}

// A positive exposure flag is still shown when the peer read is marked
// unknown — only an unmeasured false is withheld.
func TestBuildPrompt_ExposureTrueShownEvenIfPeersUnknown(t *testing.T) {
	p := buildPrompt(respond.ContextPack{
		Finding:  finding.Finding{Title: "x"},
		Exposure: respond.ExposureFlags{InternetFacing: true},
	})
	require.Contains(t, p, "internet_facing=true")
}

func TestBuildPrompt_IncludesProvenance(t *testing.T) {
	p := buildPrompt(respond.ContextPack{
		Finding: finding.Finding{Title: "open sg", ResourceID: "i-1"},
		Provenance: respond.Provenance{
			Connector: "aws", AccountID: "1234", Region: "eu-west-1",
			Owner: "payments-team", Environment: "prod", AgeBucket: "established",
		},
	})
	require.Contains(t, p, "Provenance: shipped_by=aws (acct 1234, eu-west-1)")
	// env/owner are free-form cloud tags, fenced (fence()'s markers land right
	// after the "env=" / "owner=" prefix, which is why these aren't a plain
	// Contains(t, p, "env=prod") anymore — see TestProvenanceLine below).
	require.Contains(t, p, "env=<<<UNTRUSTED>>>prod<<<END UNTRUSTED>>>")
	require.Contains(t, p, "owner=<<<UNTRUSTED>>>payments-team<<<END UNTRUSTED>>>")
	require.Contains(t, p, "age=established")
}

func TestProvenanceLine(t *testing.T) {
	require.Empty(t, provenanceLine(respond.Provenance{}), "nothing known => empty")
	// Some provenance but no owner => orphaned signal.
	got := provenanceLine(respond.Provenance{Connector: "gcp", AgeBucket: "stale"})
	require.Contains(t, got, "shipped_by=gcp")
	require.Contains(t, got, "owner=unknown")
	require.Contains(t, got, "age=stale")

	// Supply-chain source with its confidence.
	src := provenanceLine(respond.Provenance{
		Connector: "kubernetes", SourceRepo: "example/payments-api", SourceConfidence: "high",
	})
	require.Contains(t, src, "deployed_from=<<<UNTRUSTED>>>example/payments-api<<<END UNTRUSTED>>> (high confidence)")
}

func TestParsePlan(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		want    respond.ActionClass
		wantErr bool
	}{
		{"plain json", `{"action_class":"remediate","summary":"patch it","rationale":"why"}`, respond.ClassRemediate, false},
		{"fenced json", "```json\n{\"action_class\":\"observe\",\"summary\":\"fine\",\"rationale\":\"why\"}\n```", respond.ClassObserve, false},
		{"prose around json", `Here is the plan: {"action_class":"isolate","summary":"cut it off","rationale":"why"} done`, respond.ClassIsolate, false},
		// A trailing sentence after the JSON object that itself contains a brace
		// pair must not corrupt the parse: json.Decoder reads exactly one JSON
		// value and ignores everything after it, so trailing prose (braces and
		// all) is inert.
		{"trailing prose containing its own braces", `{"action_class":"isolate","summary":"cut it off","rationale":"why"} Why this matters: {the identity} is compromised.`, respond.ClassIsolate, false},
		{"unknown class", `{"action_class":"nuke","summary":"x","rationale":"why"}`, "", true},
		{"empty summary", `{"action_class":"observe","summary":"","rationale":"why"}`, "", true},
		{"empty rationale", `{"action_class":"observe","summary":"fine","rationale":""}`, "", true},
		{"not json", `I cannot help with that`, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := parsePlan(tt.text)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, p.ActionClass)
		})
	}
}

func TestReason_HappyPath(t *testing.T) {
	doer := &fakeDoer{reply: `{"action_class":"modify","summary":"tighten SG","rationale":"too open"}`}
	r := &Reasoner{doer: doer}
	p, err := r.Reason(context.Background(), respond.ContextPack{Finding: finding.Finding{Title: "open sg"}})
	require.NoError(t, err)
	require.Equal(t, respond.ClassModify, p.ActionClass)
	require.Equal(t, "too open", p.Rationale)
	require.Contains(t, doer.gotUser, "open sg", "the built prompt reaches the model")
}

func TestReason_DoerError(t *testing.T) {
	r := &Reasoner{doer: &fakeDoer{err: errors.New("rate limited")}}
	_, err := r.Reason(context.Background(), respond.ContextPack{})
	require.ErrorContains(t, err, "rate limited")
}

// Reason must request doJSON with planOutputSchema, not the schema-less do —
// the whole point of adding doJSON was that Reason/Sample get a server-side
// output-format guarantee that GraphTranslator/CypherTranslator (still on
// do) do not need.
func TestReason_UsesPlanOutputSchema(t *testing.T) {
	doer := &fakeDoer{reply: `{"action_class":"observe","summary":"fine","rationale":"no meaningful exposure"}`}
	r := &Reasoner{doer: doer}
	_, err := r.Reason(context.Background(), respond.ContextPack{})
	require.NoError(t, err)
	require.Equal(t, planOutputSchema, doer.gotSchema)
}

// Mirrors TestSample_RetriesOnceAfterUngroundedEvidenceThenSucceeds
// (adjudicate_test.go) for Reason's symmetric errEmptyPlanField retry.
func TestReason_RetriesOnceAfterEmptyPlanFieldThenSucceeds(t *testing.T) {
	doer := &fakeDoer{replies: []string{
		`{"action_class":"observe","summary":"","rationale":"why"}`,
		`{"action_class":"observe","summary":"fine","rationale":"why"}`,
	}}
	r := &Reasoner{doer: doer}

	p, err := r.Reason(context.Background(), respond.ContextPack{})
	require.NoError(t, err)
	require.Equal(t, respond.ClassObserve, p.ActionClass)
	require.Equal(t, "fine", p.Summary)
	require.Equal(t, 2, doer.calls, "one empty-field reply must cost exactly one retry, not more")
}

// Mirrors TestSample_TwoConsecutiveUngroundedRepliesFailsOnce
// (adjudicate_test.go): the retry itself must not retry again.
func TestReason_TwoConsecutiveEmptyPlanFieldRepliesFailsOnce(t *testing.T) {
	doer := &fakeDoer{replies: []string{
		`{"action_class":"observe","summary":"","rationale":"why"}`,
		`{"action_class":"observe","summary":"","rationale":"why"}`,
	}}
	r := &Reasoner{doer: doer}

	_, err := r.Reason(context.Background(), respond.ContextPack{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "empty summary")
	require.Equal(t, 2, doer.calls, "the retry itself must not retry again — one failure, counted once")
}

// Sample must request doJSON with verdictOutputSchema — same reasoning as
// TestReason_UsesPlanOutputSchema, for the adjudicator's own schema.
func TestSample_UsesVerdictOutputSchema(t *testing.T) {
	doer := &fakeDoer{reply: `{"severity":"low","evidence":[{"clause":"c","source":"s","fact":"f"}]}`}
	r := &Reasoner{doer: doer}
	_, err := r.Sample(context.Background(), adjIn())
	require.NoError(t, err)
	require.Equal(t, verdictOutputSchema, doer.gotSchema)
}

// fakeLLM records the last request and returns a canned response.
type fakeLLM struct {
	got  llm.Request
	resp *llm.Response
	err  error
}

func (f *fakeLLM) Complete(_ context.Context, req llm.Request) (*llm.Response, error) {
	f.got = req
	if f.resp == nil {
		return &llm.Response{StopReason: llm.StopEnd}, f.err
	}
	return f.resp, f.err
}

func (f *fakeLLM) Stream(ctx context.Context, req llm.Request, _ func(string)) (*llm.Response, error) {
	return f.Complete(ctx, req)
}

func (f *fakeLLM) Provider() llm.Provider { return "fake" }

// Schema-constrained callers (Reason/Sample) must request reasoning with the
// larger budget and a cacheable system prompt.
func TestLLMDoer_SchemaRequestsReasoningAndCachesSystem(t *testing.T) {
	f := &fakeLLM{resp: &llm.Response{StopReason: llm.StopEnd, Text: "{}"}}
	d := &llmDoer{client: f, model: "pinned"}
	_, err := d.doJSON(context.Background(), "sys", "usr", planOutputSchema)
	require.NoError(t, err)
	require.Equal(t, "pinned", f.got.Model)
	require.Equal(t, planOutputSchema, f.got.JSONSchema)
	require.NotNil(t, f.got.Reasoning)
	require.EqualValues(t, reasoningMaxTokens, f.got.Reasoning.MaxTokens)
	require.EqualValues(t, maxTokens, f.got.MaxTokens)
	require.True(t, f.got.System[0].Cache)
}

// The schema-less do() path (GraphTranslator/CypherTranslator) must be
// completely unaffected: no reasoning and no schema. Turning reasoning on for
// every call would be an unannounced latency/cost change to an interactive
// feature.
func TestLLMDoer_NilSchemaRequestsNoReasoning(t *testing.T) {
	f := &fakeLLM{}
	d := &llmDoer{client: f}
	_, err := d.do(context.Background(), "sys", "usr")
	require.NoError(t, err)
	require.Nil(t, f.got.Reasoning)
	require.Nil(t, f.got.JSONSchema)
	require.Empty(t, f.got.Model, "empty model defers to the provider default")
}

func TestLLMDoer_NilClientIsNotConfiguredError(t *testing.T) {
	_, err := (&llmDoer{}).do(context.Background(), "s", "u")
	require.ErrorIs(t, err, errNotConfigured)
}

// A truncated response must surface as a plain, distinguishable error rather
// than falling through to a confusing "invalid JSON" parse failure.
func TestExtractReplyText_MaxTokensTruncationIsDistinguishable(t *testing.T) {
	_, err := extractReplyText(&llm.Response{StopReason: llm.StopMaxTokens, MaxTokens: reasoningMaxTokens})
	require.ErrorContains(t, err, "truncated")
	require.ErrorContains(t, err, "max_tokens")
	require.ErrorContains(t, err, "8192", "names whichever budget this request actually used, not a hardcoded one")
}

func TestExtractReplyText_RefusalIsDistinguishable(t *testing.T) {
	_, err := extractReplyText(&llm.Response{
		StopReason: llm.StopRefusal,
		Refusal:    llm.Refusal{Category: "cyber", Explanation: "policy"},
	})
	require.ErrorContains(t, err, "refused")
	require.ErrorContains(t, err, "cyber")
}

func TestValidClass(t *testing.T) {
	require.True(t, validClass(respond.ClassDestroy))
	require.False(t, validClass(respond.ActionClass("bogus")))
}

func TestBuildPrompt_ScoreFactors(t *testing.T) {
	p := buildPrompt(respond.ContextPack{
		Finding: finding.Finding{Title: "vuln", Score: 78, ScoreBand: "page"},
		Factors: []enrich.Factor{
			{Source: "base_severity", Points: 30, Detail: "high"},
			{Source: "blast_radius", Points: 16},
			{Source: "kev", Points: 30, Floor: 81},
		},
	})
	require.Contains(t, p, "Score breakdown")
	require.Contains(t, p, "base_severity: +30")
	require.Contains(t, p, "kev: +30")
	require.Contains(t, p, "(floor 81)")
	// Detail carries remote-controlled values from takeover-probe sources, so
	// it's fenced — "— high" is no longer contiguous, the fence markers sit
	// between the dash and the value.
	require.Contains(t, p, "— <<<UNTRUSTED>>>high<<<END UNTRUSTED>>>")
}

func TestBuildPrompt_CVEContext(t *testing.T) {
	p := buildPrompt(respond.ContextPack{
		Finding: finding.Finding{
			Title: "log4shell", CheckID: "CVE-2021-44228",
			KnownExploited: true, Remediation: "log4j 2.17.1",
		},
		CVE: &respond.CVEContext{
			CVEID: "CVE-2021-44228", EPSS: 0.714, EPSSBand: "critical",
			KEV: true, FixedVersion: "log4j 2.17.1",
			Advisory: "Remote code execution via JNDI lookup in log messages.",
		},
	})
	require.Contains(t, p, "CVE context (<<<UNTRUSTED>>>CVE-2021-44228<<<END UNTRUSTED>>>)")
	require.Contains(t, p, "71.4%")
	require.Contains(t, p, "critical")
	require.Contains(t, p, "KEV: yes")
	require.Contains(t, p, "Fix available: <<<UNTRUSTED>>>log4j 2.17.1<<<END UNTRUSTED>>>")
	require.Contains(t, p, "Remote code execution")
}

func TestBuildPrompt_CVEContext_NonCVE_Absent(t *testing.T) {
	p := buildPrompt(respond.ContextPack{
		Finding: finding.Finding{Title: "cspm finding", CheckID: "aws-s3-public"},
	})
	require.NotContains(t, p, "CVE context")
	require.NotContains(t, p, "EPSS")
}

func TestBuildPrompt_IdentityChain(t *testing.T) {
	p := buildPrompt(respond.ContextPack{
		Finding: finding.Finding{Title: "workload vuln", ResourceID: "pod/x"},
		Identity: &respond.IdentityLinks{
			ExecutesAsID:     "arn:aws:iam::123:role/prod-app-role",
			AttachedRoleIDs:  []string{"arn:aws:iam::123:role/read-only"},
			FederatedRepoIDs: []string{"github.com/org/deploy-actions"},
		},
	})
	require.Contains(t, p, "Identity chain")
	require.Contains(t, p, "arn:aws:iam::123:role/prod-app-role")
	require.Contains(t, p, "arn:aws:iam::123:role/read-only")
	require.Contains(t, p, "github.com/org/deploy-actions")
	require.Contains(t, p, "OIDC access")
}

func TestBuildPrompt_SupplyChainPath(t *testing.T) {
	p := buildPrompt(respond.ContextPack{
		Finding: finding.Finding{Title: "lodash vuln", Source: "supply_chain"},
		SupplyChain: &respond.SupplyChainPath{
			RepoIDs: []string{"github.com/org/payments-service"},
			Workloads: []respond.WorkloadSummary{
				{ID: "prod/payments-api", Type: "k8s_deployment"},
			},
		},
	})
	require.Contains(t, p, "Supply-chain blast path")
	require.Contains(t, p, "github.com/org/payments-service")
	require.Contains(t, p, "1 workload(s)")
	require.Contains(t, p, "k8s_deployment:1")
}

func TestBuildPrompt_PeersSortedWithScoreAndTitle(t *testing.T) {
	p := buildPrompt(respond.ContextPack{
		Finding: finding.Finding{Title: "s3 open"},
		Peers: []respond.PeerSummary{
			{Type: "ciem_privesc", CheckID: "privesc-1", ScoreBand: "page", Score: 88, Title: "Admin role assumable"},
		},
	})
	// Peer titles are untrusted scan data, so they're fenced, not quoted.
	require.Contains(t, p, "<<<UNTRUSTED>>>Admin role assumable<<<END UNTRUSTED>>>")
	require.Contains(t, p, "score=88/page")
}

// canaryIsFenced reports whether EVERY occurrence of canary in output sits
// inside a <<<UNTRUSTED>>> ... <<<END UNTRUSTED>>> pair: the nearest open
// marker before it and a close marker after it, with no close marker in
// between (which would mean that occurrence is past a fence that already
// closed). A field written twice, once fenced and once plain, fails.
func canaryIsFenced(output, canary string) bool {
	found := false
	for start := 0; ; {
		rel := strings.Index(output[start:], canary)
		if rel < 0 {
			return found
		}
		idx := start + rel
		openIdx := strings.LastIndex(output[:idx], fenceOpen)
		closeIdx := strings.Index(output[idx:], fenceClose)
		if openIdx < 0 || closeIdx < 0 || strings.Contains(output[openIdx:idx], fenceClose) {
			return false
		}
		found = true
		start = idx + len(canary)
	}
}

func TestCanaryIsFenced_EveryOccurrence(t *testing.T) {
	require.True(t, canaryIsFenced(fence("c")+" "+fence("c"), "c"))
	require.False(t, canaryIsFenced(fence("c")+" c", "c"), "a second plain occurrence must fail")
	require.False(t, canaryIsFenced("nothing here", "c"))
}

// TestBuildPrompt_EveryStringFieldIsFenced is the guard buildPrompt's own doc
// comment promises: every attacker-influenceable field group gets a unique
// canary seeded through it, and every canary must land inside a fence pair.
// The canaries are a hand-written list: a new field is covered only once it
// gets its own canary here.
func TestBuildPrompt_EveryStringFieldIsFenced(t *testing.T) {
	pack := respond.ContextPack{
		Finding: finding.Finding{
			Title:        "canary-title",
			Description:  "canary-description",
			ResourceID:   "canary-resource-id",
			ResourceType: "canary-resource-type",
			CheckID:      "canary-check-id",
			Score:        50, ScoreBand: "monitor",
		},
		Provenance: respond.Provenance{
			Owner: "canary-owner", Environment: "canary-env", SourceRepo: "canary-source-repo",
		},
		Blast: respond.BlastSummary{
			Count:     1,
			CanAssume: []string{"canary-can-assume"},
			TopReachable: []respond.AssetRef{
				{ID: "x", Name: "canary-asset-name", Type: "ec2_instance", Score: 10},
			},
		},
		// The fix-location hint repeats the source repo (fixLocationOf), so the
		// source-repo canary appears twice and both must be fenced.
		Impact: respond.ImpactAssessment{
			FixLocation: respond.FixLocation{
				Kind: respond.FixSourceRepo, Repo: "canary-source-repo",
				Hint: "Change the configuration in canary-source-repo and redeploy",
			},
		},
		Factors: []enrich.Factor{
			{Source: "dns_takeover", Points: 10, Detail: "canary-factor-detail"},
		},
		CVE: &respond.CVEContext{
			CVEID: "canary-cve-id", FixedVersion: "canary-fixed-version", Advisory: "canary-advisory",
		},
		Identity: &respond.IdentityLinks{
			ExecutesAsID:     "canary-executes-as",
			AttachedRoleIDs:  []string{"canary-attached-role"},
			FederatedRepoIDs: []string{"canary-federated-repo"},
		},
		SupplyChain: &respond.SupplyChainPath{
			RepoIDs: []string{"canary-supplychain-repo"},
		},
		Peers: []respond.PeerSummary{
			{Type: "cspm", CheckID: "canary-peer-check-id", Title: "canary-peer-title"},
		},
	}
	p := buildPrompt(pack)

	canaries := []string{
		"canary-title", "canary-description", "canary-resource-id",
		"canary-owner", "canary-env", "canary-can-assume", "canary-asset-name",
		"canary-factor-detail", "canary-advisory", "canary-executes-as",
		"canary-attached-role", "canary-federated-repo",
		"canary-supplychain-repo", "canary-peer-title",
		"canary-resource-type", "canary-check-id", "canary-source-repo",
		"canary-cve-id", "canary-fixed-version", "canary-peer-check-id",
	}
	for _, c := range canaries {
		require.Contains(t, p, c, "canary must appear in the prompt at all")
		require.True(t, canaryIsFenced(p, c), "canary %q must sit inside a fence pair", c)
	}
}
