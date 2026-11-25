package alertctx

import "time"

// Response is the wire shape shared by the REST handler and the MCP tool. It
// is a separate type from the domain Result so no internal field leaks and the
// JSON is snake_case.
type Response struct {
	Summary       string               `json:"summary"`
	Truncated     bool                 `json:"truncated"`
	Identifiers   []IdentifierResponse `json:"identifiers"`
	Assets        []AssetResponse      `json:"assets"`
	OmittedAssets []string             `json:"omitted_assets"`
}

type IdentifierResponse struct {
	Input       string          `json:"input"`
	Normalized  string          `json:"normalized"`
	Status      string          `json:"status"`
	Reason      string          `json:"reason,omitempty"`
	MoreMatches bool            `json:"more_matches"`
	Matches     []MatchResponse `json:"matches"`
}

type MatchResponse struct {
	AssetID    string `json:"asset_id"`
	MatchType  string `json:"match_type"`
	Confidence string `json:"confidence"`
}

type AssetResponse struct {
	Asset      AssetSummaryResponse  `json:"asset"`
	MatchedBy  []IdentifierMatchResp `json:"matched_by"`
	Exposure   ExposureResponse      `json:"exposure"`
	Blast      BlastResponse         `json:"blast_radius"`
	Findings   FindingsResponse      `json:"findings"`
	Privileges *PrivilegesResponse   `json:"privileges,omitempty"`
	Summary    string                `json:"summary"`
}

type IdentifierMatchResp struct {
	Input      string `json:"input"`
	MatchType  string `json:"match_type"`
	Confidence string `json:"confidence"`
}

type AssetSummaryResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Provider    string `json:"provider"`
	AccountID   string `json:"account_id"`
	Region      string `json:"region"`
	Environment string `json:"environment"`
	Owner       string `json:"owner"`
	PublicIP    string `json:"public_ip"`
	PrivateIP   string `json:"private_ip"`
	Domain      string `json:"domain"`
	RiskScore   int    `json:"risk_score"`
	// RiskScoreSource is "ladybug" (graph-propagated) or "stored" (the asset
	// row's pre-propagation score).
	RiskScoreSource string    `json:"risk_score_source"`
	LastSeen        time.Time `json:"last_seen"`
}

// Every section carries known + unavailable_reason. known=false means the
// section was not measured and its other fields must not be read as a result.
type ExposureResponse struct {
	Known             bool   `json:"known"`
	UnavailableReason string `json:"unavailable_reason,omitempty"`
	ExposedToInternet bool   `json:"exposed_to_internet"`
}

type ReachableAssetResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	RiskScore int    `json:"risk_score"`
}

type BlastResponse struct {
	Known             bool                     `json:"known"`
	UnavailableReason string                   `json:"unavailable_reason,omitempty"`
	Count             int                      `json:"count"`
	ByType            map[string]int           `json:"by_type"`
	TopReachable      []ReachableAssetResponse `json:"top_reachable"`
	Truncated         bool                     `json:"truncated"`
}

type FindingRefResponse struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	Severity      string `json:"severity"`
	Score         int    `json:"score"`
	CheckID       string `json:"check_id"`
	MustFixClass  string `json:"must_fix_class"`
	MustFixReason string `json:"must_fix_reason,omitempty"`
}

type FindingsResponse struct {
	Known             bool                 `json:"known"`
	UnavailableReason string               `json:"unavailable_reason,omitempty"`
	Total             int                  `json:"total"`
	BySeverity        map[string]int       `json:"by_severity"`
	MustFix           []FindingRefResponse `json:"must_fix"`
	Top               []FindingRefResponse `json:"top"`
	Truncated         bool                 `json:"truncated"`
}

type PrivilegesResponse struct {
	Known             bool     `json:"known"`
	UnavailableReason string   `json:"unavailable_reason,omitempty"`
	CanEscalate       bool     `json:"can_escalate"`
	Techniques        []string `json:"techniques"`
}

// ToResponse shapes a Result for the wire. Slices and maps are never nil so
// the JSON has [] and {} rather than null.
func ToResponse(r Result) Response {
	out := Response{
		Summary: r.Summary, Truncated: r.Truncated,
		Identifiers:   make([]IdentifierResponse, 0, len(r.Identifiers)),
		Assets:        make([]AssetResponse, 0, len(r.Assets)),
		OmittedAssets: append([]string{}, r.OmittedAssets...),
	}
	for _, id := range r.Identifiers {
		ir := IdentifierResponse{
			Input: id.Input, Normalized: id.Normalized, Status: id.Status, Reason: id.Reason,
			MoreMatches: id.MoreMatches, Matches: make([]MatchResponse, 0, len(id.Matches)),
		}
		for _, m := range id.Matches {
			ir.Matches = append(ir.Matches, MatchResponse{AssetID: m.AssetID, MatchType: string(m.MatchType), Confidence: string(m.Confidence)})
		}
		out.Identifiers = append(out.Identifiers, ir)
	}
	for _, a := range r.Assets {
		out.Assets = append(out.Assets, assetResponse(a))
	}
	return out
}

func assetResponse(a AssetContext) AssetResponse {
	s := a.Asset
	r := AssetResponse{
		Asset: AssetSummaryResponse{
			ID: s.ID, Name: s.Name, Type: s.Type, Provider: s.Provider, AccountID: s.AccountID,
			Region: s.Region, Environment: s.Environment, Owner: s.Owner, PublicIP: s.PublicIP,
			PrivateIP: s.PrivateIP, Domain: s.Domain, RiskScore: int(s.RiskScore),
			RiskScoreSource: string(s.RiskScoreSource), LastSeen: s.LastSeen,
		},
		MatchedBy: make([]IdentifierMatchResp, 0, len(a.MatchedBy)),
		Exposure: ExposureResponse{
			Known: a.Exposure.Known, UnavailableReason: a.Exposure.Reason, ExposedToInternet: a.Exposure.ExposedToInternet,
		},
		Summary: a.Summary,
	}
	for _, m := range a.MatchedBy {
		r.MatchedBy = append(r.MatchedBy, IdentifierMatchResp{Input: m.Input, MatchType: string(m.MatchType), Confidence: string(m.Confidence)})
	}

	b := a.Blast
	r.Blast = BlastResponse{
		Known: b.Known, UnavailableReason: b.Reason, Count: b.Count, Truncated: b.Truncated,
		ByType: nonNilMap(b.ByType), TopReachable: make([]ReachableAssetResponse, 0, len(b.TopReachable)),
	}
	for _, t := range b.TopReachable {
		r.Blast.TopReachable = append(r.Blast.TopReachable, ReachableAssetResponse{ID: t.ID, Name: t.Name, Type: t.Type, RiskScore: int(t.RiskScore)})
	}

	f := a.Findings
	r.Findings = FindingsResponse{
		Known: f.Known, UnavailableReason: f.Reason, Total: f.Total, Truncated: f.Truncated,
		BySeverity: nonNilMap(f.BySeverity), MustFix: findingRefs(f.MustFix), Top: findingRefs(f.Top),
	}
	if p := a.Privileges; p != nil {
		r.Privileges = &PrivilegesResponse{
			Known: p.Known, UnavailableReason: p.Reason, CanEscalate: p.CanEscalate,
			Techniques: append([]string{}, p.Techniques...),
		}
	}
	return r
}

func findingRefs(in []FindingRef) []FindingRefResponse {
	out := make([]FindingRefResponse, 0, len(in))
	for _, f := range in {
		out = append(out, FindingRefResponse{
			ID: f.ID, Title: f.Title, Severity: f.Severity, Score: int(f.Score), CheckID: f.CheckID,
			MustFixClass: f.MustFixClass, MustFixReason: f.MustFixReason,
		})
	}
	return out
}

func nonNilMap(m map[string]int) map[string]int {
	if m == nil {
		return map[string]int{}
	}
	return m
}
