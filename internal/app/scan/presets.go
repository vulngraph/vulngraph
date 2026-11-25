package scan

import (
	"fmt"

	"github.com/vulngraph/vulngraph/internal/app/enrich"
)

// TargetPreset is a named Cypher query that the workflow builder offers as
// a one-click starting point for the WHO section. Users can pick a preset and
// further customise the generated query.
type TargetPreset struct {
	ID          string `json:"id"`
	Label       string `json:"label"`
	Description string `json:"description"`
	Query       string `json:"query"`
}

// TriggerPreset is a named combination of schedule + drift_enabled that the
// workflow builder offers as a one-click option for the WHEN section.
type TriggerPreset struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	Description  string `json:"description"`
	Schedule     string `json:"schedule"`      // cron expression; "" = no schedule
	DriftEnabled bool   `json:"drift_enabled"` // true = scan on asset change
}

// exposedMatch is the shared traversal every internet-exposure preset starts
// from: an asset with a direct ExposedToInternet edge to the internet node.
const exposedMatch = `MATCH (a:Asset)-[:ExposedToInternet]->(:Asset {id: 'internet'})`

// targetQuery composes a preset's Cypher: a MATCH, an optional WHERE, and then
// the ordering-and-bound tail that EVERY target query must carry.
//
// The `LIMIT MaxTargets` is not cosmetic and must never be dropped. Target
// resolution runs the query against Ladybug under a node budget, and the budget is
// enforced by graphstore's result-consumption loop (repo_cypher.go): it stops
// pulling rows once it holds budget.MaxNodes of them and reports Truncated.
// That happens AFTER the engine's ORDER BY has sorted — so an unbounded query
// is not scrambled, it is simply flagged truncated, and the worker's resolver
// refuses a truncated result outright (a truncated target LIST is unusable
// input to a scan's scope decision, unlike a truncated dashboard count). The
// consequence of dropping the LIMIT is therefore not "scans an arbitrary
// subset" but "fails every single run".
//
// This shares only the CAP with the non-Cypher path, not the selection. That
// path uses ListExternal(MaxTargets), whose query orders by max(last_seen) DESC
// (asset/repo.go's externalAssetIDs) — most-recently-seen, not highest-risk.
// These presets order by a.score, the post-BFS risk score that lives only in
// Ladybug. Do not describe the two as equivalent; they answer different questions
// and only happen to return the same number of rows.
func targetQuery(match, where string) string {
	q := match
	if where != "" {
		q += "\n" + where
	}
	return fmt.Sprintf("%s\nRETURN a\nORDER BY a.score DESC\nLIMIT %d", q, MaxTargets)
}

// TargetPresets is the catalog of pre-built Cypher target queries for the
// workflow builder. Each preset pre-fills the WHO Cypher editor; the user
// can further customise the query after selecting one.
//
// Every entry with a non-empty Query is bounded by targetQuery — see its doc
// comment for why an unbounded target query fails rather than scans more.
// TestEveryTargetPresetIsBounded enforces it.
var TargetPresets = []TargetPreset{
	{
		ID:    "all_exposed",
		Label: "Top internet-exposed assets by risk",
		Description: fmt.Sprintf("The %d highest-risk assets reachable from the internet. "+
			"A single scan run is capped at %d targets, so this is the whole of what one run can cover.",
			MaxTargets, MaxTargets),
		Query: targetQuery(exposedMatch, ""),
	},
	{
		ID:    "high_risk",
		Label: fmt.Sprintf("High-risk exposed (score \u2265 %d)", enrich.ThresholdHigh),
		Description: fmt.Sprintf("Internet-exposed assets with a risk score of %d or above — "+
			"the highest-priority scan targets.", enrich.ThresholdHigh),
		Query: targetQuery(exposedMatch, fmt.Sprintf("WHERE a.score >= %d", enrich.ThresholdHigh)),
	},
	{
		ID:          "kev_exposed",
		Label:       "Exposed assets with KEV packages",
		Description: "Internet-exposed assets that run packages with CISA Known-Exploited Vulnerabilities.",
		Query:       targetQuery(exposedMatch, "WHERE a.has_kev = 1"),
	},
	{
		ID:          "aws_exposed",
		Label:       "AWS exposed assets",
		Description: "Internet-exposed assets in AWS accounts, highest risk first.",
		Query:       targetQuery(exposedMatch, "WHERE a.provider = 'aws'"),
	},
	{
		ID:          "gcp_exposed",
		Label:       "GCP exposed assets",
		Description: "Internet-exposed assets in GCP projects, highest risk first.",
		Query:       targetQuery(exposedMatch, "WHERE a.provider = 'gcp'"),
	},
	{
		ID:          "k8s_services",
		Label:       "K8s internet-exposed services",
		Description: "Kubernetes LoadBalancer / NodePort services directly reachable from the internet.",
		Query:       targetQuery(exposedMatch, "WHERE a.type = 'k8s_service'"),
	},
	{
		ID:    "privesc_exposed",
		Label: "Exposed assets executing as high-risk roles",
		Description: "Internet-exposed workloads whose IAM role has a risk score of 70 or more. " +
			"Risk score ranks findings and reachability, not the permissions a role holds.",
		Query: targetQuery(`MATCH (a:Asset)-[:ExecutesAs|HasRole]->(r:IamRole)`, "WHERE a.exposed = 1 AND r.score >= 70"),
	},
	{
		ID:          "custom",
		Label:       "Custom Cypher query",
		Description: "Write your own Cypher query to select exactly the assets you want to scan.",
		Query:       "",
	},
}

// TriggerPresets is the catalog of named WHEN options for the workflow builder.
var TriggerPresets = []TriggerPreset{
	{
		ID:           "manual",
		Label:        "Manual only",
		Description:  "Run this workflow only when you trigger it explicitly.",
		Schedule:     "",
		DriftEnabled: false,
	},
	{
		ID:           "weekly",
		Label:        "Every week",
		Description:  "Runs automatically every Monday at 02:00 UTC.",
		Schedule:     "0 2 * * 1",
		DriftEnabled: false,
	},
	{
		ID:           "daily",
		Label:        "Every day",
		Description:  "Runs automatically every day at 02:00 UTC.",
		Schedule:     "0 2 * * *",
		DriftEnabled: false,
	},
	{
		ID:           "monthly",
		Label:        "Every month",
		Description:  "Runs automatically on the 1st of each month at 02:00 UTC.",
		Schedule:     "0 2 1 * *",
		DriftEnabled: false,
	},
	{
		ID:           "drift",
		Label:        "On asset change",
		Description:  "Triggered automatically when a connector sync reports that an external asset changed. Only profiles with no target query are drift-triggered.",
		Schedule:     "",
		DriftEnabled: true,
	},
	{
		ID:           "drift_weekly",
		Label:        "On change + weekly",
		Description:  "Triggered on asset change AND runs a full sweep every week — best of both worlds.",
		Schedule:     "0 2 * * 1",
		DriftEnabled: true,
	},
	{
		ID:           "custom",
		Label:        "Custom schedule",
		Description:  "Enter a cron expression and optionally enable drift scanning.",
		Schedule:     "",
		DriftEnabled: false,
	},
}
