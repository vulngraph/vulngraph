package jobs

import (
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

const (
	feedAlertRulesPath = "../../deploy/helm-chart/graph/alerts/rules.yaml"
	feedVMRulePath     = "../../deploy/helm-chart/graph/templates/vmrule.yaml"
)

// absentFeedRef matches the feed an absent() on the feed-refresh gauge waits for.
var absentFeedRef = regexp.MustCompile(`absent\(graph_feed_last_success_timestamp_seconds\{[^}]*feed="([a-z_]+)"`)

// chartGatedFeedGroups are the rules.yaml groups templates/vmrule.yaml renders
// only when the chart value that turns their feed on is set, keyed by group,
// with the exact condition the template must gate the group on.
var chartGatedFeedGroups = map[string]string{
	"graph-intel-scc": `{{- if or (ne .name "graph-intel-scc") $.Values.config.sccOrgId }}`,
}

// An absent() rule on the feed-refresh gauge fires when the feed has never
// refreshed, so on a feed that is off by default it fires forever on every
// install that has not turned it on. Such a rule must sit in a group the chart
// renders only once the feed is configured.
func TestNoAbsentFeedAlertTargetsAFeedOffByDefault(t *testing.T) {
	defaults, err := PeriodicConfigFromEnv(func(string) string { return "" })
	require.NoError(t, err)
	onByDefault := map[string]bool{}
	for kind, on := range map[string]bool{
		"refresh_kev":         defaults.KEV,
		"refresh_osv":         defaults.OSV,
		"refresh_osv_malfeed": defaults.MalFeed,
		"refresh_epss":        defaults.EPSS,
		"refresh_scc":         defaults.SCC,
		"domain_monitor":      defaults.DomainMonitor,
	} {
		feed := feedForJobKind(kind)
		require.NotEmptyf(t, feed, "%s is not a feed-refresh job kind", kind)
		onByDefault[feed] = on
	}

	raw, err := os.ReadFile(feedAlertRulesPath)
	require.NoError(t, err)
	var rules struct {
		Groups []struct {
			Name  string `yaml:"name"`
			Rules []struct {
				Alert string `yaml:"alert"`
				Expr  string `yaml:"expr"`
			} `yaml:"rules"`
		} `yaml:"groups"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &rules))

	tpl, err := os.ReadFile(feedVMRulePath)
	require.NoError(t, err)
	gatedSeen := map[string]bool{}
	checked := 0
	for _, g := range rules.Groups {
		gate, gated := chartGatedFeedGroups[g.Name]
		if gated {
			gatedSeen[g.Name] = true
			require.Containsf(t, string(tpl), gate,
				"templates/vmrule.yaml must render group %s only when its feed is configured", g.Name)
		}
		for _, r := range g.Rules {
			for _, m := range absentFeedRef.FindAllStringSubmatch(r.Expr, -1) {
				on, known := onByDefault[m[1]]
				require.Truef(t, known, "%s waits for feed %q, which no feed-refresh job stamps", r.Alert, m[1])
				checked++
				if !on {
					require.Truef(t, gated,
						"%s waits for feed %q, which is off by default, so it fires forever on an install "+
							"without that feed; move it to a group listed in chartGatedFeedGroups", r.Alert, m[1])
				}
			}
		}
	}
	require.NotZero(t, checked, "no absent() feed rule found; did rules.yaml change shape?")
	for name := range chartGatedFeedGroups {
		require.Truef(t, gatedSeen[name], "chartGatedFeedGroups names group %s, which rules.yaml does not have", name)
	}
}
