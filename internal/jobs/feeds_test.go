package jobs

import (
	"testing"

	"github.com/riverqueue/river"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/distro"
)

func TestFeedsFromEnv(t *testing.T) {
	all := Feeds{KEV: true, EPSS: true, MalFeed: true, OSV: true, ALAS: true, ELSA: true, DomainMonitor: true}
	without := func(edit func(*Feeds)) Feeds {
		f := all
		edit(&f)
		return f
	}
	cases := []struct {
		name string
		env  map[string]string
		want Feeds
	}{
		{"unset: every feed on (defaults unchanged)", map[string]string{}, all},
		{"KEV off", map[string]string{KEVDisabledEnv: "true"}, without(func(f *Feeds) { f.KEV = false })},
		{"EPSS off", map[string]string{EPSSDisabledEnv: "true"}, without(func(f *Feeds) { f.EPSS = false })},
		{"malfeed off", map[string]string{MalFeedDisabledEnv: "true"}, without(func(f *Feeds) { f.MalFeed = false })},
		{"OSV off", map[string]string{OSVDisabledEnv: "true"}, without(func(f *Feeds) { f.OSV = false })},
		{"ALAS off", map[string]string{ALASDisabledEnv: "true"}, without(func(f *Feeds) { f.ALAS = false })},
		{"ELSA off", map[string]string{ELSADisabledEnv: "true"}, without(func(f *Feeds) { f.ELSA = false })},
		{"domain monitor off", map[string]string{DomainMonitorDisabledEnv: "true"}, without(func(f *Feeds) { f.DomainMonitor = false })},
		{"1 and yes switch a feed off", map[string]string{KEVDisabledEnv: "1", OSVDisabledEnv: "yes"}, without(func(f *Feeds) { f.KEV, f.OSV = false, false })},
		{"off and 0 leave a feed on", map[string]string{KEVDisabledEnv: "off", OSVDisabledEnv: "0"}, all},
		{"OFFLINE_MODE turns everything off", map[string]string{"OFFLINE_MODE": "true"}, Feeds{}},
		{"OFFLINE_MODE beats a per-feed false", map[string]string{"OFFLINE_MODE": "true", EPSSDisabledEnv: "false"}, Feeds{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := FeedsFromEnv(func(k string) string { return tc.env[k] })
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

// An unrecognised value is a startup error, and the feeds it returns are all
// off: OFFLINE_MODE must never fail open.
func TestFeedsFromEnvRejectsUnrecognisedValues(t *testing.T) {
	for _, env := range []map[string]string{
		{"OFFLINE_MODE": "enabled"},
		{"OFFLINE_MODE": "y"},
		{KEVDisabledEnv: "ture"},
		{DomainMonitorDisabledEnv: "disabled"},
	} {
		got, err := FeedsFromEnv(func(k string) string { return env[k] })
		require.Errorf(t, err, "env %v", env)
		assert.Equalf(t, Feeds{}, got, "env %v", env)
	}
}

func TestFeedsDisabledNamesTheSwitches(t *testing.T) {
	assert.Empty(t, Feeds{KEV: true, EPSS: true, MalFeed: true, OSV: true, ALAS: true, ELSA: true, DomainMonitor: true}.Disabled())
	assert.Equal(t,
		[]string{KEVDisabledEnv, EPSSDisabledEnv, MalFeedDisabledEnv, OSVDisabledEnv, ALASDisabledEnv, ELSADisabledEnv, DomainMonitorDisabledEnv},
		Feeds{}.Disabled())
}

func TestFeedsDistroAdvisorySources(t *testing.T) {
	assert.Empty(t, Feeds{}.DistroAdvisorySources())
	for _, s := range (Feeds{ALAS: true}).DistroAdvisorySources() {
		assert.Contains(t, s.Ecosystem, "Amazon Linux")
	}
	for _, s := range (Feeds{ELSA: true}).DistroAdvisorySources() {
		assert.Contains(t, s.Ecosystem, "Oracle Linux")
	}
}

// Every distro family's advisory source is named, so a switched-off feed reaches
// the VM collectors' package_cve_gap; OFFLINE_MODE turns all of them off.
func TestFeedsAdvisorySources(t *testing.T) {
	onFeeds, err := FeedsFromEnv(func(string) string { return "" })
	require.NoError(t, err)
	on := onFeeds.AdvisorySources()
	for _, f := range distro.Families() {
		if f.Source != "" {
			assert.True(t, on[f.Source], "%s's source %q must be reported on when its feed is", f.Name, f.Source)
		}
	}
	offFeeds, err := FeedsFromEnv(func(k string) string { return map[string]string{"OFFLINE_MODE": "true"}[k] })
	require.NoError(t, err)
	off := offFeeds.AdvisorySources()
	for src, enabled := range off {
		assert.False(t, enabled, src)
	}
	assert.Equal(t, distro.Sources{distro.SourceOSV: true, distro.SourceALAS: false, distro.SourceELSA: true},
		Feeds{OSV: true, ELSA: true}.AdvisorySources())
}

// A switched-off feed's worker stays registered (the OSV and image-vuln workers
// enqueue KEV refreshes of their own) and must complete without touching
// anything — not error, which would burn retries on a kind nothing can work.
func TestDisabledFeedWorkersNoOp(t *testing.T) {
	ctx := t.Context()
	require.NoError(t, (&KEVWorker{}).Work(ctx, &river.Job[RefreshKEVArgs]{}))
	require.NoError(t, (&OSVWorker{}).Work(ctx, &river.Job[RefreshOSVArgs]{}))
	require.NoError(t, (&MalFeedWorker{}).Work(ctx, &river.Job[RefreshMalFeedArgs]{}))
	require.NoError(t, (&DistroAdvisoryWorker{}).Work(ctx, &river.Job[RefreshDistroAdvisoriesArgs]{}))
}
