package aws

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/vulngraph/vulngraph/internal/app/asset"
)

func TestStampRDSEngineVersionFacts(t *testing.T) {
	f := newFakeRDSPosture()
	f.engines = map[string][]string{
		"mysql":    {"8.0.35", "8.0.36"},
		"postgres": {"16.2"},
	}
	f.engineErr = map[string]bool{"mariadb": true}
	inst := func(engine, version string) asset.Asset {
		md := map[string]string{"engine": engine}
		if version != "" {
			md["engine_version"] = version
		}
		return asset.Asset{Type: "rds_instance", Metadata: md}
	}
	instances := []asset.Asset{
		inst("mysql", "8.0.36"),    // second page of the catalogue
		inst("mysql", "5.7.44"),    // retired
		inst("postgres", "16.2"),   // current
		inst("mariadb", "10.6.14"), // catalogue unreadable
		inst("oracle-ee", "19.0"),  // catalogue empty
		inst("mysql", ""),          // version unread
	}
	stampRDSEngineVersionFacts(context.Background(), f, "eu-west-1", instances)

	got := func(i int) (string, bool) {
		v, ok := instances[i].Metadata["engine_version_available"]
		return v, ok
	}
	v, _ := got(0)
	require.Equal(t, "true", v)
	v, _ = got(1)
	require.Equal(t, "false", v)
	v, _ = got(2)
	require.Equal(t, "true", v)
	for _, i := range []int{3, 4, 5} {
		_, ok := got(i)
		require.False(t, ok, "instance %d: an unreadable catalogue or version is unknown, not retired", i)
	}
}
