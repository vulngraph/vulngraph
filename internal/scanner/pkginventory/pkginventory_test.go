package pkginventory

import (
	"context"
	"testing"
	"testing/fstest"
)

func TestInventoryPackages_ParsesManifests(t *testing.T) {
	root := fstest.MapFS{
		"var/lib/dpkg/status": &fstest.MapFile{Data: []byte(
			"Package: openssl\nVersion: 1.1.1f-1ubuntu2\nStatus: install ok installed\n\n" +
				"Package: curl\nVersion: 7.68.0-1ubuntu2\n\n")},
		"etc/os-release": &fstest.MapFile{Data: []byte(
			"NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"20.04\"\n")},
		"requirements.txt": &fstest.MapFile{Data: []byte("requests==2.25.1\n# comment\nflask==1.1.2\n")},
	}
	pkgs := InventoryPackages(context.Background(), root).Packages

	byName := map[string]InstalledPackage{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	// Ubuntu is its own OSV ecosystem: labelling it "Debian" sorts 1.1.1f-1ubuntu2
	// below nearly every Debian fixed-version, so it reports as unpatched forever.
	// The release carries the :LTS qualifier — the bare "Ubuntu:20.04" form
	// unions in other releases' advisories (see ubuntuEcosystem).
	if p, ok := byName["openssl"]; !ok || p.Version != "1.1.1f-1ubuntu2" || p.Ecosystem != "Ubuntu:20.04:LTS" {
		t.Errorf("openssl not parsed correctly: %+v", p)
	}
	if p, ok := byName["requests"]; !ok || p.Version != "2.25.1" || p.Ecosystem != "PyPI" {
		t.Errorf("requests not parsed correctly: %+v", p)
	}
}
