package pkginventory

import (
	"context"
	"testing"
	"testing/fstest"
	"time"
)

// The whole product for "where is package X used" is the runs_package edge:
// package ← runs_package ← ec2_instance. Findings alone leave the fleet dark.
func TestInventoryGraph_EmitsPackageAssetsAndRunsPackageEdges(t *testing.T) {
	root := fstest.MapFS{
		"etc/os-release":      &fstest.MapFile{Data: []byte("ID=debian\nVERSION_ID=\"12\"\n")},
		"var/lib/dpkg/status": &fstest.MapFile{Data: []byte("Package: openssl\nVersion: 3.0.11-1\n\n")},
	}
	assets, edges := InventoryGraph("i-123", "ec2_instance", InventoryPackages(context.Background(), root).Packages, time.Now())

	const purl = "pkg:deb/debian/openssl@3.0.11-1"
	if len(assets) != 1 || assets[0].ID != purl || assets[0].Type != "package" {
		t.Fatalf("expected one package asset %q, got %+v", purl, assets)
	}
	if assets[0].Metadata["ecosystem"] != "Debian:12" {
		t.Errorf("package asset lost its release-qualified ecosystem: %+v", assets[0].Metadata)
	}
	if len(edges) != 1 {
		t.Fatalf("expected one runs_package edge, got %+v", edges)
	}
	e := edges[0]
	if e.EdgeType != "runs_package" || e.SrcID != "i-123" || e.SrcType != "ec2_instance" ||
		e.DstID != purl || e.DstType != "package" {
		t.Errorf("edge does not link the instance to the package: %+v", e)
	}
}

// One package resolved from two manifests is one node and one edge, not two.
func TestInventoryGraph_DedupesPackagesByPurl(t *testing.T) {
	lock := `{"packages":{
		"node_modules/lodash":{"version":"4.17.21"},
		"node_modules/a/node_modules/lodash":{"version":"4.17.21"}
	}}`
	root := fstest.MapFS{"package-lock.json": &fstest.MapFile{Data: []byte(lock)}}
	assets, edges := InventoryGraph("i-1", "ec2_instance", InventoryPackages(context.Background(), root).Packages, time.Now())
	if len(assets) != 1 || len(edges) != 1 {
		t.Fatalf("expected lodash@4.17.21 once, got %d assets / %d edges", len(assets), len(edges))
	}
}

func TestPURL(t *testing.T) {
	cases := []struct {
		name string
		pkg  InstalledPackage
		want string
	}{
		// The purl drops OSV's release qualifier: the same package version on
		// Debian 11 and Debian 12 is ONE node, not two.
		{"debian keeps one node per version", InstalledPackage{Ecosystem: "Debian:12", Name: "OpenSSL", Version: "3.0.11-1"}, "pkg:deb/debian/openssl@3.0.11-1"},
		{"ubuntu is its own namespace", InstalledPackage{Ecosystem: "Ubuntu:22.04", Name: "curl", Version: "7.81.0-1"}, "pkg:deb/ubuntu/curl@7.81.0-1"},
		{"alpine", InstalledPackage{Ecosystem: "Alpine:v3.19", Name: "musl", Version: "1.2.4-r2"}, "pkg:apk/alpine/musl@1.2.4-r2"},
		{"npm has no scope", InstalledPackage{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}, "pkg:npm/lodash@4.17.21"},
		{"pypi", InstalledPackage{Ecosystem: "PyPI", Name: "requests", Version: "2.25.1"}, "pkg:pypi/requests@2.25.1"},
		// An unmapped ecosystem is degraded coverage, never a dropped package.
		{"unknown falls back to generic", InstalledPackage{Ecosystem: "Conda", Name: "numpy", Version: "1.26"}, "pkg:generic/conda/numpy@1.26"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := PURL(tc.pkg); got != tc.want {
				t.Errorf("PURL = %q, want %q", got, tc.want)
			}
		})
	}
}
