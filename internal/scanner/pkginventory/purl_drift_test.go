package pkginventory_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vulngraph/vulngraph/internal/scanner/imagevuln"
	"github.com/vulngraph/vulngraph/internal/scanner/pkginventory"
)

// The purl is the package asset's NODE ID, and two readers mint it: the image
// scanner while streaming a layer, and the filesystem walk (InventoryPackages)
// shaped into nodes by InventoryGraph, the same shaping the VM inventory
// collectors use. They must produce byte-identical strings for the same package
// or one package forks into two graph nodes, and "where is openssl used"
// answers for one kind of workload but never for both.
//
// Both mint through PURL, but each reads the filesystem its own way, so this
// test drives both over the SAME fixture filesystem and compares the package
// node ids they emit.
func TestPURLMatchesImageScanner(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/os-release", "ID=debian\nVERSION_ID=\"12\"\n")
	write(t, root, "var/lib/dpkg/status",
		"Package: openssl\nVersion: 3.0.11-1~deb12u2\n\n"+
			"Package: libc6\nVersion: 2.36-9+deb12u3\n\n")
	write(t, root, "requirements.txt", "requests==2.25.1\n")
	write(t, root, "package-lock.json", `{"packages":{"node_modules/lodash":{"version":"4.17.21"}}}`)
	// Language packages at depth — the shapes that only exist because installed
	// artifacts are read anywhere in the tree. They belong in THIS fixture because
	// they are exactly where the two implementations can drift: the image scanner
	// parses them while streaming a layer, InventoryPackages while walking a
	// filesystem, and only the node ids they mint are comparable.
	write(t, root, "usr/src/app/node_modules/@example/widget/package.json",
		`{"name":"@example/widget","version":"1.4.0"}`)
	write(t, root, "usr/lib/python3/site-packages/PyYAML-6.0.dist-info/METADATA",
		"Name: PyYAML\nVersion: 6.0\n")
	write(t, root, "usr/lib/ruby/gems/3.1.0/specifications/CFPropertyList-3.0.8.gemspec",
		"Gem::Specification.new")

	// Image side: the package asset ids the image scanner would write.
	imgRes, err := imagevuln.New(imagevuln.LocalImageSource{Root: root}, nil).
		ScanImage(context.Background(), "sha256:deadbeef", "example/img:1")
	if err != nil {
		t.Fatalf("ScanImage: %v", err)
	}
	imagePurls := map[string]bool{}
	for _, a := range imgRes.Assets {
		imagePurls[a.ID] = true
	}
	if len(imagePurls) == 0 {
		t.Fatal("image scanner produced no package assets — fixture is not exercising either scanner")
	}
	// Guard the guard: if the language half of the fixture stopped being read, the
	// two sides would still agree — on OS packages only — and this test would pass
	// while covering nothing. That is precisely the state it was in before, when
	// both language manifests were read at the rootfs root and no image had them.
	for _, want := range []string{
		"pkg:npm/@example/widget@1.4.0",
		"pkg:pypi/pyyaml@6.0",
		"pkg:gem/CFPropertyList@3.0.8",
	} {
		if !imagePurls[want] {
			t.Errorf("the image scanner did not mint %q — this test no longer covers language packages", want)
		}
	}

	// Walk side: the same filesystem, through InventoryPackages + InventoryGraph.
	vmAssets, _ := pkginventory.InventoryGraph("i-123", "ec2_instance",
		pkginventory.InventoryPackages(context.Background(), os.DirFS(root)).Packages, time.Now())
	vmPurls := map[string]bool{}
	for _, a := range vmAssets {
		vmPurls[a.ID] = true
	}

	for purl := range imagePurls {
		if !vmPurls[purl] {
			t.Errorf("image scanner mints %q but the filesystem walk does not — the same package forks into two graph nodes", purl)
		}
	}
	for purl := range vmPurls {
		if !imagePurls[purl] {
			t.Errorf("the filesystem walk mints %q but the image scanner does not — the same package forks into two graph nodes", purl)
		}
	}
}

func write(t *testing.T, root, path, body string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
