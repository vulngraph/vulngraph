package pkginventory

import (
	"bufio"
	"encoding/json"
	"io"
	"io/fs"

	"github.com/klauspost/compress/zstd"
)

// chiselManifestPath is where an Ubuntu Chiseled image built with the
// base-files_chisel slice records what chisel installed. A chiseled image has
// no dpkg status database at all, so without this its Ubuntu packages are
// invisible: the manifest is the only inventory there is.
const chiselManifestPath = "var/lib/chisel/manifest.wall"

// maxChiselManifestBytes caps the DECOMPRESSED manifest. It lists every path
// chisel wrote as well as the packages, so it is larger than a dpkg status
// file of the same image, but a few MiB at most; the cap stops a zstd bomb.
const maxChiselManifestBytes = 64 << 20

// chiselPackages reads the chisel manifest: a zstd-compressed jsonwall, one
// JSON object per line, of which the {"kind":"package"} entries name the
// installed Debian packages. The manifest carries no source package, so the
// packages it yields have none, and OSCVEGap reports the Ubuntu advisories —
// which are keyed by source package — as not fully matchable.
//
// A manifest that cannot be decoded yields nothing; with os-release naming
// Ubuntu, OSCVEGap then reports the OS packages unread rather than absent.
func chiselPackages(root fs.FS, ecosystem string) []InstalledPackage {
	f, err := root.Open(chiselManifestPath)
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()

	dec, err := zstd.NewReader(f, zstd.WithDecoderMaxMemory(maxChiselManifestBytes), zstd.WithDecoderConcurrency(1))
	if err != nil {
		return nil
	}
	defer dec.Close()

	var out []InstalledPackage
	limited := &io.LimitedReader{R: dec, N: maxChiselManifestBytes + 1}
	sc := bufio.NewScanner(limited)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var e struct {
			Kind    string `json:"kind"`
			Name    string `json:"name"`
			Version string `json:"version"`
		}
		if json.Unmarshal(sc.Bytes(), &e) != nil || e.Kind != "package" || e.Name == "" || e.Version == "" {
			continue
		}
		out = append(out, InstalledPackage{Ecosystem: ecosystem, Name: e.Name, Version: e.Version, Source: chiselManifestPath})
	}
	if sc.Err() != nil || limited.N == 0 {
		// A truncated, corrupt or oversized stream is part of a list, which reads like a
		// smaller image: report none, so the root reads as unread instead.
		return nil
	}
	return out
}
