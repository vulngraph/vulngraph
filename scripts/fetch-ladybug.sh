#!/usr/bin/env bash
# Fetch the prebuilt LadybugDB shared library for local development and CI.
#
# The Go package internal/graphdb/ladybug links against
#   internal/graphdb/ladybug/lib/dynamic/<platform>/liblbug.{so,dylib}
# which is downloaded, never committed. Run this once after cloning and again
# whenever LADYBUG_VERSION below changes. The Dockerfile pins the same version.
#
# Usage:
#   scripts/fetch-ladybug.sh                # this machine's platform
#   scripts/fetch-ladybug.sh linux-amd64    # or: linux-arm64, darwin-arm64, darwin-amd64
#   scripts/fetch-ladybug.sh --install-dir /usr/local/lib linux-amd64
#   scripts/fetch-ladybug.sh --licenses-dir /licenses/ladybug
#
# --licenses-dir collects the licence texts the library needs to ship with
# (the release assets carry none): LadybugDB's own LICENSE, the licence files of
# the C++ components it bundles (third_party/), and the copyright notices of the
# single-header components and adapted files that carry theirs inline. They come
# from the source archive of the same pinned tag, checksum-verified like the
# library.
#
# The release links OpenSSL 3 dynamically: macOS needs `brew install openssl@3`
# (the script warns after the download when it is missing), Debian 13 and
# Ubuntu 24.04 need libssl3t64 (libssl3 on older releases).
set -euo pipefail

LADYBUG_VERSION="0.21.2"
# sha256 of https://github.com/LadybugDB/ladybug/archive/refs/tags/v$LADYBUG_VERSION.tar.gz
# GitHub generates that archive on request. Should its bytes ever change, the
# licence step fails closed (checksum mismatch) rather than shipping unverified
# texts: re-download, diff against the tag, and re-pin.
LADYBUG_SOURCE_SHA256="8b3f98df08a6a1a37ff9a45dc32f83b0a52fb063082b7875d9518654775ac150"

# Bundled components with no licence file of their own: the file whose comment
# blocks carry the copyright and licence. Paths are relative to the source root.
INLINE_NOTICES=(
  third_party/fast_float/include/fast_float.h
  third_party/glob/glob/glob.hpp
  third_party/httplib/httplib.h
  third_party/pyparse/pyparse.h
  third_party/roaring_bitmap/roaring.h
  src/common/checksum.cpp
  src/include/storage/compression/sign_extend.h
)
# Upstream licence files for inline-noticed components whose notice is not the
# full licence text (httplib.h and checksum.cpp name MIT without its terms;
# fast_float.h has the terms without a copyright line), plus the openCypher
# grammar (Apache-2.0, Neo4j) that the generated Cypher parser in
# third_party/antlr4_cypher is built from (LadybugDB's src/antlr4/Cypher.g4
# derives from it; the Apache-2.0 text is the same at every openCypher release)
# with its Apache-2.0 §4(d) NOTICE.
# Each is fetched at a pinned commit and checksum-verified:
#   <destination under --licenses-dir> <raw URL> <sha256>
UPSTREAM_LICENCES=(
  "third_party/httplib/LICENSE https://raw.githubusercontent.com/yhirose/cpp-httplib/f14accb7b6ff4499321e14c61497bc7e4b28e49b/LICENSE 4b45cbe16d7b71b89ae6127e26e0d90a029198ca5e958ad8e3d0b8bbed364d8b"
  "third_party/fast_float/LICENSE-MIT https://raw.githubusercontent.com/fastfloat/fast_float/b7f9d6ca3980de0f47251921f307e88c894f6daa/LICENSE-MIT e562f3f974ced7e69dd1db77b820b36bcf8f30377f1aa105723fba449c53c4e6"
  "src/common/checksum.cpp.duckdb-LICENSE https://raw.githubusercontent.com/duckdb/duckdb/71c5c07cdd295e9409c0505885033ae9eb6b5ddd/LICENSE 7e17fd31249fa875cb3b1c5e05c6c3e99b75509f6a2804ca176c217834de1dcb"
  "third_party/antlr4_cypher/openCypher-LICENSE https://raw.githubusercontent.com/opencypher/openCypher/677cbafabb8c3c5eed458fd3b1ec0daec8d67d23/LICENSE cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30"
  "third_party/antlr4_cypher/openCypher-NOTICE https://raw.githubusercontent.com/opencypher/openCypher/677cbafabb8c3c5eed458fd3b1ec0daec8d67d23/NOTICE 31e925892196a078ed5bf9ec2b243f3dce1c71ee4489af0cfc4ecd88e62d518b"
  "src/common/checksum.cpp.robin-hood-hashing-LICENSE https://raw.githubusercontent.com/martinus/robin-hood-hashing/9145f963d80d6a02f0f96a47758050a89184a3ed/LICENSE 686cf8d62cc44fecff4be967238aba89665f9b6acf8a728987801ffc3a626bc7"
)
# third_party directories that need no licence of their own: build recipes
# that are not compiled into the library.
NO_LICENCE_DIRS=(ports)

sha256_for() {
  case "$1" in
    linux-x86_64)  echo "f3de0f9be86fffd0919bc7a7f65699d1b099d0a1df7115142fa1606ba83c94c4" ;;
    linux-aarch64) echo "0dad6e03cf644491f7d50b9c218b9e85c983ceaed77a14338c33fb75f2ae39ee" ;;
    osx-arm64)     echo "573a54126e2e1d4609680c8becee4399038ad82d3515f4d464bc481e4515c4b1" ;;
    osx-x86_64)    echo "9ec18274694ed3cc312a6d6840b9261d94dcd0c34ca87ad024dc3c553acd3e6e" ;;
    *) echo "no pinned checksum for $1" >&2; exit 1 ;;
  esac
}

sha256() {
  if command -v sha256sum >/dev/null; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# notice_blocks prints every comment block (/* ... */ or a run of // lines) in
# a source file that mentions a copyright or licence.
notice_blocks() {
  awk '
    function flush() { if (buf != "" && tolower(buf) ~ /copyright|licen[cs]e|permission is hereby granted/) printf "%s\n", buf; buf = "" }
    inblock { buf = buf $0 "\n"; if ($0 ~ /\*\//) { inblock = 0; flush() }; next }
    /^[ \t]*\/\*/ { flush(); buf = $0 "\n"; if ($0 !~ /\*\//) inblock = 1; else flush(); next }
    /^[ \t]*\/\// { buf = buf $0 "\n"; next }
    { flush() }
    END { flush() }
  ' "$1"
}

fetch_licences() {
  local out="$1" src rel f n dir entry dest url want
  tmp="$(mktemp -d)" # global: the EXIT trap runs after this function returns
  trap 'rm -rf "$tmp"' EXIT
  curl -fsSL --retry 3 -o "$tmp/src.tar.gz" \
    "https://github.com/LadybugDB/ladybug/archive/refs/tags/v$LADYBUG_VERSION.tar.gz"
  if [ "$(sha256 "$tmp/src.tar.gz")" != "$LADYBUG_SOURCE_SHA256" ]; then
    echo "checksum mismatch for the LadybugDB v$LADYBUG_VERSION source archive" >&2
    exit 1
  fi
  tar -xzf "$tmp/src.tar.gz" -C "$tmp"
  src="$tmp/ladybug-$LADYBUG_VERSION"
  mkdir -p "$out"
  install -m 0644 "$src/LICENSE" "$out/LICENSE"

  while IFS= read -r f; do
    rel="${f#"$src"/}"
    mkdir -p "$out/$(dirname "$rel")"
    install -m 0644 "$f" "$out/$rel"
  done < <(find "$src/third_party" -type f \( -iname 'LICEN[CS]E*' -o -iname 'COPYING*' \
    -o -iname 'NOTICE*' -o -iname '*.license*' \) | sort)
  # fastpfor's README is where it carries the DuckDB notice for its 8/16-bit code.
  install -m 0644 "$src/third_party/fastpfor/README" "$out/third_party/fastpfor/README"

  for rel in "${INLINE_NOTICES[@]}"; do
    n="$(notice_blocks "$src/$rel")"
    if [ -z "$n" ]; then
      echo "no copyright notice found in $rel (did v$LADYBUG_VERSION move it?)" >&2
      exit 1
    fi
    mkdir -p "$out/$(dirname "$rel")"
    printf 'Copyright and licence notices from %s (LadybugDB v%s)\n\n%s\n' \
      "$rel" "$LADYBUG_VERSION" "$n" > "$out/$rel.NOTICE"
  done

  for entry in "${UPSTREAM_LICENCES[@]}"; do
    read -r dest url want <<<"$entry"
    curl -fsSL --retry 3 -o "$tmp/upstream" "$url"
    if [ "$(sha256 "$tmp/upstream")" != "$want" ]; then
      echo "checksum mismatch for $url" >&2
      exit 1
    fi
    mkdir -p "$out/$(dirname "$dest")"
    install -m 0644 "$tmp/upstream" "$out/$dest"
  done

  # Every bundled component must be covered: a version bump that adds one
  # without a licence file fails here rather than shipping without its terms.
  for dir in "$src"/third_party/*/; do
    dir="$(basename "$dir")"
    if printf '%s\n' "${NO_LICENCE_DIRS[@]}" | grep -qxF "$dir"; then continue; fi
    if [ -z "$(find "$out/third_party/$dir" -type f 2>/dev/null | head -1)" ]; then
      echo "LadybugDB v$LADYBUG_VERSION third_party/$dir has no collected licence" >&2
      exit 1
    fi
  done
  echo "LadybugDB v$LADYBUG_VERSION licence texts -> $out"
}

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
install_dir=""
if [ "${1:-}" = "--licenses-dir" ]; then
  fetch_licences "$2"
  exit 0
fi
if [ "${1:-}" = "--install-dir" ]; then
  install_dir="$2"
  shift 2
fi

target="${1:-}"
if [ -z "$target" ]; then
  case "$(uname -s)-$(uname -m)" in
    Darwin-arm64)  target=darwin-arm64 ;;
    Darwin-x86_64) target=darwin-amd64 ;;
    Linux-x86_64)  target=linux-amd64 ;;
    Linux-aarch64) target=linux-arm64 ;;
    *) echo "unsupported platform $(uname -s)-$(uname -m)" >&2; exit 1 ;;
  esac
fi

case "$target" in
  linux-amd64)  asset=linux-x86_64;  plat=linux-amd64; lib=liblbug.so ;;
  linux-arm64)  asset=linux-aarch64; plat=linux-arm64; lib=liblbug.so ;;
  darwin-arm64) asset=osx-arm64;     plat=darwin;      lib=liblbug.dylib ;;
  darwin-amd64) asset=osx-x86_64;    plat=darwin;      lib=liblbug.dylib ;;
  *) echo "unknown target $target" >&2; exit 1 ;;
esac

dest="${install_dir:-$root/internal/graphdb/ladybug/lib/dynamic/$plat}"
tarball="liblbug-$asset.tar.gz"
url="https://github.com/LadybugDB/ladybug/releases/download/v$LADYBUG_VERSION/$tarball"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl -fsSL --retry 3 -o "$tmp/$tarball" "$url"

want="$(sha256_for "$asset")"
got="$(sha256 "$tmp/$tarball")"
if [ "$got" != "$want" ]; then
  echo "checksum mismatch for $tarball: got $got, want $want" >&2
  exit 1
fi

tar -xzf "$tmp/$tarball" -C "$tmp"
mkdir -p "$dest"
# Replace, never overwrite in place: macOS caches a loaded library's code
# signature per inode, and rewriting the same file gets every process that
# later loads it SIGKILLed ("signal: killed").
rm -f "$dest/$lib"
# Copy the real file under the unversioned name the linker resolves (-llbug).
cp -L "$tmp/$lib" "$dest/$lib"
# The binary records the library's versioned name (SONAME liblbug.so.0 /
# install name @rpath/liblbug.0.dylib), so that name must resolve too.
if [ "$plat" = "darwin" ]; then
  ln -sf "$lib" "$dest/liblbug.0.dylib"
else
  ln -sf "$lib" "$dest/liblbug.so.0"
fi
# The macOS release records OpenSSL at Homebrew's default prefix for its
# architecture (/opt/homebrew on Apple silicon, /usr/local on Intel). When that
# file is missing, dyld searches only DYLD_FALLBACK_LIBRARY_PATH, which has no
# default for binaries built with a current SDK, so a copy elsewhere does not
# count: every recorded path that does not exist is reported.
if [ "$plat" = "darwin" ] && [ "$(uname -s)" = "Darwin" ]; then
  if ! command -v otool >/dev/null; then
    echo "warning: otool not found, so the OpenSSL dependency was not checked: install the" \
      "Xcode Command Line Tools (xcode-select --install), which cgo needs too" >&2
  else
    missing=()
    while read -r dep _; do
      case "$dep" in /usr/lib/* | /System/* | @*) continue ;; esac
      if [ -e "$dep" ]; then continue; fi
      missing+=("$dep")
    done < <(otool -L "$dest/$lib" | tail -n +2)
    if [ "${#missing[@]}" -gt 0 ]; then
      echo "warning: $dest/$lib needs these, which are not installed:" >&2
      printf '  %s\n' "${missing[@]}" >&2
      echo "Run 'brew install openssl@3'. With OpenSSL 3 under another prefix, create each path" >&2
      echo "above as a symlink to its copy there. DYLD_FALLBACK_LIBRARY_PATH=<its lib directory> works" >&2
      echo "only when go is not started through a script (an asdf shim is one): macOS strips" >&2
      echo "DYLD_* variables when it runs /usr/bin/env or /bin/bash." >&2
    fi
  fi
fi
echo "LadybugDB v$LADYBUG_VERSION -> $dest/$lib"
