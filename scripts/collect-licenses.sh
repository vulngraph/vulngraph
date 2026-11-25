#!/usr/bin/env bash
# Collect the licence texts of everything linked or bundled into the graph
# binary, for the container image (/usr/share/doc/graph/licenses). MIT, BSD and
# Apache-2.0 all require the licence text to travel with a binary distribution;
# THIRD_PARTY_LICENSES.md only names and links them.
#
# Usage:
#   scripts/collect-licenses.sh go  <out-dir> <package>...   # Go modules + stdlib
#   scripts/collect-licenses.sh npm <out-dir> <node_modules>  # frontend packages
#
# Go: every non-standard package the given packages depend on (`go list -deps`,
# so exactly what the build links) contributes the licence files found in its
# module root and in its own package directory (a vendored sub-package such as
# goja/ftoa keeps its own). Run it with the same GOFLAGS/CGO environment as the
# build so the package set matches.
#
# npm: run against a production-only install (`bun install --production`), so
# only packages that can reach the bundle are collected.
#
# Fails, naming the module or package, when one has no licence file at all: a
# dependency whose terms cannot be shipped must stop the build, not be skipped.
set -euo pipefail

licence_files() {
  find "$1" -maxdepth 1 -type f \( -iname 'LICEN[CS]E*' -o -iname 'COPYING*' \
    -o -iname 'NOTICE*' -o -iname 'COPYRIGHT*' -o -iname 'UNLICENSE*' \) | sort
}

copy_licences() { # <src-dir> <dest-dir>; prints how many files were copied
  local n=0 f
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    mkdir -p "$2"
    # 0644, not the source's mode: the Go module cache is read-only.
    install -m 0644 "$f" "$2/"
    n=$((n + 1))
  done < <(licence_files "$1")
  echo "$n"
}

collect_go() {
  local out="$1" self path dir mod moddir n seen found
  shift
  self="$(go list -m)"
  seen="$(mktemp)" found="$(mktemp)"
  cp "$(go env GOROOT)/LICENSE" "$out/go-stdlib-LICENSE"
  while IFS=$'\t' read -r path dir mod moddir; do
    [ -n "$mod" ] || continue # standard library
    # The main module is this project: its LICENSE ships at the doc root.
    [ "$mod" = "$self" ] && continue
    n=0
    if ! grep -qxF "$mod" "$seen"; then
      echo "$mod" >> "$seen"
      n=$(copy_licences "$moddir" "$out/go/$mod")
    fi
    if [ "$dir" != "$moddir" ]; then
      n=$((n + $(copy_licences "$dir" "$out/go/$path")))
    fi
    if [ "$n" -gt 0 ]; then echo "$mod" >> "$found"; fi
  done < <(go list -deps -f '{{.ImportPath}}{{"\t"}}{{.Dir}}{{"\t"}}{{with .Module}}{{.Path}}{{"\t"}}{{.Dir}}{{end}}' "$@" | sort -u)
  local missing
  missing="$(comm -23 <(sort -u "$seen") <(sort -u "$found"))"
  rm -f "$seen" "$found"
  if [ -n "$missing" ]; then
    printf 'no licence file for Go module:\n%s\n' "$missing" >&2
    exit 1
  fi
}

collect_npm() {
  local out="$1" nm="$2" missing=() pkg name
  # A package is a directory directly under a node_modules directory, or under
  # an @scope directory there; package.json files deeper inside a package are
  # its own sub-entry points, not packages.
  while IFS= read -r pkg; do
    name="${pkg#"$nm"/}"
    if [ "$(copy_licences "$pkg" "$out/npm/$name")" -eq 0 ]; then
      missing+=("$name")
    fi
  done < <(find "$nm" -name package.json -type f | sed 's|/package.json$||' \
    | grep -E '(^|/)node_modules/(@[^/]+/)?[^/@.][^/]*$' | sort)
  if [ "${#missing[@]}" -gt 0 ]; then
    printf 'no licence file for npm package:\n' >&2
    printf '  %s\n' "${missing[@]}" >&2
    exit 1
  fi
}

mode="${1:-}"
out="${2:-}"
if [ -z "$mode" ] || [ -z "$out" ] || [ $# -lt 3 ]; then
  echo "usage: $0 go <out-dir> <package>... | npm <out-dir> <node_modules>" >&2
  exit 2
fi
shift 2
mkdir -p "$out"
case "$mode" in
  go) collect_go "$out" "$@" ;;
  npm) collect_npm "$out" "$1" ;;
  *) echo "unknown mode $mode" >&2; exit 2 ;;
esac
