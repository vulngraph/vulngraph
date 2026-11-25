package pkginv

import (
	"bytes"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidate_RejectsEachRule(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Request)
		want   string
	}{
		{"scanner name missing", func(q *Request) { q.Scanner.Name = "" }, "scanner.name"},
		{"scanner name uppercase", func(q *Request) { q.Scanner.Name = "Acme" }, "scanner.name"},
		{"scanner name too long", func(q *Request) { q.Scanner.Name = strings.Repeat("a", 64) }, "scanner.name"},
		{"scanner name with newline", func(q *Request) { q.Scanner.Name = "a\nb" }, "scanner.name"},
		{"scanner version missing", func(q *Request) { q.Scanner.Version = "" }, "scanner.version"},
		{"scanner version with space", func(q *Request) { q.Scanner.Version = "1 2" }, "scanner.version"},
		{"observed_at missing", func(q *Request) { q.ObservedAt = "" }, "observed_at"},
		{"observed_at not RFC 3339", func(q *Request) { q.ObservedAt = "2026-11-25" }, "observed_at"},
		{"observed_at in the future", func(q *Request) { q.ObservedAt = clock.Add(6 * time.Minute).Format(time.RFC3339) }, "future"},
		{"observed_at too old", func(q *Request) { q.ObservedAt = clock.Add(-31 * 24 * time.Hour).Format(time.RFC3339) }, "30 days"},
		{"asset_id with control char", func(q *Request) { q.AssetID = "i-1\n2" }, "asset_id"},
		{"cloud_resource_id with space", func(q *Request) { q.CloudResourceID = "i 1" }, "cloud_resource_id"},
		{"os id uppercase", func(q *Request) { q.OS = &RequestOS{ID: "Ubuntu"} }, "os.id"},
		{"os version bad char", func(q *Request) { q.OS = &RequestOS{ID: "ubuntu", VersionID: "22 04"} }, "os.version_id"},
		{"os name with newline", func(q *Request) { q.OS = &RequestOS{ID: "ubuntu", Name: "x\ny"} }, "os.name"},
		{"over the package cap", func(q *Request) { q.Packages = make([]RequestPkg, MaxPackages+1) }, "over_package_cap"},
		{"package name empty", func(q *Request) { q.Packages = []RequestPkg{{Version: "1"}} }, "name"},
		{"package name with space", func(q *Request) { q.Packages = []RequestPkg{{Name: "a b", Version: "1"}} }, "name"},
		{"package name too long", func(q *Request) { q.Packages = []RequestPkg{{Name: strings.Repeat("a", 201), Version: "1"}} }, "name"},
		{"package version empty", func(q *Request) { q.Packages = []RequestPkg{{Name: "a"}} }, "version"},
		{"package version with newline", func(q *Request) { q.Packages = []RequestPkg{{Name: "a", Version: "1\n2"}} }, "version"},
		{"package version non-ASCII", func(q *Request) { q.Packages = []RequestPkg{{Name: "a", Version: "1é"}} }, "version"},
		{"source name bad", func(q *Request) { q.Packages = []RequestPkg{{Name: "a", Version: "1", SourceName: "x y"}} }, "source_name"},
		{"source version bad", func(q *Request) { q.Packages = []RequestPkg{{Name: "a", Version: "1", SourceVersion: "x y"}} }, "source_version"},
		{"epoch not digits", func(q *Request) { q.Packages = []RequestPkg{{Name: "a", Version: "1", Epoch: "x"}} }, "epoch"},
		{"release bad", func(q *Request) { q.Packages = []RequestPkg{{Name: "a", Version: "1", Release: "a b"}} }, "release"},
		{"unknown ecosystem", func(q *Request) { q.Packages = []RequestPkg{{Ecosystem: "Cobol", Name: "a", Version: "1"}} }, "ecosystem"},
		{"os family that is not the os block's", func(q *Request) { q.Packages = []RequestPkg{{Ecosystem: "Debian", Name: "a", Version: "1"}} }, "ecosystem"},
		{"purl and name together", func(q *Request) { q.Packages = []RequestPkg{{PURL: "pkg:npm/left-pad@1.3.0", Name: "x"}} }, "not both"},
		{"purl without pkg prefix", func(q *Request) { q.Packages = []RequestPkg{{PURL: "npm/left-pad@1.3.0"}} }, "purl"},
		{"purl with qualifiers", func(q *Request) { q.Packages = []RequestPkg{{PURL: "pkg:npm/left-pad@1.3.0?arch=x"}} }, "purl"},
		{"purl without version", func(q *Request) { q.Packages = []RequestPkg{{PURL: "pkg:npm/left-pad"}} }, "purl"},
		{"purl bad percent encoding", func(q *Request) { q.Packages = []RequestPkg{{PURL: "pkg:npm/left-pad@%zz"}} }, "purl"},
		{"purl unsupported type", func(q *Request) { q.Packages = []RequestPkg{{PURL: "pkg:nuget/Foo@1.0"}} }, "not supported"},
		{"purl type contradicts ecosystem", func(q *Request) { q.Packages = []RequestPkg{{PURL: "pkg:npm/left-pad@1.3.0", Ecosystem: "PyPI"}} }, "does not match"},
		{"deb purl for another distro", func(q *Request) { q.Packages = []RequestPkg{{PURL: "pkg:deb/debian/bash@5.1"}} }, "does not match the os block"},
		{"rpm purl on a deb host", func(q *Request) { q.Packages = []RequestPkg{{PURL: "pkg:rpm/redhat/bash@5.1"}} }, "does not match the os block"},
		{"covered with neither", func(q *Request) { q.Covered = []Covered{{}} }, "exactly one"},
		{"covered with both", func(q *Request) { q.Covered = []Covered{{Path: "/a", VolumeID: "v"}} }, "exactly one"},
		{"covered relative path", func(q *Request) { q.Covered = []Covered{{Path: "etc"}} }, "covered[0].path"},
		{"covered too many", func(q *Request) { q.Covered = make([]Covered, MaxCovered+1) }, "covered"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			q := goodRequest()
			tc.mutate(&q)
			_, err := Validate(q, clock)
			require.ErrorIs(t, err, ErrInvalid)
			require.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestValidate_AcceptsAndNormalises(t *testing.T) {
	q := goodRequest()
	q.ObservedAt = clock.Add(MaxFutureSkew).Format(time.RFC3339)
	q.Covered = []Covered{{Path: "/"}, {VolumeID: "vol-0123"}}
	q.Packages = []RequestPkg{
		{Name: "libssl3", Version: "3.0.2-0ubuntu1.10", SourceName: "openssl"},
		{Name: "libssl3", Version: "3.0.2-0ubuntu1.10", SourceName: "openssl"}, // duplicate collapses
		{Ecosystem: "os", Name: "bash", Version: "5.1"},
		{Ecosystem: "Ubuntu", Name: "curl", Version: "7.81.0"},
		{PURL: "pkg:deb/ubuntu/zlib1g@1%3A1.2.11", SourceName: "zlib"},
		{PURL: "pkg:npm/%40scope/pkg@1.0.0"},
		{PURL: "pkg:golang/github.com/foo/bar@v1.2.3%2Bincompatible"},
		{PURL: "pkg:pypi/Requests@2.0"},
		{Ecosystem: "Maven", Name: "org.apache.logging.log4j:log4j-core", Version: "2.17.1"},
	}
	s, err := Validate(q, clock)
	require.NoError(t, err)
	require.Len(t, s.Packages, 8)
	require.Len(t, s.Covered, 2)
	require.Equal(t, "@scope/pkg", s.Packages[4].Name)
	require.Equal(t, "npm", s.Packages[4].Ecosystem)
	require.Equal(t, "1:1.2.11", s.Packages[3].Version)
	require.Equal(t, "", s.Packages[3].Ecosystem, "an OS package takes the os block's ecosystem")
	require.Equal(t, "github.com/foo/bar", s.Packages[5].Name)
	require.Equal(t, "v1.2.3+incompatible", s.Packages[5].Version)
}

func TestValidate_AcceptsBoundaryTimes(t *testing.T) {
	for _, at := range []time.Time{clock.Add(MaxFutureSkew), clock.Add(-MaxAge)} {
		q := goodRequest()
		q.ObservedAt = at.Format(time.RFC3339)
		_, err := Validate(q, clock)
		require.NoError(t, err, at)
	}
}

func TestDecodeRequest(t *testing.T) {
	t.Run("unknown fields are rejected", func(t *testing.T) {
		_, err := DecodeRequest(strings.NewReader(`{"scanner":{"name":"a","version":"1"},"inventory_known":true}`))
		require.ErrorIs(t, err, ErrInvalid)
		require.Contains(t, err.Error(), "inventory_known")
	})
	t.Run("an agent cannot state known-ness or findings", func(t *testing.T) {
		for _, f := range []string{"inventory_known", "cve_matchable_known", "gap", "findings", "vulnerabilities", "clean", "source"} {
			_, err := DecodeRequest(strings.NewReader(`{"` + f + `":true}`))
			require.ErrorIs(t, err, ErrInvalid, f)
		}
	})
	t.Run("unknown nested field", func(t *testing.T) {
		_, err := DecodeRequest(strings.NewReader(`{"packages":[{"name":"a","version":"1","severity":"high"}]}`))
		require.ErrorIs(t, err, ErrInvalid)
	})
	t.Run("trailing data", func(t *testing.T) {
		_, err := DecodeRequest(strings.NewReader(`{} {}`))
		require.ErrorIs(t, err, ErrInvalid)
	})
	t.Run("not json", func(t *testing.T) {
		_, err := DecodeRequest(strings.NewReader(`nope`))
		require.ErrorIs(t, err, ErrInvalid)
	})
	t.Run("complete defaults to false", func(t *testing.T) {
		req, err := DecodeRequest(strings.NewReader(`{"scanner":{"name":"a","version":"1"}}`))
		require.NoError(t, err)
		require.False(t, req.Complete)
	})
	t.Run("a body over the limit is not an invalid-input error", func(t *testing.T) {
		r := http.MaxBytesReader(nil, readerOf(strings.Repeat(" ", 100)+`{}`), 10)
		_, err := DecodeRequest(r)
		var tooBig *http.MaxBytesError
		require.True(t, errors.As(err, &tooBig))
		require.NotErrorIs(t, err, ErrInvalid)
	})
}

func readerOf(s string) *nopCloser { return &nopCloser{bytes.NewBufferString(s)} }

type nopCloser struct{ *bytes.Buffer }

func (nopCloser) Close() error { return nil }
