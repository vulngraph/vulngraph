package imagevuln

import (
	"context"
	"net/http/httptest"
	"net/url"
	"testing"
	"testing/fstest"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/stretchr/testify/require"
)

// pythonSlimAnnotations is the amd64 manifest's annotation set of
// docker.io/library/python:3.12-slim (sha256:2b4f19da…, pulled 2026-10-08),
// trimmed to the keys that matter plus one that must be ignored.
var pythonSlimAnnotations = map[string]string{
	"org.opencontainers.image.base.digest": "sha256:918311b7b6c4c6f68b232ba516584925f6c78ad82b6fd534b98979df6438e483",
	"org.opencontainers.image.base.name":   "debian:trixie-slim",
	"org.opencontainers.image.version":     "3.12.15-slim-trixie",
}

// annotatedFS is a fixture rootfs that also carries image annotations, the
// shape RegistryImageSource's view has.
type annotatedFS struct {
	fstest.MapFS
	ann map[string]string
}

func (a annotatedFS) ImageAnnotations() map[string]string { return a.ann }

func TestIdentifyBase(t *testing.T) {
	cases := []struct {
		name string
		ann  map[string]string // nil: the view carries no annotations at all
		eco  string
		want BaseIdentity
	}{
		{
			name: "official image annotation wins and keeps its digest",
			ann:  pythonSlimAnnotations, eco: "Debian:13",
			want: BaseIdentity{Image: "debian:trixie-slim", Digest: pythonSlimAnnotations[annotationBaseDigest],
				Source: BaseSourceAnnotation, OS: "Debian:13"},
		},
		{
			name: "annotation without a usable digest keeps the name only",
			ann:  map[string]string{annotationBaseName: "alpine:3.22", annotationBaseDigest: "md5:abc"},
			eco:  "Alpine:v3.22",
			want: BaseIdentity{Image: "alpine:3.22", Source: BaseSourceAnnotation, OS: "Alpine:v3.22"},
		},
		{
			name: "no annotation: the OS release is the base",
			ann:  map[string]string{}, eco: "Ubuntu:22.04:LTS",
			want: BaseIdentity{Source: BaseSourceOSRelease, OS: "Ubuntu:22.04:LTS"},
		},
		{
			name: "a mounted rootfs has no annotations at all",
			eco:  "Red Hat:9",
			want: BaseIdentity{Source: BaseSourceOSRelease, OS: "Red Hat:9"},
		},
		{
			// docker.io/library/alpine:3.18 (pulled 2026-10-08) annotates its
			// base as scratch: it is a base, named by its OS release.
			name: "an official base image's scratch annotation is not a base",
			ann:  map[string]string{annotationBaseName: "scratch"}, eco: "Alpine:v3.18",
			want: BaseIdentity{Source: BaseSourceOSRelease, OS: "Alpine:v3.18"},
		},
		{
			name: "a hostile annotation is not an identity",
			ann:  map[string]string{annotationBaseName: "debian:12\nFROM evil"}, eco: "Debian:12",
			want: BaseIdentity{Source: BaseSourceOSRelease, OS: "Debian:12"},
		},
		{
			name: "dpkg without os-release: unqualified Debian is no release",
			eco:  "Debian",
			want: BaseIdentity{Source: BaseSourceUnknown},
		},
		{
			name: "apk without a release",
			eco:  "Alpine",
			want: BaseIdentity{Source: BaseSourceUnknown},
		},
		{
			name: "scratch: no OS packages, no annotation",
			want: BaseIdentity{Source: BaseSourceUnknown},
		},
		{
			name: "annotated scratch image still names its base",
			ann:  map[string]string{annotationBaseName: "gcr.io/distroless/static-debian12"},
			want: BaseIdentity{Image: "gcr.io/distroless/static-debian12", Source: BaseSourceAnnotation},
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var got BaseIdentity
			if tt.ann == nil {
				got = identifyBase(fstest.MapFS{}, tt.eco)
			} else {
				got = identifyBase(annotatedFS{MapFS: fstest.MapFS{}, ann: tt.ann}, tt.eco)
			}
			require.Equal(t, tt.want, got)
		})
	}
}

// ScanImage reports the base it identified, from the same os-release the
// package ecosystem came from.
func TestScanImage_ReportsBase(t *testing.T) {
	root := annotatedFS{
		MapFS: fstest.MapFS{
			"var/lib/dpkg/status": {Data: []byte("Package: libssl3t64\nSource: openssl\nVersion: 3.5.1-1\n\n")},
			"usr/lib/os-release":  {Data: []byte("ID=debian\nVERSION_ID=\"13\"\n")},
		},
		ann: pythonSlimAnnotations,
	}
	res, err := New(fixtureSource{root}, &fakeVulns{}).ScanImage(context.Background(), "sha256:abc", "registry.example/app:1")
	require.NoError(t, err)
	require.Equal(t, BaseSourceAnnotation, res.Base.Source)
	require.Equal(t, "debian:trixie-slim", res.Base.Image)
	require.Equal(t, "Debian:13", res.Base.OS)

	res, err = New(fixtureSource{fstest.MapFS{"app/server": {Data: []byte("static")}}}, &fakeVulns{}).
		ScanImage(context.Background(), "sha256:def", "registry.example/static:1")
	require.NoError(t, err)
	require.Equal(t, BaseIdentity{Source: BaseSourceUnknown}, res.Base, "nothing identifies a scratch image")
}

// pushV1Image serves an in-process registry holding img.
func pushV1Image(t *testing.T, img v1.Image) (ref, digest string) {
	t.Helper()
	srv := httptest.NewServer(registry.New())
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	tag, err := name.NewTag(u.Host + "/test/base:v1")
	require.NoError(t, err)
	require.NoError(t, remote.Write(tag, img))
	d, err := img.Digest()
	require.NoError(t, err)
	return tag.String(), d.String()
}

// The registry view exposes manifest annotations over config labels, so an
// image pulled by digest names its base exactly as docker-library publishes it.
func TestRegistryImageSource_ReadsBaseAnnotations(t *testing.T) {
	img, err := mutate.AppendLayers(empty.Image, layerFrom(t, map[string]string{
		"var/lib/dpkg/status": "Package: bash\nVersion: 5.2.37-2\n\n",
		"etc/os-release":      "ID=debian\nVERSION_ID=\"13\"\n",
	}))
	require.NoError(t, err)
	img, err = mutate.Config(img, v1.Config{Labels: map[string]string{
		annotationBaseName: "debian:stale-label",
		"maintainer":       "someone",
	}})
	require.NoError(t, err)
	annotated, ok := mutate.Annotations(img, pythonSlimAnnotations).(v1.Image)
	require.True(t, ok)
	ref, digest := pushV1Image(t, annotated)

	res, err := New(testSource(), &fakeVulns{}).ScanImage(context.Background(), digest, ref)
	require.NoError(t, err)
	require.Equal(t, BaseSourceAnnotation, res.Base.Source)
	require.Equal(t, "debian:trixie-slim", res.Base.Image, "the manifest annotation outranks the config label")
	require.Equal(t, pythonSlimAnnotations[annotationBaseDigest], res.Base.Digest)
	require.Equal(t, "Debian:13", res.Base.OS)
}

// A Dockerfile LABEL is the fallback spelling when no manifest annotation is set.
func TestRegistryImageSource_LabelFallback(t *testing.T) {
	img, err := mutate.AppendLayers(empty.Image, layerFrom(t, map[string]string{
		"lib/apk/db/installed": "P:musl\nV:1.2.5-r10\no:musl\n\n",
		"etc/alpine-release":   "3.22.1\n",
	}))
	require.NoError(t, err)
	img, err = mutate.Config(img, v1.Config{Labels: map[string]string{annotationBaseName: "alpine:3.22"}})
	require.NoError(t, err)
	ref, digest := pushV1Image(t, img)

	res, err := New(testSource(), &fakeVulns{}).ScanImage(context.Background(), digest, ref)
	require.NoError(t, err)
	require.Equal(t, BaseIdentity{Image: "alpine:3.22", Source: BaseSourceAnnotation, OS: "Alpine:v3.22"}, res.Base)
}
