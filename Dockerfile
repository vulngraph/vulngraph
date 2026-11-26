# syntax=docker/dockerfile:1.27.1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
#
# 4-stage build (plus an empty Go-cache seed stage): ladybug (prebuilt library) → frontend → go binary → runtime
#
# `docker build .` needs nothing pre-staged locally: stage 0 downloads the
# pinned prebuilt LadybugDB library from GitHub releases
# (scripts/fetch-ladybug.sh verifies its sha256), so there is no C++ compile.
# Only public Docker Hub images are used, each pinned by digest: the base
# images (Dependabot's docker ecosystem bumps them) and the syntax frontend on
# line 1 (bumped by hand). The golang and bun tags match .tool-versions; CI
# fails when they drift.
#
# Multi-arch: stages 0 and 1 run on the build host's platform (their output —
# the target arch's prebuilt library, the JS bundle — does not depend on it);
# only the cgo build and the runtime stage run as TARGETPLATFORM.
#
# VERSION is stamped into the binary (`graph version`); the release workflow
# passes the git tag. Local builds report "dev".

# ── 0) LadybugDB shared library (pinned prebuilt release) ─────────────────────
FROM --platform=$BUILDPLATFORM debian:13-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad AS build-ladybug
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*
COPY scripts/fetch-ladybug.sh /fetch-ladybug.sh
RUN /fetch-ladybug.sh --install-dir /usr/local/lib "linux-${TARGETARCH:-amd64}"
# Licence texts for liblbug and the C++ components it bundles, from the source
# archive of the same pinned tag (sha256-verified; the release ships none).
RUN /fetch-ladybug.sh --licenses-dir /licenses/ladybug

# ── 1) Frontend ─────────────────────────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM oven/bun:1.4.5@sha256:3aa040e5445efa09d75bb428a64ba50db13e2b3ac9b6b0c7f145615f62b2ee18 AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/bun.lock ./
RUN bun install --frozen-lockfile
COPY frontend/ .
RUN bun run build
# Licence texts of the packages that can reach the bundle: a production-only
# install from the same frozen lockfile, collected by package.
COPY scripts/collect-licenses.sh /collect-licenses.sh
RUN mkdir /prod && cp package.json bun.lock /prod/ && \
    cd /prod && bun install --production --frozen-lockfile --ignore-scripts && \
    bash /collect-licenses.sh npm /licenses /prod/node_modules

# ── 2) Go binary (CGO, liblbug fetched above) ──────────────────────────────
# Seed for the Go build cache. Empty unless the caller passes
# `--build-context gocache=<dir>` (the release workflow hands in a warm GOCACHE:
# BuildKit cache mounts do not survive an ephemeral CI runner, and the compile
# of the dependency graph is most of this image's build time).
FROM scratch AS gocache

FROM golang:1.26.11-trixie@sha256:f9e99477a80ccd7adfb69780510b22c7249ce9169885f18aa762cd886e75e018 AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates git && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY go.mod go.sum ./
COPY internal/graphdb/ladybug/go.mod internal/graphdb/ladybug/go.sum ./internal/graphdb/ladybug/
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
COPY --from=frontend /app/web/dist ./web/dist
COPY --from=build-ladybug /usr/local/lib/liblbug.so* /usr/local/lib/
RUN ldconfig

ENV CGO_ENABLED=1
ENV CGO_LDFLAGS="-L/usr/local/lib -llbug -Wl,-rpath,/usr/local/lib"

ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=bind,from=gocache,target=/gocache-seed \
    cp -a /gocache-seed/. /root/.cache/go-build/ && \
    go build -ldflags="-s -w -X main.version=${VERSION}" -trimpath -o /graph ./cmd/graph
# Licence texts of every Go module linked into /graph, plus the Go standard
# library's, resolved with the same environment as the build above. The build
# fails if a linked module has no licence file.
RUN --mount=type=cache,target=/go/pkg/mod \
    bash scripts/collect-licenses.sh go /licenses ./cmd/graph

# ── 3) Runtime ──────────────────────────────────────────────────────────────────
FROM debian:13-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates libssl3t64 && \
    rm -rf /var/lib/apt/lists/*
COPY --from=build-ladybug /usr/local/lib/liblbug.so* /usr/local/lib/
RUN ldconfig
COPY --from=builder /graph /graph
# Licence texts for everything linked into /graph, embedded in it (the UI) and
# bundled in liblbug.so: MIT, BSD and Apache-2.0 require them to ship with a
# binary distribution. Layout: licenses/go (Go modules), licenses/go-stdlib-LICENSE,
# licenses/npm (frontend packages), licenses/ladybug (liblbug and third_party).
COPY LICENSE NOTICE THIRD_PARTY_LICENSES.md /usr/share/doc/graph/
COPY --from=builder /licenses /usr/share/doc/graph/licenses
COPY --from=frontend /licenses/npm /usr/share/doc/graph/licenses/npm
COPY --from=build-ladybug /licenses/ladybug /usr/share/doc/graph/licenses/ladybug
# /graph stays root-owned (0755): the runtime user can run it, not replace it.
# /data/ladybug is the worker's snapshot directory. Creating it owned by
# nonroot lets a Docker named volume mounted there (deploy/docker-compose)
# inherit a writable owner; on Kubernetes the PVC's fsGroup does the same.
RUN useradd --system --create-home --uid 65532 nonroot && \
    chown root:root /graph && chmod 0755 /graph && \
    mkdir -p /data/ladybug && chown nonroot /data/ladybug
USER nonroot
EXPOSE 8080
ENTRYPOINT ["/graph"]
CMD ["serve"]
