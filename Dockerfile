# syntax=docker/dockerfile:1

# One image, two ways to run: as a Lambda (the zip is /app/bootstrap copied out
# of this image by `make lambda-zip`) or as a daemon polling ALERTDEST_QUEUE_URL
# (docker run / ECS / Kubernetes). The binary picks the mode at start from
# AWS_LAMBDA_RUNTIME_API.

# Builder pinned to the Go minor in go.mod (1.25) and to a multi-arch index
# digest, so a moving tag cannot change what an image was built with. It runs
# on the build host's platform and cross-compiles, which is fast and exact for a
# static binary.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine@sha256:1ae0735f00daffa3aaf1363a5184c0d2dc55c78e3db4ec70241cdac97bf84b59 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# TARGETARCH follows --platform, which the Makefile pins to linux/amd64: the
# Lambda is x86_64, and an arm64 bootstrap fails at invoke time with
# Runtime.InvalidEntrypoint rather than at build time. Following the platform
# rather than hard-coding amd64 keeps the binary and the base image in step if
# someone builds for another one on purpose.
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath \
      -ldflags "-s -w -X github.com/samma-io/alert-destination/internal/version.Version=${VERSION}" \
      -o /out/bootstrap ./cmd/alert-destination

# distroless/static: CA certificates and tzdata, no shell, no package manager,
# running as uid 65532. There is no health check because the daemon serves
# nothing; its liveness is the queue depth and the DLQ alarm.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
ARG VERSION=dev
LABEL org.opencontainers.image.title="alert-destination" \
      org.opencontainers.image.description="Routes detection.alert.v1 messages to Slack and GitHub, exactly once per destination" \
      org.opencontainers.image.source="https://github.com/samma-io/alert-destination" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}"
# The path is the contract with `make lambda-zip` and aws-siem's
# hack/build-images.sh, which copy it out as the zip's bootstrap.
COPY --from=build --chmod=0755 /out/bootstrap /app/bootstrap
USER 65532:65532
ENTRYPOINT ["/app/bootstrap"]
