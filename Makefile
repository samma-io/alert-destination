# Every Go invocation runs in a container, so the result does not depend on the
# host toolchain. CI uses the same commands with the runner's Go instead.
BINARY   := bootstrap
PKG      := ./cmd/alert-destination
MODULE   := github.com/samma-io/alert-destination

# The image is built and pushed by us, not by a release workflow. The tag is
# whatever the builder passes; the recommended value, and the default, is the
# short git sha. aws-siem/hack/build-images.sh runs
# `make image push IMAGE=... TAG=...` here and then extracts the Lambda zip.
IMAGE    ?= ghcr.io/samma-io/alert-destination
TAG      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
# Every Lambda and ECS task in aws-siem is x86_64.
PLATFORM ?= linux/amd64
# The version baked into the binary (and the GitHub User-Agent) is the tag.
VERSION  ?= $(TAG)

GO_IMAGE   ?= golang:1.25
LINT_IMAGE ?= golangci/golangci-lint:v2.4.0
# A named volume for the module cache so repeated runs do not re-download.
DOCKER_GO  := docker run --rm -v "$(CURDIR)":/w -w /w -v alert-destination-gomod:/go/pkg/mod
GO         := $(DOCKER_GO) -e CGO_ENABLED=0 $(GO_IMAGE) go
# The race detector needs cgo.
GO_RACE    := $(DOCKER_GO) -e CGO_ENABLED=1 $(GO_IMAGE) go
# No VCS stamp: git inside the container refuses a checkout owned by another
# uid, and the image (built without .git) carries none either.
GO_LINUX   := $(DOCKER_GO) -e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=amd64 -e GOFLAGS=-buildvcs=false $(GO_IMAGE) go

LDFLAGS := -s -w -X $(MODULE)/internal/version.Version=$(VERSION)
SHA256  := $(shell command -v sha256sum 2>/dev/null || echo "shasum -a 256")

# The default gate. Run this before opening a PR.
.PHONY: all
all: fmt-check vet test-race

.PHONY: fmt
fmt:
	$(GO) fmt ./...

.PHONY: fmt-check
fmt-check:
	@unformatted=$$($(DOCKER_GO) $(GO_IMAGE) gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "not gofmt'd:"; echo "$$unformatted"; exit 1; fi

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: test
test:
	$(GO) test ./...

# The race detector is not optional here: the secret cache is shared across
# concurrent invocations in one execution environment.
.PHONY: test-race
test-race:
	$(GO_RACE) test -race ./...

.PHONY: lint
lint:
	$(DOCKER_GO) $(LINT_IMAGE) golangci-lint run

.PHONY: tidy
tidy:
	$(GO) mod tidy

# provided.al2023 runs a binary called bootstrap; nothing else about the name is
# load-bearing, but the runtime will not find it under any other. GOARCH is
# pinned to the function's x86_64 architecture rather than inherited from the
# host: an arm64 binary fails at invoke time with Runtime.InvalidEntrypoint,
# not at build time.
.PHONY: build
build:
	$(GO_LINUX) build -trimpath -ldflags='$(LDFLAGS)' -o bin/$(BINARY) $(PKG)

# The image: a static binary at /app/bootstrap on distroless/static. It runs as
# a daemon when started outside Lambda (see "Running outside Lambda" in the
# README) and is also where the Lambda zip comes from.
.PHONY: image
image:
	docker build --platform $(PLATFORM) --build-arg VERSION=$(VERSION) -t $(IMAGE):$(TAG) .

.PHONY: push
push:
	docker push $(IMAGE):$(TAG)

# The Lambda deployment package: /app/bootstrap copied out of the image and
# zipped as a single file named bootstrap at the root, which is what
# provided.al2023 runs. Built from the image rather than from `make build` so
# the zip and the image can never be two different binaries. The timestamp is
# pinned so the same binary always gives the same zip, and so the same
# source_code_hash in Terraform.
.PHONY: lambda-zip
lambda-zip: image
	mkdir -p dist
	rm -f dist/alert-destination.zip dist/$(BINARY)
	cid=$$(docker create --platform $(PLATFORM) $(IMAGE):$(TAG)) && \
	  docker cp "$$cid:/app/bootstrap" dist/$(BINARY); \
	  status=$$?; docker rm "$$cid" >/dev/null 2>&1; exit $$status
	chmod 0755 dist/$(BINARY)
	touch -d '1980-01-01T00:00:00' dist/$(BINARY)
	cd dist && zip -q -X alert-destination.zip $(BINARY) && rm $(BINARY)
	@cd dist && $(SHA256) alert-destination.zip

# Kept for muscle memory; the release asset it used to mirror no longer exists.
.PHONY: package
package: lambda-zip

.PHONY: clean
clean:
	rm -rf bin dist

# The integration suite needs DynamoDB Local. Everything else it needs -- Slack
# and GitHub -- it stands up in-process with httptest, so there is no localstack
# and no fake-server container to keep in step with the real APIs.
.PHONY: local-up
local-up:
	docker compose -f hack/local/docker-compose.yml up -d --wait

.PHONY: local-down
local-down:
	docker compose -f hack/local/docker-compose.yml down -v

# The tests run in a container too, so DynamoDB Local's published port is
# reached through host.docker.internal (the test probes for it).
.PHONY: test-integration
test-integration: local-up
	$(DOCKER_GO) -e CGO_ENABLED=0 --add-host=host.docker.internal:host-gateway $(GO_IMAGE) \
	  go test -tags integration -count=1 ./integration/...

# Smoke tests against a real Slack workspace and a real GitHub repository. They
# post a visible message and open a real issue, both clearly marked as tests,
# which is why they are behind a build tag and take their credentials from the
# environment. There are no defaults: set all four ALERTDEST_SMOKE_* variables.
#
# What they catch that nothing else does: a bot that was never invited to the
# channel, a fine-grained PAT that was never granted the repository, and a label
# the renderer applies that the repository does not have. All three are
# permanent delivery failures in production and a minute's fix here.
.PHONY: smoke
smoke:
	@for v in ALERTDEST_SMOKE_SLACK_CHANNEL ALERTDEST_SMOKE_GITHUB_REPO \
	          ALERTDEST_SMOKE_SLACK_TOKEN ALERTDEST_SMOKE_GITHUB_TOKEN; do \
	  if [ -z "$$(printenv $$v)" ]; then echo "$$v is not set"; exit 1; fi; done
	$(DOCKER_GO) -e CGO_ENABLED=0 \
	  -e ALERTDEST_SMOKE_SLACK_CHANNEL -e ALERTDEST_SMOKE_GITHUB_REPO \
	  -e ALERTDEST_SMOKE_SLACK_TOKEN -e ALERTDEST_SMOKE_GITHUB_TOKEN \
	  $(GO_IMAGE) go test -tags smoke -count=1 -v ./internal/destination/

# Fails if anything that looks like a private-organisation identifier is in the tree.
.PHONY: scrub
scrub:
	./hack/scrub-check.sh .

# Everything CI runs, in one command (CI also builds the image and scans it).
.PHONY: check
check: fmt-check vet test-race scrub
