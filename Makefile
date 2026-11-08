# Build hallpass, run its tests, or cross-build release binaries.
VERSION ?= dev
# The guard checks the checkout that holds this Makefile, not the directory
# make runs from.
WORKTREE := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))bin/worktree
GOBUILD := CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build test fuzz corpus schema install dist

build:
	$(GOBUILD) -o bin/hallpass ./cmd/hallpass

test:
	go vet ./...
	GOOS=darwin go vet ./...
	go test -count=1 ./...

# Fuzzes the push checks, the only guard against workflow edits over git,
# for FUZZTIME each. go test runs the seeds on every make test.
FUZZTIME ?= 30s
fuzz:
	for t in FuzzReadPack FuzzWorkflowChanges FuzzApplyDelta; do \
	  go test -run '^$$' -fuzz "^$$t$$" -fuzztime $(FUZZTIME) ./internal/policy/ || exit 1; \
	done

# Records what GH sends for the commands agents run, then checks hallpass
# allows all of it. Run it for each new gh release.
GH ?= gh
corpus:
	go run ./tools/ghcorpus -gh $(GH)
	go test -count=1 -run 'TestGHCorpus' ./internal/policy/

# Replaces the embedded GraphQL schema with GitHub's current one and lists
# the new fields to review, then checks the policy tables still match it.
schema:
	go run ./tools/ghschema
	go test -count=1 ./internal/policy/

# Builds, then copies the binary into /opt/hallpass/bin and starts the broker.
# Refuses in a lane: the live broker runs main, installed from the primary
# checkout by bin/worktree sync after a PR merges.
install:
	@$(WORKTREE) guard --deny "make install"
	$(GOBUILD) -o bin/hallpass ./cmd/hallpass
	sudo ./bin/hallpass install

dist:
	rm -rf dist && mkdir -p dist
	for os in linux darwin; do \
	  for arch in amd64 arm64; do \
	    GOOS=$$os GOARCH=$$arch $(GOBUILD) -o dist/hallpass-$$os-$$arch ./cmd/hallpass || exit 1; \
	  done; \
	done
	cd dist && sha256sum hallpass-* > SHA256SUMS
