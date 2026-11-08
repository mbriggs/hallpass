# Build hallpass, run its tests or lint, or cross-build release binaries.
VERSION ?= dev
# The guard checks the checkout that holds this Makefile, not the directory
# make runs from.
WORKTREE := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))bin/worktree
GOBUILD := CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build test lint fuzz schema install dist

build:
	$(GOBUILD) -o bin/hallpass ./cmd/hallpass

test:
	go vet ./...
	GOOS=darwin go vet ./...
	go test -count=1 ./...

# golangci-lint must be built with this module's Go to load its packages, so
# make builds the pinned version into bin/ rather than using one on PATH.
# ./... skips the verify-hallpass fakes because their directory starts with
# a dot, so they're named here.
GOLANGCI_LINT_VERSION := v2.15.0
GOLANGCI_LINT := bin/golangci-lint-$(GOLANGCI_LINT_VERSION)
lint: $(GOLANGCI_LINT)
	$(GOLANGCI_LINT) run ./... ./.claude/skills/verify-hallpass/scripts/...
	GOOS=darwin $(GOLANGCI_LINT) run ./...

$(GOLANGCI_LINT):
	GOBIN=$(abspath tmp/golangci-lint) go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	mv tmp/golangci-lint/golangci-lint $@

# Fuzzes the push checks, the only guard against workflow edits over git,
# for FUZZTIME each. go test runs the seeds on every make test.
FUZZTIME ?= 30s
fuzz:
	for t in FuzzReadPack FuzzWorkflowChanges FuzzApplyDelta; do \
	  go test -run '^$$' -fuzz "^$$t$$" -fuzztime $(FUZZTIME) ./internal/policy/ || exit 1; \
	done

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
	@# bin/worktree sync reads this to tell whether the live broker runs main.
	git rev-parse HEAD > "$$(git rev-parse --absolute-git-dir)/hallpass-installed"

dist:
	rm -rf dist && mkdir -p dist
	for os in linux darwin; do \
	  for arch in amd64 arm64; do \
	    GOOS=$$os GOARCH=$$arch $(GOBUILD) -o dist/hallpass-$$os-$$arch ./cmd/hallpass || exit 1; \
	  done; \
	done
	cd dist && sha256sum hallpass-* > SHA256SUMS
