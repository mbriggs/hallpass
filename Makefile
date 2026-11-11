# Build hallpass, run its tests or lint, or cross-build release binaries.
VERSION ?= dev
# The guard checks the checkout that holds this Makefile, not the directory
# make runs from.
WORKTREE := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))bin/worktree
GOBUILD := CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build test lint fuzz mutate schema install dist

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

# Fuzzes the parsers that read what agents send, for FUZZTIME each: pushes,
# packs, GraphQL requests, repo names, and the audit log lines that hold
# them, and GitHub's answer to a push. go test runs the seeds on every
# make test. A failing input lands in the package's testdata/fuzz/; commit
# it with the fix so the seeds keep it.
FUZZTIME ?= 30s
FUZZ_TARGETS := policy:FuzzReadPush policy:FuzzReadPack policy:FuzzWorkflowChanges \
  policy:FuzzApplyDelta policy:FuzzGraphQLReprint policy:FuzzCodeSearchRepo policy:FuzzReportStatus \
  github:FuzzParseRepo audit:FuzzParse sshgate:FuzzCopyRequest sshgate:FuzzReadCapabilities
fuzz:
	for t in $(FUZZ_TARGETS); do \
	  go test -run '^$$' -fuzz "^$${t#*:}$$" -fuzztime $(FUZZTIME) ./internal/$${t%%:*}/ || exit 1; \
	done

# Mutates PKG's code and runs the whole suite against each mutant, for a
# manual audit, not CI. .claude/skills/mutation-audit says how to read the
# report, which lists every mutant in tmp/. gremlins is built into bin/ with
# this module's Go, as golangci-lint is.
#   -count=1        gremlins times each mutant from its coverage run, and a
#                   cached coverage run makes every mutant time out.
#   --integration --coverpkg
#                   PKG's own tests alone miss what other packages' tests
#                   reach and catch, like sshgate's push relay, which only
#                   cmd/hallpass's tests drive.
#   --timeout-coefficient
#                   Each mutant gets 3 coverage runs by default, which a
#                   suite run beside a dozen others overruns, so mutants
#                   that live report TIMED OUT.
#   --invert-*      && and || swaps and break and continue swaps, which can
#                   flip an allow or a deny, are off by default.
GREMLINS_VERSION := v0.6.0
GREMLINS := bin/gremlins-$(GREMLINS_VERSION)
PKG ?= ./internal/policy
mutate: $(GREMLINS)
	mkdir -p tmp
	GOFLAGS=-count=1 $(GREMLINS) unleash --integration --coverpkg $(PKG) --timeout-coefficient 10 \
	  --invert-logical --invert-loopctrl -S lct \
	  -o tmp/mutate-$(subst /,_,$(patsubst ./%,%,$(PKG))).json $(PKG)

$(GREMLINS):
	GOBIN=$(abspath tmp/gremlins) go install github.com/go-gremlins/gremlins/cmd/gremlins@$(GREMLINS_VERSION)
	mv tmp/gremlins/gremlins $@

# Replaces the embedded GraphQL schema with GitHub's current one and lists
# the new fields to review, then checks the policy tables still match it.
schema:
	go run ./tools/ghschema
	go test -count=1 ./internal/policy/

# Builds, then copies the binary into /opt/hallpass/bin and starts the broker.
# Refuses in a lane: the live broker runs main, installed from the primary
# checkout by bin/worktree sync after a PR merges. sync passes SUDO='sudo -n ',
# so a missing sudo credential fails at once instead of prompting.
SUDO ?= sudo
install:
	@$(WORKTREE) guard --deny "make install"
	$(GOBUILD) -o bin/hallpass ./cmd/hallpass
	$(SUDO) ./bin/hallpass install
	@# bin/worktree sync reads this to tell whether the live broker runs main,
	@# so an install run by hand counts too.
	git rev-parse HEAD > "$$(git rev-parse --path-format=absolute --git-common-dir)/worktree-installed"

dist:
	rm -rf dist && mkdir -p dist
	for os in linux darwin; do \
	  for arch in amd64 arm64; do \
	    GOOS=$$os GOARCH=$$arch $(GOBUILD) -o dist/hallpass-$$os-$$arch ./cmd/hallpass || exit 1; \
	  done; \
	done
	cd dist && sha256sum hallpass-* > SHA256SUMS
