# Build hallpass, run its tests, or cross-build release binaries.
VERSION ?= dev
GOBUILD := CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$(VERSION)"

.PHONY: build test install dist

build:
	$(GOBUILD) -o bin/hallpass ./cmd/hallpass

test:
	go vet ./...
	GOOS=darwin go vet ./...
	go test -count=1 ./...

# Builds, then copies the binary into /opt/hallpass/bin and starts the broker.
install: build
	sudo ./bin/hallpass install

dist:
	rm -rf dist && mkdir -p dist
	for os in linux darwin; do \
	  for arch in amd64 arm64; do \
	    GOOS=$$os GOARCH=$$arch $(GOBUILD) -o dist/hallpass-$$os-$$arch ./cmd/hallpass || exit 1; \
	  done; \
	done
	cd dist && sha256sum hallpass-* > SHA256SUMS
