# Harbinger CLI — build, test, release.
#
# The client is zero-dependency stdlib Go, so builds are trivially reproducible.
BINARY   := harbinger
PKG      := ./cmd/harbinger
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS  := -s -w -X main.Version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: all build test vet fmt run check clean release checksums tidy

all: vet test build

# -buildvcs=false matches the release build exactly; without it Go stamps the
# commit and the working tree's cleanliness in, and no two builds agree.
build:
	CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l -w .

# End-to-end smoke: self-test + analyze the bundled sample.
check: build
	./bin/$(BINARY) check
	./bin/$(BINARY) analyze testdata/goad-mini --no-color

# Reproducible cross-compiled release binaries + SHA256SUMS.
release: clean
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		out="dist/$(BINARY)-$(VERSION)-$$os-$$arch$$ext"; \
		echo "building $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -buildvcs=false -ldflags "$(LDFLAGS)" -o "$$out" $(PKG) || exit 1; \
	done
	@$(MAKE) checksums

checksums:
	@cd dist && shasum -a 256 * > SHA256SUMS && cat SHA256SUMS

tidy:
	go mod tidy

clean:
	rm -rf bin dist
