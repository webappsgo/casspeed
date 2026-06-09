# Infer PROJECTNAME and PROJECTORG from git remote or directory path (NEVER hardcode)
PROJECTNAME := $(shell git remote get-url origin 2>/dev/null | sed -E 's|.*/([^/]+)(\.git)?$$|\1|' || basename "$$(pwd)")
PROJECTORG  := $(shell git remote get-url origin 2>/dev/null | sed -E 's|.*/([^/]+)/[^/]+(\.git)?$$|\1|' || basename "$$(dirname "$$(pwd)")")

# Version: env var > release.txt > default
VERSION ?= $(shell cat release.txt 2>/dev/null || echo "0.1.0")

# Build info
BUILD_DATE := $(shell date +"%a %b %d, %Y at %H:%M:%S %Z")
COMMIT_ID  := $(shell git rev-parse --short HEAD 2>/dev/null || echo "N/A")

# Official site (optional — only if site.txt exists)
OFFICIAL_SITE ?= $(shell cat site.txt 2>/dev/null || echo "")

# Linker flags to embed build info
LDFLAGS := -s -w \
	-X 'main.Version=$(VERSION)' \
	-X 'main.CommitID=$(COMMIT_ID)' \
	-X 'main.BuildDate=$(BUILD_DATE)' \
	-X 'main.OfficialSite=$(OFFICIAL_SITE)'

# Directories
BINDIR  := binaries
RELDIR  := releases

# Go module and build cache (host dirs; Docker mounts them into the container)
GO_CACHE ?= $(HOME)/go/pkg/mod
GO_BUILD ?= $(HOME)/.cache/go-build

# Platforms for cross-compilation
PLATFORMS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 freebsd/amd64 freebsd/arm64

# Docker container image for builds (NEVER build Go on the host)
REGISTRY  := ghcr.io/$(PROJECTORG)/$(PROJECTNAME)

GO_DOCKER := docker run --rm -it \
	--name $(PROJECTNAME)-$$(tr -dc 'a-z0-9' </dev/urandom | head -c8) \
	-v $(PWD):/app \
	-v $(GO_CACHE):/usr/local/share/go/pkg/mod \
	-v $(GO_BUILD):/usr/local/share/go/cache \
	-w /app \
	casjaysdev/go:latest

.PHONY: dev local build test release docker clean

# =============================================================================
# DEV - Quick development build (single host platform, into temp dir)
# =============================================================================
dev:
	@mkdir -p $(GO_CACHE) $(GO_BUILD) "$${TMPDIR:-/tmp}/$(PROJECTORG)"
	@BUILD_DIR=$$(mktemp -d "$${TMPDIR:-/tmp}/$(PROJECTORG)/$(PROJECTNAME)-XXXXXX") && \
		echo "Quick dev build..." && \
		$(GO_DOCKER) go build -o $$BUILD_DIR/$(PROJECTNAME) ./src && \
		$(GO_DOCKER) go build -o $$BUILD_DIR/$(PROJECTNAME)-cli ./src/client && \
		echo "Built: $$BUILD_DIR/$(PROJECTNAME)" && \
		echo "Test:  docker run --rm -it --name $(PROJECTNAME)-test -v $$BUILD_DIR:/app alpine:latest /app/$(PROJECTNAME) --help"

# =============================================================================
# LOCAL - Production test build (host platform only, to binaries/)
# =============================================================================
local:
	@mkdir -p $(BINDIR) $(GO_CACHE) $(GO_BUILD)
	@echo "Local build $(VERSION)..."
	@$(GO_DOCKER) sh -c "GOOS=$$(go env GOOS) GOARCH=$$(go env GOARCH) \
		go build -ldflags \"$(LDFLAGS)\" -o /app/$(BINDIR)/$(PROJECTNAME) ./src"
	@$(GO_DOCKER) sh -c "GOOS=$$(go env GOOS) GOARCH=$$(go env GOARCH) \
		go build -ldflags \"$(LDFLAGS)\" -o /app/$(BINDIR)/$(PROJECTNAME)-cli ./src/client"
	@echo "Built: $(BINDIR)/$(PROJECTNAME)"

# =============================================================================
# BUILD - All 8 platforms (server + cli)
# =============================================================================
build: clean
	@mkdir -p $(BINDIR) $(GO_CACHE) $(GO_BUILD)
	@echo "Building version $(VERSION) for all platforms..."
	@for platform in $(PLATFORMS); do \
		OS=$${platform%/*}; \
		ARCH=$${platform#*/}; \
		SRVOUT=/app/$(BINDIR)/$(PROJECTNAME)-$$OS-$$ARCH; \
		CLIOUT=/app/$(BINDIR)/$(PROJECTNAME)-cli-$$OS-$$ARCH; \
		[ "$$OS" = "windows" ] && SRVOUT=$$SRVOUT.exe && CLIOUT=$$CLIOUT.exe; \
		echo "  $$OS/$$ARCH..."; \
		$(GO_DOCKER) sh -c "GOOS=$$OS GOARCH=$$ARCH \
			go build -ldflags \"$(LDFLAGS)\" -o $$SRVOUT ./src" || exit 1; \
		$(GO_DOCKER) sh -c "GOOS=$$OS GOARCH=$$ARCH \
			go build -ldflags \"$(LDFLAGS)\" -o $$CLIOUT ./src/client" || exit 1; \
	done
	@echo "Build complete: $(BINDIR)/"

# =============================================================================
# TEST - Run tests via Docker
# =============================================================================
test:
	@mkdir -p $(GO_CACHE) $(GO_BUILD)
	@echo "Running tests..."
	@$(GO_DOCKER) go vet ./...
	@$(GO_DOCKER) go test -v -cover ./...
	@echo "Tests complete"

# =============================================================================
# RELEASE - Build all platforms + create GitHub release
# =============================================================================
release: build
	@mkdir -p $(RELDIR)
	@echo "Preparing release $(VERSION)..."
	@echo "$(VERSION)" > $(RELDIR)/version.txt
	@for f in $(BINDIR)/$(PROJECTNAME)-*; do \
		[ -f "$$f" ] || continue; \
		cp "$$f" $(RELDIR)/; \
	done
	@tar --exclude='.git' --exclude='.github' --exclude='.gitea' \
		--exclude='$(BINDIR)' --exclude='$(RELDIR)' --exclude='*.tar.gz' \
		-czf $(RELDIR)/$(PROJECTNAME)-$(VERSION)-source.tar.gz .
	@gh release delete $(VERSION) --yes 2>/dev/null || true
	@git tag -d $(VERSION) 2>/dev/null || true
	@git push origin :refs/tags/$(VERSION) 2>/dev/null || true
	@gh release create $(VERSION) $(RELDIR)/* \
		--title "$(PROJECTNAME) $(VERSION)" \
		--notes "Release $(VERSION)" \
		--latest
	@echo "Release complete: $(VERSION)"

# =============================================================================
# DOCKER - Build multi-arch container (no push; CI/CD pushes)
# =============================================================================
docker:
	@echo "Building Docker image $(VERSION)..."
	@docker buildx version > /dev/null 2>&1 || (echo "docker buildx required" && exit 1)
	@docker buildx create --name $(PROJECTNAME)-builder --use 2>/dev/null || \
		docker buildx use $(PROJECTNAME)-builder
	@docker buildx build \
		-f docker/Dockerfile \
		--platform linux/amd64,linux/arm64 \
		--build-arg VERSION="$(VERSION)" \
		--build-arg BUILD_DATE="$(BUILD_DATE)" \
		--build-arg COMMIT_ID="$(COMMIT_ID)" \
		-t $(REGISTRY):$(VERSION) \
		-t $(REGISTRY):latest \
		--load \
		.
	@echo "Docker build complete: $(REGISTRY):$(VERSION)"

# =============================================================================
# CLEAN - Remove build artifacts
# =============================================================================
clean:
	@rm -rf $(BINDIR) $(RELDIR)
