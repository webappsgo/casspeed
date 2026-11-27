# Read project identity from IDEA.md before falling back to the Git remote or directory.
PROJECT_NAME := $(shell sed -n 's/^project_name:[[:space:]]*//p' IDEA.md 2>/dev/null | head -n1 | tr -d '[:space:]')
ifeq ($(PROJECT_NAME),)
PROJECT_NAME := $(shell git remote get-url origin 2>/dev/null | sed -E 's|.*/([^/]+)(\.git)?$$|\1|' || basename "$(PWD)")
endif
PROJECT_ORG := $(shell sed -n 's/^project_org:[[:space:]]*//p' IDEA.md 2>/dev/null | head -n1 | tr -d '[:space:]')
ifeq ($(PROJECT_ORG),)
PROJECT_ORG := $(shell git remote get-url origin 2>/dev/null | sed -E 's|.*/([^/]+)/[^/]+(\.git)?$$|\1|' || basename "$(dir $(PWD))")
endif
INTERNAL_NAME := $(shell sed -n 's/^internal_name:[[:space:]]*//p' IDEA.md 2>/dev/null | head -n1 | tr -d '[:space:]')
ifeq ($(INTERNAL_NAME),)
INTERNAL_NAME := $(PROJECT_NAME)
endif

# The user may override VERSION explicitly; otherwise use release.txt or the devel commit id.
VERSION ?= $(shell version=; [ -r release.txt ] && version=$$(tr -d '[:space:]' < release.txt); if [ -n "$$version" ]; then echo "$$version"; else git rev-parse --short=7 HEAD 2>/dev/null || echo devel; fi)
BUILD_EPOCH := $(shell date -u +%s)
BUILD_DATE := $(shell date -u -d @$(BUILD_EPOCH) +"%Y-%m-%dT%H:%M:%SZ")
COMMIT_ID := $(shell git rev-parse --short=7 HEAD 2>/dev/null || echo N/A)
OFFICIAL_SITE := $(shell [ -f site.txt ] && cat site.txt || echo "$${OFFICIAL_SITE:-}")

LDFLAGS := -s -w \
	-X 'main.Version=$(VERSION)' \
	-X 'main.CommitID=$(COMMIT_ID)' \
	-X 'main.BuildEpoch=$(BUILD_EPOCH)' \
	-X 'main.OfficialSite=$(OFFICIAL_SITE)'

BINDIR := binaries
RELDIR := releases
GO_CACHE ?= $(HOME)/go/pkg/mod
GO_BUILD ?= $(HOME)/.cache/go-build/$(PROJECT_NAME)
PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 freebsd/amd64 freebsd/arm64
DOCKER_MEM ?= 4g
DOCKER_CPUS ?= 2
DOCKER_CPU_SHARES ?= 256
DOCKER_TIMEOUT ?= 3600
REGISTRY ?= ghcr.io/$(PROJECT_ORG)/$(PROJECT_NAME)

# Share one bounded toolchain container across the build targets.
GO_DOCKER_RUN := timeout -k 30 $(DOCKER_TIMEOUT) docker run --rm --no-healthcheck \
	--name $(PROJECT_NAME)-$$(head -c6 /dev/urandom | od -An -tx1 | tr -d ' \n' | cut -c1-8) \
	--memory=$(DOCKER_MEM) --cpus=$(DOCKER_CPUS) --cpu-shares=$(DOCKER_CPU_SHARES) \
	-v $(PWD):/app \
	-v $(GO_CACHE):/usr/local/share/go/pkg/mod \
	-v $(GO_BUILD):/usr/local/share/go/cache \
	-w /app -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false
GO_DOCKER := $(GO_DOCKER_RUN) casjaysdev/go:latest

.PHONY: build local release release-check docker test lint dev clean

build: clean
	@mkdir -p $(BINDIR) $(GO_CACHE) $(GO_BUILD)
	@echo "Building $(PROJECT_NAME) $(VERSION) for local and all supported platforms..."
	@$(GO_DOCKER_RUN) -e BUILD_LDFLAGS="$(LDFLAGS)" casjaysdev/go:latest sh -c '\
		set -e; \
		go mod tidy; \
		go mod download; \
		GOOS=$$(go env GOOS) GOARCH=$$(go env GOARCH) go build -trimpath -ldflags "$$BUILD_LDFLAGS" -o $(BINDIR)/$(PROJECT_NAME) ./src; \
		go build -trimpath -ldflags "$$BUILD_LDFLAGS" -o $(BINDIR)/$(PROJECT_NAME)-cli ./src/client; \
		for platform in $(PLATFORMS); do \
			OS=$${platform%/*}; ARCH=$${platform#*/}; EXT=""; \
			if [ "$$OS" = windows ]; then EXT=.exe; fi; \
			GOOS=$$OS GOARCH=$$ARCH go build -trimpath -ldflags "$$BUILD_LDFLAGS" -o $(BINDIR)/$(PROJECT_NAME)-$$OS-$$ARCH$$EXT ./src; \
			GOOS=$$OS GOARCH=$$ARCH go build -trimpath -ldflags "$$BUILD_LDFLAGS" -o $(BINDIR)/$(PROJECT_NAME)-cli-$$OS-$$ARCH$$EXT ./src/client; \
		done'
	@echo "Build complete: $(BINDIR)/"

local: clean
	@mkdir -p $(BINDIR) $(GO_CACHE) $(GO_BUILD)
	@echo "Building local binaries for $(PROJECT_NAME) $(VERSION)..."
	@$(GO_DOCKER_RUN) -e BUILD_LDFLAGS="$(LDFLAGS)" casjaysdev/go:latest sh -c '\
		set -e; go mod tidy; go mod download; \
		GOOS=$$(go env GOOS) GOARCH=$$(go env GOARCH) go build -trimpath -ldflags "$$BUILD_LDFLAGS" -o $(BINDIR)/$(PROJECT_NAME) ./src; \
		go build -trimpath -ldflags "$$BUILD_LDFLAGS" -o $(BINDIR)/$(PROJECT_NAME)-cli ./src/client'
	@echo "Local build complete: $(BINDIR)/"

release-check:
	@echo "$(VERSION)" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$$' >/dev/null || { echo "ERROR: make release requires a stable SemVer X.Y.Z in release.txt (got '$(VERSION)')" >&2; exit 78; }

release: release-check build
	@mkdir -p $(RELDIR)
	@printf '%s\n' '$(VERSION)' > $(RELDIR)/version.txt
	@for file in $(BINDIR)/$(PROJECT_NAME)-*; do \
		[ -f "$$file" ] || continue; \
		strip "$$file" 2>/dev/null || true; \
		cp "$$file" $(RELDIR)/; \
	done
	@sha256sum $(RELDIR)/$(PROJECT_NAME)-* > $(RELDIR)/sha256.txt
	@sha512sum $(RELDIR)/$(PROJECT_NAME)-* > $(RELDIR)/sha512.txt
	@tar --exclude='.git' --exclude='.github' --exclude='.gitea' --exclude='binaries' --exclude='releases' --exclude='*.tar.gz' -czf $(RELDIR)/$(PROJECT_NAME)-$(VERSION)-source.tar.gz .
	@gh release delete v$(VERSION) --yes 2>/dev/null || true
	@git tag -d v$(VERSION) 2>/dev/null || true
	@git push origin :refs/tags/v$(VERSION) 2>/dev/null || true
	@gh release create v$(VERSION) $(RELDIR)/* --title "v$(VERSION)" --notes "Release v$(VERSION)" --latest
	@echo "Release complete: v$(VERSION)"

docker:
	@docker buildx version >/dev/null 2>&1 || { echo "ERROR: docker buildx is required" >&2; exit 1; }
	@docker buildx create --name multiarch-builder --use 2>/dev/null || docker buildx use multiarch-builder
	@docker buildx build -f docker/Dockerfile --platform linux/amd64,linux/arm64 \
		--build-arg VERSION="$(VERSION)" --build-arg BUILD_DATE="$(BUILD_DATE)" \
		--build-arg BUILD_EPOCH="$(BUILD_EPOCH)" --build-arg COMMIT_ID="$(COMMIT_ID)" \
		--build-arg OFFICIAL_SITE="$(OFFICIAL_SITE)" \
		-t $(REGISTRY):$(VERSION) -t $(REGISTRY):latest .
	@docker buildx build -f docker/Dockerfile --platform linux/amd64 --load \
		--build-arg VERSION="$(VERSION)" --build-arg BUILD_DATE="$(BUILD_DATE)" \
		--build-arg BUILD_EPOCH="$(BUILD_EPOCH)" --build-arg COMMIT_ID="$(COMMIT_ID)" \
		--build-arg OFFICIAL_SITE="$(OFFICIAL_SITE)" \
		-t $(REGISTRY):$(VERSION) -t $(REGISTRY):latest .
	@docker run --rm --entrypoint sh $(REGISTRY):latest -c 'for c in bash curl tor i2pd tini; do command -v "$$c" || exit 1; done'
	@set -eu; \
		mkdir -p "$${TMPDIR:-/tmp}/$(PROJECT_ORG)"; \
		TEST_DIR=$$(mktemp -d "$${TMPDIR:-/tmp}/$(PROJECT_ORG)/$(INTERNAL_NAME)-XXXXXX"); \
		chmod 700 "$$TEST_DIR"; mkdir -p "$$TEST_DIR/config" "$$TEST_DIR/data"; \
		CONTAINER_NAME="$(PROJECT_NAME)-contract-$$(tr -dc 'a-z0-9' </dev/urandom | head -c8)"; \
		cleanup() { docker rm -f "$$CONTAINER_NAME" >/dev/null 2>&1 || true; rm -rf -- "$$TEST_DIR"; }; \
		trap cleanup EXIT INT TERM; \
		docker run -d --name "$$CONTAINER_NAME" -p 127.0.0.1::80 -e LISTEN=0.0.0.0 -e PORT=80 \
			-v "$$TEST_DIR/config:/config" -v "$$TEST_DIR/data:/data" $(REGISTRY):latest >/dev/null; \
		PORT=$$(docker port "$$CONTAINER_NAME" 80/tcp | sed -E 's|.*:||'); STATE=; \
		for attempt in $$(seq 1 180); do \
			if ! docker inspect -f '{{.State.Running}}' "$$CONTAINER_NAME" | grep -qx true; then docker logs "$$CONTAINER_NAME"; exit 1; fi; \
			BODY=$$(curl -q -fsS --max-time 3 -H 'Accept: application/json' "http://127.0.0.1:$$PORT/server/healthz" 2>/dev/null || true); \
			STATE=$$(printf '%s' "$$BODY" | sed -n 's/.*"tor":{[^}]*"status":"\([^"]*\)".*/\1/p'); \
			case "$$STATE" in healthy) break ;; error) docker logs "$$CONTAINER_NAME"; exit 1 ;; starting|unavailable|'') sleep 1 ;; *) docker logs "$$CONTAINER_NAME"; exit 1 ;; esac; \
		done; \
		if [ "$$STATE" != healthy ]; then \
			if [ "$${REQUIRE_OVERLAY:-0}" = 1 ]; then docker logs "$$CONTAINER_NAME"; echo 'ERROR: Tor did not become healthy within 180 seconds' >&2; exit 1; fi; \
			if curl -q -fsS --connect-timeout 5 --max-time 8 https://example.com/ >/dev/null 2>&1; then docker logs "$$CONTAINER_NAME"; echo "ERROR: outbound network is available but Tor did not become healthy (status: $${STATE:-unknown})" >&2; exit 1; fi; \
			case "$$STATE" in starting|unavailable) echo 'SKIP: no outbound network' >&2 ;; *) docker logs "$$CONTAINER_NAME"; echo 'ERROR: no valid Tor status from /server/healthz' >&2; exit 1 ;; esac; \
		fi

test:
	@mkdir -p $(GO_CACHE) $(GO_BUILD)
	@echo "Running Go tests with coverage enforcement..."
	@$(GO_DOCKER) sh -ec '\
		mkdir -p "$${TMPDIR:-/tmp}/$(PROJECT_ORG)"; \
		COVDIR=$$(mktemp -d "$${TMPDIR:-/tmp}/$(PROJECT_ORG)/$(INTERNAL_NAME)-XXXXXX"); \
		trap '\''[ -n "$$COVDIR" ] && rm -rf "$$COVDIR"'\'' EXIT; \
		export TMPDIR="$$COVDIR/tmp"; \
		mkdir -p "$$COVDIR/data" "$$TMPDIR"; \
		go mod download; \
		go vet ./...; \
		go test -v -cover ./... -args -test.gocoverdir="$$COVDIR/data"; \
		go tool covdata textfmt -i="$$COVDIR/data" -o="$$COVDIR/coverage.out"; \
		COVERAGE=$$(go tool cover -func="$$COVDIR/coverage.out" | awk "/^total:/ {gsub(\"%\", \"\", \$$3); print \$$3}"); \
		echo "Aggregate coverage: $$COVERAGE%"; \
		awk -v coverage="$$COVERAGE" "BEGIN { exit !(coverage >= 60) }" || { echo "ERROR: coverage is $$COVERAGE%; required: >= 60%" >&2; exit 1; }'
	@if [ "$(RUN_INTEGRATION)" = "1" ]; then bash tests/docker.sh; fi

lint:
	@mkdir -p $(GO_CACHE) $(GO_BUILD)
	@$(GO_DOCKER) sh -ec 'go mod download; go vet ./...; govulncheck ./...; staticcheck ./...'

dev:
	@mkdir -p $(GO_CACHE) $(GO_BUILD) "$${TMPDIR:-/tmp}/$(PROJECT_ORG)"
	@BUILD_DIR=$$(mktemp -d "$${TMPDIR:-/tmp}/$(PROJECT_ORG)/$(INTERNAL_NAME)-XXXXXX") && \
		$(GO_DOCKER_RUN) -v "$$BUILD_DIR:/build" casjaysdev/go:latest sh -c '\
			set -e; go mod tidy; \
			go build -buildvcs=false -o /build/$(PROJECT_NAME) ./src; \
			go build -buildvcs=false -o /build/$(PROJECT_NAME)-cli ./src/client' && \
		echo "Built: $$BUILD_DIR/$(PROJECT_NAME)" && echo "Built: $$BUILD_DIR/$(PROJECT_NAME)-cli"

clean:
	@rm -rf $(BINDIR) $(RELDIR)
