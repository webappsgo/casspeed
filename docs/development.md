# Development

CasSpeed is a Go project. Docker, Make, and Git are required; the supported Go toolchain runs in the `casjaysdev/go:latest` container.

## Build and validate

```sh
make build       # debug server and CLI binaries for all configured platforms
make test        # vet, static analysis, vulnerability and shell checks, coverage, and container smoke tests
make docker      # build and load a host-platform image locally; does not push
make release     # release artifacts for supported platforms
```

`make test` runs Go vet, Staticcheck, govulncheck, shell checks, Go tests with coverage, and the isolated basic smoke suite. Temporary coverage output is removed when the suite exits. `make docker` uses Buildx to build and load the current host platform as `ghcr.io/casapps/casspeed:latest`; it does not push an image.

Use the repository's test/lint wrapper for direct test and lint commands. Run formatting in the project toolchain container. Do not run Go builds or binaries directly on the host.

## Run the application locally in a container

Build the local host-platform image, then start it with private persistent Docker volumes:

```sh
make docker
docker run --rm --name casspeed-development \
  -p 127.0.0.1:64580:80 \
  -v casspeed-development-config:/config \
  -v casspeed-development-data:/data \
  -e MODE=development -e DEBUG=true \
  ghcr.io/casapps/casspeed:latest
```

Open `http://127.0.0.1:64580` on the development machine. This is a local-development URL; production deployments should use HTTPS through a trusted reverse proxy.

## Source layout

- `src/`: server, CLI, configuration, auth, storage, and supporting packages
- `src/server/template/` and `src/server/static/`: embedded web templates and assets
- `docker/`: production and development container definitions
- `docs/`: MkDocs and Read the Docs content only
- `tests/`: test and isolated-environment scripts

Runtime databases, logs, test outputs, and temporary build products belong in project-scoped OS temporary directories or the configured runtime directories, never in the source tree. `binaries/` is an ignored build output for the documented Make targets.

## Contribution workflow

Read `AI.md`, `IDEA.md`, and applicable project rules before making changes. Update user documentation with behavior changes. Run the relevant test and lint gates, review the full diff, and document every changed file in `.git/COMMIT_MESS` before using the repository's `gitcommit` workflow. CI runs on GitHub Actions and the other configured providers.
