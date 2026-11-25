# Development

CasSpeed is a Go project. Docker, Make, and Git are required; the supported Go toolchain runs in the `casjaysdev/go:latest` container.

## Build and validate

```sh
make build       # server and CLI for supported platforms
make test        # go vet, package tests, and aggregate coverage gate
make docker      # multi-architecture image build; does not push or load it locally
make dev         # local platform binaries in a project-scoped temp directory
```

Use the repository's test/lint wrapper for direct test and lint commands. Run formatting in the project toolchain container. Do not run Go builds or binaries directly on the host.

## Source layout

- `src/`: server, CLI, configuration, auth, storage, and supporting packages
- `src/server/template/` and `src/server/static/`: embedded web templates and assets
- `docker/`: production and development container definitions
- `docs/`: MkDocs and Read the Docs content only
- `tests/`: test and isolated-environment scripts

Runtime databases, logs, test outputs, and temporary build products belong in project-scoped OS temporary directories or the configured runtime directories, never in the source tree. `binaries/` is an ignored build output for the documented Make targets.

## Contribution workflow

Read `AI.md`, `IDEA.md`, and applicable project rules before making changes. Update user documentation with behavior changes. Run the relevant test and lint gates, review the full diff, and document every changed file in `.git/COMMIT_MESS` before using the repository's `gitcommit` workflow. CI runs on GitHub Actions and the other configured providers.
