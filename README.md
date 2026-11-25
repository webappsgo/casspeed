# CasSpeed

[![CI](https://github.com/webappsgo/casspeed/actions/workflows/ci.yml/badge.svg)](https://github.com/webappsgo/casspeed/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/webappsgo/casspeed)](https://github.com/webappsgo/casspeed/releases)
[![License](https://img.shields.io/github/license/webappsgo/casspeed)](LICENSE.md)
[![Documentation](https://readthedocs.org/projects/casapps-casspeed/badge/?version=latest)](https://casapps-casspeed.readthedocs.io)

## About

CasSpeed is a self-hosted, privacy-respecting internet speed testing service. It measures download and upload throughput, latency, jitter, and packet loss without advertisements or tracking. Anonymous results are private to the originating session; a result becomes public only when its owner explicitly creates a share link.

## Features

- Browser speed tests with live progress and command-line tests for terminals or scripts
- Anonymous testing and registered-user history
- Private device and API-token management
- Explicitly shared results with PNG and SVG exports
- Self-hosted operation with no required external measurement service

## Production

Download the server binary and CLI client for your platform from [GitHub Releases](https://github.com/webappsgo/casspeed/releases). The server runs in the foreground by default and chooses an available port in the 64xxx range when no port is configured. See the [installation guide](https://casapps-casspeed.readthedocs.io/en/latest/installation/) for Docker, binary, and systemd instructions.

## Client

Run `casspeed-cli` for the interactive terminal interface. Use `casspeed-cli --server URL` to select a CasSpeed server. See the [CLI reference](https://casapps-casspeed.readthedocs.io/en/latest/cli/) for the complete command-line options.

## Configuration

The server creates its configuration in the OS-specific configuration directory on first run. Command-line flags and supported environment variables can override paths and listener settings. See [configuration reference](https://casapps-casspeed.readthedocs.io/en/latest/configuration/).

## API

The versioned API is rooted at `/api/v1`. Speed-test routes include `POST /speed-tests`, `GET /speed-tests/{id}`, and the test transfer endpoints. Unshared results require the originating session or owning account. See the [API reference](https://casapps-casspeed.readthedocs.io/en/latest/api/) for request and response details.

MCP clients can use `/api/v1/server/mcp` (also `/api/mcp` and `/mcp`) with the same bearer API token. The endpoint uses Streamable HTTP and exposes OpenAPI operations as tools; see the [integration guide](https://casapps-casspeed.readthedocs.io/en/latest/integrations/#mcp-clients).

Read-only GraphQL is available at `/api/v1/server/graphql` (alias `/api/graphql`), with the local GraphiQL explorer at `/server/docs/graphql`. It serves public health, the caller's owned results, and explicitly shared results; it has no mutations.

## Other

Public service pages are available under `/server/`, including `/server/about`, `/server/privacy`, `/server/terms`, `/server/help`, and `/server/healthz`. Swagger UI is at `/server/docs/swagger`; the OpenAPI document is at `/api/v1/server/swagger`.

## Development

Build the server and CLI for supported platforms with `make build`; run the project test and coverage gate with `make test`. Go commands run in the project toolchain container. See the [development guide](https://casapps-casspeed.readthedocs.io/en/latest/development/).

## Disclaimer

CasSpeed measurements are estimates affected by the client device, network path, server capacity, and other traffic. They are not a guarantee of service-provider performance.

## License

CasSpeed is distributed under the MIT License. See [LICENSE.md](LICENSE.md).
