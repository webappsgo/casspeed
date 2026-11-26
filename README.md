# CasSpeed

CasSpeed is a self-hosted, privacy-respecting internet speed testing service. It measures download and upload throughput, latency, jitter, and packet loss without advertisements, tracking, or paid features.

[![CI](https://github.com/webappsgo/casspeed/actions/workflows/ci.yml/badge.svg)](https://github.com/webappsgo/casspeed/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/webappsgo/casspeed)](https://github.com/webappsgo/casspeed/releases)
[![License](https://img.shields.io/github/license/webappsgo/casspeed)](LICENSE.md)
[![Documentation](https://readthedocs.org/projects/casapps-casspeed/badge/?version=latest)](https://casapps-casspeed.readthedocs.io)

## About

Run the server on your own infrastructure and test against that server. Anonymous visitors can test without creating an account. Results stay private until their owner creates a share link.

## Features

- Browser tests with live progress and measurements for latency, jitter, packet loss, download, and upload
- Anonymous testing and registered-user history
- Private device and API-token management
- Explicitly shared results with PNG and SVG exports
- A command-line client with an interactive terminal interface
- A self-hosted measurement service with no required external test API

## Production

### Docker

The published image is `ghcr.io/casapps/casspeed:latest`. Persist `/config` and `/data`; bind the internal HTTP listener to the Docker bridge for use behind a reverse proxy:

```sh
docker run -d --name casspeed --restart unless-stopped \
  -p 172.17.0.1:64580:80 \
  -v casspeed-config:/config \
  -v casspeed-data:/data \
  ghcr.io/casapps/casspeed:latest
```

The repository also provides `docker/docker-compose.yml`. Review its environment and volume settings before deploying it, then start it with `docker compose -f docker/docker-compose.yml up -d`.

### Server binary

Download the matching `casspeed-{os}-{arch}` release asset and run it in the foreground under your service supervisor. Windows binaries use the `.exe` suffix.

| Platform | Architectures |
|---|---|
| Linux | `amd64`, `arm64` |
| macOS | `amd64` (Intel), `arm64` (Apple Silicon) |
| Windows | `amd64`, `arm64` |
| FreeBSD | `amd64`, `arm64` |

For example, install the Linux `amd64` server binary:

```sh
curl -q -LSsf -o casspeed https://github.com/webappsgo/casspeed/releases/latest/download/casspeed-linux-amd64
chmod +x casspeed
sudo install -m 0755 casspeed /usr/local/bin/casspeed
```

macOS may require removing the quarantine attribute after downloading: `xattr -d com.apple.quarantine /usr/local/bin/casspeed`. Select the architecture-specific asset that matches the host.

### Docker Compose

The Compose file is [docker/docker-compose.yml](docker/docker-compose.yml). The default listener is bound to `172.17.0.1:64580`; configure a trusted reverse proxy to expose the service and provide HTTPS.

## Client

The `casspeed-cli` client supports the same eight OS and architecture combinations as the server. Release assets are named `casspeed-cli-{os}-{arch}` (with `.exe` on Windows).

```sh
curl -q -LSsf -o casspeed-cli https://github.com/webappsgo/casspeed/releases/latest/download/casspeed-cli-linux-amd64
chmod +x casspeed-cli
sudo install -m 0755 casspeed-cli /usr/local/bin/casspeed-cli
casspeed-cli --help
```

In an interactive terminal, run `casspeed-cli` to open the TUI. To run a test directly, specify a server:

```sh
casspeed-cli --server https://YOUR_SERVER test
casspeed-cli --server https://YOUR_SERVER --output json test
```

See the [CLI guide](https://casapps-casspeed.readthedocs.io/en/latest/cli/) for available commands and options.

## Configuration

The server creates its configuration in the operating system's configuration directory. On first run, it prints the one-time administrator setup credential; save it securely. Runtime configuration is managed through the server settings and administration interface. See the [configuration guide](https://casapps-casspeed.readthedocs.io/en/latest/configuration/).

## API

The versioned REST API is rooted at `/api/v1`. The server publishes its OpenAPI document at `/api/v1/server/swagger` and its Swagger UI at `/server/docs/swagger`.

| Endpoint | Purpose |
|---|---|
| `GET /server/healthz` | Server health |
| `POST /api/v1/speed-tests` | Start a speed test |
| `GET /api/v1/speed-tests` | List the authenticated user's history |
| `POST /api/v1/speed-tests/{id}/shares` | Explicitly share an owned result |
| `GET /api/v1/shares/{code}` | Read a public shared result |

Unshared results require their originating anonymous browser session or owning account. See the [API guide](https://casapps-casspeed.readthedocs.io/en/latest/api/) for authentication, ownership, and response details.

## Other

Public information and help pages are served below `/server/`. The browser interface includes account, device, token, test-history, and administration pages. Read-only GraphQL is available at `/api/v1/server/graphql`, with a browser explorer at `/server/docs/graphql`. MCP clients can connect to `/api/v1/server/mcp` using a scoped bearer token; see the [integration guide](https://casapps-casspeed.readthedocs.io/en/latest/integrations/).

## Development

### Prerequisites

- Docker with Buildx
- Make and Git

Go commands run in the `casjaysdev/go:latest` toolchain container. Do not build Go binaries directly on the host.

### Build and test

```sh
make dev       # Quick local server and CLI builds in the OS temp directory
make build     # Server and CLI for all eight OS/architecture combinations
make test      # Vet, unit tests, and coverage gate
make lint      # Vet and static analysis
make docker    # Multi-architecture image build
```

See the [development guide](https://casapps-casspeed.readthedocs.io/en/latest/development/) for source layout and contribution workflow.

## Disclaimer

CasSpeed measurements are estimates affected by the client device, network path, server capacity, and other traffic. They do not guarantee the performance a service provider delivers. This software is provided "as is," without warranty of any kind; evaluate it before production use and keep independent backups of important data.

## License

CasSpeed is distributed under the MIT License. See [LICENSE.md](LICENSE.md).
