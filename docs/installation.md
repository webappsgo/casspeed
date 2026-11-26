# Installation

CasSpeed is available as a Docker image and as server and CLI binaries. Pick one installation method and keep runtime configuration and data in persistent storage.

## Docker Compose

The production Compose file runs the server with a Valkey cache. It publishes HTTP on the Docker bridge address `172.17.0.1:64580`, intended for a reverse proxy on the host. Configure HTTPS at that proxy and restrict direct access to the bridge listener.

```sh
docker compose -f docker/docker-compose.yml pull
docker compose -f docker/docker-compose.yml up -d
docker compose -f docker/docker-compose.yml ps
```

Compose volume paths are relative to `docker/`. Keep `docker/volumes/config` and `docker/volumes/data` persistent and protected; the data volume also contains the Valkey store. Back up the config and data volumes together. For development, use `docker/docker-compose.dev.yml`; it runs the `:devel` image in development mode. The test Compose file is reserved for automated tests.

## Server and CLI binaries

Download the matching server asset and, optionally, the CLI asset from [GitHub Releases](https://github.com/webappsgo/casspeed/releases). Names include the operating system and architecture:

| Platform | Architectures | Server asset | CLI asset |
|---|---|---|---|
| Linux | `amd64`, `arm64` | `casspeed-linux-{arch}` | `casspeed-cli-linux-{arch}` |
| macOS | `amd64`, `arm64` | `casspeed-darwin-{arch}` | `casspeed-cli-darwin-{arch}` |
| Windows | `amd64`, `arm64` | `casspeed-windows-{arch}.exe` | `casspeed-cli-windows-{arch}.exe` |
| FreeBSD | `amd64`, `arm64` | `casspeed-freebsd-{arch}` | `casspeed-cli-freebsd-{arch}` |

On Linux or FreeBSD, install the server binary and install it as a service:

```sh
chmod 0755 casspeed
sudo install -m 0755 casspeed /usr/local/bin/casspeed
sudo casspeed --service --install
```

The service manager runs the server in the foreground and owns its lifecycle. The first start creates the runtime configuration and prints the one-time operator setup credential; save it securely. Use `casspeed --help`, `casspeed --service help`, and `casspeed --maintenance help` for the commands available on your platform. Do not run the server with `--daemon`; service managers and containers supervise foreground processes.

Install the CLI separately if needed:

```sh
chmod 0755 casspeed-cli
sudo install -m 0755 casspeed-cli /usr/local/bin/casspeed-cli
casspeed-cli --help
```

The CLI can connect to a self-hosted server and run tests, inspect health, and access authenticated history. See the [CLI reference](cli.md).

## First-run setup

Open the server address in a browser and follow the administrator setup page using the one-time setup credential. The wizard creates the initial administrator API token and displays it once. Store it in a password manager. The operator token and generated secrets are stored in the private configuration directory with restrictive permissions.

## Build from source

Docker with Buildx, Make, and Git are required. The project uses the `casjaysdev/go:latest` toolchain image for Go commands.

```sh
git clone https://github.com/webappsgo/casspeed.git
cd casspeed
make build
```

Build outputs are written under the ignored `binaries/` directory. See [Development](development.md) for the project toolchain and verification commands.
