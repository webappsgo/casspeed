# Installation

CasSpeed ships as a server binary, a terminal client, and a Docker image. See [GitHub Releases](https://github.com/webappsgo/casspeed/releases) for published artifacts.

## Docker

```sh
docker run --rm --name casspeed -p 64580:80 \
  -v casspeed-config:/config \
  -v casspeed-data:/data \
  ghcr.io/casapps/casspeed:latest
```

Persist the application data directory for database durability. Configure the published port to match the listener selected by the server. The container runs the server in the foreground; Docker restart policies or an orchestrator manage its lifecycle.

## Binary

Download the server and, if desired, CLI binaries for your OS and architecture. Run the server in the foreground under a service manager. The server selects an available port in the 64xxx range unless configured otherwise.

```sh
./casspeed --help
./casspeed --status
./casspeed
```

## systemd

Use a dedicated unprivileged service account and a systemd unit with `Type=simple`. Run the binary in the foreground and configure its data, configuration, and log directories using supported flags or environment variables. Avoid daemon mode; process supervision belongs to systemd.

## Build from source

Docker and Make are required. Builds use the project's Go toolchain container.

```sh
git clone https://github.com/webappsgo/casspeed.git
cd casspeed
make build
```

The server and CLI outputs are in the ignored `binaries/` directory. See [Development](development.md) for testing and toolchain details.
