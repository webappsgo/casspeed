# casspeed

A free self-hosted alternative to speedtest.net with all the features but free and opensource with no ads, tracking, and no feature gating.

[![Documentation](https://readthedocs.org/projects/casapps-casspeed/badge/?version=latest)](https://casapps-casspeed.readthedocs.io)

## Features

- 🚀 Multi-threaded download/upload tests
- 📊 Real-time WebSocket progress updates
- 🔗 Shareable test results with PNG/SVG export
- 👥 Multi-user support with device tracking
- 🔐 API token authentication
- 📱 Responsive dark theme web UI
- 💻 CLI client with real-time display and graphs
- 🐳 Docker and multi-platform support

## Quick Start

### Docker

```bash
docker-compose up -d
```

Visit `http://localhost:64580` to access the web interface.

### Binary

Download from releases and run:

```bash
./casspeed
```

Default port: 64580 (random port per spec)

## CLI Client

```bash
casspeed-cli                  # Launch TUI mode
casspeed-cli --server URL     # Connect to custom server
```

## Documentation

Full documentation available at [https://casapps-casspeed.readthedocs.io](https://casapps-casspeed.readthedocs.io)

## Building from Source

```bash
make build
```

Requires Docker (all builds use `golang:alpine` container).

## License

MIT License - see LICENSE.md for details.
