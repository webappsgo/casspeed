# casspeed - Project Idea

## Purpose

CasSpeed is a self-hosted internet speed testing service - a free, open-source alternative to speedtest.net. It provides accurate, privacy-respecting speed testing with no ads, no tracking, and no feature gating. All features are completely free and available to all users.

## Target Users

- Home users wanting to test and track internet speeds over time
- Network administrators monitoring connection quality across devices
- Developers needing speed test automation via API for CI/CD or monitoring
- Self-hosters wanting a privacy-respecting speed testing solution

## Features

- **Multi-threaded Speed Tests**: Download and upload tests using parallel connections for accurate results
- **Real-time Progress**: WebSocket-based live updates during test execution (ping, download, upload phases)
- **Shareable Results**: Generate share codes with PNG/SVG image export and Open Graph meta tags
- **Multi-user Support**: User accounts with device tracking and test history
- **API Tokens**: Programmatic access for automation and scripting
- **CLI Client**: Terminal UI (TUI) mode with real-time graphs using bubbletea
- **Privacy-First**: Client IPs are hashed before storage, never stored in plain text
- **Docker Support**: Multi-platform container deployment

## Data Models

**SpeedTest**: Single speed test result
- id, user_id (optional), device_id (optional), timestamp
- download_mbps, upload_mbps, ping_ms, jitter_ms, packet_loss
- client_ip_hash, user_agent, server_id
- share_code (optional), share_views

**User**: Registered user account
- id, username, email, share_show_username

**Device**: User's device for history tracking
- id, user_id, name, last_seen

**APIToken**: API access token
- id, user_id, token (hashed), name, last_used

## Business Rules

**Speed Testing**:
- Tests measure download, upload, latency, jitter, and packet loss
- Multi-threaded connections for accurate throughput measurement
- Test duration is configurable (default: 10 seconds per phase)
- Results stored with optional user/device association

**User Management**:
- Username: 3-32 characters, alphanumeric and underscores
- Email: Valid format, unique per account
- Device names: 1-64 characters, user-defined
- API tokens: prefix `key_`, 32 character hex value

**Sharing**:
- Share codes: 8-character alphanumeric (base62)
- Share pages include Open Graph meta for social media previews
- Image export (PNG/SVG) uses same styling as web UI

**Data Retention**:
- Anonymous test results: 30 days default (configurable)
- Authenticated user results: indefinite
- Share codes: valid while test result exists
- Deleted user data: immediately removed

**Privacy**:
- IP addresses are hashed for privacy (never stored in plain text)
- Anonymous users can run tests but cannot save history

## Endpoints

**Speed Test**:
- Start test: Initiate a new speed test, returns test ID
- WebSocket status: Real-time progress updates during test
- Download test: Endpoint for download speed measurement
- Upload test: Endpoint for upload speed measurement
- Get result: Retrieve completed test result by ID
- Get history: List user's test history with pagination

**Share**:
- Get share page: HTML page for shared result (with OG meta)
- Get share PNG: PNG image of test result
- Get share SVG: SVG image of test result
- Create share: Generate share code for a test result

**User** (per PART 33):
- Register, Login, Profile, Devices, API tokens

**Admin** (per PART 17):
- Dashboard, Settings, User management, Statistics

## Data Sources

- SQLite database (default) - stores all test results, users, devices
- PostgreSQL/MySQL (cluster mode) - for high-availability deployments
- No external API dependencies - all tests run locally

Data Location:
- Config: `{config_dir}/casapps/casspeed/server.yml`
- Database: `{data_dir}/casapps/casspeed/casspeed.db`
- Logs: `{log_dir}/casapps/casspeed/`
- Backups: `{backup_dir}/casapps/casspeed/`
