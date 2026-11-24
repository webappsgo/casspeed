# Configuration

CasSpeed loads YAML settings from `server.yml` in its resolved configuration directory. With no file present, it uses built-in defaults. Do not copy credentials into issue reports or commit a runtime configuration file.

## Listener and directories

The server configuration supports `server.address`, `server.port`, `server.fqdn`, `server.mode`, and `server.admin_path`. Defaults are `[::]`, an automatically selected 64xxx port, the local hostname, production mode, and `administration` for the admin path.

Directory flags take precedence over matching environment variables, which take precedence over OS-specific defaults:

| Flag | Environment variable |
|---|---|
| `--config` | `CONFIG_DIR` |
| `--data` | `DATA_DIR` |
| `--cache` | `CACHE_DIR` |
| `--log` | `LOG_DIR` |
| `--backup` | `BACKUP_DIR` |
| `--pid` | `PID_FILE` |
| `--address` | `LISTEN` |
| `--port` | `PORT` |
| `--mode` | `MODE` |

`DATABASE_DIR` selects the database directory. `NO_COLOR` disables colored terminal output.

## YAML settings

The following keys are currently accepted by the application:

```yaml
server:
  port: 64580
  address: "[::]"
  fqdn: localhost
  mode: production
  admin_path: administration
  pidfile: true
  daemonize: false
  branding:
    title: CasSpeed
    tagline: Self-hosted speed testing
    description: Measure internet connection quality
  rate_limit:
    enabled: true
    requests: 120
    window: 60
  database:
    driver: file
  ssl:
    enabled: false
web:
  ui:
    theme: dark
  cors: "*"
test:
  max_concurrent: 3
  min_interval: 5
  default_duration: 10
  max_threads: 8
  results_retention: 30
  chunk_size: 1048576
  timeout: 60
```

`server.ssl` also accepts certificate/key paths, minimum TLS version, and Let's Encrypt settings. The scheduler accepts named tasks and their schedules. Defaults are defined in the binary and may differ from an older installation's file. The application currently uses SQLite storage; other database driver values are not a guarantee of a supported backend.

## Modes and secrets

Use `--mode production` for a deployed service. `--debug` enables diagnostics and does not bypass authentication. Backup encryption keys are supplied through `CASSPEED_BACKUP_KEY`; protect them as secrets. The admin path is intentionally not advertised on public pages.
