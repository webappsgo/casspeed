# Configuration

CasSpeed loads YAML settings from `server.yml` in its resolved configuration directory. With no file present, it uses built-in defaults. Do not copy credentials into issue reports or commit a runtime configuration file.

## Listener and directories

The server configuration supports `server.address`, `server.port`, `server.fqdn`, `server.mode`, and `server.admin_path`. Defaults are `[::]`, an automatically selected 64xxx port, the local hostname, production mode, and `administration` for the admin path. The production container entrypoint overrides the address and port to `0.0.0.0:80` unless its environment variables override them.

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
  trusted_proxies:
    additional: []
    client_ip_header: auto
  pages:
    contact:
      enabled: true
      captcha: simple
      captcha_site_key: ""
      captcha_secret_key: ""
  security:
    reports:
      retention_days: 365
web:
  ui:
    theme: dark
  cors: "*"
  security:
    publish_pgp_key: true
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

Only trust reverse proxies that you operate. The `additional` list accepts trusted proxy addresses and CIDR ranges; proxy-provided client addresses are ignored for untrusted peers. Contact CAPTCHA supports `simple`, `recaptcha`, and `hcaptcha`; provider credentials are never returned by the form descriptor. The simple challenge works without JavaScript and without contacting a third party.

## Modes and secrets

Use `--mode production` for a deployed service. `--debug` enables diagnostics and does not bypass authentication. The administration path is configurable and should not be advertised on public pages.

The server creates `{config_dir}/secrets.yml` with mode `0600`. It stores the generated `server.token` operator credential and the security-report encryption key. The operator token uses the `adm_` prefix and is printed once when first generated; save it securely. The file is the durable copy, and subsequent starts do not print the token again. Never commit this file or paste its values into logs, documentation, or issue reports.

Public PGP key publication is enabled by default. Set `web.security.publish_pgp_key` to `false` to disable the endpoint; the matching private key remains encrypted in the configuration directory. Security report retention is controlled by `server.security.reports.retention_days`.
