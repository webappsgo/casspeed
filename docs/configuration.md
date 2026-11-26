# Configuration

CasSpeed reads `server.yml` from its configuration directory and applies built-in defaults to omitted settings. Keep `server.yml` and `secrets.yml` private. Do not commit runtime configuration or copy secret values into support requests.

## Paths and listener

Command-line path flags take precedence over their matching environment variables, which take precedence over operating-system defaults:

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

`DATABASE_DIR` selects the database directory. `NO_COLOR` disables colored terminal output. The default listener is `[::]`; the port is chosen from the 64xxx range. The Docker entrypoint supplies its container listener address and port. `server.mode` is `production` or `development`; debug mode does not bypass authentication.

## YAML settings

This example shows the main settings. Omitted values use application defaults; consult `--help` and the generated configuration for the exact defaults of the running release.

```yaml
lang: en
server:
  address: "[::]"
  port: ""
  fqdn: speed.example.org
  mode: production
  admin_path: administration
  users:
    enabled: true
    registration:
      mode: open
      require_email_verification: true
      allowed_domains: []
      blocked_domains: []
      invite_expiration_days: 7
  database:
    driver: file
  cache:
    type: memory
    host: localhost
    port: 6379
    db: 0
    tls: false
    cluster: false
  notifications:
    email:
      smtp:
        host: ""
        port: 587
        username: ""
        password: ""
        tls: auto
      from:
        name: CasSpeed
        email: no-reply@example.org
  trusted_proxies:
    additional: []
    client_ip_header: auto
  pages:
    contact:
      enabled: true
      captcha: simple
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

User configuration belongs under `server.users`. Registration mode is `open` or `private`; private mode blocks public self-registration while preserving administrator invitation and direct-creation flows. Allowed and blocked email-domain lists are checked during registration. If verification is required but SMTP is not configured, the app treats addresses as verified and does not send email.

`server.database.driver` selects the database implementation. The default `file` value uses the application's SQLite storage. Cache type can be `none`, `memory`, `valkey`, or `redis`; URL schemes `valkey://`, `redis://`, `valkeys://`, and `rediss://` are supported. Cluster mode requires database index zero. Cache connection options include TLS, certificate paths, pool sizing, timeout, key prefix, and expiry. A credential-bearing `CACHE_URL` is saved in `secrets.yml`; subsequent starts use the saved URL rather than replacing it from the environment.

SMTP settings may be supplied in `server.notifications.email.smtp` and `server.notifications.email.from`, or through `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_TLS`, `SMTP_FROM_NAME`, and `SMTP_FROM_EMAIL`. With no SMTP server, notification records remain available in the application but email delivery is skipped.

Other `server` settings include contact recipients and webhooks, DPO details, contact-form CAPTCHA and abuse controls, SSL certificates and Let's Encrypt, scheduler tasks and timezone, rate limits, branding, and SEO. `web.security.publish_pgp_key` controls public PGP-key publication. Do not put secrets in public documentation or expose them through public configuration APIs.

## Secrets and operations

The service creates `{config_dir}/secrets.yml` with restrictive permissions. It stores generated credentials, encryption material, and any credential-bearing cache URL. The operator token uses the `adm_` prefix and is printed once when first generated; save it securely. The first administrator setup flow separately issues a one-time administrator API token. Never commit either secret or include it in logs or documentation.

Only trust reverse proxies that you operate. Add their IP addresses or CIDR ranges under `server.trusted_proxies.additional`; untrusted peers cannot choose the client address through forwarding headers. Use HTTPS on untrusted networks and protect configuration, data, backup, and log directories.
