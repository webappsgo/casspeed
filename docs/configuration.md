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
| `--i2p` | `I2P_ENABLED` |

`DATABASE_DIR` selects the database directory. `NO_COLOR` disables colored terminal output. The default listener is `[::]`; the port is chosen from the 64xxx range. The Docker entrypoint supplies its container listener address and port. `server.mode` is `production` or `development`; debug mode does not bypass authentication.

## Environment variables

| Variable | When it applies | Description |
|---|---|---|
| `CONFIG_DIR`, `DATA_DIR`, `CACHE_DIR`, `LOG_DIR`, `BACKUP_DIR`, `PID_FILE` | Every startup | Override the matching directory or PID file path; the matching CLI flag takes precedence |
| `DATABASE_DIR` | Every startup | SQLite database directory |
| `PORT`, `LISTEN`, `MODE` | Every startup | Listener port, listener address, and runtime mode; CLI flags take precedence |
| `DEBUG` | Every startup | Explicitly enables debug diagnostics when set to a truthy value; `--debug` takes precedence |
| `DOMAIN` | Every startup | Comma-separated public hostnames for URL and origin resolution |
| `I2P_ENABLED` | Every startup | Enable or disable the I2P eepsite; default is enabled in containers and disabled elsewhere |
| `NO_COLOR`, `TERM` | Every startup | Control terminal color output; `TERM=dumb` disables ANSI output |
| `LC_ALL`, `LANG` | CLI | Select the CLI output language when `--lang` is not provided |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_TLS`, `SMTP_FROM_NAME`, `SMTP_FROM_EMAIL` | Every startup | Configure email delivery; secrets should be supplied through the deployment's secret mechanism |
| `APPLICATION_NAME`, `APPLICATION_TAGLINE` | First run | Seed initial branding values; later changes belong in configuration or the admin interface |
| `DATABASE_DRIVER`, `DATABASE_URL`, `CACHE_URL` | First run | Seed the database and cache connection settings; saved values take precedence on later starts |
| `CASSPEED_BACKUP_KEY` | Backup and restore commands | 64-character hexadecimal encryption key; keep it separate from backup files |
| `CASSPEED_TOKEN` | CLI | Fallback API token after `--token` and `--token-file`, before the saved user token |

`HOSTNAME` is a fallback input when resolving the server's public hostname. The service also uses operating-system variables such as `ProgramData` and `AppData` when selecting Windows paths.

The initial `--config`, `--data`, `--cache`, `--log`, and `--backup` paths use OS-specific defaults. Settings are merged from `server.yml`, ordered files under `yaml.d/`, and `secrets.yml`; the generated secrets file is private and credential-bearing connection strings are not meant to be copied into public configuration examples.

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
  api_version: v1
  branding:
    title: CasSpeed
    tagline: A privacy-respecting speed test
    content:
      about: ""
      privacy: ""
      terms: ""
  users:
    enabled: true
    registration:
      mode: open
      require_email_verification: true
      allowed_domains: []
      blocked_domains: []
      invite_expiration_days: 7
    roles:
      available: [admin, user]
      default: user
      permissions:
        admin: [read, write, delete]
        user: [read, own_profile, own_api_tokens]
    auth:
      require_2fa: false
      allow_2fa: true
      password_min_length: 8
      password_require_uppercase: false
      password_require_number: false
      password_require_special: false
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
      success_message: Thank you for your message.
    help:
      content: ""
      mcp: ""
  security:
    reports:
      retention_days: 365
  privacy:
    data:
      sold: false
      stored_on_server: true
      sharing:
        - condition: analytics
          when: Tracking is configured and the visitor consents
          data: Anonymized usage information
        - condition: email
          when: SMTP is configured
          data: Email address and message content
    retention:
      period: Account data remains while the account is active.
      export_available: true
      deletion_available: true
    consent:
      show_until_acknowledged: true
      message: We use essential cookies and, with consent, preference and analytics cookies. We never sell data.
      message_if_sold: Data may be shared or sold as described in the privacy policy.
      policy:
        text: Privacy Policy
        url: /server/privacy
        version: "1"
      buttons:
        decline: Decline
        accept: I Agree
      position: bottom
      show_preferences: true
      preferences_text: Manage Preferences
    cookies:
      essential:
        enabled: true
        description: Required for authentication and site security.
      preferences:
        enabled: true
        description: Remembers theme, language, and interface preferences.
      analytics:
        enabled: true
        description: Helps us understand how visitors use the site.
        description_suffix_not_sold: Analytics data is anonymized and never sold.
        description_suffix_sold: Analytics data may be shared with third parties.
    third_party:
      services: []
  tracking:
    type: none
    id: ""
    url: ""
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

## Configuration sections

The YAML example above highlights commonly configured values; it is not the full schema. Configuration is merged from built-in defaults, `server.yml`, `yaml.d/*.yml` in filename order, and then `secrets.yml`. The main key groups are:

| Keys | Purpose |
|---|---|
| `server.address`, `server.port`, `server.fqdn`, `server.api_version`, `server.baseurl`, `server.mode`, `server.pidfile`, `server.daemonize` | This node's listener and runtime identity |
| `server.database`, `server.cache`, `server.ssl`, `server.trusted_proxies`, `server.cluster` | Storage, cache, TLS, proxy trust, and cluster settings |
| `server.branding`, `server.seo`, `web.ui` | Site title, content, metadata, and theme |
| `web.*`, `server.cors`, `server.csrf`, `server.url_detection`, `server.compression`, `server.healthz`, `server.i18n` | Web behavior, browser security, URL handling, health aliases, and languages |
| `server.pages`, `server.contact` | Public page content, contact form fields, CAPTCHA, and abuse controls |
| `server.privacy`, `server.compliance`, `server.tracking` | Privacy disclosures, consent, compliance, and consent-gated analytics |
| `server.security`, `server.rate_limit`, `server.geoip`, `server.limits`, `server.tokens`, `data.*` | Security controls, abuse limits, GeoIP, and token policy |
| `server.logs`, `server.metrics`, `server.notifications` | Logging, telemetry, and notification delivery |
| `server.tor`, `server.i2p` | Optional overlay network listeners and service settings |
| `server.maintenance`, `server.scheduler`, `server.update`, `server.auto_update`, `server.backup`, `server.restore`, `cli` | Scheduled work, maintenance, updates, backups, restore, and CLI defaults |
| `server.auth`, `server.users`, `server.orgs`, `server.session`, `server.admin`, `server.admin_path` | Authentication, regular users, sessions, and administration |
| `test.*` | Speed-test duration, concurrency, data chunk size, and retention |

The server writes node-specific values to `server.yml`, area settings to `yaml.d/`, and credentials to `secrets.yml`. Environment variables for database and cache connection URLs seed configuration on first run; later starts use the saved values. Do not put credentials into `server.yml` when the application can keep them in `secrets.yml`.

User configuration belongs under `server.users`. Registration mode is `open` or `private`; private mode blocks public self-registration while preserving administrator invitation and direct-creation flows. Allowed and blocked email-domain lists are checked during registration. `roles.available` is the allowlist for account and invite roles; `roles.default` applies to new self-registrations. The permissions map associates configured role names with their regular-user permissions and never grants Server Admin access. The `auth` section controls password complexity and whether users may enable two-factor authentication. If verification is required but SMTP is not configured, the app treats addresses as verified and does not send email.

`server.database.driver` selects the database implementation. The default `file` value uses the application's SQLite storage. Cache type can be `none`, `memory`, `valkey`, or `redis`; URL schemes `valkey://`, `redis://`, `valkeys://`, and `rediss://` are supported. Cluster mode requires database index zero. Cache connection options include TLS, certificate paths, pool sizing, timeout, key prefix, and expiry. A credential-bearing `CACHE_URL` is saved in `secrets.yml`; subsequent starts use the saved URL rather than replacing it from the environment.

SMTP settings may be supplied in `server.notifications.email.smtp` and `server.notifications.email.from`, or through `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_TLS`, `SMTP_FROM_NAME`, and `SMTP_FROM_EMAIL`. With no SMTP server, notification records remain available in the application but email delivery is skipped.

Other `server` settings include contact recipients and webhooks, DPO details, contact-form CAPTCHA and abuse controls, SSL certificates and Let's Encrypt, scheduler tasks and timezone, rate limits, branding, and SEO. `web.security.publish_pgp_key` controls public PGP-key publication. Do not put secrets in public documentation or expose them through public configuration APIs.

The `/server/privacy` page and `/api/{api_version}/server/privacy` response use `server.privacy` to show sale status, sharing, cookie descriptions, retention, and third-party services. The CCPA controls appear only when `server.privacy.data.sold` is true. Administrators can edit these settings at `/server/{admin_path}/privacy`; the authenticated API mirror is `/api/{api_version}/server/{admin_path}/pages/privacy` (`GET` and `PATCH`). Operators may extend the built-in policy with `server.branding.content.privacy`; the built-in collection, usage, and security sections remain application content.

`server.api_version` selects `v1` or `v2` for the canonical REST prefix; the default is `v1`. The compatibility alias `/api` remains available for explicitly documented unversioned endpoints.

`server.tracking` supports `none`, `google`, `matomo`, `piwik`, `owa`, `fathom`, `plausible`, `umami`, `simple`, and `cloudflare`. Provider-specific ID and URL validation is applied at startup and when saved from `/server/{admin_path}/tracking` or its authenticated API mirror `/api/{api_version}/server/{admin_path}/tracking`. Analytics markup and provider hosts are added only after analytics consent. The same-origin `/server/tracking.js` endpoint returns 404 unless the provider is configured and the visitor has opted in; tracking is suppressed on `.onion` and `.i2p` requests.

## Secrets and operations

The service creates `{config_dir}/secrets.yml` with restrictive permissions. It stores generated credentials, encryption material, and any credential-bearing cache URL. The operator token uses the `adm_` prefix and is printed once when first generated; save it securely. The first administrator setup flow separately issues a one-time administrator API token. Never commit either secret or include it in logs or documentation.

Only trust reverse proxies that you operate. Add their IP addresses or CIDR ranges under `server.trusted_proxies.additional`; untrusted peers cannot choose the client address through forwarding headers. Use HTTPS on untrusted networks and protect configuration, data, backup, and log directories.
