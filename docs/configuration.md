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

User configuration belongs under `server.users`. Registration mode is `open` or `private`; private mode blocks public self-registration while preserving administrator invitation and direct-creation flows. Allowed and blocked email-domain lists are checked during registration. `roles.available` is the allowlist for account and invite roles; `roles.default` applies to new self-registrations. The permissions map associates configured role names with their regular-user permissions and never grants Server Admin access. The `auth` section controls password complexity and whether users may enable two-factor authentication. If verification is required but SMTP is not configured, the app treats addresses as verified and does not send email.

`server.database.driver` selects the database implementation. The default `file` value uses the application's SQLite storage. Cache type can be `none`, `memory`, `valkey`, or `redis`; URL schemes `valkey://`, `redis://`, `valkeys://`, and `rediss://` are supported. Cluster mode requires database index zero. Cache connection options include TLS, certificate paths, pool sizing, timeout, key prefix, and expiry. A credential-bearing `CACHE_URL` is saved in `secrets.yml`; subsequent starts use the saved URL rather than replacing it from the environment.

SMTP settings may be supplied in `server.notifications.email.smtp` and `server.notifications.email.from`, or through `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_TLS`, `SMTP_FROM_NAME`, and `SMTP_FROM_EMAIL`. With no SMTP server, notification records remain available in the application but email delivery is skipped.

Other `server` settings include contact recipients and webhooks, DPO details, contact-form CAPTCHA and abuse controls, SSL certificates and Let's Encrypt, scheduler tasks and timezone, rate limits, branding, and SEO. `web.security.publish_pgp_key` controls public PGP-key publication. Do not put secrets in public documentation or expose them through public configuration APIs.

The `/server/privacy` page and `/api/v1/server/privacy` response use `server.privacy` to show sale status, sharing, cookie descriptions, retention, and third-party services. The CCPA controls appear only when `server.privacy.data.sold` is true. Administrators can edit these settings at `/server/{admin_path}/privacy`; the authenticated API mirror is `/api/v1/server/{admin_path}/pages/privacy` (`GET` and `PATCH`). Operators may extend the built-in policy with `server.branding.content.privacy`; the built-in collection, usage, and security sections remain application content.

## Secrets and operations

The service creates `{config_dir}/secrets.yml` with restrictive permissions. It stores generated credentials, encryption material, and any credential-bearing cache URL. The operator token uses the `adm_` prefix and is printed once when first generated; save it securely. The first administrator setup flow separately issues a one-time administrator API token. Never commit either secret or include it in logs or documentation.

Only trust reverse proxies that you operate. Add their IP addresses or CIDR ranges under `server.trusted_proxies.additional`; untrusted peers cannot choose the client address through forwarding headers. Use HTTPS on untrusted networks and protect configuration, data, backup, and log directories.
