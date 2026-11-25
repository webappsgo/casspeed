# Server administration

The admin interface is isolated from public navigation. Its default root is `/server/administration/`; deployments may choose another `server.admin_path`. Do not add public links to this path or disclose it in public pages.

## Initial setup and authentication

Use the setup flow at `/server/{admin_path}/setup` only while the server is uninitialized. The first-start setup token is displayed once; its SHA-256 hash is retained in the private config directory until setup completes. Setup creates an administrator API token in the `adm_` format and returns the plaintext once. Store that token securely. Admin authentication and sessions are separate from regular user sessions. A regular user must not gain access to administration routes. Debug mode does not bypass authentication.

The administrator dashboard is at `/server/{admin_path}/`. Server management routes use direct section names such as `/settings`, `/ssl`, `/email`, `/scheduler`, `/logs`, `/backup`, `/updates`, `/info`, `/metrics`, `/network/tor`, `/network/geoip`, `/security/auth`, `/security/tokens`, and `/users`. The settings form updates listener mode and port plus test concurrency, thread, and duration limits in `server.yml`; restart the server for listener and test-engine changes to take effect. Do not place server settings beneath a `/config/` segment or beneath an administrator's personal profile path.

## Administration API

The implemented Admin API currently exposes `GET` and `PUT /api/v1/server/{admin_path}/settings`; both require an `adm_` bearer token. The operator token is generated into `secrets.yml` and printed once at first creation; the setup-created admin API token is also accepted and stored only as a SHA-256 hash. The live OpenAPI document is available at `/api/v1/server/swagger`. Browser form routes use the admin session and require CSRF protection; they should work without JavaScript. Other admin sections are informational pages and do not currently provide editing controls.

## Operational guidance

Protect the data and log directories, use HTTPS on untrusted networks, rotate exposed credentials, and keep backups outside the service data volume. Review audit logs after administrative changes. The admin interface does not replace OS-level access controls or backup testing.
