# Server administration

The admin interface is isolated from public navigation. Its default root is `/server/administration/`; deployments may choose another `server.admin_path`. Do not add public links to this path or disclose it in public pages.

## Initial setup and authentication

Use the setup flow at `/server/{admin_path}/setup` only while the server is uninitialized. Create a unique administrator credential and store it securely. Admin authentication and sessions are separate from regular user sessions. A regular user must not gain access to administration routes. Debug mode does not bypass authentication.

The administrator dashboard is at `/server/{admin_path}/`. Server management routes use direct section names such as `/settings`, `/ssl`, `/email`, `/scheduler`, `/logs`, `/backup`, `/updates`, `/info`, `/metrics`, `/network/tor`, `/network/geoip`, `/security/auth`, `/security/tokens`, and `/users`. Do not place server settings beneath a `/config/` segment or beneath an administrator's personal profile path.

## Administration API

Admin API routes are rooted at `/api/v1/server/{admin_path}/` and require admin authorization. The live OpenAPI document is available at `/api/v1/server/swagger`. Browser form routes require CSRF protection and should work without JavaScript.

## Operational guidance

Protect the data and log directories, use HTTPS on untrusted networks, rotate exposed credentials, and keep backups outside the service data volume. Review audit logs after administrative changes. The admin interface does not replace OS-level access controls or backup testing.
