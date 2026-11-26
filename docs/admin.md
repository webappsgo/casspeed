# Server administration

The admin interface is isolated from public navigation. Its default root is `/server/administration/`; deployments may choose another `server.admin_path`. Do not add public links to this path or disclose it in public pages.

## Initial setup and authentication

Use the setup flow at `/server/{admin_path}/setup` only while the server is uninitialized. The first-start setup token is displayed once; its SHA-256 hash is retained in the private config directory until setup completes. Setup creates an administrator API token in the `adm_` format and returns the plaintext once. Store that token securely. Admin authentication and sessions are separate from regular user sessions. A regular user must not gain access to administration routes. Debug mode does not bypass authentication.

The administrator dashboard is at `/server/{admin_path}/`. Server management routes use direct section names such as `/settings`, `/ssl`, `/email`, `/scheduler`, `/logs`, `/backup`, `/updates`, `/info`, `/metrics`, `/network/tor`, `/network/geoip`, `/security/auth`, `/security/tokens`, `/pages`, `/privacy`, `/tracking`, `/roles`, and `/users`. Page settings manage the about, help, contact, and terms content; privacy settings manage deployment disclosures, consent text, cookie descriptions, retention, and third-party services. Tracking settings manage analytics provider IDs and URLs; provider scripts load only after visitor consent. Privacy API controls are available at `/api/{api_version}/server/{admin_path}/pages/privacy`; tracking controls are at `/api/{api_version}/server/{admin_path}/tracking`. Both require an administrator bearer token. The settings form updates listener mode and port plus test concurrency, thread, and duration limits in `server.yml`; restart the server for listener and test-engine changes to take effect. Do not place server settings beneath a `/config/` segment or beneath an administrator's personal profile path.

## Regular-user account management

When multi-user accounts are enabled, `/server/{admin_path}/users` supports user search, paginated listing, direct account creation, and issuance of a one-use password-setup link. With SMTP available, direct creation emails the link; otherwise the administrator can copy it for delivery. The user chooses their password. `/server/{admin_path}/moderation/users` provides account status actions, session revocation, and confirmed deletion. Moderation views show masked email addresses and do not expose private account data or authentication secrets. Suspending a user revokes their active sessions.

Reusable registration codes are managed at `/server/{admin_path}/users/invites`; creation selects a regular-user role, expiry, and maximum uses (`0` means unlimited). The raw code is shown only when created. Administrators can list and revoke codes. The matching API routes are under `/api/v1/server/{admin_path}/users/invites` and require an administrator bearer token.

Public self-registration follows `server.users.registration.mode`: `open` permits the registration form, and `private` returns 404 for it. Administrator-issued setup links remain available in both modes. User account sessions and `usr_` tokens remain separate from administrator sessions and `adm_` tokens.

## Administration API

The Admin API exposes machine-readable server, page, privacy, tracking, role, and user-moderation settings under `/api/{api_version}/server/{admin_path}/`; requests require an `adm_` bearer token. The operator token is generated into `secrets.yml` and printed once at first creation; the setup-created admin API token is also accepted and stored only as a SHA-256 hash. The live OpenAPI document is available at `/api/{api_version}/server/swagger`. Browser form routes use the admin session and require CSRF protection; they work without JavaScript. Operational routes document their supported methods; status pages do not imply that they can change system services.

## Operational guidance

Protect the data and log directories, use HTTPS on untrusted networks, rotate exposed credentials, and keep backups outside the service data volume. Review audit logs after administrative changes. The admin interface does not replace OS-level access controls or backup testing.
