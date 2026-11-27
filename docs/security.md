# Security

## Private results and accounts

Unshared speed-test results are private to the account that owns them or the anonymous browser session that created them. Results become public only when an owner explicitly creates a share link. Shared result pages and image exports omit the plain client IP and user agent. User profiles, devices, tokens, and history are owner-scoped.

Use HTTPS for deployments exposed to untrusted networks. Forwarded headers are trusted only from configured proxy peers. The server stores a one-way client IP hash rather than a plain IP address. API tokens are bearer credentials: user tokens are shown once, stored as SHA-256 hashes, and can be scoped and expired. The operator token is stored in `secrets.yml`, printed only when first generated, and compared without storing it in the database.

## Account security

User and administrator accounts are separate. User passwords are never returned by the API. Login may require email verification and, when configured, a second factor. Users can configure authenticator-based two-factor authentication and manage passkeys under `/users/security`; recovery codes are displayed only when created or regenerated and are single-use. Passkey registration requires a secure origin and a password recheck, and a new passkey remains inactive until recovery-code setup is confirmed.

User tokens use the `usr_` prefix and administrator tokens use `adm_`. Token values are shown once; API listings contain metadata only. Administrators cannot view full user email addresses, passwords, recovery codes, or two-factor secrets. Account suspension revokes active user sessions. Private registration mode disables public registration while preserving admin-issued account setup links.

## Secrets and logs

Keep the configuration, data, and log directories private. `secrets.yml` is created with mode `0600`; it stores the operator token, security-report encryption key, and other generated secrets. Never include tokens, passwords, private keys, or report contents in logs or support requests. Security event logs contain only the metadata needed to investigate an event.

## Coordinated disclosure

Use `/.well-known/security.txt` for the configured reporting channels and `/server/security` for the human-readable instructions. The security page links to `/server/security/policy` and the report form at `/server/contact?security_id={id}`; the identifier comes from the current security contact information. Reports submitted through this security-specific form are encrypted at rest. Keep the private status token from the confirmation page; `/server/security/report/{tracking_id}` requires that token and exposes only the tracking identifier, status, researcher comment, and disclosure date. While a security keypair exists, the public key is served at `/.well-known/pgp-key.asc`. The operator can review reports and rotate the project key in the authenticated administration area.

Please include the affected component, endpoint, severity, impact, and steps to reproduce. Do not access, modify, or retain other users' data. The service sends an acknowledgment only when configured and does not include report text in that message.

## Public security endpoints

- `/.well-known/security.txt` publishes the service's configured security contact and policy.
- `/.well-known/pgp-key.asc` is available while the security keypair exists.
- `/.well-known/change-password` redirects signed-in users to password management and guests to password recovery.
- `/server/healthz` and `/api/v1/server/healthz` report component health without returning secrets or filesystem paths; JSON, text, and HTML representations are available according to the request path and content negotiation.
- `/server/security`, `/server/security/policy`, and `/server/security/thanks` provide the public security pages.
- `/server/security/report/{tracking_id}` requires the report's private status token.

Unknown `/.well-known/` entries return 404. Debug endpoints are available only when debug mode is enabled and still require the operator token.
