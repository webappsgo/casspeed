# Security

## Private results and accounts

Unshared speed-test results are private to the account that owns them or the anonymous browser session that created them. Results become public only when an owner explicitly creates a share link. Shared result pages and image exports omit the plain client IP and user agent. User profiles, devices, tokens, and history are owner-scoped.

Use HTTPS for deployments exposed to untrusted networks. Forwarded headers are trusted only from configured proxy peers. The server stores a one-way client IP hash rather than a plain IP address. API tokens are bearer credentials: user tokens are shown once, stored as SHA-256 hashes, and can be scoped and expired. The operator token is stored in `secrets.yml`, printed only when first generated, and compared without storing it in the database.

## Secrets and logs

Keep the configuration, data, and log directories private. `secrets.yml` is created with mode `0600`; it stores the operator token, security-report encryption key, and other generated secrets. Never include tokens, passwords, private keys, or report contents in logs or support requests. Security event logs contain only the metadata needed to investigate an event.

## Coordinated disclosure

Use `/server/security` for the current reporting instructions and `/server/security/policy` for the disclosure policy. Security reports are encrypted at rest and their public status page exposes only the tracking identifier, status, researcher comment, and disclosure date. When PGP publication is enabled, the public key is served at `/.well-known/pgp-key.asc`. The operator can review reports and rotate the project key in the authenticated administration area.

Please include the affected component, endpoint, severity, impact, and steps to reproduce. Do not access, modify, or retain other users' data. The service sends an acknowledgment only when configured and does not include report text in that message.

## Public security endpoints

- `/.well-known/security.txt` publishes the service's configured security contact and policy.
- `/.well-known/pgp-key.asc` is available only when public-key publication is enabled.
- `/server/security`, `/server/security/policy`, and `/server/security/thanks` provide the public security pages.
- `/server/security/report/{tracking_id}` requires the report's private status token.

Unknown `/.well-known/` entries return 404. Debug endpoints are available only when debug mode is enabled and still require the operator token.
