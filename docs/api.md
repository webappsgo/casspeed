# HTTP API

CasSpeed's canonical REST base is `/api/{api_version}`, selected by `server.api_version` (`v1` by default; `v1` and `v2` are supported). Routes below use `v1` as the default example; substitute the configured version when it is `v2`. The running server publishes its OpenAPI contract at `/api/{api_version}/server/swagger`; Swagger UI is available at `/server/docs/swagger`. JSON responses use an `ok` field and structured data or errors. Error bodies must not expose filesystem paths, credentials, or private user data.

## Speed tests and sharing

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/api/v1/speed-tests` | Start an anonymous or authenticated test |
| `GET` | `/api/v1/speed-tests/{id}/status` | Connect to the test's WebSocket progress/result channel |
| `GET` | `/api/v1/speed-tests/{id}/download` | Download bounded measurement data |
| `POST` | `/api/v1/speed-tests/{id}/uploads` | Submit bounded upload measurement data |
| `GET` | `/api/v1/speed-tests/{id}` | Read an owned private result |
| `GET` | `/api/v1/speed-tests` | List the authenticated user's history |
| `POST` | `/api/v1/speed-tests/{id}/shares` | Explicitly create a public share link |
| `GET` | `/api/v1/shares/{code}` | Read a shared result |
| `GET` | `/api/v1/shares/{code}/images/png` | Export a shared result as PNG |
| `GET` | `/api/v1/shares/{code}/images/svg` | Export a shared result as SVG |

An unshared result is visible only to its owning account or the anonymous browser session that started it. A share link makes the result public. Shared responses omit the plain client IP and user agent. Treat the share URL as public.

## Accounts

The browser registration route is `/server/auth/register`; public registration is available only when `users.enabled` is true and `users.registration.mode` is `open`. Login, logout, registration, and password recovery are also available as API operations:

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/api/v1/server/auth/register` | Register when open registration is enabled |
| `POST` | `/api/v1/server/auth/login` | Start an account session |
| `POST` | `/api/v1/server/auth/logout` | Revoke the current account session |
| `POST` | `/api/v1/server/auth/password/forgot` | Request a password reset without revealing whether an account exists |
| `POST` | `/api/v1/server/auth/password/reset` | Use a valid one-time reset token |
| `POST` | `/api/v1/server/auth/verify` | Verify an email address with a one-time token |
| `POST` | `/api/v1/server/auth/2fa` | Complete a pending TOTP login challenge |
| `POST` | `/api/v1/server/auth/recovery/use` | Complete a pending login with a one-time recovery code |
| `POST` | `/api/v1/server/auth/passkey/challenge` | Start passkey sign-in |
| `POST` | `/api/v1/server/auth/passkey/verify` | Verify a passkey sign-in response |
| `GET` / `POST` | `/api/v1/server/auth/invite/user/{token}` | Inspect or accept a user invitation |
| `GET` | `/api/v1/users` | Read the current user's profile |
| `PATCH` | `/api/v1/users` | Update the current user's profile |
| `GET` | `/api/v1/users/settings` | Read the current user's settings |
| `GET` | `/api/v1/users/security` | Read the current user's security summary |
| `PATCH` | `/api/v1/users/email` | Request an account email change |
| `GET` | `/api/v1/users/security/2fa` | Read authenticator-based two-factor status |
| `POST` | `/api/v1/users/security/2fa/enable` | Enable two-factor authentication after code confirmation |
| `POST` | `/api/v1/users/security/2fa/disable` | Disable two-factor authentication after reauthentication |
| `GET` | `/api/v1/users/security/recovery` | Read recovery-code status |
| `POST` | `/api/v1/users/security/recovery/regenerate` | Regenerate recovery codes |
| `GET` / `POST` | `/api/v1/users/security/passkeys` | List passkeys or begin registration |
| `DELETE` | `/api/v1/users/security/passkeys/{passkey_id}` | Revoke an owned passkey |
| `GET` | `/api/v1/users/devices` | List the current user's devices |
| `POST` | `/api/v1/users/devices` | Add a named device |
| `DELETE` | `/api/v1/users/devices/{deviceId}` | Remove an owned device |
| `GET` | `/api/v1/users/tokens` | List token metadata (never token values) |
| `POST` | `/api/v1/users/tokens` | Create a user token; its value is returned once |
| `DELETE` | `/api/v1/users/tokens/{tokenId}` | Revoke an owned token |
| `POST` | `/api/v1/users/data/export` | Request a personal data export |
| `GET` | `/api/v1/users/data/export/{export_id}` | Download a ready export |
| `POST` | `/api/v1/users/data/delete` | Request account deletion |

User self-management routes require an authenticated user identity. API tokens are sent as `Authorization: Bearer <token>`; browser forms use the account session and CSRF protection. Routes identify the current user from the credential and do not accept a caller-selected user ID. There is no API to read another user's profile, devices, tokens, or test history. The live OpenAPI document is the authoritative request/response schema.

Public registration is available only with `server.users.enabled: true` and `server.users.registration.mode: open`; private mode returns 404 for public registration. Server administrators can issue a single-use user setup link in either mode. Users choose their own password through that link. Admin moderation routes are under `/api/v1/server/{admin_path}/moderation/users`; user email addresses are masked in moderation responses.

## Preferences, consent, and contact

Guest preferences use a cookie and do not require an account. The browser form at `/server/preferences` uses CSRF protection; JSON preferences are available through these routes:

| Method | Route | Purpose |
|---|---|---|
| `GET` / `POST` | `/api/v1/server/preferences` | Read or update theme, language, and consent preferences |
| `GET` | `/api/v1/server/preferences/sync` | Export preferences for use on another device |
| `GET` | `/api/v1/server/preferences/sync/import` | Import preferences using a sync code |
| `GET` / `POST` | `/api/v1/server/contact` | Read the contact form descriptor or submit a reviewed report |

Contact submission is a two-stage flow: first validate and review the submitted fields, then confirm delivery. CAPTCHA and security-report fields depend on the configured form type. The descriptor does not return secret provider credentials.

Public server pages with JSON representations are available at `/api/v1/server/{page}` for the pages enabled in the running application. The public profile lookup is `GET /api/v1/users/{username}` and returns only fields allowed by that user's visibility settings.

### User invite administration

Administrator bearer tokens can manage reusable user-registration codes at `/api/v1/server/{admin_path}/users/invites`:

| Method | Route | Purpose |
|---|---|---|
| `GET` | `/api/v1/server/{admin_path}/users/invites` | List invite metadata |
| `POST` | `/api/v1/server/{admin_path}/users/invites` | Create a code with a role, expiry, and maximum uses |
| `GET` | `/api/v1/server/{admin_path}/users/invites/{id}` | Read invite metadata |
| `DELETE` | `/api/v1/server/{admin_path}/users/invites/{id}` | Revoke an invite |

The raw invite code is returned only at creation; storage retains its SHA-256 hash. A maximum of `0` means unlimited uses. Public invite acceptance is available at `/api/v1/server/auth/invite/user/{token}` and the matching browser flow is `/server/auth/invite/user/{token}`. The live OpenAPI document specifies request and response fields.

Public server pages have JSON representations under `/api/v1/server/`, including health, help, privacy, DPO, security policy, security acknowledgments, and about information. Contact form submissions use a two-step review and confirmation flow; the API descriptor exposes active form fields and captcha requirements without returning provider secrets.

Administrators configure analytics at `/server/{admin_path}/tracking` and `GET`/`PATCH /api/v1/server/{admin_path}/tracking`. Provider scripts are emitted only after analytics consent. Privacy configuration is available through `GET`/`PATCH /api/v1/server/{admin_path}/pages/privacy`.

## Administration API

Administration APIs are below `/api/v1/server/{admin_path}/` and require an administrator bearer token. The mounted management families are:

| Methods | Route | Purpose |
|---|---|---|
| `GET`, `PUT` | `/api/v1/server/{admin_path}/settings` | Read or update server settings |
| `GET`, `PATCH` | `/api/v1/server/{admin_path}/pages` | Read or update public page content |
| `GET`, `PATCH` | `/api/v1/server/{admin_path}/pages/{section}` | Read or update one public page section |
| `GET`, `PATCH` | `/api/v1/server/{admin_path}/privacy` | Read or update privacy disclosures |
| `GET`, `PATCH` | `/api/v1/server/{admin_path}/pages/privacy` | Privacy settings compatibility path |
| `GET`, `PATCH` | `/api/v1/server/{admin_path}/tracking` | Read or update analytics settings |
| `GET`, `POST`, `PATCH`, `DELETE` | `/api/v1/server/{admin_path}/roles[/{id}]` | List, create, update, or remove user roles |
| `GET`, `POST`, `DELETE` | `/api/v1/server/{admin_path}/users/invites[/{id}]` | List, create, inspect, or revoke user invites |
| `GET`, `DELETE` | `/api/v1/server/{admin_path}/moderation/users[/{id}]` | List, inspect, or delete regular user accounts |
| `POST` | `/api/v1/server/{admin_path}/moderation/users/disable` | Suspend a regular user |
| `POST` | `/api/v1/server/{admin_path}/moderation/users/enable` | Restore a suspended regular user |

Admin profile API routes also support TOTP and passkey status, enrollment, and revocation under `/api/v1/server/{admin_path}/{username}/profile/security`. These routes act on the signed-in administrator's own profile. The OpenAPI document at `/api/v1/server/swagger` describes the operations currently published by the server.

Password reset requests use `POST /api/v1/server/auth/password/forgot` or the server-rendered `GET`/`POST /server/auth/password/forgot` form. With SMTP configured, the service emails a one-hour, single-use link. Complete the reset with `POST /api/v1/server/auth/password/reset` or use the server-rendered form at `/server/auth/password/reset`; completing a reset changes the stored password and revokes the user's existing sessions. Responses do not disclose whether the submitted email belongs to an account.

## Authentication and scope

Public API routes work without a token. Send `Authorization: Bearer <token>` for private account data, server administration, and MCP. API session cookies do not identify a user; the anonymous owner cookie is used only to authorize that browser's own speed-test result. Invalid bearer credentials return `401`; a valid token without the required scope or ownership returns `403`.

Tokens use the `adm_` administrator or `usr_` user prefix and a cryptographically random 32-character base62 suffix. Tokens are shown once and stored as SHA-256 hashes. Their scopes are `global`, `read-write`, or `read`; agent scope is restricted to agent routes. The operator token is generated into the private `secrets.yml` file and printed once on first creation. Setup also returns one administrator API token once; it authenticates to admin API routes and is stored as a SHA-256 hash.

## GraphQL

The read-only GraphQL endpoint is `/api/v1/server/graphql`, with `/api/graphql` as an alias. It exposes public health data and, for the authenticated account, profile, settings, security summary, device and API-token metadata, test history, and owned results; public fields from shared results are available by share code. Send a user bearer token for private account data; browser sessions identify a user only on web pages. The schema has no mutations and never returns credentials, token secrets, or private keys. GraphiQL is available at `/server/docs/graphql`.

## MCP

The Streamable HTTP MCP endpoint is `/api/v1/server/mcp`, with direct aliases `/api/mcp` and `/mcp`. It uses the same bearer token, ownership checks, and scopes as REST. MCP requests use JSON-RPC 2.0 over `POST` with protocol revision `2026-07-28`, matching `MCP-Protocol-Version`, `Mcp-Method`, and `_meta` values. Browser origins must match the request origin or an explicit configured CORS origin; wildcard CORS does not authorize cross-origin MCP requests.

## Overlay network administration

Tor administration is available to an administrator bearer token at `/api/{api_version}/server/{admin_path}/network/tor`: `GET` returns status and settings, `PATCH` validates, saves, and applies settings, and `POST` to `/validate`, `/restart`, or `/regenerate` validates settings, restarts Tor, or creates a new onion identity. Vanity search uses `GET`, `POST`, and `DELETE` at `/vanity`; apply a candidate with `POST /vanity/apply` and import external Tor v3 key files with multipart `POST /import`. The corresponding web interface is `/server/{admin_path}/network/tor` and requires an administrator session.

I2P administration is available to an administrator bearer token at `/api/{api_version}/server/{admin_path}/network/i2p`: `GET` returns runtime status and settings, and `PATCH` validates, saves, and applies settings. `POST` to `/validate`, `/restart`, or `/regenerate` validates settings, restarts the provider, or creates a new `.b32.i2p` identity. The corresponding web interface is `/server/{admin_path}/network/i2p` and requires an administrator session. Public autodiscovery includes an overlay hostname only when its `expose` setting is enabled and the service is healthy.

## Health and public server information

Health is available at `/server/healthz`, `/api/v1/server/healthz`, and `/api/healthz`. The root `/healthz` alias is available only when `server.healthz.root.enabled` is enabled. Append `.json` or `.txt` to the server health paths for an explicit representation, or request `text/plain` through content negotiation. The health payload reports component state, including optional cache and overlay-network health, without disclosing secrets or filesystem paths. Public server information includes `/api/v1/server/about`, `/api/v1/server/privacy`, `/api/v1/server/help`, `/api/v1/server/dpo`, and `/api/v1/server/security/policy`.

Metrics are available when `server.metrics.enabled` is true at `/api/{api_version}/server/metrics[/{service}]`, `/server/metrics[/{service}]`, and `/api/metrics[/{service}]`. The root `/metrics[/{service}]` alias is mounted only when `server.metrics.root.enabled` is true. Services are `prometheus`, `grafana`, and `loki`. Unless unauthenticated access is explicitly enabled, each service requires its own `mtr_` bearer token from `server.metrics.auth.tokens.{service}` in `secrets.yml`; a token for one service does not authorize another. The admin interface provides a separate metrics overview page.

## Autodiscovery

`GET /api/autodiscover` is unversioned so clients can discover the server's current API version before choosing a versioned route. It returns the standard JSON envelope with `ok: true` and a `data` object containing `name`, `version`, `api.current_version`, `urls`, `onion`, `i2p`, `cli_versions`, `cli_min_version`, `agent_versions`, and `agent_min_version`. `urls` contains deduplicated public origins; overlay addresses are exposed in their own fields only when configured. Each available CLI or agent version entry includes its version and SHA-256. The response does not publish admin paths, secrets, settings, or a configuration schema.

## Representations

The API uses JSON. Health endpoints also support plain text through content negotiation and `.txt` suffixes. Image exports return `image/png` or `image/svg+xml`.
