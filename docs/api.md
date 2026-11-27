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
| `POST` | `/api/v1/server/auth/login` | Authenticate and return a 24-hour named Bearer token; returns a single-use partial token when 2FA is required |
| `POST` | `/api/v1/server/auth/logout` | Revoke the authenticated Bearer token |
| `POST` | `/api/v1/server/auth/password/forgot` | Request a password reset without revealing whether an account exists |
| `POST` | `/api/v1/server/auth/password/reset` | Use a valid one-time reset token |
| `POST` | `/api/v1/server/auth/username/forgot` | Request a username reminder without revealing whether an account exists |
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

API login accepts `identifier` and `password`; a user identifier may be a numeric user ID, username, or email address. API login sets no cookie. A regular-user login returns `data.token` as a one-time-displayed `usr_` Bearer token; an administrator login returns a named `adm_` Bearer token. Both are stored by hash with a 24-hour expiry and can be revoked. When TOTP or a passkey requires another step, login returns `data.requires_2fa` and a five-minute `data.partial_token` instead.

User self-management routes require an authenticated user identity. API tokens are sent as `Authorization: Bearer <token>`; browser forms use the account session and CSRF protection. Routes identify the current user from the credential and do not accept a caller-selected user ID. There is no API to read another user's profile, devices, tokens, or test history. The live OpenAPI document is the authoritative request/response schema.

## Administration

The administrator rate-limit settings are available at `/api/{api_version}/server/{admin_path}/security/ratelimit`. `GET` returns the current always-on limits under `settings`; `PATCH` accepts a partial JSON object with any of `read`, `write`, `health`, `strict`, `auth_failures`, `global_burst`, and `auth`. Each window is expressed in seconds. Values must be positive and within the supported bounds. These routes require an administrator Bearer token; the browser settings page uses a CSRF-protected HTML form at `/server/{admin_path}/security/ratelimit`.

Additional account-security operations include `POST /api/v1/users/security/password` to change a password, `GET /api/v1/users/security/sessions` to list active sessions, `DELETE /api/v1/users/security/sessions/{session_id}` to revoke one, and `POST /api/v1/users/security/recovery-keys/ack` to acknowledge one-time recovery-code display. User token metadata can be read at `GET /api/v1/users/tokens/{token_id}`; the raw secret is returned only by token creation.

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

Public server pages have JSON representations under `/api/v1/server/`, including health, help, privacy, DPO, security policy, security acknowledgments, and about information. On Tor requests, privacy responses keep third-party service names and disclosures but omit external policy URLs; consent links stay on the onion service. Contact form submissions use a two-step review and confirmation flow; the API descriptor exposes active form fields, stable option values, localized option labels, and captcha requirements without returning provider secrets.

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
| `GET`, `PATCH` | `/api/v1/server/{admin_path}/security/ratelimit` | Read or update always-on request limits |
| `GET`, `PATCH` | `/api/v1/server/{admin_path}/security/auth` | Read or update password, two-factor, and external-provider enablement settings |
| `GET` | `/api/v1/server/{admin_path}/security/tokens` | List user and administrator API token metadata |
| `DELETE` | `/api/v1/server/{admin_path}/security/tokens/{id}` | Revoke an API token |
| `POST` | `/api/v1/server/{admin_path}/security/tokens/{id}/rotate` | Rotate an API token and return its new secret once |
| `GET` | `/api/v1/server/auth/ldap` | List display names for enabled LDAP providers |
| `GET` | `/api/v1/server/auth/saml` | List display names for enabled SAML providers |
| `GET`, `POST` | `/api/v1/server/{admin_path}/security/auth/{oidc|ldap|saml}/providers` | List or create an external identity provider |
| `GET`, `PATCH`, `DELETE` | `/api/v1/server/{admin_path}/security/auth/{oidc|ldap|saml}/providers/{provider}` | Read, update, or remove an external identity provider |
| `GET`, `PATCH` | `/api/v1/server/{admin_path}/web/well-known` | Read or update security.txt and llms.txt configuration without changing entry availability |
| `GET`, `POST`, `PATCH`, `DELETE` | `/api/v1/server/{admin_path}/roles[/{id}]` | List, create, update, or remove user roles |
| `GET`, `POST`, `DELETE` | `/api/v1/server/{admin_path}/users/invites[/{id}]` | List, create, inspect, or revoke user invites |
| `GET`, `DELETE` | `/api/v1/server/{admin_path}/moderation/users[/{id}]` | List, inspect, or delete regular user accounts |
| `POST` | `/api/v1/server/{admin_path}/moderation/users/disable` | Suspend a regular user |
| `POST` | `/api/v1/server/{admin_path}/moderation/users/enable` | Restore a suspended regular user |

Admin profile API routes also support TOTP and passkey status, enrollment, and revocation under `/api/v1/server/{admin_path}/{username}/profile/security`. These routes act on the signed-in administrator's own profile. The OpenAPI document at `/api/v1/server/swagger` describes the operations currently published by the server.

Password reset requests use `POST /api/v1/server/auth/password/forgot` or the server-rendered `GET`/`POST /server/auth/password/forgot` form. With SMTP configured, the service emails a one-hour, single-use link. Complete the reset with `POST /api/v1/server/auth/password/reset` or use the server-rendered form at `/server/auth/password/reset`; completing a reset changes the stored password and revokes the user's existing sessions. Responses do not disclose whether the submitted email belongs to an account.

Username reminders use `POST /api/v1/server/auth/username/forgot` or the server-rendered `GET`/`POST /server/auth/username/forgot` form. If the email belongs to an enabled admin or user and SMTP is configured, the username is sent to that mailbox. The response is the same whether the email matches an account or delivery succeeds.

## Authentication and scope

Public API routes work without a token. Send `Authorization: Bearer <token>` for private account data, server administration, and MCP. API session cookies do not identify a user; the anonymous owner cookie is used only to authorize that browser's own speed-test result. Invalid bearer credentials return `401`; a valid token without the required scope or ownership returns `403`.

Tokens use the `adm_` administrator or `usr_` user prefix and a cryptographically random 32-character base62 suffix. Tokens are shown once and stored as SHA-256 hashes. Their scopes are `global`, `read-write`, or `read`; agent scope is restricted to agent routes. API password login creates a named `login` token that expires after 24 hours. The operator token is generated into the private `secrets.yml` file and printed once on first creation. Setup also returns one administrator API token once; it authenticates to admin API routes and is stored as a SHA-256 hash.

External identity provider CRUD requires an administrator bearer token. OIDC client secrets, LDAP bind passwords, and SAML signing private keys are encrypted in `secrets.yml` and never returned by provider reads; responses include a `*_configured` flag instead. Browser administration can list, create, edit, and remove providers. The public LDAP and SAML provider-list endpoints return only enabled provider names and display names. Connection tests, SP metadata and certificate management, and external login flows are not yet available.

## GraphQL

The read-only GraphQL endpoint is `/api/v1/server/graphql`, with `/api/graphql` as an alias. It exposes public health data and, for the authenticated account, profile, settings, security summary, device and API-token metadata, test history, and owned results; public fields from shared results are available by share code. Send a user bearer token for private account data; browser sessions identify a user only on web pages. The schema has no mutations and never returns credentials, token secrets, or private keys. GraphiQL is available at `/server/docs/graphql`.

## MCP

The Streamable HTTP MCP endpoint is `/api/v1/server/mcp`, with direct aliases `/api/mcp` and `/mcp`. It uses the same bearer token, ownership checks, and scopes as REST. MCP requests use JSON-RPC 2.0 over `POST` with protocol revision `2026-07-28`, matching `MCP-Protocol-Version`, `Mcp-Method`, and `_meta` values. Browser origins must match the request origin or an explicit configured CORS origin; wildcard CORS does not authorize cross-origin MCP requests.

## Overlay network administration

Tor administration is available to an administrator bearer token at `/api/{api_version}/server/{admin_path}/network/tor`: `GET` returns status and settings, `PATCH` validates, saves, and applies settings, and `POST` to `/validate` or `/regenerate` validates settings or creates a new onion identity. Vanity search uses `GET`, `POST`, and `DELETE` at `/vanity`; apply a candidate with `POST /vanity/apply` and import external Tor v3 key files with multipart `POST /import`. The corresponding web interface is `/server/{admin_path}/network/tor` and requires an administrator session.

I2P administration is available to an administrator bearer token at `/api/{api_version}/server/{admin_path}/network/i2p`: `GET` returns runtime status and settings, and `PATCH` validates, saves, and applies settings. `POST` to `/validate`, `/restart`, or `/regenerate` validates settings, restarts the provider, or creates a new `.b32.i2p` identity. The corresponding web interface is `/server/{admin_path}/network/i2p` and requires an administrator session. Public autodiscovery includes an overlay hostname only when its `expose` setting is enabled and the service is healthy.

## Server administration APIs

Administrative requests use an `adm_` bearer token and are scoped under `/api/{api_version}/server/{admin_path}/`. Current API groups include server status and statistics, backup create/list/restore/download, branding, SSL/TLS and Let's Encrypt settings, email settings and templates, scheduler operations, public-page content, privacy and tracking settings, compliance and breach records, user moderation and invitations, network blocklists, Tor and I2P controls, and security allowlist, blocked-address, and account-lock controls. SSL settings are available through `GET` and `PATCH .../ssl`; the private key path is redacted in responses. `POST .../ssl/renew` is routed but currently returns `503` because certificate renewal is not implemented. The log API lists available files with `GET .../logs`, returns at most 500 entries with `GET .../logs/{type}?limit=100&offset=0`, downloads the named file with `GET .../logs/{type}/download`, and clears a non-audit log with `POST .../logs/{type}/clear`. Log names are allowlisted and reads are bounded; attempts to clear the append-only audit log return `403`. Consult the live OpenAPI document for exact schemas and currently mounted routes.

## Health and public server information

Health is available at `/server/healthz`, `/api/v1/server/healthz`, and `/api/healthz`. The root `/healthz` alias is available only when `server.healthz.root.enabled` is enabled. Append `.json` or `.txt` to the server health paths for an explicit representation, or request `text/plain` through content negotiation. The health payload reports component state, including optional cache and overlay-network health, without disclosing secrets or filesystem paths. Public server information includes `/api/v1/server/about`, `/api/v1/server/privacy`, `/api/v1/server/help`, `/api/v1/server/dpo`, and `/api/v1/server/security/policy`.

Metrics are available when `server.metrics.enabled` is true at `/api/{api_version}/server/metrics[/{service}]`, `/server/metrics[/{service}]`, and `/api/metrics[/{service}]`. The root `/metrics[/{service}]` alias is mounted only when `server.metrics.root.enabled` is true. Services are `prometheus`, `grafana`, and `loki`. Unless unauthenticated access is explicitly enabled, each service requires its own `mtr_` bearer token from `server.metrics.auth.tokens.{service}` in `secrets.yml`; a token for one service does not authorize another. The admin interface provides a separate metrics overview page.

## Autodiscovery

`GET /api/autodiscover` is unversioned so clients can discover the server's current API version before choosing a versioned route. It returns the standard JSON envelope with `ok: true` and a `data` object containing `name`, `version`, `api.current_version`, `urls`, `onion`, `i2p`, `cli_versions`, `cli_min_version`, `agent_versions`, and `agent_min_version`. `urls` contains deduplicated public origins on clearnet requests; a Tor request receives only its current onion origin. Overlay addresses are exposed in their own fields only when configured. Each available CLI or agent version entry includes its version and SHA-256. The response does not publish admin paths, secrets, settings, or a configuration schema.

## Representations

API responses default to JSON. An API request with `Accept: text/plain`, a recognized non-interactive HTTP-tool user agent, or a `.txt` suffix returns plain text; an explicit `Accept: application/json` takes precedence over user-agent detection, while `.txt` takes precedence over headers. Object responses print an `OK:` message followed by fields in JSON model order, nested fields use dot notation, and lists print an item count followed by their entries. Error responses use `ERROR: CODE: message` and retain the JSON response's HTTP status. Binary successes such as image exports keep their original media type and bytes for negotiated text requests; requesting their `.txt` form returns 404. Health endpoints keep their dedicated flat `key: value` text format.
