# HTTP API

CasSpeed's canonical REST base is `/api/v1`. The running server publishes its OpenAPI contract at `/api/v1/server/swagger`; Swagger UI is available at `/server/docs/swagger`. JSON responses use an `ok` field and structured data or errors. Error bodies must not expose filesystem paths, credentials, or private user data.

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
| `GET` | `/api/v1/users` | Read the current user's profile |
| `PATCH` | `/api/v1/users` | Update the current user's profile |
| `GET` | `/api/v1/users/settings` | Read the current user's settings |
| `GET` | `/api/v1/users/security` | Read the current user's security summary |
| `GET` | `/api/v1/users/devices` | List the current user's devices |
| `POST` | `/api/v1/users/devices` | Add a named device |
| `DELETE` | `/api/v1/users/devices/{deviceId}` | Remove an owned device |
| `GET` | `/api/v1/users/tokens` | List token metadata (never token values) |
| `POST` | `/api/v1/users/tokens` | Create a user token; its value is returned once |
| `DELETE` | `/api/v1/users/tokens/{tokenId}` | Revoke an owned token |

User self-management routes require an authenticated user identity. API tokens are sent as `Authorization: Bearer <token>`; browser forms use the account session and CSRF protection. Routes identify the current user from the credential and do not accept a caller-selected user ID. There is no API to read another user's profile, devices, tokens, or test history. The live OpenAPI document is the authoritative request/response schema.

Public server pages have JSON representations under `/api/v1/server/`, including health, help, privacy, DPO, security policy, security acknowledgments, and about information. Contact form submissions use a two-step review and confirmation flow; the API descriptor exposes active form fields and captcha requirements without returning provider secrets.

Password reset requests use `POST /api/v1/server/auth/password/forgot` or the server-rendered `GET`/`POST /server/auth/password/forgot` form. With SMTP configured, the service emails a one-hour, single-use link. Complete the reset with `POST /api/v1/server/auth/password/reset` or use the server-rendered form at `/server/auth/password/reset`; completing a reset changes the stored password and revokes the user's existing sessions. Responses do not disclose whether the submitted email belongs to an account.

## Authentication and scope

Public API routes work without a token. Send `Authorization: Bearer <token>` for private account data, server administration, and MCP. API session cookies do not identify a user; the anonymous owner cookie is used only to authorize that browser's own speed-test result. Invalid bearer credentials return `401`; a valid token without the required scope or ownership returns `403`.

Tokens use the `adm_` administrator or `usr_` user prefix and a cryptographically random 32-character base62 suffix. Tokens are shown once and stored as SHA-256 hashes. Their scopes are `global`, `read-write`, or `read`; agent scope is restricted to agent routes. The operator token is generated into the private `secrets.yml` file and printed once on first creation. Setup also returns one administrator API token once; it authenticates to admin API routes and is stored as a SHA-256 hash.

## GraphQL

The read-only GraphQL endpoint is `/api/v1/server/graphql`, with `/api/graphql` as an alias. It exposes public health data, a user's own history and results, and public fields from shared results. Send a user bearer token for API access; browser sessions identify the user only on web pages. The schema has no mutations. GraphiQL is available at `/server/docs/graphql`.

## MCP

The Streamable HTTP MCP endpoint is `/api/v1/server/mcp`, with direct aliases `/api/mcp` and `/mcp`. It uses the same bearer token, ownership checks, and scopes as REST. MCP requests use JSON-RPC 2.0 over `POST` with protocol revision `2026-07-28`, matching `MCP-Protocol-Version`, `Mcp-Method`, and `_meta` values. Browser origins must match the request origin or an explicit configured CORS origin; wildcard CORS does not authorize cross-origin MCP requests.

## Health and public server information

Health is available at `/server/healthz`, `/healthz`, `/api/v1/server/healthz`, and `/api/healthz`. Append `.json` or `.txt` to the server health paths for an explicit representation, or request `text/plain` through content negotiation. The health payload reports component state, including optional cache and overlay-network health, without disclosing secrets or filesystem paths. Public server information includes `/api/v1/server/about`, `/api/v1/server/privacy`, `/api/v1/server/help`, `/api/v1/server/dpo`, and `/api/v1/server/security/policy`.

## Representations

The API uses JSON. Health endpoints also support plain text through content negotiation and `.txt` suffixes. Image exports return `image/png` or `image/svg+xml`.
