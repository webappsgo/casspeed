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

## Users and server pages

Registration, login, profile, device, token, and server administration operations are listed in the live OpenAPI document. Public server pages also have JSON representations under `/api/v1/server/`, including the health, security, help, privacy, and about pages. Contact form submissions are two-step: submit the form and captcha to receive a review, then confirm it with the returned review token.

Password reset requests use `POST /api/v1/server/auth/password/forgot`. With SMTP configured, the service emails a one-hour, single-use link. Complete the reset with `POST /api/v1/server/auth/password/reset` or use the server-rendered form at `/server/auth/password/reset`; completing a reset changes the stored password and revokes the user's existing sessions.

## Authentication and scope

Public API routes work without a token. Send `Authorization: Bearer <token>` for private account data, server administration, and MCP. API session cookies do not identify a user; the anonymous owner cookie is used only to authorize that browser's own speed-test result. Invalid bearer credentials return `401`; a valid token without the required scope or ownership returns `403`.

Tokens use the `adm_` administrator or `usr_` user prefix and a cryptographically random 32-character base62 suffix. Tokens are shown once and stored as SHA-256 hashes. Their scopes are `global`, `read-write`, or `read`; agent scope is restricted to agent routes. The operator token is generated into the private `secrets.yml` file and printed once on first creation. Setup also returns one administrator API token once; it authenticates to admin API routes and is stored as a SHA-256 hash.

## GraphQL

The read-only GraphQL endpoint is `/api/v1/server/graphql`, with `/api/graphql` as an alias. It exposes public health data, a user's own history and results, and public fields from shared results. Send a user bearer token for API access; browser sessions identify the user only on web pages. The schema has no mutations. GraphiQL is available at `/server/docs/graphql`.

## MCP

The Streamable HTTP MCP endpoint is `/api/v1/server/mcp`, with direct aliases `/api/mcp` and `/mcp`. It uses the same bearer token, ownership checks, and scopes as REST. MCP requests use JSON-RPC 2.0 over `POST` with protocol revision `2026-07-28`, matching `MCP-Protocol-Version`, `Mcp-Method`, and `_meta` values. Browser origins must match the request origin or an explicit configured CORS origin; wildcard CORS does not authorize cross-origin MCP requests.

## Representations

The API uses JSON. Health endpoints also support plain text through content negotiation and `.txt` suffixes. Image exports return `image/png` or `image/svg+xml`.
