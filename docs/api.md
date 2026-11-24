# HTTP API

The canonical versioned API base is `/api/v1`. Requests accept JSON where an endpoint takes a structured body; errors use HTTP status codes and must not expose internal paths or secrets. Authentication uses a session cookie for browser flows and a bearer token for automation.

## Speed tests

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/api/v1/speed-tests` | Start a test and return its identifier/state |
| `GET` | `/api/v1/speed-tests/{id}/status` | Receive live progress for the originating test |
| `GET` | `/api/v1/speed-tests/{id}/download` | Download measurement data for that test |
| `POST` | `/api/v1/speed-tests/{id}/uploads` | Submit bounded upload measurement data |
| `GET` | `/api/v1/speed-tests/{id}` | Read a result if the caller owns it or it is shared |
| `GET` | `/api/v1/speed-tests` | List the authenticated user's history |
| `POST` | `/api/v1/speed-tests/{id}/shares` | Explicitly create a share link for an owned result |
| `GET` | `/api/v1/shares/{code}` | Read a shared result |
| `GET` | `/api/v1/shares/{code}/images/png` | Export the shared result as PNG |
| `GET` | `/api/v1/shares/{code}/images/svg` | Export the shared result as SVG |

An unshared result is private to the originating anonymous session or the owning account. A share link is public and should be treated as a public URL. Never put user IDs in a history query to select another user's data; ownership is determined by the authenticated caller.

## User and server endpoints

Account registration and login, profile, device, token, and server administration endpoints are documented by the live OpenAPI document at `/api/v1/server/swagger`. Swagger UI is available at `/server/docs/swagger`. The health endpoint is `/api/v1/server/healthz`; `/api/healthz` is a direct alias.

## Authentication

Send `Authorization: Bearer <token>` for supported automation requests. Keep tokens secret, use the least necessary account, and revoke a token if it is exposed. Browser sign-in uses a session and CSRF protection. Failed authentication should not disclose whether an account exists.

## Representations

The server API uses JSON by default. Health endpoints also support plain text through content negotiation and the `.txt` suffix. The live server's OpenAPI document is the machine-readable reference for current request and response fields.
