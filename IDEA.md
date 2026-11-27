# CasSpeed — Project Idea

## Project description

CasSpeed is a self-hosted, privacy-respecting internet speed testing service and a free, open-source alternative to commercial speed test sites. Home users, network administrators, and developers use it to measure and track connection quality without advertisements, tracking, or paid feature gates.

## Project variables

project_name: casspeed
project_org: casapps
internal_name: casspeed
internal_org: casapps
api_version: v1

## Business logic

### Product scope & non-goals

- Measure download and upload throughput, latency, jitter, and packet loss.
- Use parallel connections for representative throughput measurements and show live progress through ping, download, and upload phases.
- Test duration is configurable, with a default of 10 seconds per phase.
- Let anonymous visitors run tests. Anonymous results are retained for a configurable period, 30 days by default; anonymous visitors cannot keep account history.
- Let registered users keep test history, associate tests with named devices, and use API tokens for automation.
- Let registered users protect their accounts with TOTP or passkeys, use one-time recovery codes, export their personal data, and delete their account.
- Let a test owner, including an anonymous visitor for the active session's result, explicitly create a shareable result page and export it as PNG or SVG. Shared pages provide social preview metadata.
- PNG and SVG exports use the same styling as the shared result page.
- Provide a command-line client with an interactive terminal interface and live test progress.
- All product features are free. The product has no advertisements, tracking, or feature gating.
- Speed testing has no required external API dependency.
- Organizations and custom domains are not part of the product scope.

### Roles & permissions

- **Anonymous visitor:** run tests and view their immediate results in the originating browser session; may explicitly create a share link; cannot retain account history.
- **Regular user:** manage their own profile, account security, devices, API tokens, test history, and personal-data export or deletion; create and manage shares for tests they own.
- **Server admin:** configure and administer the service using the mandatory server administration features in AI.md.
- Users cannot read or change another user's private account data, devices, tokens, or history.

### Data model & sensitivity

- **Speed test:** identifier, optional user and device association, timestamp, download/upload Mbps, ping/jitter milliseconds, packet loss, hashed client IP, user agent, server identifier, optional share code, and share-view count. Results may be anonymous or associated with an account. Unshared results are visible only to the originating anonymous session or owning account; shared results expose only fields allowed by the owner's preference.
- **User:** identifier, username, email address, public-profile visibility, and whether the username may appear on shared results. Account email and non-public profile fields are private. Passwords, TOTP secrets, passkey credentials, and recovery codes are protected authentication data. Public profile fields follow the profile visibility controls required by AI.md PART 34; the PART 34 default is public, and a user may make their profile private.
- **Device:** identifier, owning user, user-defined name, and last-seen time. Device records are private to their owner.
- **API token:** identifier, owning user, name, hashed user token, and last-used time. The raw token is a secret and is never stored or shown again after creation. Tokens follow the format required by AI.md PART 11.
- **Share:** an eight-character base62 code associated with a result; valid only while the result exists. A share may expose only the result fields permitted by the owner's sharing preference.
- Speed-test result records never store a plaintext client IP; they retain only a one-way hash. AI.md requires resolved full client IPs in operational access/security logs and rate-limit/audit records, so those operational records follow the logging rules in AI.md. Deleted user data is removed immediately; anonymous results expire according to configured retention; authenticated history has no automatic expiry. Device names are user-defined and 1–64 characters long.

### Trust boundaries & external services

- Internet clients and all request data are untrusted, including forwarded-address headers unless the deployment explicitly trusts the forwarding proxy.
- The service operator controls the host, configuration, database, and server-admin account. Regular users control only their own account data.
- The speed-test service does not depend on external APIs or remote test servers; measurement traffic is handled by the CasSpeed server itself.
- Users may submit API tokens from automation clients. Tokens grant access only to the owning user's permitted resources and must be revocable.

### Threat model & abuse cases

- **Protected assets:** account credentials, API tokens, private test history, device records, database contents, server availability, and the integrity of reported measurements.
- **Threats:** credential stuffing, account enumeration, token theft, share-code guessing, history scraping, forged proxy headers, malformed inputs, oversized uploads, and resource exhaustion through concurrent or repeated tests.
- **Required outcomes:** authentication failures do not reveal account existence; tokens and passwords are not stored in recoverable form; private history is owner-scoped; share codes are unguessable and reveal only shareable fields; request and test resources are bounded; client IP privacy is preserved; input and output are validated for their use context.
- **Operational failure:** unavailable storage or measurement resources must produce a safe error without exposing internal details or corrupting saved results.

### Security decisions & exceptions

- Client IP privacy is a product requirement for speed-test result data: only a one-way hash may be persisted there. Operational logging follows AI.md's explicit requirement to record the resolved full client IP for access, security, rate-limit, and audit purposes.
- Sharing is opt-in per result and does not make the owner's private account history public.
- SAML service-provider support uses `github.com/supatype/saml` v0.7.0, maintained at [github.com/supatype/saml](https://github.com/supatype/saml), rather than upstream `github.com/crewjam/saml`. The fork documents namespace binding for signed assertion identity and attributes, replay checks, and fixes addressing Go advisory GO-2026-6909 ([official advisory](https://pkg.go.dev/vuln/GO-2026-6909)); retain the `govulncheck` gate and reassess this choice if upstream publishes a fixed release.
- There are no intentional security exceptions or weaker compatibility modes.

### API routes

The API version is `v1`. There is no external-service compatibility API.

| Method and route | Auth | Purpose | Request / response | Browser page |
|---|---|---|---|---|
| `POST /api/v1/speed-tests` | Anonymous or authenticated | Start a test | Test options; returns a test identifier and initial state | `GET /` starts and displays the test |
| `GET /api/v1/speed-tests/{id}/status` | Originating anonymous session or owning account | Stream live phase and progress updates over WebSocket | Test identifier; progress events | `GET /speed-tests/{id}` displays progress |
| `GET /api/v1/speed-tests/{id}/download` | Originating test session | Supply download measurement data | Test identifier and transfer parameters; returns bounded test bytes | Machine-only transfer endpoint used by the test page |
| `POST /api/v1/speed-tests/{id}/uploads` | Originating test session | Receive upload measurement data | Test identifier and bounded payload; returns accepted byte count and timing | Machine-only transfer endpoint used by the test page |
| `GET /api/v1/speed-tests/{id}` | Originating anonymous session or owning account | Retrieve an unshared result | Test identifier; returns the owner's result | `GET /speed-tests/{id}` |
| `GET /api/v1/speed-tests` | Authenticated user | List the current user's history with pagination | Pagination parameters; returns result summaries and pagination metadata | `GET /history` |
| `POST /api/v1/speed-tests/{id}/shares` | Originating anonymous session or owning account | Explicitly create a share for a result | Sharing preference; returns the share code and URL | Share form on `GET /speed-tests/{id}` |
| `GET /api/v1/shares/{code}` | Public | Retrieve fields allowed on a shared result | Share code; returns public result data | `GET /shares/{code}` |
| `GET /api/v1/shares/{code}/images/png` | Public | Export a shared result image | Share code; returns PNG image bytes | Linked from `GET /shares/{code}` |
| `GET /api/v1/shares/{code}/images/svg` | Public | Export a shared result image | Share code; returns SVG image bytes | Linked from `GET /shares/{code}` |

The authentication, profile, device, token, and server-administration routes are defined by AI.md's required server features and selected PART 34; this inventory lists only CasSpeed-specific routes.
