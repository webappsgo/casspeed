# Security

## Authentication and private data

Registered-user sessions and API tokens authorize access to that user's data. Tokens must be treated as passwords and revoked if exposed. User history, devices, and tokens are private to their owner. Admin authentication is separate from user authentication and is scoped to the configured server administration path.

Anonymous tests are private to the originating browser session. Sharing is an explicit owner action; public share links expose only the fields selected for sharing. Do not put share links in public spaces unless you intend to publish the result.

## Operational security

Run the service behind HTTPS when it is reachable over an untrusted network. Protect the database and runtime directories with OS permissions, keep server software updated, and avoid exposing debug endpoints in production. CasSpeed stores client IPs as hashes rather than plaintext; deployment proxies should not be trusted unless they are under operator control.

## Public endpoints

- `/.well-known/security.txt`: security contact and policy metadata
- `/.well-known/change-password`: password-management discovery redirect
- `/server/security`, `/server/security/policy`, `/server/security/thanks`: human-readable security pages
- `/server/healthz` and `/api/v1/server/healthz`: service health representations
- `/api/v1/server/swagger`: OpenAPI document

Unknown `/.well-known/` entries should return 404. CasSpeed currently has no PGP key endpoint configured.

## Reporting

Use the security contact published by the running service. Include the affected URL, steps to reproduce, and impact. Avoid accessing, changing, or retaining other users' data while investigating. Coordinated disclosure gives the operator time to assess and remediate a report.
