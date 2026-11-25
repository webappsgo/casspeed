# CasSpeed

CasSpeed is a self-hosted internet speed testing service for measuring download and upload throughput, latency, jitter, and packet loss. Its product contract is documented in the repository's [`IDEA.md`](https://github.com/webappsgo/casspeed/blob/main/IDEA.md); implementation requirements are in [`AI.md`](https://github.com/webappsgo/casspeed/blob/main/AI.md).

## Guides

- [Installation](installation.md): Docker, binary, and service deployment
- [Configuration](configuration.md): paths, listener, and server settings
- [API](api.md): versioned HTTP API and result privacy
- [CLI](cli.md): interactive terminal client
- [Admin](admin.md): server administration and setup
- [Security](security.md): authentication, private results, and reporting
- [Integrations](integrations.md): discovery endpoints and external services
- [Development](development.md): build, test, and contribution workflow
- [Translating](translating.md): localization contribution guidance

## Browser pages

The public browser pages live below `/server/`: about, privacy, help, terms, DPO, security, and health. Interactive API tools are available at `/server/docs/swagger` (REST) and `/server/docs/graphql` (read-only GraphQL). Their machine-readable contracts are `/api/v1/server/swagger` and `/api/v1/server/graphql`.

## Privacy model

An unshared result is visible only to the originating anonymous session or owning account. A result is public only after its owner explicitly creates a share link. Anonymous results expire according to the configured retention period; authenticated history has no automatic expiry. Account deletion and individual result deletion are not currently exposed through the account UI or API.
