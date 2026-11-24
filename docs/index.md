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

The public browser pages live below `/server/`: about, privacy, contact, help, terms, DPO, security, and health. Interactive API documentation is available at `/server/docs/swagger`; the OpenAPI document is `/api/v1/server/swagger`.

## Privacy model

An unshared result is visible only to the originating anonymous session or owning account. A result is public only after its owner explicitly creates a share link. Anonymous result retention is controlled by the server operator; account history remains until deleted.
