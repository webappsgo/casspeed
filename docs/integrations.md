# Integrations

## Public API and discovery

- REST API: `/api/v1`
- OpenAPI JSON: `/api/v1/server/swagger` and `/api/swagger`
- Swagger UI: `/server/docs/swagger`
- GraphQL UI: `/server/docs/graphql`
- GraphQL request endpoint: `/api/v1/server/graphql`
- Health API: `/api/v1/server/healthz` and `/api/healthz`
- Security contact metadata: `/.well-known/security.txt`
- MCP Streamable HTTP: `/api/v1/server/mcp` (aliases: `/api/mcp`, `/mcp`)

The speed test runs against the CasSpeed server itself. No external test network or identity provider is required. OIDC, LDAP, SAML, webhooks, federation, Android App Links, and Apple Universal Links are not enabled by this project configuration.

### MCP clients

MCP clients connect to any MCP endpoint above using the same API bearer token as REST. Requests use JSON-RPC 2.0 over HTTP `POST` and protocol revision `2026-07-28`; include `MCP-Protocol-Version`, `Mcp-Method`, and the matching protocol version in `_meta`. The server currently exposes API operations from the OpenAPI document through `tools/list` and `tools/call`. Browser-origin requests must be same-origin. Do not send browser session cookies or put tokens in URLs.

## Deployment integrations

The service can run as a container or a foreground binary managed by a service supervisor. Configure a trusted reverse proxy to provide HTTPS when needed. Do not enable forwarding-header trust for an arbitrary internet-facing proxy.
