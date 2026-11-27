# TODO.AI.md

## Status

- [ ] Replace the partial Swagger operation metadata and independently mounted API routes with the single `Route` registry required by AI.md. The registry must mount each API route and provide the shared source for OpenAPI, llms.txt, GraphQL/MCP visibility, and response negotiation.
- [ ] Implement the AI.md API text serializer and negotiation rules across `/api/**`, including `.txt` routes, non-interactive clients, ordered object/list formatting, error responses, primary-value routes, and binary response behavior.
- [ ] Make the route drift test compare the AI.md template route inventory and IDEA.md project API inventory against both the router and generated OpenAPI. Resolve or precisely isolate any remaining template contradictions in `~/Projects/github/webappsgo/TODO.SERVER.md`; do not weaken the test to pass around undocumented routes.
- [ ] Audit and align every required AI.md feature, API, user/admin page, configuration default, security behavior, operation, CLI behavior, and documentation section against the current implementation. Update the matching project docs and tests as each gap is resolved.
- [ ] Verify the complete aligned project with the required test, lint, build, documentation, container smoke, and provider CI workflows. Fix all failures and keep this list current until no implementation or verification gap remains.
