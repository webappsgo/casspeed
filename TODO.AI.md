# TODO.AI.md

## Status

- [ ] Complete the shared `Route` registry required by AI.md. Route registration now passes through the registry and it feeds Swagger and llms.txt; finish moving operation metadata, GraphQL/MCP visibility, request/response schemas, `Primary`, `Binary`, `DebugOnly`, and response negotiation into that single contract.
- [ ] Complete the AI.md API text serializer contract. Middleware now handles `.txt`, `Accept`, detected HTTP tools, ordered object/list formatting, errors, binary responses, and streaming; populate route `Primary`/`Message` metadata and verify every API response shape against its model, default message, and health format.
- [ ] Make the route drift test compare the AI.md template route inventory and IDEA.md project API inventory against both the router and generated OpenAPI. Resolve or precisely isolate any remaining template contradictions in `~/Projects/github/webappsgo/TODO.SERVER.md`; do not weaken the test to pass around undocumented routes.
- [ ] Audit and align every required AI.md feature, API, user/admin page, configuration default, security behavior, operation, CLI behavior, and documentation section against the current implementation. Update the matching project docs and tests as each gap is resolved.
- [ ] Verify the complete aligned project with the required test, lint, build, documentation, container smoke, and provider CI workflows. Fix all failures and keep this list current until no implementation or verification gap remains.
