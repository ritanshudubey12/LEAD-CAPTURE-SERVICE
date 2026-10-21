# Form API microservice

Node.js + TypeScript + Express + PostgreSQL (`pg`, parameterized SQL), per the Form API analysis report.

## Run
    docker compose up -d --build      # API on :3000, Postgres on :5432 (migrations run on start)
    npm test                          # needs the db container; uses database form_api_test
    npm run typecheck && npm run build
    npm run postman                   # newman run of postman/ (API must be running)

Swagger UI: http://localhost:3000/api/docs - OpenAPI JSON: /api/v1/openapi.json

## Auth
`AUTH_MODE=direct-jwt` (default): `Authorization: Bearer <HS256 JWT>` with claims `sub`, `tenant_id`,
`organization_id`, `roles`, plus configured `iss`/`aud`. Tenant/org/user come only from verified claims;
`X-Tenant-Id` / `X-Organization-Id` / `X-User-Id` headers are optional and must match or the call gets 403.

`AUTH_MODE=gateway-context`: Bearer is `INTERNAL_SERVICE_TOKEN`; the trusted gateway injects
`X-Tenant-Id`, `X-Organization-Id`, `X-User-Id`, `X-User-Roles`. Keep ingress private in this mode.

Roles (assumed, see src/middleware/authorization.ts): `form_admin`, `form_editor`, `form_viewer`.
Public route `POST /api/v1/public/forms/:formId/submissions` needs no credentials.

All successful responses are HTTP 200 with `{ success, message, data, meta.requestId }`.
Secrets in docker-compose.yml are local-dev defaults only.
