# Unified Security UI (Phase 6)

This is the dedicated TypeScript frontend for the enterprise operator console.

## Scope

- Dashboard, findings explorer, asset inventory
- Policy management and approval queues
- Remediation workflow operations
- Notifications, scan job operations, audit trail, report export
- Role/scope-adaptive route and action controls from `/v1/auth/me` session scopes

## Runtime

- Tooling: Vite + React + TypeScript
- API target: same-origin `/v1/*` control-plane APIs
- Auth model: bearer token and SSO session reuse (`/auth/oidc/start`, `/auth/logout`)
- Server-backed reporting endpoints:
  - `/v1/reports/summary`
  - `/v1/reports/findings/export?format=json|csv`

## Local Development

```bash
cp .env.example .env
npm install
npm run dev
```

`VITE_CONTROL_PLANE_PROXY` defaults to `http://localhost:8080` and proxies `/v1/*` and `/auth/*` during local dev.

## Build

```bash
npm run build
```

The current embedded UI under `control-plane/internal/httpapi/static/` remains available as fallback.
