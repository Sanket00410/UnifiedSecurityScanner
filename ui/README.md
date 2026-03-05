# Unified Security UI (Phase 6)

This is the dedicated TypeScript frontend for the enterprise operator console.

## Scope

- Dashboard, findings explorer, asset inventory
- Policy management and approval queues
- Remediation workflow operations
- Notifications, scan job operations, audit trail, report export

## Runtime

- Tooling: Vite + React + TypeScript
- API target: same-origin `/v1/*` control-plane APIs
- Auth model: bearer token and SSO session reuse (`/auth/oidc/start`, `/auth/logout`)

## Local Development

```bash
npm install
npm run dev
```

## Build

```bash
npm run build
```

The current embedded UI under `control-plane/internal/httpapi/static/` remains available as fallback.

