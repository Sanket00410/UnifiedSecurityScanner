# Platform Services

`platform-services` is now a runnable production service with:

- Connector registry (Jira, ServiceNow, SIEM, CMDB, webhook/chat)
- Retryable external dispatch job queue with backoff and dead-letter
- Notification fanout workflow
- Audit export workflow
- Rule/feed sync workflow
- API and worker binaries

## Binaries

- API: `go run ./cmd/api`
- Worker: `go run ./cmd/worker`

## Key Environment Variables

- `USS_PLATFORM_SERVICES_BIND` (default `:18090`)
- `USS_DATABASE_URL`
- `USS_PLATFORM_SERVICES_API_TOKEN`
- `USS_PLATFORM_SERVICES_WORKER_ID`
- `USS_PLATFORM_SERVICES_WORKER_INTERVAL`
- `USS_PLATFORM_SERVICES_WORKER_LEASE_TTL`
- `USS_PLATFORM_SERVICES_WORKER_BATCH_SIZE`
- `USS_PLATFORM_SERVICES_EXPORT_ROOT`

## API Endpoints

- `GET /healthz`
- `GET /readyz`
- `GET /metrics`
- `GET /v1/metrics`
- `GET|POST /v1/connectors`
- `GET|PUT /v1/connectors/{id}`
- `POST /v1/connectors/{id}/dispatch`
- `GET|POST /v1/jobs`
- `GET /v1/jobs/{id}`
- `POST /v1/jobs/{id}/retry`
- `GET|POST /v1/notifications`
- `POST /v1/notifications/{id}/ack`
- `GET|POST /v1/audit-exports`
- `GET|POST /v1/sync-runs`

Use either:

- `Authorization: Bearer <token>`
- `X-USS-API-Token: <token>`

Optional headers:

- `X-USS-Tenant-ID`
- `X-USS-Actor`
