# Production Runbooks

## Incident: Control Plane API Unhealthy

1. Check API container/pod logs for `database_unavailable`, `migration`, or panic errors.
2. Verify Postgres readiness (`pg_isready`) and latency.
3. Confirm `USS_DATABASE_URL` and token/secret env values.
4. If migrations failed, roll forward by fixing migration SQL and redeploying.
5. Validate `/readyz` returns `ready` and monitor `uss_scan_jobs_queued` stabilization.

## Incident: Worker Backlog Growing

1. Check `uss_scan_jobs_queued` and `uss_platform_jobs_total{status="queued"}`.
2. Verify worker liveness and heartbeat metrics (`uss_workers_healthy`).
3. Scale worker replicas up and watch queue decay.
4. Inspect failed/dead-letter platform jobs via:
   - `GET /v1/jobs?status=dead_letter`
5. Replay with:
   - `POST /v1/jobs/{id}/retry`

## Incident: Connector Delivery Failures (Jira/ServiceNow/SIEM/CMDB)

1. Query dead-letter jobs by connector kind (`job_kind` + `connector_id`).
2. Validate endpoint reachability and auth secret format (`bearer/basic/header`).
3. Confirm connector retry policy values:
   - `retry_max_attempts`
   - `retry_base_delay_seconds`
   - `retry_max_delay_seconds`
4. Requeue failed jobs after fixing endpoint/auth.

## Incident: Audit Export Failure

1. Check `GET /v1/audit-exports?status=failed`.
2. Inspect corresponding platform job records and last error.
3. Validate export filesystem volume availability (`/var/lib/uss/exports`).
4. Retry export by creating a new export request with the same filter set.

## Incident: SLO Breach (Endpoint Availability)

1. Check Grafana panel `Endpoint Availability (5m)`.
2. Identify failing endpoint from `HTTP Probe Success by Endpoint`.
3. Confirm app logs and dependencies for failing endpoint.
4. Mitigate with pod restart or rollout.
5. Open postmortem with:
   - start/end timestamps
   - impact scope
   - detected root cause
   - preventive fix
