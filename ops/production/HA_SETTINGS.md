# High Availability Settings

## Baseline Replica Strategy

- `control-plane-api`: 2 replicas
- `platform-services-api`: 2 replicas
- `risk-engine-api`: 2 replicas
- `worker-runtime`: 2+ replicas (scale with queue depth)
- `platform-services-worker`: 2+ replicas
- `control-plane-scheduler`: 1 replica (single active scheduler model)
- `ui`: 2 replicas

## Data and Durability

- Postgres must run with managed HA in production (primary + standby + automated failover).
- Evidence and export storage should use durable object/block storage, not node-local disks.
- Enable periodic backups and restore verification drills.

## Recommended Kubernetes Hardening

- Add PodDisruptionBudgets for APIs and workers.
- Add anti-affinity and topology spread constraints across zones.
- Use separate node pools for:
  - API/control services
  - scanner/worker execution services
- Enforce resource requests/limits and namespace quotas.

## SLO Targets

- API availability (`/readyz`): >= 99.9%
- Queue processing freshness:
  - scan queue P95 wait < 5 min
  - platform job queue P95 wait < 2 min
- Worker heartbeat freshness:
  - >= 99% workers healthy over 5m windows

## Recovery Targets

- RPO: <= 15 minutes
- RTO: <= 60 minutes

## Change Management

- Use rolling updates with maxUnavailable=0 for API deployments.
- Use canary rollout for scanner/connector policy changes.
- Keep immutable image tags and rollback-ready deployment manifests.
