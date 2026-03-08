# Production Deployment Bundle

This directory provides one production deployment path in two formats:

- `docker-compose.yml` for self-hosted container deployments.
- `k8s/` for Kubernetes deployments via `kustomize`.

It includes:

- Core platform services (control-plane API/scheduler, worker runtime, risk engine, platform-services API/worker, UI).
- Postgres state for local/self-hosted operation.
- Observability stack (Prometheus, Grafana, Blackbox exporter) with pre-provisioned SLO dashboard.
- Runbook and HA guidance for enterprise operation.

## 1. Container Deployment (Compose)

```powershell
cd ops/production
docker compose up -d --build
```

Primary URLs:

- Control plane API: `http://localhost:8080`
- Dedicated UI: `http://localhost:5180`
- Platform-services API: `http://localhost:18090`
- Grafana: `http://localhost:3000`
- Prometheus: `http://localhost:9091`

Default auth tokens (override in environment):

- `USS_BOOTSTRAP_ADMIN_TOKEN` (control-plane)
- `USS_PLATFORM_SERVICES_API_TOKEN` (platform-services)

## 2. Kubernetes Deployment

```powershell
kubectl apply -k ops/production/k8s
```

Then create real image tags and update image values in `k8s/deployments.yaml`.

## 3. Observability / SLO

Prometheus scrapes:

- `/metrics` on control-plane API and platform-services API
- HTTP probe success for control-plane, platform-services, risk-engine, and UI endpoints

Grafana dashboard:

- `USS Platform Overview`

## 4. Operations

- Runbooks: [RUNBOOKS.md](./RUNBOOKS.md)
- High-availability settings: [HA_SETTINGS.md](./HA_SETTINGS.md)
