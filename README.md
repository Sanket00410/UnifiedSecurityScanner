# Unified Security Platform

This repository defines an enterprise-grade unified application security platform for:
- Code security (SAST)
- Software composition analysis (SCA)
- Secret detection
- Infrastructure and cloud configuration scanning
- Container and Kubernetes posture scanning
- Web and API runtime testing (DAST)
- Automated pentesting with curated Kali-class tool adapters
- Business-aware risk scoring and remediation workflows

## Core Principle
Detection alone is not the product. Correlated, explainable, prioritized risk is the product.

## Enterprise Pipeline
Code/Assets -> Ingestion and Context -> Orchestration and Policy -> SAST/SCA/Secrets/IaC -> DAST -> Automated Pentesting -> Correlation Graph -> Risk Engine -> Findings Lifecycle and Remediation -> Developer and Security Operations UI

## Platform Characteristics
- Single web application with API-driven control plane
- Cross-platform execution using Windows, Linux, and macOS runners
- Multi-tenant, RBAC-enabled, SSO-ready, audit logged
- Safe by design: active validation only on approved scoped targets with tool guardrails
- Built for production deployment, not a demo or MVP

## Current Delivery Status
- Phases 1-5 are implemented in code (control plane, policy/risk/remediation workflows, and broad analyzer coverage).
- Phase 6 now has a dedicated TypeScript frontend under `ui/` (Vite + React + TS) for enterprise operator workflows.
- The route-driven embedded console served at `/app/` remains available as a fallback/admin shell during transition.

## Recommended Structure
- `control-plane/` API gateway, auth, orchestration, policy, tenancy
- `worker-runtime/` cross-platform scanner runners and job execution
- `adapters/` engine integrations for static, dependency, IaC, dynamic, and validation tools
- `risk-engine/` correlation, exploitability, business impact, and prioritization
- `platform-services/` rule packs, feed sync, notifications, admin, and update management
- `ui/` developer, AppSec, and management experience
- `docs/` architecture and implementation guides
- `.msd/` mirrored high-level system design documents

## Immediate Build Priorities
1. Define a normalized finding schema and evidence model shared by every scanner.
2. Implement the control plane, job scheduler, and per-tenant policy engine.
3. Build cross-platform worker agents with isolated scanner adapters.
4. Add finding correlation, reachability analysis, and business risk scoring.
5. Add rule/template update services, target registry, and findings lifecycle management.
6. Expose one unified UI plus APIs for CI/CD, ticketing, SIEM, and governance integrations.

## Local End-to-End UI Run
- Dedicated UI E2E guide: `docs/LOCAL_UI_E2E_SCAN.md`
- One-command local stack starter: `ops/start-local-e2e.ps1`
- Docker-based UI startup (no local npm): `ops/start-local-e2e.ps1 -UseDockerUI`
- To make dedicated UI primary behind control-plane, set `USS_UI_DIST_PATH=../ui/dist` before starting API.

## Production Bundle
- Unified production compose path: `ops/production/docker-compose.yml`
- Kubernetes path: `ops/production/k8s/` (`kubectl apply -k ops/production/k8s`)
- Observability pack: `ops/production/observability/` (Prometheus + Grafana dashboard provisioning)
- Operations docs: `ops/production/RUNBOOKS.md` and `ops/production/HA_SETTINGS.md`
