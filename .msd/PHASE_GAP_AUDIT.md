# Phase Gap Audit (2026-03-05)

This audit is based on the current code in:
- `control-plane/`
- `worker-runtime/`
- `risk-engine/`
- `adapters/`
- `ui/`

## Phase 1: Auth / Tenancy / RBAC / SSO

### Implemented
- Auth-required `withUserAuth` guards on all `/v1/*` endpoints.
- Role and scope checks.
- OIDC SSO flow and API token support.
- Tenant-scoped store APIs for findings/assets/policies/remediations/jobs.
- Audit event persistence and API.

### Added in this pass
- `control-plane/internal/rbac/` explicit authorization module.
- `control-plane/internal/tenant/` explicit tenant scoping module.
- `withUserAuth` now uses these modules directly.

### Remaining hardening
- Add SCIM/group sync and stronger enterprise identity mapping policies.

## Phase 2: Policy Engine and Governance

### Implemented
- Policy CRUD/versioning/rollback APIs.
- Structured rule model + exceptions.
- Approval gating for restricted adapters.
- Policy checks before job creation and task dispatch.

### Remaining expansion
- Full scope inheritance tree (`global -> tenant -> project -> asset`) with explicit precedence metadata.
- More explicit per-project/asset policy assignment APIs.

## Phase 3: Business Risk Engine

### Implemented
- Risk enrichment logic with priority/SLA scoring.
- Asset criticality/environment/exposure weighting.
- Dedup/reopen/trend and waiver-aware scoring support.
- Separate `risk-engine/` service codebase present.

### Remaining expansion
- Wire risk-engine service as external deployable dependency in production topologies by default (currently local engine path is primary).

## Phase 4: Remediation Workflow System

### Implemented
- Remediation state transitions and activity timeline.
- Retest and verification APIs.
- Exception and assignment approval workflows.
- Evidence and ticket-link workflows.
- Escalation sweep and notification APIs.

### Remaining expansion
- Additional external ticket providers/workflow adapters in `platform-services/`.

## Phase 5: Deeper Analyzer Coverage

### Implemented
- Broad adapter coverage across SAST/SCA/secrets/IaC/DAST/pentest.
- Tool policy manifests and normalization fixtures are present for major paths.
- Controlled metasploit wrapper/policy path present.

### Remaining expansion
- Deeper mobile analyzer depth and cross-tool governance automation for rulepack lifecycle.

## Phase 6: Full Enterprise UI

### Implemented
- Embedded enterprise console under `/app/`.
- Dedicated TypeScript UI codebase under `ui/` with:
  - dashboard, findings, assets, policies, approvals, remediations, operations, reports
  - API-backed actions for key workflows
  - export and operational controls
- Session-scope adaptive route visibility and write-action controls in dedicated UI.
- Server-backed report summary and findings export APIs (`/v1/reports/summary`, `/v1/reports/findings/export`).

### Remaining expansion
- Complete migration from embedded `/app/` to dedicated UI deployment artifact and CI build/release pipeline.
- Additional SSO UX polish (provider UX hints and tenant branding customization).
