# Unified Security Platform

This is a standalone project folder for a business-focused security platform that combines:
- SAST
- DAST
- IaC scanning
- Dependency scanning
- Secret detection
- Unified business risk scoring

## Core Principle
Detection alone is not the product. Prioritized, explainable risk is the product.

## High-Level Pipeline
Code/Infra -> SAST -> Dependency+Secrets -> IaC -> DAST -> Risk Engine -> Developer UI

## Initial Structure
- `backend/` API + orchestration services
- `frontend/` Developer and security UI
- `scanners/` Integrations (Semgrep, CodeQL, ZAP, Trivy, Gitleaks, Checkov)
- `risk-engine/` Correlation and business impact scoring
- `orchestrator/` Workflow execution and scan scheduling
- `docs/` Architecture and implementation guides

## Next Build Steps
1. Build scanner adapters for existing engines.
2. Normalize all findings into one schema.
3. Correlate findings across scanners.
4. Implement risk score and confidence scoring.
5. Add actionable fix suggestions with patch output.
