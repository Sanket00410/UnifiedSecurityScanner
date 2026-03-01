# Unified Security Scanner Enterprise Architecture

## Mission

Build one enterprise application that unifies code security, software supply-chain security, infrastructure posture scanning, dynamic application testing, and controlled attack validation across Windows, Linux, and macOS environments.

This is a production architecture, not an MVP. The system must be scalable, auditable, policy-driven, and safe to run inside regulated enterprise networks.

## Design Principles

- One control plane, many specialized scanners
- Cross-platform worker execution instead of OS-specific product forks
- Correlation first: one finding graph, one risk model, one remediation workflow
- Safe active testing: no unrestricted exploit execution, only approved and isolated validation
- Enterprise defaults: tenancy, RBAC, SSO, audit trails, encryption, HA, and API-first integration
- Separate user-facing cross-platform support from scanner runtime placement; route each tool to the OS it is best supported on
- Prefer streaming pipelines and bounded-memory services over large in-memory scan aggregation

## Target Architecture

                           +----------------------------------+
                           | Repos / CI / Artifacts / Assets  |
                           | Git, registries, SBOMs, targets  |
                           +----------------+-----------------+
                                            |
                                            v
     +----------------------------------------------------------------------------+
     | Ingestion and Context Layer                                                 |
     | - Repo connectors, webhooks, CI intake, asset inventory                     |
     | - Build metadata, runtime metadata, ownership, tagging                      |
     | - Secret broker references, credential vault integration                    |
     +--------------------------------------+-------------------------------------+
                                            |
                                            v
     +----------------------------------------------------------------------------+
     | Control Plane                                                               |
     | - API gateway and job API                                                   |
     | - SSO (SAML/OIDC), RBAC, tenant isolation                                   |
     | - Scheduler, queueing, scan orchestration, policy engine                    |
     | - Rate limits, target approvals, maintenance windows, audit logging         |
     +--------------------------------------+-------------------------------------+
                                            |
                                            v
     +----------------------------------------------------------------------------+
     | Cross-Platform Execution Plane                                              |
     | - Windows worker agents                                                     |
     | - Linux worker agents                                                       |
     | - macOS worker agents                                                       |
     | - Ephemeral sandbox runners for untrusted scanners                          |
     +-----------------+-------------------+-------------------+------------------+
                       |                   |                   |
                       v                   v                   v
     +---------------------------+ +---------------------+ +----------------------+
     | Code Security             | | Supply Chain        | | Cloud / IaC /        |
     | - AST and semantic SAST   | | - SCA and SBOM      | | Container Security   |
     | - Taint and data flow     | | - Reachability      | | - Terraform/CFN/ARM  |
     | - API misuse detection    | | - License policy    | | - K8s/Docker/images  |
     | - Custom rule packs       | | - Secret scanning   | | - Drift/misconfig    |
     +---------------------------+ +---------------------+ +----------------------+
                       |                   |                   |
                       +-------------------+-------------------+
                                            |
                                            v
     +----------------------------------------------------------------------------+
     | Runtime Security Layer                                                      |
     | - DAST for web apps and APIs                                                |
     | - Authenticated crawl and API schema testing                                |
     | - Stateful session handling and business-flow coverage                      |
     | - Passive and active verification with traffic evidence                     |
     +--------------------------------------+-------------------------------------+
                                            |
                                            v
     +----------------------------------------------------------------------------+
     | Automated Pentest and Attack Validation Layer                               |
     | - Curated Kali-class adapters, not blanket execution of all Kali tools      |
     | - Scoped target approvals and per-engagement policy packs                   |
     | - Isolated runners, network guardrails, timeouts, and evidence capture      |
     | - Human approval gates for high-impact validation steps                     |
     +--------------------------------------+-------------------------------------+
                                            |
                                            v
     +----------------------------------------------------------------------------+
     | Correlation and Finding Graph                                               |
     | - Normalize all findings into one schema                                    |
     | - Link code, dependency, container, cloud, and runtime evidence             |
     | - Merge duplicates and create exploit paths                                 |
     | - Track asset ownership, exposure, and remediation state                    |
     +--------------------------------------+-------------------------------------+
                                            |
                                            v
     +----------------------------------------------------------------------------+
     | Risk Engine                                                                 |
     | - Business impact scoring                                                   |
     | - Exploitability, reachability, and exposure weighting                      |
     | - Confidence scoring and policy exceptions                                  |
     | - SLA, compliance, and remediation prioritization                           |
     +--------------------------------------+-------------------------------------+
                                            |
                                            v
     +----------------------------------------------------------------------------+
     | Unified User Experience and Integrations                                    |
     | - Developer UI, AppSec console, management dashboards                       |
     | - REST/GraphQL API, webhooks, CI/CD integrations                            |
     | - Jira/ServiceNow, SIEM, Slack/Teams, email                                 |
     | - Reports, evidence export, audit export                                    |
     +----------------------------------------------------------------------------+

## Shared Platform Backbone

These services span every layer and are mandatory for an end-to-end enterprise product:

- Identity and tenant service for SSO, RBAC, SCIM, service accounts, and data partitioning
- Rule, policy, and template management for SAST rules, Nuclei templates, allow-lists, and scan profiles
- Threat intelligence and advisory feed sync for CVEs, OSV, KEV-class priorities, license data, and rule updates
- Findings lifecycle service for baselines, suppressions, retests, ticket sync, SLAs, and closure state
- Notification and workflow service for approvals, escalations, chatops, and change events
- Administration and upgrade service for worker registration, version compatibility, rollout, rollback, and air-gapped package sync
- Observability service for metrics, traces, logs, capacity, and incident diagnostics

## Functional Layers

### 1. Ingestion and Context

- Connect Git providers, artifact registries, container registries, and cloud accounts.
- Import SBOMs, build manifests, runtime asset inventories, and ownership metadata.
- Maintain application, service, environment, and business criticality mapping.
- Store scanner credentials in an external secret manager, never in scanner configs.

### 2. Control Plane

- Expose a versioned API for scan creation, target registration, policy assignment, and findings retrieval.
- Enforce SSO, RBAC, and tenant boundaries for every job, artifact, and result.
- Schedule scans by event, cron, release gate, pull request, or on-demand workflow.
- Apply policy packs that define which scanners run, how aggressive they may be, and whether human approval is required.

### 3. Cross-Platform Execution Plane

- Use a thin signed worker agent for Windows, Linux, and macOS.
- Run scanners in isolated processes, containers, or lightweight VMs based on trust level.
- Keep scanner adapters versioned and independently updatable from the core control plane.
- Support offline and air-gapped workers by syncing signed rule packs and advisories.

### 4. Code Security (SAST)

- Use AST parsing, semantic analysis, taint tracking, data-flow, and control-flow modeling.
- Focus on high-value defects: injection, SSRF, IDOR, authz bypass, deserialization, unsafe file handling, weak crypto, secret exposure, and RCE paths.
- Add framework-aware rules for common enterprise stacks and custom internal frameworks.
- Correlate code findings with reachable endpoints, exposed services, and vulnerable dependencies.

### 5. Supply Chain Security

- Build and ingest SBOMs for direct and transitive dependencies.
- Map vulnerabilities from OSV, NVD, vendor advisories, and curated intelligence feeds.
- Prioritize reachable vulnerable code, not just package presence.
- Enforce license policy, malicious package detection, integrity checks, and typosquat rules.

### 6. Secret Detection

- Combine signatures, entropy, and context-aware validation.
- Detect credentials in source, config, IaC, build logs, and generated artifacts.
- Suppress approved fixtures and test data through policy-managed allowlists.
- Support secret revocation hooks and rotation workflow integration.

### 7. Cloud / IaC / Container Security

- Scan Terraform, CloudFormation, ARM/Bicep, Kubernetes manifests, Helm charts, Dockerfiles, and container images.
- Detect public exposure, privilege escalation, missing encryption, weak network boundaries, insecure defaults, and compliance gaps.
- Compare desired state to deployed state where cloud connectors are available.
- Feed workload, namespace, and account context into the risk engine.

### 8. Runtime Security (DAST)

- Support authenticated crawling for browser apps, APIs, GraphQL, and service endpoints.
- Reuse recorded login flows, API specifications, and test accounts.
- Capture evidence for passive findings and limit active attacks through policy thresholds.
- Validate whether high-confidence SAST and IaC issues are actually reachable in production-like environments.

### 9. Automated Pentesting and Controlled Attack Validation

- Automatic pentesting is a first-class subsystem, but it must use a curated allow-list of enterprise-approved adapters rather than unrestricted access to the full Kali catalog.
- Recommended enterprise starter pack: `Nmap` for discovery and service mapping, `Nuclei` for template-driven exposure checks, `testssl.sh` for TLS and protocol validation, `ffuf` and `feroxbuster` for content discovery, `Nikto` for web misconfiguration checks, `sqlmap` for approved SQL injection validation, `OWASP ZAP` for authenticated web and API attack workflows, and `Metasploit` for restricted exploit confirmation.
- `Metasploit` must be wrapped behind a policy-enforced adapter with approved module allow-lists, payload restrictions, execution timeouts, full evidence capture, and no post-exploitation, persistence, pivoting, or unrestricted reverse-shell delivery by default.
- Optional protocol-specific adapters can be enabled per tenant and per scope for approved internal assessments, but only through the same adapter, approval, and audit framework.
- Every automated pentest action must be tied to an approved target scope, a tenant policy pack, per-tool guardrails, evidence retention, audit logs, and kill switches.

### 10. Correlation and Risk

- Normalize all scanner outputs into a canonical finding schema.
- Build a graph that links source files, packages, images, cloud resources, endpoints, and business services.
- Score findings using exploitability, exposure, reachability, asset criticality, data sensitivity, and compensating controls.
- Present one remediation item when many raw detections point to the same root cause.

### 11. Asset Registry and Scope Governance

- Maintain a canonical inventory of repositories, applications, APIs, domains, cloud accounts, containers, clusters, and environments.
- Enforce in-scope and out-of-scope boundaries for every dynamic scan and pentest job.
- Bind each target to business owners, environment classification, approval policy, and maintenance windows.
- Track target exposure state so public-facing assets are prioritized correctly.

### 12. Rule, Template, and Threat Intelligence Lifecycle

- Version and sign all scanner rule packs, pentest templates, and approved module allow-lists.
- Roll out rule updates through staged channels with compatibility tests and rollback support.
- Continuously ingest vulnerability, exploitability, and package intelligence feeds into the platform.
- Keep custom enterprise rules separate from vendor packs so customer-specific logic is maintainable.

### 13. Findings Lifecycle and Remediation

- Separate new findings from historical baseline findings to reduce alert noise.
- Support suppressions, policy exceptions, and risk acceptances with owners, reasons, and expiry dates.
- Sync remediation work to Jira, ServiceNow, and CI/CD quality gates.
- Generate retest jobs automatically after code, dependency, infrastructure, or deployment changes.
- Support fix suggestions and patch generation for code and IaC where confidence is high.

### 14. Operations, Reliability, and Administration

- Manage worker enrollment, certificate rotation, heartbeat checks, and version skew.
- Enforce retry policies, dead-letter queues, back-pressure, and graceful degradation under load.
- Define backup, retention, archival, and disaster recovery for metadata and evidence.
- Expose tenant-safe diagnostics, audit exports, and operational health dashboards.

## Data Architecture

- `PostgreSQL`: tenants, assets, policies, jobs, findings metadata
- `Object storage`: raw scanner evidence, SARIF, logs, screenshots, packet captures, reports
- `Graph store` or graph index: exploit path and asset relationship correlation
- `Search index`: fast finding search, aggregations, and dashboards
- `Queue`: scan dispatch, retry, back-pressure, and worker heartbeats
- `Cache`: session state, short-lived orchestration state, advisory lookups

## End-to-End Scan Flow

1. A repo change, scheduled job, or manual request enters the ingestion layer with target metadata and tenant context.
2. The control plane resolves the scan profile, target scope, approval requirements, credentials, and routing policy.
3. The scheduler dispatches work to the correct worker pool based on tool capability, OS compatibility, trust level, and capacity.
4. Scanner adapters execute in isolated sandboxes, stream logs and partial results, and store raw evidence outside process memory as early as possible.
5. The correlation layer normalizes raw outputs into one finding model and merges related evidence across code, dependencies, infrastructure, and runtime.
6. The risk engine computes priority using exploitability, reachability, exposure, asset criticality, and compensating controls.
7. The findings lifecycle service updates baselines, opens or reopens remediation work, applies SLAs, and publishes notifications.
8. The UI and APIs expose current state, evidence, approvals, exceptions, trend data, and retest actions.

## Cross-Platform Delivery Model

- The product is cross-platform because the user experience is a web application and the worker agents are available for Windows, Linux, and macOS.
- Do not force every scanner to run natively on every OS. Many security tools are Linux-first, and pretending otherwise creates an unstable design.
- Use heterogeneous worker pools with explicit OS-specific responsibilities.
- Windows workers for Windows-native source access, PowerShell analysis, AD-aware collection, and approved native adapters
- Linux workers for container analysis, most IaC tooling, DAST farms, and most Kali-class automated pentest tooling
- macOS workers for local developer workflows, Apple-specific builds, and platform-specific source analysis
- Keep an adapter capability matrix so the scheduler routes each job to supported OS and runtime combinations.
- If a tool is not available on a tenant's chosen OS, fall back to a remote isolated worker pool instead of blocking the entire platform.

## Deployment Topologies

- SaaS: vendor-operated control plane with customer-installed workers for internal assets and private targets
- Hybrid: vendor-operated control plane with dedicated private worker pools, private connectors, and private evidence storage options
- Self-hosted: customer-operated control plane and workers in private cloud or datacenter
- Air-gapped: offline deployment with signed package bundles, mirrored feeds, staged update import, and no always-on internet dependency
- Keep the same APIs, worker protocol, and artifact model across all deployment modes so the product does not fork operationally

## Enterprise Platform Requirements

- High availability across control plane services
- Horizontal worker scaling with queue-based back-pressure
- Full audit logging for scans, approvals, policy changes, and exports
- Signed rule packs, signed workers, and scanner provenance tracking
- Encryption in transit and at rest
- Customer-managed keys support for enterprise deployments
- Regional deployment options and data residency controls
- Air-gapped or private-network deployment mode
- Observability with metrics, tracing, structured logs, and health checks

## Security Guardrails

- Default to passive analysis unless policy explicitly enables active validation
- Require target ownership verification before dynamic or validation scans
- Isolate active testing runners from the control plane and customer production systems
- Block unrestricted lateral movement, unrestricted internet egress, and uncontrolled credential reuse
- Maintain per-tool kill switches, per-tenant rate limits, and emergency stop controls
- Store evidence incrementally and compress large artifacts so long-running scans do not retain large in-memory buffers
- Use streaming parsers and chunked normalization for large repositories, SARIF files, logs, and scan captures

## Recommended Technology and Language Strategy

- Best overall split for performance, memory efficiency, and cross-platform support is `Rust` for hot-path runtime components, `Go` for most backend services, and `TypeScript` for the web UI.
- `Rust`: worker agent, sandbox supervisor, scan stream processor, performance-critical correlation components, and any custom parsers or taint engines
- `Go`: control plane APIs, scheduler, connectors, queue consumers, notification services, and most distributed backend services
- `TypeScript`: web UI only
- If you want one primary backend language across most services, choose `Go`. It is simpler to hire for, compiles to small cross-platform binaries, and is usually the best balance of speed, memory use, and delivery velocity.
- If you want the lowest memory footprint and strongest safety for hot-path components, use `Rust` selectively where performance matters most instead of forcing the whole stack into Rust.
- Avoid making Python or Node.js the core runtime for heavy scan orchestration or evidence processing if memory efficiency is a top requirement. They are fine for isolated glue code, prototypes, or third-party wrappers, but not ideal for the core engine.
- SAST engines: Semgrep, CodeQL, and language-specific parsers with custom rules
- Supply chain and container: Trivy or equivalent, plus internal reachability correlation
- IaC: Checkov or equivalent, plus custom policy packs
- DAST: ZAP-class browser/API scanning with authenticated workflows
- Automated pentest adapters: `Nmap`, `Nuclei`, `testssl.sh`, `ffuf`, `feroxbuster`, `Nikto`, `sqlmap`, `OWASP ZAP`, and a policy-restricted `Metasploit` wrapper

## High-Level Implementation Shape

- `Go` control plane processes should stay stateless where possible and push large artifacts directly to object storage.
- `Rust` worker components should use async I/O, bounded queues, and zero-copy parsing where practical to keep memory stable under concurrency.
- Keep scanner adapters as isolated subprocesses with streaming stdout/stderr ingestion instead of loading full reports into memory.
- Normalize findings incrementally and persist intermediate state so a large scan can resume without reprocessing everything.
- Prefer message-driven boundaries between services so CPU-heavy jobs do not block user-facing APIs.

## Delivery Focus

Build the platform in this order:
1. Control plane, finding schema, and worker framework
2. SAST, SCA, secret, and IaC adapters
3. Correlation graph and risk engine
4. DAST with authenticated workflows
5. Controlled attack validation with strict approvals and isolated runners

This sequence produces an enterprise foundation first, then adds higher-risk active testing only after governance, isolation, and evidence handling are in place.
