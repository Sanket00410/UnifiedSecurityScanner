# Enterprise Security Platform Architecture

## Target Architecture

                +-------------+
                |  Code Repo  |
                +------+------+ 
                       |
                       v
     +---------------------------------+
     | Static Analysis Layer (SAST)    |
     | - AST parsing / semantics       |
     | - taint tracking                |
     | - data/control-flow             |
     +---------------------------------+
                       |
                       v
     +---------------------------------+
     | Dependency + Secret Scanner     |
     +---------------------------------+
                       |
                       v
     +---------------------------------+
     | IaC Scanner                     |
     | (Terraform/CFN/ARM/K8s/Docker) |
     +---------------------------------+
                       |
                       v
     +---------------------------------+
     | Runtime Scanner (DAST)          |
     +---------------------------------+
                       |
                       v
             +-------------------+
             | Risk Engine       |
             | (Business Impact) |
             +---------+---------+
                       |
                       v
             +-------------------+
             | Developer UI      |
             +-------------------+

## Scanner Responsibilities

### SAST
- Detect high-impact issues first: SQLi, NoSQLi, command injection, SSRF, IDOR, broken authz, unsafe deserialization, RCE sinks, weak crypto, dangerous uploads, XSS in sensitive flows.
- Enforce source -> sanitizer -> sink modeling.
- Taint tracking required for credibility.

### DAST
- Crawl endpoints and authenticated paths.
- Fuzz parameters and body inputs.
- Validate exploitability of SAST findings where possible.

### IaC
- Analyze Terraform, CloudFormation, ARM, K8s YAML, Dockerfiles.
- Flag public storage, open SGs, privileged/root containers, missing encryption/logging, and hardcoded credentials.

### Dependency
- CVE mapping, license risk, typosquatting detection.
- Prioritize reachable vulnerable code paths over unused dependencies.

### Secrets
- Pattern + entropy + context-aware detection.
- Suppress known fixtures/tests where appropriate.

## Integration-First Strategy
Use proven engines and build differentiation in correlation + prioritization:
- Semgrep (multi-language SAST)
- CodeQL (deep flow)
- OWASP ZAP (DAST)
- Trivy (dependency/IaC/container)
- Checkov (IaC)
- Gitleaks (secrets)

## Business Risk Scoring

score = (impact * exploitability * exposure * reachability) - mitigation

Example scale:
- Impact: account takeover 10, data breach 9, RCE 10, DoS 6
- Exploitability: public exploit 9, auth required 5, complex chain 3
- Exposure: internet-facing 9, internal 4
- Reachability: direct 10, theoretical 3

## Product Differentiators
- High signal findings only
- Explicit exploit path visualization
- Business impact statement
- Fix patch generation
- Confidence score (High/Medium/Needs Review)
