use crate::adapter::{AdapterRequest, AdapterResult, ExecutionMode, ScannerAdapter};
use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub fn execute(request: &AdapterRequest) -> Result<AdapterResult, String> {
    match request.adapter_id.as_str() {
        "zap" => ZapAdapter.execute(request),
        "zap-api" => ZapAPIAdapter.execute(request),
        "nmap" => NmapAdapter.execute(request),
        "nuclei" => NucleiAdapter.execute(request),
        "browser-probe" => BrowserProbeAdapter.execute(request),
        "metasploit" => MetasploitAdapter.execute(request),
        "semgrep" => SemgrepAdapter.execute(request),
        "mobsfscan" => MobSFScanAdapter.execute(request),
        "gosec" => GosecAdapter.execute(request),
        "spotbugs" => SpotBugsAdapter.execute(request),
        "pmd" => PmdAdapter.execute(request),
        "bundler-audit" => BundlerAuditAdapter.execute(request),
        "brakeman" => BrakemanAdapter.execute(request),
        "devskim" => DevSkimAdapter.execute(request),
        "bandit" => BanditAdapter.execute(request),
        "eslint" => EslintAdapter.execute(request),
        "phpstan" => PhpStanAdapter.execute(request),
        "detect-secrets" => DetectSecretsAdapter.execute(request),
        "shellcheck" => ShellCheckAdapter.execute(request),
        "dotnet-audit" => DotnetAuditAdapter.execute(request),
        "npm-audit" => NpmAuditAdapter.execute(request),
        "composer-audit" => ComposerAuditAdapter.execute(request),
        "osv-scanner" => OsvScannerAdapter.execute(request),
        "syft" => SyftAdapter.execute(request),
        "trivy" => TrivyAdapter.execute(request),
        "trivy-image" => TrivyImageAdapter.execute(request),
        "trivy-config" => TrivyConfigAdapter.execute(request),
        "trivy-secrets" => TrivySecretsAdapter.execute(request),
        "grype" => GrypeAdapter.execute(request),
        "gitleaks" => GitleaksAdapter.execute(request),
        "checkov" => CheckovAdapter.execute(request),
        "cfn-lint" => CfnLintAdapter.execute(request),
        "hadolint" => HadolintAdapter.execute(request),
        "kics" => KicsAdapter.execute(request),
        "prowler" => ProwlerAdapter.execute(request),
        "kubesec" => KubeSecAdapter.execute(request),
        "kube-score" => KubeScoreAdapter.execute(request),
        "tfsec" => TfsecAdapter.execute(request),
        unsupported => Err(format!("unsupported adapter: {unsupported}")),
    }
}

struct ZapAdapter;
struct ZapAPIAdapter;
struct NmapAdapter;
struct NucleiAdapter;
struct BrowserProbeAdapter;
struct MetasploitAdapter;
struct SemgrepAdapter;
struct MobSFScanAdapter;
struct GosecAdapter;
struct SpotBugsAdapter;
struct PmdAdapter;
struct BundlerAuditAdapter;
struct BrakemanAdapter;
struct DevSkimAdapter;
struct BanditAdapter;
struct EslintAdapter;
struct PhpStanAdapter;
struct DetectSecretsAdapter;
struct ShellCheckAdapter;
struct DotnetAuditAdapter;
struct NpmAuditAdapter;
struct ComposerAuditAdapter;
struct OsvScannerAdapter;
struct SyftAdapter;
struct TrivyAdapter;
struct TrivyImageAdapter;
struct TrivyConfigAdapter;
struct TrivySecretsAdapter;
struct GrypeAdapter;
struct GitleaksAdapter;
struct CheckovAdapter;
struct CfnLintAdapter;
struct HadolintAdapter;
struct KicsAdapter;
struct ProwlerAdapter;
struct KubeSecAdapter;
struct KubeScoreAdapter;
struct TfsecAdapter;

impl ScannerAdapter for ZapAdapter {
    fn id(&self) -> &'static str {
        "zap"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(
            mode,
            ExecutionMode::Passive | ExecutionMode::ActiveValidation
        )
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "zap-output.log")?;
        let policy_snapshot = write_web_runtime_policy_snapshot(request)?;
        let binary = env::var("USS_ZAP_CMD").unwrap_or_else(|_| default_zap_binary().to_string());

        let mut args = vec![
            "-cmd".to_string(),
            "-quickurl".to_string(),
            request.target.clone(),
            "-quickout".to_string(),
            report_path.to_string_lossy().to_string(),
            "-quickprogress".to_string(),
        ];
        append_zap_policy_args(request, &mut args);

        if matches!(request.execution_mode, ExecutionMode::Passive) {
            args.push("-silent".to_string());
        }

        let mut evidence_paths = vec![report_path.clone()];
        if let Some(snapshot_path) = policy_snapshot {
            evidence_paths.push(snapshot_path);
        }

        run_process(
            self.id(),
            &binary,
            &args,
            &report_path,
            request.max_runtime_seconds,
            evidence_paths,
            None,
        )
    }
}

impl ScannerAdapter for ZapAPIAdapter {
    fn id(&self) -> &'static str {
        "zap-api"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(
            mode,
            ExecutionMode::Passive | ExecutionMode::ActiveValidation
        )
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "zap-api-output.log")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "zap-api-exec.log")?;
        let policy_snapshot = write_web_runtime_policy_snapshot(request)?;
        let binary =
            env::var("USS_ZAP_API_CMD").unwrap_or_else(|_| default_zap_binary().to_string());

        let mut args = vec![
            "-cmd".to_string(),
            "-openapiurl".to_string(),
            request.target.clone(),
            "-quickout".to_string(),
            report_path.to_string_lossy().to_string(),
            "-quickprogress".to_string(),
        ];
        append_zap_policy_args(request, &mut args);

        if matches!(request.execution_mode, ExecutionMode::Passive) {
            args.push("-silent".to_string());
        }

        let mut evidence_paths = vec![report_path.clone()];
        if let Some(snapshot_path) = policy_snapshot {
            evidence_paths.push(snapshot_path);
        }

        run_process(
            self.id(),
            &binary,
            &args,
            &log_path,
            request.max_runtime_seconds,
            evidence_paths,
            None,
        )
    }
}

impl ScannerAdapter for NmapAdapter {
    fn id(&self) -> &'static str {
        "nmap"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::ActiveValidation)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let log_path = ensure_evidence_path(&request.evidence_dir, "nmap-output.log")?;
        let binary = env::var("USS_NMAP_CMD").unwrap_or_else(|_| "nmap".to_string());
        let report_path = ensure_evidence_path(&request.evidence_dir, "nmap-report.txt")?;

        let args = vec![
            "-Pn".to_string(),
            "-T4".to_string(),
            "-oN".to_string(),
            report_path.to_string_lossy().to_string(),
            request.target.clone(),
        ];

        run_process(
            self.id(),
            &binary,
            &args,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path],
            None,
        )
    }
}

impl ScannerAdapter for NucleiAdapter {
    fn id(&self) -> &'static str {
        "nuclei"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::ActiveValidation)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "nuclei-results.jsonl")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "nuclei-exec.log")?;
        let policy_snapshot = write_web_runtime_policy_snapshot(request)?;
        let binary = env::var("USS_NUCLEI_CMD").unwrap_or_else(|_| "nuclei".to_string());
        let mut args = vec![
            "-u".to_string(),
            request.target.clone(),
            "-jsonl".to_string(),
            "-o".to_string(),
            report_path.to_string_lossy().to_string(),
        ];
        append_nuclei_policy_args(request, &mut args);

        let mut evidence_paths = vec![report_path.clone()];
        if let Some(snapshot_path) = policy_snapshot {
            evidence_paths.push(snapshot_path);
        }

        run_process(
            self.id(),
            &binary,
            &args,
            &log_path,
            request.max_runtime_seconds,
            evidence_paths,
            None,
        )
    }
}

impl ScannerAdapter for BrowserProbeAdapter {
    fn id(&self) -> &'static str {
        "browser-probe"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(
            mode,
            ExecutionMode::Passive | ExecutionMode::ActiveValidation
        )
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path =
            ensure_evidence_path(&request.evidence_dir, "browser-probe-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "browser-probe-exec.log")?;
        let policy_snapshot = write_web_runtime_policy_snapshot(request)?;
        let binary =
            env::var("USS_BROWSER_PROBE_CMD").unwrap_or_else(|_| "browser-probe".to_string());

        let mut args = vec![
            "--target".to_string(),
            request.target.clone(),
            "--output".to_string(),
            report_path.to_string_lossy().to_string(),
            "--format".to_string(),
            "json".to_string(),
        ];
        append_browser_probe_policy_args(request, &mut args);

        if let Ok(extra) = env::var("USS_BROWSER_PROBE_EXTRA_ARGS") {
            for value in extra.split_whitespace() {
                let normalized = value.trim();
                if !normalized.is_empty() {
                    args.push(normalized.to_string());
                }
            }
        }

        let mut evidence_paths = vec![report_path.clone()];
        if let Some(snapshot_path) = policy_snapshot {
            evidence_paths.push(snapshot_path);
        }

        run_process(
            self.id(),
            &binary,
            &args,
            &log_path,
            request.max_runtime_seconds,
            evidence_paths,
            None,
        )
    }
}

impl ScannerAdapter for MetasploitAdapter {
    fn id(&self) -> &'static str {
        "metasploit"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::RestrictedExploit)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)?;

        if request.approved_modules.is_empty() {
            return Err("metasploit requires at least one approved module".to_string());
        }

        Ok(())
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let evidence_path = ensure_evidence_path(&request.evidence_dir, "metasploit-output.log")?;
        let binary = env::var("USS_METASPLOIT_CMD").unwrap_or_else(|_| "msfconsole".to_string());
        let module = &request.approved_modules[0];

        let script = format!(
            "use {module}; set RHOSTS {target}; check; exit -y",
            module = module,
            target = request.target
        );
        let args = vec!["-q".to_string(), "-x".to_string(), script];

        run_process(
            self.id(),
            &binary,
            &args,
            &evidence_path,
            request.max_runtime_seconds,
            vec![evidence_path.clone()],
            None,
        )
    }
}

impl ScannerAdapter for SemgrepAdapter {
    fn id(&self) -> &'static str {
        "semgrep"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "semgrep-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "semgrep-exec.log")?;
        let binary = env::var("USS_SEMGREP_CMD").unwrap_or_else(|_| "semgrep".to_string());
        let semgrep_config = env::var("USS_SEMGREP_CONFIG").unwrap_or_else(|_| "auto".to_string());
        let args = vec![
            "scan".to_string(),
            "--config".to_string(),
            semgrep_config,
            "--json".to_string(),
            "--output".to_string(),
            report_path.to_string_lossy().to_string(),
            request.target.clone(),
        ];

        run_process(
            self.id(),
            &binary,
            &args,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path],
            None,
        )
    }
}

impl ScannerAdapter for MobSFScanAdapter {
    fn id(&self) -> &'static str {
        "mobsfscan"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "mobsfscan-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "mobsfscan-exec.log")?;
        let binary = env::var("USS_MOBSFSCAN_CMD").unwrap_or_else(|_| "mobsfscan".to_string());
        let args = vec![
            "--json".to_string(),
            "-o".to_string(),
            report_path.to_string_lossy().to_string(),
            request.target.clone(),
        ];

        run_process(
            self.id(),
            &binary,
            &args,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path],
            None,
        )
    }
}

impl ScannerAdapter for GosecAdapter {
    fn id(&self) -> &'static str {
        "gosec"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "gosec-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "gosec-exec.log")?;
        let binary = env::var("USS_GOSEC_CMD").unwrap_or_else(|_| "gosec".to_string());
        let args = vec![
            "-fmt".to_string(),
            "json".to_string(),
            "-out".to_string(),
            report_path.to_string_lossy().to_string(),
            "./...".to_string(),
        ];

        run_process(
            self.id(),
            &binary,
            &args,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path],
            Some(Path::new(&request.target)),
        )
    }
}

impl ScannerAdapter for SpotBugsAdapter {
    fn id(&self) -> &'static str {
        "spotbugs"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "spotbugs-results.xml")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "spotbugs-exec.log")?;
        let binary = env::var("USS_SPOTBUGS_CMD").unwrap_or_else(|_| "spotbugs".to_string());
        let args = vec![
            "-textui".to_string(),
            "-xml:withMessages".to_string(),
            "-output".to_string(),
            report_path.to_string_lossy().to_string(),
            request.target.clone(),
        ];

        run_process(
            self.id(),
            &binary,
            &args,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path],
            None,
        )
    }
}

impl ScannerAdapter for PmdAdapter {
    fn id(&self) -> &'static str {
        "pmd"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "pmd-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "pmd-exec.log")?;
        let binary = env::var("USS_PMD_CMD").unwrap_or_else(|_| "pmd".to_string());
        let args = vec![
            "check".to_string(),
            "-R".to_string(),
            "category/java/bestpractices.xml".to_string(),
            "-f".to_string(),
            "json".to_string(),
            "-d".to_string(),
            request.target.clone(),
            "--report-file".to_string(),
            report_path.to_string_lossy().to_string(),
        ];

        run_process(
            self.id(),
            &binary,
            &args,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path],
            None,
        )
    }
}

impl ScannerAdapter for BundlerAuditAdapter {
    fn id(&self) -> &'static str {
        "bundler-audit"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path =
            ensure_evidence_path(&request.evidence_dir, "bundler-audit-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "bundler-audit-exec.log")?;
        let binary =
            env::var("USS_BUNDLER_AUDIT_CMD").unwrap_or_else(|_| "bundle-audit".to_string());
        let args = vec![
            "check".to_string(),
            "--format".to_string(),
            "json".to_string(),
        ];

        run_process_with_stdout_report_allow_exit_codes(
            self.id(),
            &binary,
            &args,
            &report_path,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path.clone()],
            &[1],
            Some(Path::new(&request.target)),
        )
    }
}

impl ScannerAdapter for BrakemanAdapter {
    fn id(&self) -> &'static str {
        "brakeman"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "brakeman-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "brakeman-exec.log")?;
        let binary = env::var("USS_BRAKEMAN_CMD").unwrap_or_else(|_| "brakeman".to_string());
        let args = vec![
            "-q".to_string(),
            "-f".to_string(),
            "json".to_string(),
            "-o".to_string(),
            report_path.to_string_lossy().to_string(),
            request.target.clone(),
        ];

        run_process(
            self.id(),
            &binary,
            &args,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path],
            None,
        )
    }
}

impl ScannerAdapter for DevSkimAdapter {
    fn id(&self) -> &'static str {
        "devskim"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "devskim-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "devskim-exec.log")?;
        let binary = env::var("USS_DEVSKIM_CMD").unwrap_or_else(|_| "devskim".to_string());
        let args = vec![
            "analyze".to_string(),
            request.target.clone(),
            "--output-format".to_string(),
            "json".to_string(),
            "--output-file".to_string(),
            report_path.to_string_lossy().to_string(),
        ];

        run_process(
            self.id(),
            &binary,
            &args,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path],
            None,
        )
    }
}

impl ScannerAdapter for BanditAdapter {
    fn id(&self) -> &'static str {
        "bandit"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "bandit-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "bandit-exec.log")?;
        let binary = env::var("USS_BANDIT_CMD").unwrap_or_else(|_| "bandit".to_string());
        let args = vec![
            "-r".to_string(),
            request.target.clone(),
            "-f".to_string(),
            "json".to_string(),
            "-o".to_string(),
            report_path.to_string_lossy().to_string(),
        ];

        run_process(
            self.id(),
            &binary,
            &args,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path],
            None,
        )
    }
}

impl ScannerAdapter for EslintAdapter {
    fn id(&self) -> &'static str {
        "eslint"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "eslint-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "eslint-exec.log")?;
        let binary = env::var("USS_ESLINT_CMD").unwrap_or_else(|_| "eslint".to_string());
        let args = vec![
            "--format".to_string(),
            "json".to_string(),
            request.target.clone(),
        ];

        run_process_with_stdout_report_allow_exit_codes(
            self.id(),
            &binary,
            &args,
            &report_path,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path.clone()],
            &[1],
            None,
        )
    }
}

impl ScannerAdapter for PhpStanAdapter {
    fn id(&self) -> &'static str {
        "phpstan"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "phpstan-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "phpstan-exec.log")?;
        let binary = env::var("USS_PHPSTAN_CMD").unwrap_or_else(|_| "phpstan".to_string());
        let args = vec![
            "analyse".to_string(),
            "--error-format".to_string(),
            "json".to_string(),
            request.target.clone(),
        ];

        run_process_with_stdout_report_allow_exit_codes(
            self.id(),
            &binary,
            &args,
            &report_path,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path.clone()],
            &[1],
            None,
        )
    }
}

impl ScannerAdapter for DetectSecretsAdapter {
    fn id(&self) -> &'static str {
        "detect-secrets"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path =
            ensure_evidence_path(&request.evidence_dir, "detect-secrets-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "detect-secrets-exec.log")?;
        let binary =
            env::var("USS_DETECT_SECRETS_CMD").unwrap_or_else(|_| "detect-secrets".to_string());
        let args = vec![
            "scan".to_string(),
            "--all-files".to_string(),
            request.target.clone(),
        ];

        run_process_with_stdout_report(
            self.id(),
            &binary,
            &args,
            &report_path,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path.clone()],
            None,
        )
    }
}

impl ScannerAdapter for ShellCheckAdapter {
    fn id(&self) -> &'static str {
        "shellcheck"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "shellcheck-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "shellcheck-exec.log")?;
        let binary = env::var("USS_SHELLCHECK_CMD").unwrap_or_else(|_| "shellcheck".to_string());
        let args = vec![
            "--format".to_string(),
            "json1".to_string(),
            request.target.clone(),
        ];

        run_process_with_stdout_report_allow_exit_codes(
            self.id(),
            &binary,
            &args,
            &report_path,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path.clone()],
            &[1],
            None,
        )
    }
}

impl ScannerAdapter for NpmAuditAdapter {
    fn id(&self) -> &'static str {
        "npm-audit"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "npm-audit-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "npm-audit-exec.log")?;
        let binary = env::var("USS_NPM_CMD").unwrap_or_else(|_| "npm".to_string());
        let args = vec!["audit".to_string(), "--json".to_string()];

        run_process_with_stdout_report_allow_exit_codes(
            self.id(),
            &binary,
            &args,
            &report_path,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path.clone()],
            &[1],
            Some(Path::new(&request.target)),
        )
    }
}

impl ScannerAdapter for ComposerAuditAdapter {
    fn id(&self) -> &'static str {
        "composer-audit"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path =
            ensure_evidence_path(&request.evidence_dir, "composer-audit-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "composer-audit-exec.log")?;
        let binary = env::var("USS_COMPOSER_CMD").unwrap_or_else(|_| "composer".to_string());
        let args = vec!["audit".to_string(), "--format=json".to_string()];

        run_process_with_stdout_report_allow_exit_codes(
            self.id(),
            &binary,
            &args,
            &report_path,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path.clone()],
            &[1],
            Some(Path::new(&request.target)),
        )
    }
}

impl ScannerAdapter for DotnetAuditAdapter {
    fn id(&self) -> &'static str {
        "dotnet-audit"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "dotnet-audit-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "dotnet-audit-exec.log")?;
        let binary = env::var("USS_DOTNET_CMD").unwrap_or_else(|_| "dotnet".to_string());
        let args = vec![
            "list".to_string(),
            "package".to_string(),
            "--vulnerable".to_string(),
            "--include-transitive".to_string(),
            "--format".to_string(),
            "json".to_string(),
        ];

        run_process_with_stdout_report(
            self.id(),
            &binary,
            &args,
            &report_path,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path.clone()],
            Some(Path::new(&request.target)),
        )
    }
}

impl ScannerAdapter for OsvScannerAdapter {
    fn id(&self) -> &'static str {
        "osv-scanner"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "osv-scanner-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "osv-scanner-exec.log")?;
        let binary = env::var("USS_OSV_SCANNER_CMD").unwrap_or_else(|_| "osv-scanner".to_string());
        let args = vec![
            "scan".to_string(),
            "-r".to_string(),
            request.target.clone(),
            "--format".to_string(),
            "json".to_string(),
            "--output".to_string(),
            report_path.to_string_lossy().to_string(),
        ];

        run_process(
            self.id(),
            &binary,
            &args,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path],
            None,
        )
    }
}

impl ScannerAdapter for SyftAdapter {
    fn id(&self) -> &'static str {
        "syft"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;
        run_syft_adapter(self.id(), request, "syft-results.json", "syft-exec.log")
    }
}

impl ScannerAdapter for TrivyAdapter {
    fn id(&self) -> &'static str {
        "trivy"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;
        run_trivy_adapter(
            self.id(),
            request,
            "trivy-results.json",
            "trivy-exec.log",
            vec![
                "fs".to_string(),
                "--quiet".to_string(),
                "--format".to_string(),
                "json".to_string(),
                "--output".to_string(),
                "__REPORT__".to_string(),
                "--scanners".to_string(),
                "vuln".to_string(),
                request.target.clone(),
            ],
        )
    }
}

impl ScannerAdapter for TrivyImageAdapter {
    fn id(&self) -> &'static str {
        "trivy-image"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;
        run_trivy_adapter(
            self.id(),
            request,
            "trivy-image-results.json",
            "trivy-image-exec.log",
            vec![
                "image".to_string(),
                "--quiet".to_string(),
                "--format".to_string(),
                "json".to_string(),
                "--output".to_string(),
                "__REPORT__".to_string(),
                request.target.clone(),
            ],
        )
    }
}

impl ScannerAdapter for TrivyConfigAdapter {
    fn id(&self) -> &'static str {
        "trivy-config"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;
        run_trivy_adapter(
            self.id(),
            request,
            "trivy-config-results.json",
            "trivy-config-exec.log",
            vec![
                "config".to_string(),
                "--quiet".to_string(),
                "--format".to_string(),
                "json".to_string(),
                "--output".to_string(),
                "__REPORT__".to_string(),
                request.target.clone(),
            ],
        )
    }
}

impl ScannerAdapter for TrivySecretsAdapter {
    fn id(&self) -> &'static str {
        "trivy-secrets"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;
        run_trivy_adapter(
            self.id(),
            request,
            "trivy-secrets-results.json",
            "trivy-secrets-exec.log",
            vec![
                "fs".to_string(),
                "--quiet".to_string(),
                "--format".to_string(),
                "json".to_string(),
                "--output".to_string(),
                "__REPORT__".to_string(),
                "--scanners".to_string(),
                "secret".to_string(),
                request.target.clone(),
            ],
        )
    }
}

impl ScannerAdapter for GrypeAdapter {
    fn id(&self) -> &'static str {
        "grype"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "grype-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "grype-exec.log")?;
        let binary = env::var("USS_GRYPE_CMD").unwrap_or_else(|_| "grype".to_string());
        let normalized_target_kind = canonical_target_kind(&request.target_kind);
        let scan_target = match normalized_target_kind.as_str() {
            "repo" | "repository" | "codebase" | "filesystem" => {
                if let Some(sbom_path) =
                    try_prepare_syft_sbom(request, "grype-sbom.cdx.json", "grype-syft-exec.log")
                {
                    format!("sbom:{}", sbom_path.to_string_lossy())
                } else {
                    format!("dir:{}", request.target)
                }
            }
            "image" => {
                if let Some(sbom_path) =
                    try_prepare_syft_sbom(request, "grype-sbom.cdx.json", "grype-syft-exec.log")
                {
                    format!("sbom:{}", sbom_path.to_string_lossy())
                } else {
                    request.target.clone()
                }
            }
            _ => request.target.clone(),
        };
        let args = vec![scan_target, "-o".to_string(), "json".to_string()];

        run_process_with_stdout_report(
            self.id(),
            &binary,
            &args,
            &report_path,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path.clone()],
            None,
        )
    }
}

impl ScannerAdapter for KubeScoreAdapter {
    fn id(&self) -> &'static str {
        "kube-score"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "kube-score-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "kube-score-exec.log")?;
        let binary = env::var("USS_KUBE_SCORE_CMD").unwrap_or_else(|_| "kube-score".to_string());
        let args = vec![
            "score".to_string(),
            "--output-format".to_string(),
            "json".to_string(),
            request.target.clone(),
        ];

        run_process_with_stdout_report(
            self.id(),
            &binary,
            &args,
            &report_path,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path.clone()],
            None,
        )
    }
}

impl ScannerAdapter for TfsecAdapter {
    fn id(&self) -> &'static str {
        "tfsec"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "tfsec-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "tfsec-exec.log")?;
        let binary = env::var("USS_TFSEC_CMD").unwrap_or_else(|_| "tfsec".to_string());
        let args = vec![
            request.target.clone(),
            "--format".to_string(),
            "json".to_string(),
            "--no-color".to_string(),
        ];

        run_process_with_stdout_report(
            self.id(),
            &binary,
            &args,
            &report_path,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path.clone()],
            None,
        )
    }
}

impl ScannerAdapter for GitleaksAdapter {
    fn id(&self) -> &'static str {
        "gitleaks"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "gitleaks-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "gitleaks-exec.log")?;
        let binary = env::var("USS_GITLEAKS_CMD").unwrap_or_else(|_| "gitleaks".to_string());
        let args = vec![
            "detect".to_string(),
            "--no-banner".to_string(),
            "--report-format".to_string(),
            "json".to_string(),
            "--report-path".to_string(),
            report_path.to_string_lossy().to_string(),
            "--source".to_string(),
            request.target.clone(),
        ];

        run_process(
            self.id(),
            &binary,
            &args,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path],
            None,
        )
    }
}

impl ScannerAdapter for CheckovAdapter {
    fn id(&self) -> &'static str {
        "checkov"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "checkov-results.json")?;
        let binary = env::var("USS_CHECKOV_CMD").unwrap_or_else(|_| "checkov".to_string());
        let args = vec![
            "-d".to_string(),
            request.target.clone(),
            "-o".to_string(),
            "json".to_string(),
        ];

        run_process(
            self.id(),
            &binary,
            &args,
            &report_path,
            request.max_runtime_seconds,
            vec![report_path.clone()],
            None,
        )
    }
}

impl ScannerAdapter for CfnLintAdapter {
    fn id(&self) -> &'static str {
        "cfn-lint"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "cfn-lint-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "cfn-lint-exec.log")?;
        let binary = env::var("USS_CFN_LINT_CMD").unwrap_or_else(|_| "cfn-lint".to_string());
        let args = vec!["-f".to_string(), "json".to_string(), request.target.clone()];

        run_process_with_stdout_report_allow_exit_codes(
            self.id(),
            &binary,
            &args,
            &report_path,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path.clone()],
            &[2, 4],
            None,
        )
    }
}

impl ScannerAdapter for HadolintAdapter {
    fn id(&self) -> &'static str {
        "hadolint"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "hadolint-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "hadolint-exec.log")?;
        let binary = env::var("USS_HADOLINT_CMD").unwrap_or_else(|_| "hadolint".to_string());
        let args = vec![
            "--format".to_string(),
            "json".to_string(),
            request.target.clone(),
        ];

        run_process_with_stdout_report(
            self.id(),
            &binary,
            &args,
            &report_path,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path.clone()],
            None,
        )
    }
}

impl ScannerAdapter for KicsAdapter {
    fn id(&self) -> &'static str {
        "kics"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "kics-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "kics-exec.log")?;
        let binary = env::var("USS_KICS_CMD").unwrap_or_else(|_| "kics".to_string());
        let output_root = Path::new(&request.evidence_dir);
        let args = vec![
            "scan".to_string(),
            "-p".to_string(),
            request.target.clone(),
            "--report-formats".to_string(),
            "json".to_string(),
            "--output-path".to_string(),
            output_root.to_string_lossy().to_string(),
            "--output-name".to_string(),
            "kics-results".to_string(),
            "--silent".to_string(),
        ];

        run_process(
            self.id(),
            &binary,
            &args,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path],
            None,
        )
    }
}

impl ScannerAdapter for ProwlerAdapter {
    fn id(&self) -> &'static str {
        "prowler"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "prowler-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "prowler-exec.log")?;
        let binary = env::var("USS_PROWLER_CMD").unwrap_or_else(|_| "prowler".to_string());
        let provider = match request.target_kind.trim().to_ascii_lowercase().as_str() {
            "gcp_project" => "gcp",
            "azure_subscription" => "azure",
            _ => "aws",
        };
        let args = vec![
            provider.to_string(),
            "--output-modes".to_string(),
            "json".to_string(),
        ];

        run_process_with_stdout_report_allow_exit_codes(
            self.id(),
            &binary,
            &args,
            &report_path,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path.clone()],
            &[3],
            None,
        )
    }
}

impl ScannerAdapter for KubeSecAdapter {
    fn id(&self) -> &'static str {
        "kubesec"
    }

    fn supports(&self, mode: &ExecutionMode) -> bool {
        matches!(mode, ExecutionMode::Passive)
    }

    fn validate(&self, request: &AdapterRequest) -> Result<(), String> {
        validate_common(self, request)
    }

    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String> {
        self.validate(request)?;

        let report_path = ensure_evidence_path(&request.evidence_dir, "kubesec-results.json")?;
        let log_path = ensure_evidence_path(&request.evidence_dir, "kubesec-exec.log")?;
        let binary = env::var("USS_KUBESEC_CMD").unwrap_or_else(|_| "kubesec".to_string());
        let args = vec!["scan".to_string(), request.target.clone()];

        run_process_with_stdout_report(
            self.id(),
            &binary,
            &args,
            &report_path,
            &log_path,
            request.max_runtime_seconds,
            vec![report_path.clone()],
            None,
        )
    }
}

fn validate_common(adapter: &dyn ScannerAdapter, request: &AdapterRequest) -> Result<(), String> {
    if !adapter.supports(&request.execution_mode) {
        return Err(format!(
            "adapter {} does not support mode {:?}",
            adapter.id(),
            request.execution_mode
        ));
    }

    if request.target.trim().is_empty() {
        return Err("target is required".to_string());
    }

    if request.max_runtime_seconds == 0 {
        return Err("max_runtime_seconds must be greater than zero".to_string());
    }

    fs::create_dir_all(&request.evidence_dir)
        .map_err(|err| format!("create evidence directory: {err}"))?;

    Ok(())
}

fn ensure_evidence_path(dir: &str, filename: &str) -> Result<PathBuf, String> {
    let root = Path::new(dir);
    fs::create_dir_all(root).map_err(|err| format!("create evidence directory: {err}"))?;
    Ok(root.join(filename))
}

fn run_trivy_adapter(
    adapter_id: &str,
    request: &AdapterRequest,
    report_filename: &str,
    log_filename: &str,
    arg_template: Vec<String>,
) -> Result<AdapterResult, String> {
    let report_path = ensure_evidence_path(&request.evidence_dir, report_filename)?;
    let log_path = ensure_evidence_path(&request.evidence_dir, log_filename)?;
    let binary = env::var("USS_TRIVY_CMD").unwrap_or_else(|_| "trivy".to_string());
    let report_value = report_path.to_string_lossy().to_string();
    let args = arg_template
        .into_iter()
        .map(|value| {
            if value == "__REPORT__" {
                report_value.clone()
            } else {
                value
            }
        })
        .collect::<Vec<_>>();

    run_process(
        adapter_id,
        &binary,
        &args,
        &log_path,
        request.max_runtime_seconds,
        vec![report_path],
        None,
    )
}

fn run_syft_adapter(
    adapter_id: &str,
    request: &AdapterRequest,
    report_filename: &str,
    log_filename: &str,
) -> Result<AdapterResult, String> {
    let report_path = ensure_evidence_path(&request.evidence_dir, report_filename)?;
    let log_path = ensure_evidence_path(&request.evidence_dir, log_filename)?;
    let binary = env::var("USS_SYFT_CMD").unwrap_or_else(|_| "syft".to_string());
    let args = vec![
        syft_scan_target(&request.target_kind, &request.target),
        "-o".to_string(),
        "cyclonedx-json".to_string(),
    ];

    run_process_with_stdout_report(
        adapter_id,
        &binary,
        &args,
        &report_path,
        &log_path,
        request.max_runtime_seconds,
        vec![report_path.clone()],
        None,
    )
}

fn try_prepare_syft_sbom(
    request: &AdapterRequest,
    report_filename: &str,
    log_filename: &str,
) -> Option<PathBuf> {
    let report_path = ensure_evidence_path(&request.evidence_dir, report_filename).ok()?;
    let result = run_syft_adapter("syft", request, report_filename, log_filename).ok()?;
    if result.success {
        Some(report_path)
    } else {
        None
    }
}

fn syft_scan_target(target_kind: &str, target: &str) -> String {
    match canonical_target_kind(target_kind).as_str() {
        "repo" | "repository" | "codebase" | "filesystem" => target.to_string(),
        "image" => target.to_string(),
        _ => target.to_string(),
    }
}

fn canonical_target_kind(value: &str) -> String {
    match value.trim().to_ascii_lowercase().as_str() {
        "go_repo" | "java_repo" | "dockerfile" | "terraform" | "kubernetes" => "repo".to_string(),
        "container_image" => "image".to_string(),
        other => other.to_string(),
    }
}

fn run_process(
    adapter_id: &str,
    binary: &str,
    args: &[String],
    log_path: &Path,
    max_runtime_seconds: u64,
    reported_paths: Vec<PathBuf>,
    working_dir: Option<&Path>,
) -> Result<AdapterResult, String> {
    let stdout_file = File::create(log_path).map_err(|err| format!("create log file: {err}"))?;
    let stderr_file = stdout_file
        .try_clone()
        .map_err(|err| format!("clone log file: {err}"))?;
    let evidence_paths = if reported_paths.is_empty() {
        vec![log_path.to_string_lossy().to_string()]
    } else {
        reported_paths
            .iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect::<Vec<_>>()
    };

    let mut command = Command::new(binary);
    command
        .args(args)
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));
    if let Some(dir) = working_dir {
        command.current_dir(dir);
    }
    let mut child = command
        .spawn()
        .map_err(|err| format!("spawn {adapter_id}: {err}"))?;

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(AdapterResult {
                        success: true,
                        finding_count: 0,
                        evidence_paths,
                        summary: format!("{adapter_id} completed successfully"),
                        error_message: None,
                    });
                }

                return Ok(AdapterResult {
                    success: false,
                    finding_count: 0,
                    evidence_paths,
                    summary: format!("{adapter_id} exited with status {status}"),
                    error_message: Some(format!("{adapter_id} exited with non-zero status")),
                });
            }
            Ok(None) => {
                if started.elapsed() > Duration::from_secs(max_runtime_seconds) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "{adapter_id} timed out after {max_runtime_seconds} seconds"
                    ));
                }

                thread::sleep(Duration::from_millis(200));
            }
            Err(err) => {
                return Err(format!("wait on {adapter_id}: {err}"));
            }
        }
    }
}

fn run_process_with_stdout_report(
    adapter_id: &str,
    binary: &str,
    args: &[String],
    report_path: &Path,
    log_path: &Path,
    max_runtime_seconds: u64,
    reported_paths: Vec<PathBuf>,
    working_dir: Option<&Path>,
) -> Result<AdapterResult, String> {
    let stdout_file =
        File::create(report_path).map_err(|err| format!("create report file: {err}"))?;
    let stderr_file = File::create(log_path).map_err(|err| format!("create log file: {err}"))?;
    let evidence_paths = if reported_paths.is_empty() {
        vec![report_path.to_string_lossy().to_string()]
    } else {
        reported_paths
            .iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect::<Vec<_>>()
    };

    let mut command = Command::new(binary);
    command
        .args(args)
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));
    if let Some(dir) = working_dir {
        command.current_dir(dir);
    }
    let mut child = command
        .spawn()
        .map_err(|err| format!("spawn {adapter_id}: {err}"))?;

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    return Ok(AdapterResult {
                        success: true,
                        finding_count: 0,
                        evidence_paths,
                        summary: format!("{adapter_id} completed successfully"),
                        error_message: None,
                    });
                }

                return Ok(AdapterResult {
                    success: false,
                    finding_count: 0,
                    evidence_paths,
                    summary: format!("{adapter_id} exited with status {status}"),
                    error_message: Some(format!("{adapter_id} exited with non-zero status")),
                });
            }
            Ok(None) => {
                if started.elapsed() > Duration::from_secs(max_runtime_seconds) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "{adapter_id} timed out after {max_runtime_seconds} seconds"
                    ));
                }

                thread::sleep(Duration::from_millis(200));
            }
            Err(err) => {
                return Err(format!("wait on {adapter_id}: {err}"));
            }
        }
    }
}

fn run_process_with_stdout_report_allow_exit_codes(
    adapter_id: &str,
    binary: &str,
    args: &[String],
    report_path: &Path,
    log_path: &Path,
    max_runtime_seconds: u64,
    reported_paths: Vec<PathBuf>,
    allowed_exit_codes: &[i32],
    working_dir: Option<&Path>,
) -> Result<AdapterResult, String> {
    let stdout_file =
        File::create(report_path).map_err(|err| format!("create report file: {err}"))?;
    let stderr_file = File::create(log_path).map_err(|err| format!("create log file: {err}"))?;
    let evidence_paths = if reported_paths.is_empty() {
        vec![report_path.to_string_lossy().to_string()]
    } else {
        reported_paths
            .iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect::<Vec<_>>()
    };

    let mut command = Command::new(binary);
    command
        .args(args)
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));
    if let Some(dir) = working_dir {
        command.current_dir(dir);
    }
    let mut child = command
        .spawn()
        .map_err(|err| format!("spawn {adapter_id}: {err}"))?;

    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let exit_code = status.code().unwrap_or(-1);
                if status.success() || allowed_exit_codes.contains(&exit_code) {
                    return Ok(AdapterResult {
                        success: true,
                        finding_count: 0,
                        evidence_paths,
                        summary: format!("{adapter_id} completed successfully"),
                        error_message: None,
                    });
                }

                return Ok(AdapterResult {
                    success: false,
                    finding_count: 0,
                    evidence_paths,
                    summary: format!("{adapter_id} exited with status {status}"),
                    error_message: Some(format!("{adapter_id} exited with non-zero status")),
                });
            }
            Ok(None) => {
                if started.elapsed() > Duration::from_secs(max_runtime_seconds) {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "{adapter_id} timed out after {max_runtime_seconds} seconds"
                    ));
                }

                thread::sleep(Duration::from_millis(200));
            }
            Err(err) => {
                return Err(format!("wait on {adapter_id}: {err}"));
            }
        }
    }
}

fn append_zap_policy_args(request: &AdapterRequest, args: &mut Vec<String>) {
    if let Some(max_depth) = request_label_u64(request, "web_max_depth") {
        args.push("-config".to_string());
        args.push(format!("spider.maxDepth={max_depth}"));
    }
    if let Some(max_requests) = request_label_u64(request, "web_max_requests") {
        args.push("-config".to_string());
        args.push(format!("spider.maxChildren={max_requests}"));
    }
}

fn append_nuclei_policy_args(request: &AdapterRequest, args: &mut Vec<String>) {
    if let Some(rate_limit) = request_label_u64(request, "web_request_budget_per_minute") {
        args.push("-rate-limit".to_string());
        args.push(rate_limit.to_string());
    }
}

fn append_browser_probe_policy_args(request: &AdapterRequest, args: &mut Vec<String>) {
    if let Some(max_depth) = request_label_u64(request, "web_max_depth") {
        args.push("--max-depth".to_string());
        args.push(max_depth.to_string());
    }
    if let Some(max_requests) = request_label_u64(request, "web_max_requests") {
        args.push("--max-requests".to_string());
        args.push(max_requests.to_string());
    }
    if let Some(rate_limit) = request_label_u64(request, "web_request_budget_per_minute") {
        args.push("--rate-limit".to_string());
        args.push(rate_limit.to_string());
    }

    if let Some(login_url) = request.labels.get("web_auth_login_url") {
        let normalized = login_url.trim();
        if !normalized.is_empty() {
            args.push("--login-url".to_string());
            args.push(normalized.to_string());
        }
    }
    if let Some(auth_type) = request.labels.get("web_auth_type") {
        let normalized = auth_type.trim();
        if !normalized.is_empty() {
            args.push("--auth-type".to_string());
            args.push(normalized.to_string());
        }
    }
}

fn write_web_runtime_policy_snapshot(request: &AdapterRequest) -> Result<Option<PathBuf>, String> {
    const POLICY_KEYS: [&str; 22] = [
        "web_target_id",
        "web_target_type",
        "web_safe_mode",
        "web_auth_profile_id",
        "web_auth_type",
        "web_auth_login_url",
        "web_auth_csrf_mode",
        "web_auth_token_refresh_strategy",
        "web_auth_username_secret_ref",
        "web_auth_password_secret_ref",
        "web_auth_bearer_token_secret_ref",
        "web_auth_session_bootstrap_json",
        "web_auth_test_personas_json",
        "web_max_depth",
        "web_max_requests",
        "web_request_budget_per_minute",
        "web_allow_paths",
        "web_deny_paths",
        "web_seed_urls",
        "web_min_route_coverage",
        "web_min_api_coverage",
        "web_min_auth_coverage",
    ];

    let mut lines = Vec::new();
    for key in POLICY_KEYS {
        if let Some(value) = request.labels.get(key) {
            let normalized = value.trim();
            if normalized.is_empty() {
                continue;
            }
            lines.push(format!("{key}={normalized}"));
        }
    }

    if lines.is_empty() {
        return Ok(None);
    }

    let snapshot_path = ensure_evidence_path(&request.evidence_dir, "web-runtime-policy.txt")?;
    fs::write(&snapshot_path, lines.join("\n"))
        .map_err(|err| format!("write web runtime policy snapshot: {err}"))?;
    Ok(Some(snapshot_path))
}

fn request_label_u64(request: &AdapterRequest, key: &str) -> Option<u64> {
    request
        .labels
        .get(key)
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
}

fn default_zap_binary() -> &'static str {
    if cfg!(windows) {
        "zap.bat"
    } else {
        "zap.sh"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;

    fn base_request() -> AdapterRequest {
        AdapterRequest {
            job_id: "task-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            adapter_id: "zap".to_string(),
            target_kind: "url".to_string(),
            target: "https://app.example.com".to_string(),
            execution_mode: ExecutionMode::ActiveValidation,
            approved_profile: "runtime".to_string(),
            approved_modules: vec![],
            labels: BTreeMap::new(),
            evidence_dir: std::env::temp_dir()
                .join(format!("uss-worker-policy-test-{}", std::process::id()))
                .to_string_lossy()
                .to_string(),
            max_runtime_seconds: 60,
        }
    }

    #[test]
    fn append_zap_policy_args_uses_limits() {
        let mut request = base_request();
        request
            .labels
            .insert("web_max_depth".to_string(), "4".to_string());
        request
            .labels
            .insert("web_max_requests".to_string(), "900".to_string());

        let mut args = vec!["-cmd".to_string()];
        append_zap_policy_args(&request, &mut args);

        let joined = args.join(" ");
        assert!(joined.contains("spider.maxDepth=4"));
        assert!(joined.contains("spider.maxChildren=900"));
    }

    #[test]
    fn append_nuclei_policy_args_uses_rate_limit() {
        let mut request = base_request();
        request.labels.insert(
            "web_request_budget_per_minute".to_string(),
            "180".to_string(),
        );

        let mut args = vec!["-u".to_string(), request.target.clone()];
        append_nuclei_policy_args(&request, &mut args);

        let joined = args.join(" ");
        assert!(joined.contains("-rate-limit 180"));
    }

    #[test]
    fn append_browser_probe_policy_args_uses_auth_and_limits() {
        let mut request = base_request();
        request
            .labels
            .insert("web_max_depth".to_string(), "5".to_string());
        request
            .labels
            .insert("web_max_requests".to_string(), "1400".to_string());
        request.labels.insert(
            "web_request_budget_per_minute".to_string(),
            "220".to_string(),
        );
        request.labels.insert(
            "web_auth_login_url".to_string(),
            "https://app.example.com/login".to_string(),
        );
        request
            .labels
            .insert("web_auth_type".to_string(), "form".to_string());

        let mut args = vec!["--target".to_string(), request.target.clone()];
        append_browser_probe_policy_args(&request, &mut args);

        let joined = args.join(" ");
        assert!(joined.contains("--max-depth 5"));
        assert!(joined.contains("--max-requests 1400"));
        assert!(joined.contains("--rate-limit 220"));
        assert!(joined.contains("--login-url https://app.example.com/login"));
        assert!(joined.contains("--auth-type form"));
    }

    #[test]
    fn write_web_runtime_policy_snapshot_writes_file() {
        let mut request = base_request();
        request
            .labels
            .insert("web_target_id".to_string(), "web-target-123".to_string());
        request
            .labels
            .insert("web_safe_mode".to_string(), "true".to_string());

        let path = write_web_runtime_policy_snapshot(&request)
            .expect("write policy snapshot")
            .expect("policy snapshot path");
        let content = fs::read_to_string(&path).expect("read policy snapshot");

        assert!(content.contains("web_target_id=web-target-123"));
        assert!(content.contains("web_safe_mode=true"));

        let _ = fs::remove_dir_all(&request.evidence_dir);
    }
}
