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
        "nmap" => NmapAdapter.execute(request),
        "metasploit" => MetasploitAdapter.execute(request),
        "semgrep" => SemgrepAdapter.execute(request),
        "trivy" => TrivyAdapter.execute(request),
        "trivy-image" => TrivyImageAdapter.execute(request),
        "trivy-config" => TrivyConfigAdapter.execute(request),
        "trivy-secrets" => TrivySecretsAdapter.execute(request),
        "gitleaks" => GitleaksAdapter.execute(request),
        "checkov" => CheckovAdapter.execute(request),
        unsupported => Err(format!("unsupported adapter: {unsupported}")),
    }
}

struct ZapAdapter;
struct NmapAdapter;
struct MetasploitAdapter;
struct SemgrepAdapter;
struct TrivyAdapter;
struct TrivyImageAdapter;
struct TrivyConfigAdapter;
struct TrivySecretsAdapter;
struct GitleaksAdapter;
struct CheckovAdapter;

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
        let binary = env::var("USS_ZAP_CMD").unwrap_or_else(|_| default_zap_binary().to_string());

        let mut args = vec![
            "-cmd".to_string(),
            "-quickurl".to_string(),
            request.target.clone(),
            "-quickout".to_string(),
            report_path.to_string_lossy().to_string(),
            "-quickprogress".to_string(),
        ];

        if matches!(request.execution_mode, ExecutionMode::Passive) {
            args.push("-silent".to_string());
        }

        run_process(
            self.id(),
            &binary,
            &args,
            &report_path,
            request.max_runtime_seconds,
            vec![report_path.clone()],
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
        let args = vec![
            "scan".to_string(),
            "--config".to_string(),
            "auto".to_string(),
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
        )
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
    )
}

fn run_process(
    adapter_id: &str,
    binary: &str,
    args: &[String],
    log_path: &Path,
    max_runtime_seconds: u64,
    reported_paths: Vec<PathBuf>,
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

    let mut child = Command::new(binary)
        .args(args)
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
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

fn default_zap_binary() -> &'static str {
    if cfg!(windows) {
        "zap.bat"
    } else {
        "zap.sh"
    }
}
