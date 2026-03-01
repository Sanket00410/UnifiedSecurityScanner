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
        unsupported => Err(format!("unsupported adapter: {unsupported}")),
    }
}

struct ZapAdapter;
struct NmapAdapter;
struct MetasploitAdapter;

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

        let evidence_path = ensure_evidence_path(&request.evidence_dir, "zap-output.log")?;
        let binary = env::var("USS_ZAP_CMD").unwrap_or_else(|_| default_zap_binary().to_string());

        let mut args = vec![
            "-cmd".to_string(),
            "-quickurl".to_string(),
            request.target.clone(),
            "-quickout".to_string(),
            evidence_path.to_string_lossy().to_string(),
            "-quickprogress".to_string(),
        ];

        if matches!(request.execution_mode, ExecutionMode::Passive) {
            args.push("-silent".to_string());
        }

        run_process(
            self.id(),
            &binary,
            &args,
            &evidence_path,
            request.max_runtime_seconds,
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

        let evidence_path = ensure_evidence_path(&request.evidence_dir, "nmap-output.log")?;
        let binary = env::var("USS_NMAP_CMD").unwrap_or_else(|_| "nmap".to_string());
        let output_file = ensure_evidence_path(&request.evidence_dir, "nmap-report.txt")?;

        let args = vec![
            "-Pn".to_string(),
            "-T4".to_string(),
            "-oN".to_string(),
            output_file.to_string_lossy().to_string(),
            request.target.clone(),
        ];

        run_process(
            self.id(),
            &binary,
            &args,
            &evidence_path,
            request.max_runtime_seconds,
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

fn run_process(
    adapter_id: &str,
    binary: &str,
    args: &[String],
    log_path: &Path,
    max_runtime_seconds: u64,
) -> Result<AdapterResult, String> {
    let stdout_file = File::create(log_path).map_err(|err| format!("create log file: {err}"))?;
    let stderr_file = stdout_file
        .try_clone()
        .map_err(|err| format!("clone log file: {err}"))?;

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
                        evidence_paths: vec![log_path.to_string_lossy().to_string()],
                        summary: format!("{adapter_id} completed successfully"),
                        error_message: None,
                    });
                }

                return Ok(AdapterResult {
                    success: false,
                    finding_count: 0,
                    evidence_paths: vec![log_path.to_string_lossy().to_string()],
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
