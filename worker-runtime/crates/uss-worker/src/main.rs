use std::collections::BTreeMap;
use std::collections::HashMap;
use std::env;
use std::process;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::runtime::Builder;
use tokio::time::sleep;
use tokio_stream::iter;
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tonic::transport::Endpoint;
use tonic::Request;
use uss_worker::adapter::{AdapterRequest, AdapterResult, ExecutionMode};
use uss_worker::executors;
use uss_worker::proto;
use uss_worker::proto::worker_control_plane_client::WorkerControlPlaneClient;
use uss_worker::proto::ExecutionMode as ProtoExecutionMode;
use uss_worker::proto::JobAssignment;
use uss_worker::proto::JobResult;
use uss_worker::proto::JobState;
use uss_worker::proto::JobStatusEvent;
use uss_worker::proto::WorkerCapability;
use uss_worker::proto::WorkerRegistrationRequest;

#[derive(Debug, Clone)]
struct Config {
    worker_id: String,
    worker_version: String,
    operating_system: String,
    hostname: String,
    grpc_endpoint: String,
    heartbeat_interval: Duration,
    daemon_mode: bool,
    evidence_root: String,
    worker_shared_secret: String,
}

fn main() {
    if matches!(env::args().nth(1).as_deref(), Some("run-adapter")) {
        run_adapter_mode();
        return;
    }

    let runtime = match Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("build runtime: {err}");
            process::exit(1);
        }
    };

    if let Err(err) = runtime.block_on(run_worker()) {
        eprintln!("{err}");
        process::exit(1);
    }
}

impl Config {
    fn from_env() -> Self {
        Self {
            worker_id: env::var("USS_WORKER_ID").unwrap_or_else(|_| "worker-local".to_string()),
            worker_version: env::var("USS_WORKER_VERSION").unwrap_or_else(|_| "0.1.0".to_string()),
            operating_system: env::var("USS_WORKER_OS")
                .unwrap_or_else(|_| env::consts::OS.to_string()),
            hostname: env::var("USS_WORKER_HOST").unwrap_or_else(|_| {
                env::var("COMPUTERNAME")
                    .or_else(|_| env::var("HOSTNAME"))
                    .unwrap_or_else(|_| "worker-host".to_string())
            }),
            grpc_endpoint: env::var("USS_WORKER_GRPC_ADDR")
                .or_else(|_| env::var("USS_CONTROL_PLANE_URL"))
                .unwrap_or_else(|_| "127.0.0.1:9090".to_string()),
            heartbeat_interval: parse_duration_seconds("USS_HEARTBEAT_INTERVAL_SECONDS", 30),
            daemon_mode: parse_bool("USS_WORKER_DAEMON", false),
            evidence_root: env::var("USS_EVIDENCE_ROOT")
                .unwrap_or_else(|_| "./evidence".to_string()),
            worker_shared_secret: env::var("USS_WORKER_SHARED_SECRET").unwrap_or_default(),
        }
    }
}

async fn run_worker() -> Result<(), String> {
    let cfg = Config::from_env();
    eprintln!(
        "worker starting id={} grpc_endpoint={} daemon_mode={}",
        cfg.worker_id, cfg.grpc_endpoint, cfg.daemon_mode
    );

    let endpoint = Endpoint::from_shared(normalize_grpc_endpoint(&cfg.grpc_endpoint))
        .map_err(|err| format!("parse grpc endpoint: {err}"))?;
    let channel = endpoint
        .connect()
        .await
        .map_err(|err| format!("connect grpc: {err}"))?;
    let mut client = WorkerControlPlaneClient::new(channel);

    let registration = client
        .register_worker(worker_request(
            WorkerRegistrationRequest {
                worker_id: cfg.worker_id.clone(),
                worker_version: cfg.worker_version.clone(),
                operating_system: cfg.operating_system.clone(),
                hostname: cfg.hostname.clone(),
                capabilities: default_capabilities(),
            },
            &cfg.worker_shared_secret,
        ))
        .await
        .map_err(|err| format!("register worker: {err}"))?
        .into_inner();

    if !registration.accepted {
        return Err("worker registration was rejected".to_string());
    }

    let lease_id = registration.lease_id;
    let heartbeat_interval = if registration.heartbeat_interval_seconds > 0 {
        Duration::from_secs(registration.heartbeat_interval_seconds as u64)
    } else {
        cfg.heartbeat_interval
    };

    eprintln!(
        "worker registered lease_id={} heartbeat_interval_seconds={}",
        lease_id,
        heartbeat_interval.as_secs()
    );

    loop {
        let heartbeat = client
            .heartbeat(worker_request(
                proto::HeartbeatRequest {
                    worker_id: cfg.worker_id.clone(),
                    lease_id: lease_id.clone(),
                    timestamp_unix: current_unix_timestamp() as i64,
                    metrics: default_metrics(),
                },
                &cfg.worker_shared_secret,
            ))
            .await
            .map_err(|err| format!("worker heartbeat: {err}"))?
            .into_inner();

        if !heartbeat.assignments.is_empty() {
            eprintln!("received {} assignments", heartbeat.assignments.len());
        }

        for assignment in heartbeat.assignments {
            execute_assignment(&mut client, &cfg, assignment).await?;
        }

        if !cfg.daemon_mode {
            return Ok(());
        }

        sleep(heartbeat_interval).await;
    }
}

fn run_adapter_mode() {
    let request = match adapter_request_from_env() {
        Ok(request) => request,
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    };

    match executors::execute(&request) {
        Ok(result) => {
            println!("{}", adapter_result_json(&result));
            if !result.success {
                process::exit(2);
            }
        }
        Err(err) => {
            eprintln!("{err}");
            process::exit(1);
        }
    }
}

async fn execute_assignment(
    client: &mut WorkerControlPlaneClient<Channel>,
    cfg: &Config,
    assignment: JobAssignment,
) -> Result<(), String> {
    let job_id = assignment.job_id.clone();
    let adapter_id = assignment.adapter_id.clone();
    let target = assignment.target.clone();

    eprintln!(
        "executing assignment job_id={} adapter_id={} target={}",
        job_id, adapter_id, target
    );

    publish_status(
        client,
        &cfg.worker_id,
        &job_id,
        JobState::Running,
        format!("starting {adapter_id}"),
        &cfg.worker_shared_secret,
    )
    .await?;

    let request = assignment_to_request(cfg, assignment);
    let result = executors::execute(&request);

    let (final_state, evidence_paths, error_message, summary) = match result {
        Ok(result) => adapt_result(result),
        Err(err) => (
            JobState::Failed,
            Vec::new(),
            Some(err.clone()),
            format!("{} failed", request.adapter_id),
        ),
    };

    client
        .publish_job_result(worker_request(
            JobResult {
                worker_id: cfg.worker_id.clone(),
                job_id,
                final_state: final_state as i32,
                findings: Vec::new(),
                evidence_paths,
                error_message: error_message.unwrap_or_default(),
            },
            &cfg.worker_shared_secret,
        ))
        .await
        .map_err(|err| format!("publish job result: {err}"))?;

    eprintln!("{summary}");
    Ok(())
}

async fn publish_status(
    client: &mut WorkerControlPlaneClient<Channel>,
    worker_id: &str,
    job_id: &str,
    state: JobState,
    detail: String,
    worker_shared_secret: &str,
) -> Result<(), String> {
    client
        .publish_job_status(worker_request(
            iter(vec![JobStatusEvent {
                worker_id: worker_id.to_string(),
                job_id: job_id.to_string(),
                state: state as i32,
                detail,
                timestamp_unix: current_unix_timestamp() as i64,
            }]),
            worker_shared_secret,
        ))
        .await
        .map_err(|err| format!("publish job status: {err}"))?;

    Ok(())
}

fn assignment_to_request(cfg: &Config, assignment: JobAssignment) -> AdapterRequest {
    let evidence_dir = format!(
        "{}/{}",
        cfg.evidence_root.trim_end_matches(['/', '\\']),
        assignment.job_id
    );

    AdapterRequest {
        job_id: assignment.job_id,
        tenant_id: assignment.tenant_id,
        adapter_id: assignment.adapter_id,
        target_kind: assignment.target_kind,
        target: assignment.target,
        execution_mode: map_execution_mode(assignment.execution_mode),
        approved_profile: "assigned".to_string(),
        approved_modules: assignment.approved_modules,
        labels: assignment.labels.into_iter().collect::<BTreeMap<_, _>>(),
        evidence_dir,
        max_runtime_seconds: if assignment.max_runtime_seconds <= 0 {
            300
        } else {
            assignment.max_runtime_seconds as u64
        },
    }
}

fn adapt_result(result: AdapterResult) -> (JobState, Vec<String>, Option<String>, String) {
    let final_state = if result.success {
        JobState::Completed
    } else {
        JobState::Failed
    };

    (
        final_state,
        result.evidence_paths,
        result.error_message,
        result.summary,
    )
}

fn map_execution_mode(value: i32) -> ExecutionMode {
    match ProtoExecutionMode::try_from(value).unwrap_or(ProtoExecutionMode::ActiveValidation) {
        ProtoExecutionMode::Passive => ExecutionMode::Passive,
        ProtoExecutionMode::RestrictedExploit => ExecutionMode::RestrictedExploit,
        _ => ExecutionMode::ActiveValidation,
    }
}

fn normalize_grpc_endpoint(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    }
}

fn worker_request<T>(message: T, worker_shared_secret: &str) -> Request<T> {
    let mut request = Request::new(message);
    let secret = worker_shared_secret.trim();
    if !secret.is_empty() {
        let value =
            MetadataValue::try_from(secret).expect("worker shared secret must be valid metadata");
        request.metadata_mut().insert("x-uss-worker-secret", value);
    }
    request
}

fn default_metrics() -> HashMap<String, String> {
    let mut metrics = HashMap::with_capacity(2);
    metrics.insert("cpu".to_string(), "1".to_string());
    metrics.insert("memory_mb".to_string(), "64".to_string());
    metrics
}

fn default_capabilities() -> Vec<WorkerCapability> {
    vec![
        WorkerCapability {
            adapter_id: "zap".to_string(),
            supported_target_kinds: vec![
                "domain".to_string(),
                "api".to_string(),
                "url".to_string(),
            ],
            supported_modes: vec![
                ProtoExecutionMode::Passive as i32,
                ProtoExecutionMode::ActiveValidation as i32,
            ],
            labels: vec!["web".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "nmap".to_string(),
            supported_target_kinds: vec![
                "domain".to_string(),
                "host".to_string(),
                "ip".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::ActiveValidation as i32],
            labels: vec!["network".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "metasploit".to_string(),
            supported_target_kinds: vec![
                "domain".to_string(),
                "host".to_string(),
                "ip".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::RestrictedExploit as i32],
            labels: vec!["restricted".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "semgrep".to_string(),
            supported_target_kinds: vec![
                "repo".to_string(),
                "filesystem".to_string(),
                "go_repo".to_string(),
                "java_repo".to_string(),
                "node_repo".to_string(),
                "dotnet_repo".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["code".to_string(), "sast".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "gosec".to_string(),
            supported_target_kinds: vec![
                "repo".to_string(),
                "filesystem".to_string(),
                "go_repo".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["code".to_string(), "sast".to_string(), "go".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "spotbugs".to_string(),
            supported_target_kinds: vec![
                "repo".to_string(),
                "filesystem".to_string(),
                "java_repo".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["code".to_string(), "sast".to_string(), "java".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "pmd".to_string(),
            supported_target_kinds: vec![
                "repo".to_string(),
                "filesystem".to_string(),
                "java_repo".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["code".to_string(), "sast".to_string(), "java".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "devskim".to_string(),
            supported_target_kinds: vec![
                "dotnet_repo".to_string(),
                "repo".to_string(),
                "filesystem".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["code".to_string(), "sast".to_string(), "dotnet".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "bandit".to_string(),
            supported_target_kinds: vec!["repo".to_string(), "filesystem".to_string()],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["code".to_string(), "sast".to_string(), "python".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "eslint".to_string(),
            supported_target_kinds: vec![
                "node_repo".to_string(),
                "repo".to_string(),
                "filesystem".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec![
                "code".to_string(),
                "sast".to_string(),
                "javascript".to_string(),
            ],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "shellcheck".to_string(),
            supported_target_kinds: vec!["shell_script".to_string(), "filesystem".to_string()],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["code".to_string(), "sast".to_string(), "shell".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "osv-scanner".to_string(),
            supported_target_kinds: vec![
                "repo".to_string(),
                "filesystem".to_string(),
                "go_repo".to_string(),
                "java_repo".to_string(),
                "node_repo".to_string(),
                "dotnet_repo".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec![
                "code".to_string(),
                "sca".to_string(),
                "lockfile".to_string(),
            ],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "npm-audit".to_string(),
            supported_target_kinds: vec![
                "node_repo".to_string(),
                "repo".to_string(),
                "filesystem".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["code".to_string(), "sca".to_string(), "node".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "dotnet-audit".to_string(),
            supported_target_kinds: vec![
                "dotnet_repo".to_string(),
                "repo".to_string(),
                "filesystem".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["code".to_string(), "sca".to_string(), "dotnet".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "syft".to_string(),
            supported_target_kinds: vec![
                "repo".to_string(),
                "filesystem".to_string(),
                "go_repo".to_string(),
                "java_repo".to_string(),
                "node_repo".to_string(),
                "dotnet_repo".to_string(),
                "image".to_string(),
                "container_image".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["sca".to_string(), "sbom".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "trivy".to_string(),
            supported_target_kinds: vec![
                "repo".to_string(),
                "filesystem".to_string(),
                "go_repo".to_string(),
                "java_repo".to_string(),
                "node_repo".to_string(),
                "dotnet_repo".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["code".to_string(), "sca".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "trivy-image".to_string(),
            supported_target_kinds: vec!["image".to_string(), "container_image".to_string()],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["image".to_string(), "sca".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "trivy-config".to_string(),
            supported_target_kinds: vec![
                "repo".to_string(),
                "filesystem".to_string(),
                "go_repo".to_string(),
                "java_repo".to_string(),
                "node_repo".to_string(),
                "dotnet_repo".to_string(),
                "image".to_string(),
                "terraform".to_string(),
                "kubernetes".to_string(),
                "cloudformation".to_string(),
                "dockerfile".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["iac".to_string(), "config".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "trivy-secrets".to_string(),
            supported_target_kinds: vec![
                "repo".to_string(),
                "filesystem".to_string(),
                "go_repo".to_string(),
                "java_repo".to_string(),
                "node_repo".to_string(),
                "dotnet_repo".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["secrets".to_string(), "code".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "grype".to_string(),
            supported_target_kinds: vec![
                "repo".to_string(),
                "filesystem".to_string(),
                "go_repo".to_string(),
                "java_repo".to_string(),
                "node_repo".to_string(),
                "dotnet_repo".to_string(),
                "image".to_string(),
                "container_image".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["sca".to_string(), "image".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "gitleaks".to_string(),
            supported_target_kinds: vec![
                "repo".to_string(),
                "filesystem".to_string(),
                "go_repo".to_string(),
                "java_repo".to_string(),
                "node_repo".to_string(),
                "dotnet_repo".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["code".to_string(), "secrets".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "checkov".to_string(),
            supported_target_kinds: vec![
                "repo".to_string(),
                "filesystem".to_string(),
                "go_repo".to_string(),
                "java_repo".to_string(),
                "node_repo".to_string(),
                "dotnet_repo".to_string(),
                "terraform".to_string(),
                "kubernetes".to_string(),
                "cloudformation".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["code".to_string(), "iac".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "cfn-lint".to_string(),
            supported_target_kinds: vec![
                "cloudformation".to_string(),
                "repo".to_string(),
                "filesystem".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["iac".to_string(), "cloudformation".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "hadolint".to_string(),
            supported_target_kinds: vec!["dockerfile".to_string()],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["iac".to_string(), "container".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "kics".to_string(),
            supported_target_kinds: vec![
                "dockerfile".to_string(),
                "terraform".to_string(),
                "kubernetes".to_string(),
                "cloudformation".to_string(),
                "repo".to_string(),
                "filesystem".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["iac".to_string(), "cloud".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "kubesec".to_string(),
            supported_target_kinds: vec![
                "kubernetes".to_string(),
                "repo".to_string(),
                "filesystem".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["iac".to_string(), "kubernetes".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "kube-score".to_string(),
            supported_target_kinds: vec![
                "kubernetes".to_string(),
                "repo".to_string(),
                "filesystem".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["iac".to_string(), "kubernetes".to_string()],
            linux_preferred: false,
        },
        WorkerCapability {
            adapter_id: "tfsec".to_string(),
            supported_target_kinds: vec![
                "terraform".to_string(),
                "repo".to_string(),
                "filesystem".to_string(),
            ],
            supported_modes: vec![ProtoExecutionMode::Passive as i32],
            labels: vec!["iac".to_string(), "terraform".to_string()],
            linux_preferred: false,
        },
    ]
}

fn adapter_request_from_env() -> Result<AdapterRequest, String> {
    let approved_modules = env::var("USS_APPROVED_MODULES")
        .unwrap_or_default()
        .split(',')
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();

    Ok(AdapterRequest {
        job_id: required_env("USS_JOB_ID")?,
        tenant_id: required_env("USS_TENANT_ID")?,
        adapter_id: required_env("USS_ADAPTER_ID")?,
        target_kind: required_env("USS_TARGET_KIND")?,
        target: required_env("USS_TARGET")?,
        execution_mode: ExecutionMode::parse(&required_env("USS_EXECUTION_MODE")?)?,
        approved_profile: required_env("USS_APPROVED_PROFILE")?,
        approved_modules,
        labels: BTreeMap::new(),
        evidence_dir: env::var("USS_EVIDENCE_DIR").unwrap_or_else(|_| "./evidence".to_string()),
        max_runtime_seconds: env::var("USS_MAX_RUNTIME_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(300),
    })
}

fn required_env(key: &str) -> Result<String, String> {
    match env::var(key) {
        Ok(value) if !value.trim().is_empty() => Ok(value),
        _ => Err(format!("missing required environment variable: {key}")),
    }
}

fn parse_duration_seconds(key: &str, fallback_seconds: u64) -> Duration {
    match env::var(key) {
        Ok(value) => match value.parse::<u64>() {
            Ok(seconds) => Duration::from_secs(seconds),
            Err(_) => Duration::from_secs(fallback_seconds),
        },
        Err(_) => Duration::from_secs(fallback_seconds),
    }
}

fn parse_bool(key: &str, fallback: bool) -> bool {
    match env::var(key) {
        Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "on" => true,
            "0" | "false" | "no" | "off" => false,
            _ => fallback,
        },
        Err(_) => fallback,
    }
}

fn current_unix_timestamp() -> u64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs(),
        Err(_) => 0,
    }
}

fn adapter_result_json(value: &AdapterResult) -> String {
    let error_json = match &value.error_message {
        Some(message) => format!("\"{}\"", escape_json(message)),
        None => "null".to_string(),
    };

    format!(
        concat!(
            "{{\"success\":{},\"finding_count\":{},\"evidence_paths\":{},",
            "\"summary\":\"{}\",\"error_message\":{}}}"
        ),
        if value.success { "true" } else { "false" },
        value.finding_count,
        string_array_json(&value.evidence_paths),
        escape_json(&value.summary),
        error_json
    )
}

fn string_array_json(values: &[impl AsRef<str>]) -> String {
    let items = values
        .iter()
        .map(|value| format!("\"{}\"", escape_json(value.as_ref())))
        .collect::<Vec<_>>();
    format!("[{}]", items.join(","))
}

fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}
