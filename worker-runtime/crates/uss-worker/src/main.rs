mod adapter;
mod executors;

use adapter::{AdapterRequest, AdapterResult, ExecutionMode};
use std::collections::BTreeMap;
use std::env;
use std::process;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
struct Config {
    worker_id: String,
    control_plane: String,
    heartbeat_interval: Duration,
    daemon_mode: bool,
}

#[derive(Debug)]
struct HeartbeatEnvelope {
    worker_id: String,
    control_plane: String,
    status: &'static str,
    capabilities: Vec<&'static str>,
    timestamp_unix: u64,
}

fn main() {
    if matches!(env::args().nth(1).as_deref(), Some("run-adapter")) {
        run_adapter_mode();
        return;
    }

    let cfg = Config::from_env();
    eprintln!(
        "worker starting id={} control_plane={} daemon_mode={}",
        cfg.worker_id, cfg.control_plane, cfg.daemon_mode
    );

    let boot_contract = AdapterRequest {
        job_id: "bootstrap".to_string(),
        tenant_id: "bootstrap".to_string(),
        adapter_id: "worker-bootstrap".to_string(),
        target_kind: "system".to_string(),
        target: "control-plane".to_string(),
        execution_mode: ExecutionMode::Passive,
        approved_profile: "bootstrap".to_string(),
        approved_modules: Vec::new(),
        labels: BTreeMap::new(),
        evidence_dir: "./evidence".to_string(),
        max_runtime_seconds: 5,
    };

    eprintln!("adapter_request_contract={}", adapter_request_json(&boot_contract));

    emit_heartbeat(&cfg);

    if cfg.daemon_mode {
        loop {
            thread::sleep(cfg.heartbeat_interval);
            emit_heartbeat(&cfg);
        }
    }
}

impl Config {
    fn from_env() -> Self {
        Self {
            worker_id: env::var("USS_WORKER_ID").unwrap_or_else(|_| "worker-local".to_string()),
            control_plane: env::var("USS_CONTROL_PLANE_URL")
                .unwrap_or_else(|_| "http://127.0.0.1:8080".to_string()),
            heartbeat_interval: parse_duration_seconds("USS_HEARTBEAT_INTERVAL_SECONDS", 30),
            daemon_mode: parse_bool("USS_WORKER_DAEMON", false),
        }
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

fn emit_heartbeat(cfg: &Config) {
    let envelope = HeartbeatEnvelope {
        worker_id: cfg.worker_id.clone(),
        control_plane: cfg.control_plane.clone(),
        status: "ready",
        capabilities: vec![
            "sast",
            "sca",
            "secrets",
            "iac",
            "dast",
            "nmap",
            "nuclei",
            "zap",
            "metasploit-restricted",
        ],
        timestamp_unix: current_unix_timestamp(),
    };

    println!("{}", heartbeat_json(&envelope));
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

fn heartbeat_json(value: &HeartbeatEnvelope) -> String {
    format!(
        "{{\"worker_id\":\"{}\",\"control_plane\":\"{}\",\"status\":\"{}\",\"capabilities\":{},\"timestamp_unix\":{}}}",
        escape_json(&value.worker_id),
        escape_json(&value.control_plane),
        value.status,
        string_array_json(&value.capabilities),
        value.timestamp_unix
    )
}

fn adapter_request_json(value: &AdapterRequest) -> String {
    let labels = map_json(&value.labels);
    format!(
        concat!(
            "{{\"job_id\":\"{}\",\"tenant_id\":\"{}\",\"adapter_id\":\"{}\",\"target_kind\":\"{}\",",
            "\"target\":\"{}\",\"execution_mode\":\"{}\",\"approved_profile\":\"{}\",",
            "\"approved_modules\":{},\"labels\":{},\"evidence_dir\":\"{}\",\"max_runtime_seconds\":{}}}"
        ),
        escape_json(&value.job_id),
        escape_json(&value.tenant_id),
        escape_json(&value.adapter_id),
        escape_json(&value.target_kind),
        escape_json(&value.target),
        value.execution_mode.as_str(),
        escape_json(&value.approved_profile),
        string_array_json(&value.approved_modules),
        labels,
        escape_json(&value.evidence_dir),
        value.max_runtime_seconds
    )
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

fn map_json(values: &BTreeMap<String, String>) -> String {
    let items = values
        .iter()
        .map(|(key, value)| {
            format!(
                "\"{}\":\"{}\"",
                escape_json(key),
                escape_json(value)
            )
        })
        .collect::<Vec<_>>();
    format!("{{{}}}", items.join(","))
}

fn escape_json(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}
