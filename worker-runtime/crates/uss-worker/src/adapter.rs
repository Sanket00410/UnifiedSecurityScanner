use std::collections::BTreeMap;

#[derive(Debug, Clone)]
pub enum ExecutionMode {
    Passive,
    ActiveValidation,
    RestrictedExploit,
}

impl ExecutionMode {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "passive" => Ok(Self::Passive),
            "active_validation" => Ok(Self::ActiveValidation),
            "restricted_exploit" => Ok(Self::RestrictedExploit),
            _ => Err(format!("unsupported execution mode: {value}")),
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct AdapterRequest {
    pub job_id: String,
    pub tenant_id: String,
    pub adapter_id: String,
    pub target_kind: String,
    pub target: String,
    pub execution_mode: ExecutionMode,
    pub approved_profile: String,
    pub approved_modules: Vec<String>,
    pub labels: BTreeMap<String, String>,
    pub evidence_dir: String,
    pub max_runtime_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct AdapterResult {
    pub success: bool,
    pub finding_count: u32,
    pub evidence_paths: Vec<String>,
    pub summary: String,
    pub error_message: Option<String>,
}

pub trait ScannerAdapter {
    fn id(&self) -> &'static str;
    fn supports(&self, mode: &ExecutionMode) -> bool;
    fn validate(&self, request: &AdapterRequest) -> Result<(), String>;
    fn execute(&self, request: &AdapterRequest) -> Result<AdapterResult, String>;
}
