use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use uss_worker::proto::worker_control_plane_server::{
    WorkerControlPlane, WorkerControlPlaneServer,
};
use uss_worker::proto::{
    Ack, ExecutionMode, HeartbeatRequest, HeartbeatResponse, JobAssignment, JobResult, JobState,
    JobStatusEvent, WorkerRegistrationRequest, WorkerRegistrationResponse,
};

#[derive(Clone, Default)]
struct TestState {
    registrations: Vec<WorkerRegistrationRequest>,
    heartbeats: Vec<HeartbeatRequest>,
    status_events: Vec<JobStatusEvent>,
    results: Vec<JobResult>,
}

#[derive(Clone)]
struct TestControlPlane {
    state: Arc<Mutex<TestState>>,
}

#[tonic::async_trait]
impl WorkerControlPlane for TestControlPlane {
    async fn register_worker(
        &self,
        request: Request<WorkerRegistrationRequest>,
    ) -> Result<Response<WorkerRegistrationResponse>, Status> {
        let mut state = self.state.lock().expect("lock test state");
        state.registrations.push(request.into_inner());

        Ok(Response::new(WorkerRegistrationResponse {
            accepted: true,
            lease_id: "lease-test-worker".to_string(),
            heartbeat_interval_seconds: 30,
        }))
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let mut state = self.state.lock().expect("lock test state");
        state.heartbeats.push(request.into_inner());

        Ok(Response::new(HeartbeatResponse {
            assignments: vec![JobAssignment {
                job_id: "task-test-worker".to_string(),
                tenant_id: "tenant-test".to_string(),
                adapter_id: "zap".to_string(),
                target_kind: "url".to_string(),
                target: "https://example.com/login".to_string(),
                execution_mode: ExecutionMode::ActiveValidation as i32,
                approved_modules: Vec::new(),
                labels: Default::default(),
                max_runtime_seconds: 30,
                evidence_upload_url: "local://evidence/task-test-worker".to_string(),
            }],
        }))
    }

    async fn publish_job_status(
        &self,
        request: Request<tonic::Streaming<JobStatusEvent>>,
    ) -> Result<Response<Ack>, Status> {
        let mut stream = request.into_inner();
        let mut count = 0;

        while let Some(event) = stream.message().await? {
            count += 1;
            let mut state = self.state.lock().expect("lock test state");
            state.status_events.push(event);
        }

        Ok(Response::new(Ack {
            accepted: true,
            message: format!("processed {count} status events"),
        }))
    }

    async fn publish_job_result(
        &self,
        request: Request<JobResult>,
    ) -> Result<Response<Ack>, Status> {
        let mut state = self.state.lock().expect("lock test state");
        state.results.push(request.into_inner());

        Ok(Response::new(Ack {
            accepted: true,
            message: "stored result".to_string(),
        }))
    }
}

#[tokio::test(flavor = "current_thread")]
async fn worker_binary_processes_assignment() {
    let shared_state = Arc::new(Mutex::new(TestState::default()));
    let service_state = Arc::clone(&shared_state);
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test grpc listener");
    let address = listener.local_addr().expect("read local addr");
    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(WorkerControlPlaneServer::new(TestControlPlane {
                state: service_state,
            }))
            .serve_with_incoming_shutdown(TcpListenerStream::new(listener), async move {
                let _ = shutdown_rx.await;
            })
            .await
            .expect("serve test grpc control plane");
    });

    let temp_dir = env::temp_dir().join(format!(
        "uss-worker-it-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("unix time")
            .as_millis()
    ));
    fs::create_dir_all(&temp_dir).expect("create temp dir");

    let mock_zap = create_mock_zap(&temp_dir);
    let evidence_root = temp_dir.join("evidence");
    let worker_binary = env::var("CARGO_BIN_EXE_uss-worker")
        .map(PathBuf::from)
        .unwrap_or_else(|_| locate_worker_binary());

    let grpc_address = address.to_string();
    let output = tokio::task::spawn_blocking(move || {
        Command::new(&worker_binary)
            .env("USS_WORKER_ID", "worker-test")
            .env("USS_WORKER_VERSION", "0.2.0")
            .env("USS_WORKER_OS", env::consts::OS)
            .env("USS_WORKER_HOST", "worker-test-host")
            .env("USS_WORKER_GRPC_ADDR", grpc_address)
            .env("USS_ZAP_CMD", mock_zap)
            .env("USS_EVIDENCE_ROOT", &evidence_root)
            .output()
    })
    .await
    .expect("join worker process")
    .expect("run worker binary");

    let _ = shutdown_tx.send(());
    server.await.expect("join grpc server");

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("worker binary failed: {stderr}");
    }

    let state = shared_state.lock().expect("lock shared state").clone();
    assert_eq!(
        state.registrations.len(),
        1,
        "expected one worker registration"
    );
    assert_eq!(state.heartbeats.len(), 1, "expected one worker heartbeat");
    assert_eq!(state.status_events.len(), 1, "expected one status event");
    assert_eq!(state.results.len(), 1, "expected one result event");

    let registration = &state.registrations[0];
    assert_eq!(registration.worker_id, "worker-test");
    assert!(
        registration
            .capabilities
            .iter()
            .any(|capability| capability.adapter_id == "semgrep"),
        "expected code-analysis capabilities to be advertised"
    );

    let status = &state.status_events[0];
    assert_eq!(status.job_id, "task-test-worker");
    assert_eq!(status.state, JobState::Running as i32);

    let result = &state.results[0];
    assert_eq!(result.job_id, "task-test-worker");
    assert_eq!(result.final_state, JobState::Completed as i32);
    assert_eq!(result.evidence_paths.len(), 1);

    let evidence_path = PathBuf::from(&result.evidence_paths[0]);
    let evidence = fs::read_to_string(&evidence_path).expect("read evidence file");
    assert!(
        evidence.contains("High risk alert: SQL Injection detected"),
        "expected mock zap output in evidence file"
    );

    let _ = fs::remove_dir_all(&temp_dir);
}

fn create_mock_zap(root: &PathBuf) -> PathBuf {
    if cfg!(windows) {
        let path = root.join("mock-zap.cmd");
        fs::write(
            &path,
            "@echo off\r\necho High risk alert: SQL Injection detected\r\necho URL: https://example.com/login\r\necho Param: username\r\n",
        )
        .expect("write mock zap batch");
        return path;
    }

    let path = root.join("mock-zap.sh");
    fs::write(
        &path,
        "#!/bin/sh\necho 'High risk alert: SQL Injection detected'\necho 'URL: https://example.com/login'\necho 'Param: username'\n",
    )
    .expect("write mock zap shell");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let permissions = fs::Permissions::from_mode(0o755);
        fs::set_permissions(&path, permissions).expect("set mock zap permissions");
    }

    path
}

fn locate_worker_binary() -> PathBuf {
    let current = env::current_exe().expect("resolve current test binary");
    let target_dir = current
        .parent()
        .and_then(|path| path.parent())
        .expect("resolve target directory");
    let binary_name = if cfg!(windows) {
        "uss-worker.exe"
    } else {
        "uss-worker"
    };

    target_dir.join(binary_name)
}
