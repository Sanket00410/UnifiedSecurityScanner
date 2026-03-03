package grpcapi

import (
	"context"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"unifiedsecurityscanner/control-plane/internal/auth"
	workerv1 "unifiedsecurityscanner/control-plane/internal/gen/workerv1"
	"unifiedsecurityscanner/control-plane/internal/models"
)

const testBufSize = 1024 * 1024

type recordedTaskStatus struct {
	WorkerID string
	TaskID   string
	State    models.TaskStatus
}

type stubWorkerStore struct {
	mu sync.Mutex

	registrationResponse models.WorkerRegistrationResponse
	heartbeatResponse    models.HeartbeatResponse
	taskContext          models.TaskContext

	registrationRequests []models.WorkerRegistrationRequest
	heartbeatRequests    []models.HeartbeatRequest
	taskStatuses         []recordedTaskStatus
	finalizedTasks       []models.TaskResultSubmission
}

func (s *stubWorkerStore) RegisterWorker(_ context.Context, request models.WorkerRegistrationRequest) (models.WorkerRegistrationResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.registrationRequests = append(s.registrationRequests, request)
	return s.registrationResponse, nil
}

func (s *stubWorkerStore) RecordHeartbeat(_ context.Context, request models.HeartbeatRequest) (models.HeartbeatResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.heartbeatRequests = append(s.heartbeatRequests, request)
	return s.heartbeatResponse, nil
}

func (s *stubWorkerStore) RecordTaskStatus(_ context.Context, workerID string, taskID string, state models.TaskStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.taskStatuses = append(s.taskStatuses, recordedTaskStatus{
		WorkerID: workerID,
		TaskID:   taskID,
		State:    state,
	})
	return nil
}

func (s *stubWorkerStore) GetTaskContext(_ context.Context, taskID string) (models.TaskContext, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ctx := s.taskContext
	ctx.TaskID = taskID
	return ctx, nil
}

func (s *stubWorkerStore) FinalizeTask(_ context.Context, submission models.TaskResultSubmission) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.finalizedTasks = append(s.finalizedTasks, submission)
	return nil
}

func TestWorkerFlowOverGRPC(t *testing.T) {
	t.Parallel()

	evidencePath := filepath.Join(t.TempDir(), "zap-output.log")
	err := os.WriteFile(evidencePath, []byte("High risk alert: SQL Injection detected\n"), 0o600)
	if err != nil {
		t.Fatalf("write zap evidence: %v", err)
	}

	store := &stubWorkerStore{
		registrationResponse: models.WorkerRegistrationResponse{
			Accepted:                 true,
			LeaseID:                  "lease-test-1",
			HeartbeatIntervalSeconds: 30,
		},
		heartbeatResponse: models.HeartbeatResponse{
			Assignments: []models.JobAssignment{
				{
					JobID:             "task-test-1",
					TenantID:          "tenant-test",
					AdapterID:         "zap",
					TargetKind:        "url",
					Target:            "https://example.com/login",
					ExecutionMode:     models.ExecutionModeActiveValidation,
					ApprovedModules:   []string{},
					Labels:            map[string]string{"profile": "enterprise"},
					MaxRuntimeSeconds: 120,
					EvidenceUploadURL: "local://evidence/task-test-1",
				},
			},
		},
		taskContext: models.TaskContext{
			TaskID:     "task-test-1",
			ScanJobID:  "scan-test-1",
			TenantID:   "tenant-test",
			AdapterID:  "zap",
			TargetKind: "url",
			Target:     "https://example.com/login",
		},
	}

	client := newTestWorkerClient(t, store, "")
	ctx := context.Background()

	registration, err := client.RegisterWorker(ctx, &workerv1.WorkerRegistrationRequest{
		WorkerId:        "worker-test-1",
		WorkerVersion:   "0.2.0",
		OperatingSystem: "windows",
		Hostname:        "worker-test-host",
		Capabilities: []*workerv1.WorkerCapability{
			{
				AdapterId:            "zap",
				SupportedTargetKinds: []string{"url"},
				SupportedModes: []workerv1.ExecutionMode{
					workerv1.ExecutionMode_EXECUTION_MODE_ACTIVE_VALIDATION,
				},
				Labels: []string{"web"},
			},
		},
	})
	if err != nil {
		t.Fatalf("register worker: %v", err)
	}
	if !registration.GetAccepted() {
		t.Fatal("expected worker registration to be accepted")
	}
	if registration.GetLeaseId() != "lease-test-1" {
		t.Fatalf("unexpected lease id: %s", registration.GetLeaseId())
	}

	heartbeat, err := client.Heartbeat(ctx, &workerv1.HeartbeatRequest{
		WorkerId:      "worker-test-1",
		LeaseId:       registration.GetLeaseId(),
		TimestampUnix: 1,
		Metrics: map[string]string{
			"cpu":       "1",
			"memory_mb": "64",
		},
	})
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if len(heartbeat.GetAssignments()) != 1 {
		t.Fatalf("expected 1 assignment, got %d", len(heartbeat.GetAssignments()))
	}
	if heartbeat.GetAssignments()[0].GetJobId() != "task-test-1" {
		t.Fatalf("unexpected assignment job id: %s", heartbeat.GetAssignments()[0].GetJobId())
	}

	statusStream, err := client.PublishJobStatus(ctx)
	if err != nil {
		t.Fatalf("open status stream: %v", err)
	}

	err = statusStream.Send(&workerv1.JobStatusEvent{
		WorkerId:      "worker-test-1",
		JobId:         "task-test-1",
		State:         workerv1.JobState_JOB_STATE_RUNNING,
		Detail:        "starting zap",
		TimestampUnix: 2,
	})
	if err != nil {
		t.Fatalf("send status event: %v", err)
	}

	statusAck, err := statusStream.CloseAndRecv()
	if err != nil {
		t.Fatalf("close status stream: %v", err)
	}
	if !statusAck.GetAccepted() {
		t.Fatal("expected status ack to be accepted")
	}
	if !strings.Contains(statusAck.GetMessage(), "processed 1") {
		t.Fatalf("unexpected status ack message: %s", statusAck.GetMessage())
	}

	resultAck, err := client.PublishJobResult(ctx, &workerv1.JobResult{
		WorkerId:      "worker-test-1",
		JobId:         "task-test-1",
		FinalState:    workerv1.JobState_JOB_STATE_COMPLETED,
		EvidencePaths: []string{evidencePath},
	})
	if err != nil {
		t.Fatalf("publish job result: %v", err)
	}
	if !resultAck.GetAccepted() {
		t.Fatal("expected result ack to be accepted")
	}
	if resultAck.GetMessage() != "stored 1 normalized findings" {
		t.Fatalf("unexpected result ack message: %s", resultAck.GetMessage())
	}

	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.registrationRequests) != 1 {
		t.Fatalf("expected 1 registration request, got %d", len(store.registrationRequests))
	}
	if len(store.heartbeatRequests) != 1 {
		t.Fatalf("expected 1 heartbeat request, got %d", len(store.heartbeatRequests))
	}
	if len(store.taskStatuses) != 1 {
		t.Fatalf("expected 1 recorded task status, got %d", len(store.taskStatuses))
	}
	if store.taskStatuses[0].State != models.TaskStatusRunning {
		t.Fatalf("unexpected task status: %s", store.taskStatuses[0].State)
	}
	if len(store.finalizedTasks) != 1 {
		t.Fatalf("expected 1 finalized task, got %d", len(store.finalizedTasks))
	}

	submission := store.finalizedTasks[0]
	if submission.FinalState != "JOB_STATE_COMPLETED" {
		t.Fatalf("unexpected final state: %s", submission.FinalState)
	}
	if len(submission.ReportedFindings) != 1 {
		t.Fatalf("expected 1 normalized finding, got %d", len(submission.ReportedFindings))
	}

	finding := submission.ReportedFindings[0]
	if finding.Severity != "high" {
		t.Fatalf("unexpected finding severity: %s", finding.Severity)
	}
	if finding.Category != "web_application_exposure" {
		t.Fatalf("unexpected finding category: %s", finding.Category)
	}
}

func TestWorkerSecretValidation(t *testing.T) {
	t.Parallel()

	store := &stubWorkerStore{
		registrationResponse: models.WorkerRegistrationResponse{
			Accepted:                 true,
			LeaseID:                  "lease-test-2",
			HeartbeatIntervalSeconds: 30,
		},
	}

	client := newTestWorkerClient(t, store, "expected-secret")

	_, err := client.RegisterWorker(context.Background(), &workerv1.WorkerRegistrationRequest{
		WorkerId:        "worker-test-2",
		WorkerVersion:   "0.2.0",
		OperatingSystem: "windows",
		Hostname:        "worker-test-host",
	})
	if err == nil {
		t.Fatal("expected register worker without metadata to fail")
	}
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unexpected grpc status: %v", status.Code(err))
	}

	ctx := metadata.AppendToOutgoingContext(context.Background(), auth.WorkerSecretMetadata, "expected-secret")
	response, err := client.RegisterWorker(ctx, &workerv1.WorkerRegistrationRequest{
		WorkerId:        "worker-test-2",
		WorkerVersion:   "0.2.0",
		OperatingSystem: "windows",
		Hostname:        "worker-test-host",
	})
	if err != nil {
		t.Fatalf("register worker with metadata: %v", err)
	}
	if !response.GetAccepted() {
		t.Fatal("expected authenticated register worker call to succeed")
	}
}

func newTestWorkerClient(t *testing.T, store workerStore, workerSharedSecret string) workerv1.WorkerControlPlaneClient {
	t.Helper()

	listener := bufconn.Listen(testBufSize)
	server := grpc.NewServer()
	workerv1.RegisterWorkerControlPlaneServer(server, &workerService{
		store:              store,
		logger:             log.New(io.Discard, "", 0),
		workerSharedSecret: workerSharedSecret,
	})

	go func() {
		_ = server.Serve(listener)
	}()

	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	conn, err := grpc.DialContext(context.Background(), "bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}

	t.Cleanup(func() {
		_ = conn.Close()
	})

	return workerv1.NewWorkerControlPlaneClient(conn)
}
