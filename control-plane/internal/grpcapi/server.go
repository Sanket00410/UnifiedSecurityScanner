package grpcapi

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	workerv1 "unifiedsecurityscanner/control-plane/internal/gen/workerv1"
	"unifiedsecurityscanner/control-plane/internal/jobs"
	"unifiedsecurityscanner/control-plane/internal/models"
	"unifiedsecurityscanner/control-plane/internal/normalize"
)

type Server struct {
	logger     *log.Logger
	bind       string
	grpcServer *grpc.Server
	listener   net.Listener
	store      *jobs.Store
}

func New(bind string, store *jobs.Store, logger *log.Logger) *Server {
	server := &Server{
		logger: logger,
		bind:   bind,
		store:  store,
	}

	server.grpcServer = grpc.NewServer()
	workerv1.RegisterWorkerControlPlaneServer(server.grpcServer, &workerService{
		store:  store,
		logger: logger,
	})

	return server
}

func (s *Server) ListenAndServe() error {
	listener, err := net.Listen("tcp", s.bind)
	if err != nil {
		return fmt.Errorf("listen grpc: %w", err)
	}

	s.listener = listener
	return s.grpcServer.Serve(listener)
}

func (s *Server) Shutdown(_ context.Context) error {
	s.grpcServer.GracefulStop()
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

type workerService struct {
	workerv1.UnimplementedWorkerControlPlaneServer
	store  *jobs.Store
	logger *log.Logger
}

func (s *workerService) RegisterWorker(ctx context.Context, req *workerv1.WorkerRegistrationRequest) (*workerv1.WorkerRegistrationResponse, error) {
	if req.GetWorkerId() == "" || req.GetWorkerVersion() == "" || req.GetOperatingSystem() == "" || req.GetHostname() == "" {
		return nil, status.Error(codes.InvalidArgument, "worker_id, worker_version, operating_system, and hostname are required")
	}

	response, err := s.store.RegisterWorker(ctx, models.WorkerRegistrationRequest{
		WorkerID:        req.GetWorkerId(),
		WorkerVersion:   req.GetWorkerVersion(),
		OperatingSystem: req.GetOperatingSystem(),
		Hostname:        req.GetHostname(),
		Capabilities:    mapCapabilities(req.GetCapabilities()),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "register worker: %v", err)
	}

	return &workerv1.WorkerRegistrationResponse{
		Accepted:                 response.Accepted,
		LeaseId:                  response.LeaseID,
		HeartbeatIntervalSeconds: response.HeartbeatIntervalSeconds,
	}, nil
}

func (s *workerService) Heartbeat(ctx context.Context, req *workerv1.HeartbeatRequest) (*workerv1.HeartbeatResponse, error) {
	if req.GetWorkerId() == "" || req.GetLeaseId() == "" {
		return nil, status.Error(codes.InvalidArgument, "worker_id and lease_id are required")
	}

	response, err := s.store.RecordHeartbeat(ctx, models.HeartbeatRequest{
		WorkerID:      req.GetWorkerId(),
		LeaseID:       req.GetLeaseId(),
		TimestampUnix: req.GetTimestampUnix(),
		Metrics:       req.GetMetrics(),
	})
	if err != nil {
		if err == jobs.ErrWorkerLeaseNotFound {
			return nil, status.Error(codes.NotFound, "worker registration lease was not found")
		}
		return nil, status.Errorf(codes.Internal, "record heartbeat: %v", err)
	}

	assignments := make([]*workerv1.JobAssignment, 0, len(response.Assignments))
	for _, assignment := range response.Assignments {
		assignments = append(assignments, &workerv1.JobAssignment{
			JobId:             assignment.JobID,
			TenantId:          assignment.TenantID,
			AdapterId:         assignment.AdapterID,
			TargetKind:        assignment.TargetKind,
			Target:            assignment.Target,
			ExecutionMode:     toProtoExecutionMode(assignment.ExecutionMode),
			ApprovedModules:   assignment.ApprovedModules,
			Labels:            assignment.Labels,
			MaxRuntimeSeconds: assignment.MaxRuntimeSeconds,
			EvidenceUploadUrl: assignment.EvidenceUploadURL,
		})
	}

	return &workerv1.HeartbeatResponse{
		Assignments: assignments,
	}, nil
}

func (s *workerService) PublishJobStatus(stream grpc.ClientStreamingServer[workerv1.JobStatusEvent, workerv1.Ack]) error {
	processed := 0
	for {
		event, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&workerv1.Ack{
				Accepted: true,
				Message:  fmt.Sprintf("processed %d status events", processed),
			})
		}
		if err != nil {
			return status.Errorf(codes.Internal, "receive status event: %v", err)
		}

		taskState := toModelTaskState(event.GetState())
		if err := s.store.RecordTaskStatus(stream.Context(), event.GetWorkerId(), event.GetJobId(), taskState); err != nil {
			if err == jobs.ErrTaskNotFound {
				return status.Error(codes.NotFound, "task was not found")
			}
			return status.Errorf(codes.Internal, "record task status: %v", err)
		}

		processed++
	}
}

func (s *workerService) PublishJobResult(ctx context.Context, req *workerv1.JobResult) (*workerv1.Ack, error) {
	taskCtx, err := s.store.GetTaskContext(ctx, req.GetJobId())
	if err != nil {
		if err == jobs.ErrTaskNotFound {
			return nil, status.Error(codes.NotFound, "task was not found")
		}
		return nil, status.Errorf(codes.Internal, "get task context: %v", err)
	}

	findings, err := normalize.Parse(taskCtx.AdapterID, normalize.Context{
		TenantID:   taskCtx.TenantID,
		ScanJobID:  taskCtx.ScanJobID,
		TaskID:     taskCtx.TaskID,
		AdapterID:  taskCtx.AdapterID,
		TargetKind: taskCtx.TargetKind,
		Target:     taskCtx.Target,
	}, req.GetEvidencePaths())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "normalize evidence: %v", err)
	}

	if len(findings) == 0 && len(req.GetFindings()) > 0 {
		findings = fallbackFindings(taskCtx, req.GetFindings())
	}

	err = s.store.FinalizeTask(ctx, models.TaskResultSubmission{
		TaskID:           req.GetJobId(),
		WorkerID:         req.GetWorkerId(),
		FinalState:       req.GetFinalState().String(),
		EvidencePaths:    req.GetEvidencePaths(),
		ErrorMessage:     req.GetErrorMessage(),
		ReportedFindings: findings,
	})
	if err != nil {
		if err == jobs.ErrTaskNotFound {
			return nil, status.Error(codes.NotFound, "task was not found")
		}
		return nil, status.Errorf(codes.Internal, "finalize task: %v", err)
	}

	return &workerv1.Ack{
		Accepted: true,
		Message:  fmt.Sprintf("stored %d normalized findings", len(findings)),
	}, nil
}

func mapCapabilities(items []*workerv1.WorkerCapability) []models.WorkerCapability {
	out := make([]models.WorkerCapability, 0, len(items))
	for _, item := range items {
		if item == nil {
			continue
		}

		modes := make([]models.ExecutionMode, 0, len(item.GetSupportedModes()))
		for _, mode := range item.GetSupportedModes() {
			switch mode {
			case workerv1.ExecutionMode_EXECUTION_MODE_PASSIVE:
				modes = append(modes, models.ExecutionModePassive)
			case workerv1.ExecutionMode_EXECUTION_MODE_ACTIVE_VALIDATION:
				modes = append(modes, models.ExecutionModeActiveValidation)
			case workerv1.ExecutionMode_EXECUTION_MODE_RESTRICTED_EXPLOIT:
				modes = append(modes, models.ExecutionModeRestrictedExploit)
			}
		}

		out = append(out, models.WorkerCapability{
			AdapterID:            item.GetAdapterId(),
			SupportedTargetKinds: item.GetSupportedTargetKinds(),
			SupportedModes:       modes,
			Labels:               item.GetLabels(),
			LinuxPreferred:       item.GetLinuxPreferred(),
		})
	}
	return out
}

func toProtoExecutionMode(mode models.ExecutionMode) workerv1.ExecutionMode {
	switch mode {
	case models.ExecutionModePassive:
		return workerv1.ExecutionMode_EXECUTION_MODE_PASSIVE
	case models.ExecutionModeRestrictedExploit:
		return workerv1.ExecutionMode_EXECUTION_MODE_RESTRICTED_EXPLOIT
	default:
		return workerv1.ExecutionMode_EXECUTION_MODE_ACTIVE_VALIDATION
	}
}

func toModelTaskState(state workerv1.JobState) models.TaskStatus {
	switch state {
	case workerv1.JobState_JOB_STATE_COMPLETED:
		return models.TaskStatusCompleted
	case workerv1.JobState_JOB_STATE_FAILED:
		return models.TaskStatusFailed
	case workerv1.JobState_JOB_STATE_CANCELED:
		return models.TaskStatusCanceled
	case workerv1.JobState_JOB_STATE_RUNNING:
		return models.TaskStatusRunning
	default:
		return models.TaskStatusRunning
	}
}

func fallbackFindings(taskCtx models.TaskContext, summaries []*workerv1.FindingSummary) []models.CanonicalFinding {
	out := make([]models.CanonicalFinding, 0, len(summaries))
	now := time.Now().UTC()

	for index, summary := range summaries {
		if summary == nil {
			continue
		}
		findingID := summary.GetFindingId()
		if findingID == "" {
			findingID = fmt.Sprintf("%s-fallback-%d", taskCtx.TaskID, index+1)
		}

		out = append(out, models.CanonicalFinding{
			SchemaVersion: "1.0.0",
			FindingID:     findingID,
			TenantID:      taskCtx.TenantID,
			Scanner: models.CanonicalScannerInfo{
				Engine:    taskCtx.AdapterID,
				AdapterID: taskCtx.AdapterID,
				ScanJobID: taskCtx.ScanJobID,
			},
			Source: models.CanonicalSourceInfo{
				Layer: "pentest",
				Tool:  taskCtx.AdapterID,
			},
			Category:    summary.GetCategory(),
			Title:       summary.GetCategory(),
			Description: summary.GetCategory(),
			Severity:    strings.ToLower(summary.GetSeverity()),
			Confidence:  "medium",
			Status:      "open",
			FirstSeenAt: now,
			LastSeenAt:  now,
			Asset: models.CanonicalAssetInfo{
				AssetID:     taskCtx.Target,
				AssetType:   taskCtx.TargetKind,
				AssetName:   taskCtx.Target,
				Environment: "unknown",
				Exposure:    "internet",
			},
			Risk: models.CanonicalRisk{
				Priority:       "p2",
				OverallScore:   summary.GetRiskScore(),
				BusinessImpact: 6,
				Exploitability: 6,
				Reachability:   8,
				Exposure:       8,
			},
		})
	}

	return out
}
