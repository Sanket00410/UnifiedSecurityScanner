package grpcapi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"unifiedsecurityscanner/control-plane/internal/auth"
	workerv1 "unifiedsecurityscanner/control-plane/internal/gen/workerv1"
	"unifiedsecurityscanner/control-plane/internal/jobs"
	"unifiedsecurityscanner/control-plane/internal/models"
	"unifiedsecurityscanner/control-plane/internal/normalize"
	"unifiedsecurityscanner/control-plane/internal/risk"
)

type Server struct {
	logger                     *log.Logger
	bind                       string
	grpcServer                 *grpc.Server
	listener                   net.Listener
	initErr                    error
	store                      workerStore
	workerSharedSecret         string
	workloadIdentitySigningKey string
}

type TransportSecurityConfig struct {
	ServerCertFile    string
	ServerKeyFile     string
	ClientCAFile      string
	RequireClientCert bool
}

type workerStore interface {
	RegisterWorker(ctx context.Context, request models.WorkerRegistrationRequest) (models.WorkerRegistrationResponse, error)
	RecordHeartbeat(ctx context.Context, request models.HeartbeatRequest) (models.HeartbeatResponse, error)
	RecordTaskStatus(ctx context.Context, workerID string, taskID string, state models.TaskStatus) error
	GetTaskContext(ctx context.Context, taskID string) (models.TaskContext, error)
	FinalizeTask(ctx context.Context, submission models.TaskResultSubmission) error
}

func New(bind string, store *jobs.Store, logger *log.Logger, workerSharedSecret string, workloadIdentitySigningKey string, transportSecurity TransportSecurityConfig) *Server {
	serverOptions := make([]grpc.ServerOption, 0, 1)
	serverCredentials, err := buildServerCredentials(transportSecurity)

	server := &Server{
		logger:                     logger,
		bind:                       bind,
		store:                      store,
		workerSharedSecret:         strings.TrimSpace(workerSharedSecret),
		workloadIdentitySigningKey: strings.TrimSpace(workloadIdentitySigningKey),
	}
	if err != nil {
		server.initErr = err
	}
	if serverCredentials != nil {
		serverOptions = append(serverOptions, grpc.Creds(serverCredentials))
	}

	server.grpcServer = grpc.NewServer(serverOptions...)
	workerv1.RegisterWorkerControlPlaneServer(server.grpcServer, &workerService{
		store:                      store,
		logger:                     logger,
		workerSharedSecret:         strings.TrimSpace(workerSharedSecret),
		workloadIdentitySigningKey: strings.TrimSpace(workloadIdentitySigningKey),
	})

	return server
}

func (s *Server) ListenAndServe() error {
	if s.initErr != nil {
		return s.initErr
	}

	listener, err := net.Listen("tcp", s.bind)
	if err != nil {
		return fmt.Errorf("listen grpc: %w", err)
	}

	s.listener = listener
	return s.grpcServer.Serve(listener)
}

func buildServerCredentials(cfg TransportSecurityConfig) (credentials.TransportCredentials, error) {
	certFile := strings.TrimSpace(cfg.ServerCertFile)
	keyFile := strings.TrimSpace(cfg.ServerKeyFile)
	if certFile == "" && keyFile == "" {
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("grpc tls requires both cert and key files")
	}

	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load grpc tls keypair: %w", err)
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	}

	if cfg.RequireClientCert {
		caFile := strings.TrimSpace(cfg.ClientCAFile)
		if caFile == "" {
			return nil, fmt.Errorf("grpc mTLS requires client ca file")
		}
		caPEM, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read grpc client ca file: %w", err)
		}
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("parse grpc client ca file")
		}
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = certPool
	}

	return credentials.NewTLS(tlsConfig), nil
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
	store                      workerStore
	logger                     *log.Logger
	workerSharedSecret         string
	workloadIdentitySigningKey string
}

func (s *workerService) RegisterWorker(ctx context.Context, req *workerv1.WorkerRegistrationRequest) (*workerv1.WorkerRegistrationResponse, error) {
	if req.GetWorkerId() == "" || req.GetWorkerVersion() == "" || req.GetOperatingSystem() == "" || req.GetHostname() == "" {
		return nil, status.Error(codes.InvalidArgument, "worker_id, worker_version, operating_system, and hostname are required")
	}
	if _, err := s.validateWorkerAuthentication(ctx, req.GetWorkerId()); err != nil {
		return nil, err
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
	if _, err := s.validateWorkerAuthentication(ctx, req.GetWorkerId()); err != nil {
		return nil, err
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
	claims, err := s.validateWorkerAuthentication(stream.Context(), "")
	if err != nil {
		return err
	}
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
		if claims != nil && !strings.EqualFold(strings.TrimSpace(claims.WorkerID), strings.TrimSpace(event.GetWorkerId())) {
			return status.Error(codes.Unauthenticated, "worker identity token does not match worker_id")
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
	if _, err := s.validateWorkerAuthentication(ctx, req.GetWorkerId()); err != nil {
		return nil, err
	}
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

func (s *workerService) validateWorkerAuthentication(ctx context.Context, expectedWorkerID string) (*auth.WorkerIdentityClaims, error) {
	md, _ := metadata.FromIncomingContext(ctx)

	sharedSecret := strings.TrimSpace(s.workerSharedSecret)
	if sharedSecret != "" {
		values := md.Get(auth.WorkerSecretMetadata)
		if len(values) > 0 {
			if strings.TrimSpace(values[0]) != sharedSecret {
				return nil, status.Error(codes.Unauthenticated, "worker secret is invalid")
			}
			return nil, nil
		}
	}

	signingKey := strings.TrimSpace(s.workloadIdentitySigningKey)
	if signingKey != "" {
		authzValues := md.Get("authorization")
		if len(authzValues) == 0 {
			if sharedSecret != "" {
				return nil, status.Error(codes.Unauthenticated, "worker secret metadata is required")
			}
			return nil, status.Error(codes.Unauthenticated, "worker identity token is required")
		}

		token := auth.ParseBearerToken(authzValues[0])
		if token == "" {
			return nil, status.Error(codes.Unauthenticated, "worker identity token is invalid")
		}

		claims, err := auth.ValidateWorkerIdentityToken(signingKey, token, time.Now().UTC())
		if err != nil {
			return nil, status.Error(codes.Unauthenticated, "worker identity token is invalid")
		}
		if strings.TrimSpace(expectedWorkerID) != "" &&
			!strings.EqualFold(strings.TrimSpace(claims.WorkerID), strings.TrimSpace(expectedWorkerID)) {
			return nil, status.Error(codes.Unauthenticated, "worker identity token does not match worker_id")
		}
		return &claims, nil
	}

	if sharedSecret != "" {
		return nil, status.Error(codes.Unauthenticated, "worker secret metadata is required")
	}

	return nil, nil
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

		finding := models.CanonicalFinding{
			SchemaVersion: "1.0.0",
			FindingID:     findingID,
			TenantID:      taskCtx.TenantID,
			Scanner: models.CanonicalScannerInfo{
				Engine:    taskCtx.AdapterID,
				AdapterID: taskCtx.AdapterID,
				ScanJobID: taskCtx.ScanJobID,
			},
			Source: models.CanonicalSourceInfo{
				Layer: risk.LayerForAdapter(taskCtx.AdapterID),
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
				Exposure:    "unknown",
			},
			Risk: models.CanonicalRisk{
				OverallScore: summary.GetRiskScore(),
			},
		}

		out = append(out, risk.Enrich(finding))
	}

	return out
}
