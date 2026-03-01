package main

import (
	"context"
	"log"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	workerv1 "unifiedsecurityscanner/control-plane/internal/gen/workerv1"
)

func main() {
	log.SetOutput(os.Stdout)

	address := getEnv("USS_WORKER_GRPC_ADDR", "127.0.0.1:9090")
	mode := getEnv("USS_WORKERCTL_MODE", "register")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("dial grpc: %v", err)
	}
	defer conn.Close()

	client := workerv1.NewWorkerControlPlaneClient(conn)

	switch mode {
	case "register":
		resp, err := client.RegisterWorker(ctx, &workerv1.WorkerRegistrationRequest{
			WorkerId:        getEnv("USS_WORKER_ID", "workerctl-local"),
			WorkerVersion:   getEnv("USS_WORKER_VERSION", "0.1.0"),
			OperatingSystem: getEnv("USS_WORKER_OS", "windows"),
			Hostname:        getEnv("USS_WORKER_HOST", "workerctl"),
			Capabilities: []*workerv1.WorkerCapability{
				{
					AdapterId:            "zap",
					SupportedTargetKinds: []string{"domain", "api"},
					SupportedModes: []workerv1.ExecutionMode{
						workerv1.ExecutionMode_EXECUTION_MODE_PASSIVE,
						workerv1.ExecutionMode_EXECUTION_MODE_ACTIVE_VALIDATION,
					},
					Labels:         []string{"web"},
					LinuxPreferred: false,
				},
			},
		})
		if err != nil {
			log.Fatalf("register worker: %v", err)
		}
		log.Printf("registered lease_id=%s heartbeat_interval_seconds=%d", resp.GetLeaseId(), resp.GetHeartbeatIntervalSeconds())
	case "heartbeat":
		resp, err := client.Heartbeat(ctx, &workerv1.HeartbeatRequest{
			WorkerId: getEnv("USS_WORKER_ID", "workerctl-local"),
			LeaseId:  getEnv("USS_WORKER_LEASE_ID", ""),
			Metrics: map[string]string{
				"cpu":       "1",
				"memory_mb": "32",
			},
			TimestampUnix: time.Now().UTC().Unix(),
		})
		if err != nil {
			log.Fatalf("worker heartbeat: %v", err)
		}
		log.Printf("received %d assignments", len(resp.GetAssignments()))
		for _, assignment := range resp.GetAssignments() {
			log.Printf("assignment job_id=%s adapter_id=%s target=%s", assignment.GetJobId(), assignment.GetAdapterId(), assignment.GetTarget())
		}
	case "publish-status":
		stream, err := client.PublishJobStatus(ctx)
		if err != nil {
			log.Fatalf("open status stream: %v", err)
		}

		if err := stream.Send(&workerv1.JobStatusEvent{
			WorkerId:      getEnv("USS_WORKER_ID", "workerctl-local"),
			JobId:         getEnv("USS_JOB_ID", ""),
			State:         parseJobState(getEnv("USS_JOB_STATE", "running")),
			Detail:        getEnv("USS_JOB_DETAIL", "status update"),
			TimestampUnix: time.Now().UTC().Unix(),
		}); err != nil {
			log.Fatalf("send status event: %v", err)
		}

		ack, err := stream.CloseAndRecv()
		if err != nil {
			log.Fatalf("close status stream: %v", err)
		}
		log.Printf("status ack accepted=%t message=%s", ack.GetAccepted(), ack.GetMessage())
	case "publish-result":
		evidence := splitCSV(getEnv("USS_EVIDENCE_PATHS", ""))
		resp, err := client.PublishJobResult(ctx, &workerv1.JobResult{
			WorkerId:      getEnv("USS_WORKER_ID", "workerctl-local"),
			JobId:         getEnv("USS_JOB_ID", ""),
			FinalState:    parseJobState(getEnv("USS_JOB_STATE", "completed")),
			EvidencePaths: evidence,
			ErrorMessage:  getEnv("USS_JOB_ERROR", ""),
		})
		if err != nil {
			log.Fatalf("publish job result: %v", err)
		}
		log.Printf("result ack accepted=%t message=%s", resp.GetAccepted(), resp.GetMessage())
	default:
		log.Fatalf("unsupported USS_WORKERCTL_MODE=%s", mode)
	}
}

func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value
}

func parseJobState(value string) workerv1.JobState {
	switch value {
	case "queued":
		return workerv1.JobState_JOB_STATE_QUEUED
	case "running":
		return workerv1.JobState_JOB_STATE_RUNNING
	case "completed":
		return workerv1.JobState_JOB_STATE_COMPLETED
	case "failed":
		return workerv1.JobState_JOB_STATE_FAILED
	case "canceled", "cancelled":
		return workerv1.JobState_JOB_STATE_CANCELED
	default:
		return workerv1.JobState_JOB_STATE_UNSPECIFIED
	}
}

func splitCSV(value string) []string {
	if value == "" {
		return []string{}
	}

	out := make([]string, 0)
	start := 0
	for index := 0; index <= len(value); index++ {
		if index != len(value) && value[index] != ',' {
			continue
		}

		part := value[start:index]
		if part != "" {
			out = append(out, part)
		}
		start = index + 1
	}

	return out
}
