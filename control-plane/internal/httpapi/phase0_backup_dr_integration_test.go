package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"unifiedsecurityscanner/control-plane/internal/auth"
	"unifiedsecurityscanner/control-plane/internal/config"
	"unifiedsecurityscanner/control-plane/internal/jobs"
	"unifiedsecurityscanner/control-plane/internal/models"
)

func TestPhase0BackupAndRecoveryDrillFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping postgres-backed integration test in short mode")
	}

	adminURL := strings.TrimSpace(os.Getenv("USS_TEST_DATABASE_ADMIN_URL"))
	if adminURL == "" {
		adminURL = "postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable"
	}

	dbName := fmt.Sprintf("uss_phase0_backup_dr_it_%d", time.Now().UTC().UnixNano())
	testDatabaseURL, cleanup := createIntegrationDatabase(t, adminURL, dbName)
	defer cleanup()

	cfg := config.Load()
	cfg.DatabaseURL = testDatabaseURL
	cfg.DatabaseMaxConns = 2
	cfg.DatabaseMinConns = 0

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	store, err := jobs.NewStore(ctx, cfg)
	if err != nil {
		t.Fatalf("create integration store: %v", err)
	}
	defer store.Close()

	server := New(cfg, store)
	testServer := httptest.NewServer(server.httpServer.Handler)
	defer testServer.Close()

	client := testServer.Client()

	createSnapshotResponse, createSnapshotBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/backups/snapshots", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"scope":       "full_platform",
		"storage_ref": "s3://uss-backups/local/full-2026-03-06.tar.zst",
		"size_bytes":  1024,
		"status":      "completed",
	}, http.StatusCreated)
	defer createSnapshotResponse.Body.Close()

	var snapshot models.BackupSnapshot
	decodeJSONResponse(t, createSnapshotBody, &snapshot)
	if snapshot.ID == "" {
		t.Fatal("expected backup snapshot id")
	}

	listSnapshotsResponse, listSnapshotsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/backups/snapshots?limit=10", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer listSnapshotsResponse.Body.Close()

	var snapshotList struct {
		Items []models.BackupSnapshot `json:"items"`
	}
	decodeJSONResponse(t, listSnapshotsBody, &snapshotList)
	if len(snapshotList.Items) != 1 {
		t.Fatalf("expected 1 backup snapshot, got %d", len(snapshotList.Items))
	}

	createDrillResponse, createDrillBody := mustJSONRequest(t, client, http.MethodPost, testServer.URL+"/v1/backups/recovery-drills", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", map[string]any{
		"snapshot_id": snapshot.ID,
		"status":      "completed",
		"rto_seconds": 540,
	}, http.StatusCreated)
	defer createDrillResponse.Body.Close()

	var drill models.RecoveryDrill
	decodeJSONResponse(t, createDrillBody, &drill)
	if drill.ID == "" {
		t.Fatal("expected recovery drill id")
	}
	if drill.SnapshotID != snapshot.ID {
		t.Fatalf("expected recovery drill to reference snapshot %s, got %s", snapshot.ID, drill.SnapshotID)
	}

	listDrillsResponse, listDrillsBody := mustJSONRequest(t, client, http.MethodGet, testServer.URL+"/v1/backups/recovery-drills?limit=10", cfg.BootstrapAdminToken, auth.WorkerSecretHeader, "", nil, http.StatusOK)
	defer listDrillsResponse.Body.Close()

	var drillList struct {
		Items []models.RecoveryDrill `json:"items"`
	}
	decodeJSONResponse(t, listDrillsBody, &drillList)
	if len(drillList.Items) != 1 {
		t.Fatalf("expected 1 recovery drill, got %d", len(drillList.Items))
	}
}
