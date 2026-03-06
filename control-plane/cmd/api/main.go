package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"unifiedsecurityscanner/control-plane/internal/config"
	"unifiedsecurityscanner/control-plane/internal/grpcapi"
	"unifiedsecurityscanner/control-plane/internal/httpapi"
	"unifiedsecurityscanner/control-plane/internal/jobs"
)

func main() {
	cfg := config.Load()
	logger := log.New(os.Stdout, "api ", log.LstdFlags|log.LUTC)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := jobs.NewStore(ctx, cfg)
	if err != nil {
		logger.Fatalf("create store: %v", err)
	}
	defer store.Close()

	httpServer := httpapi.New(cfg, store)
	grpcServer := grpcapi.New(
		cfg.GRPCBindAddress,
		store,
		logger,
		cfg.WorkerSharedSecret,
		cfg.WorkloadIdentitySigningKey,
		grpcapi.TransportSecurityConfig{
			ServerCertFile:    cfg.GRPCTLSCertFile,
			ServerKeyFile:     cfg.GRPCTLSKeyFile,
			ClientCAFile:      cfg.GRPCTLSClientCAFile,
			RequireClientCert: cfg.GRPCTLSRequireClientCert,
		},
	)
	errCh := make(chan error, 2)

	go func() {
		logger.Printf("starting control plane api bind=%s version=%s", cfg.APIBindAddress, cfg.BuildVersion)
		errCh <- httpServer.ListenAndServe()
	}()

	go func() {
		logger.Printf("starting worker grpc bind=%s version=%s", cfg.GRPCBindAddress, cfg.BuildVersion)
		errCh <- grpcServer.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		logger.Println("shutdown signal received")
		if err := httpServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("graceful shutdown failed: %v", err)
		}
		if err := grpcServer.Shutdown(shutdownCtx); err != nil {
			logger.Fatalf("grpc shutdown failed: %v", err)
		}
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalf("server stopped unexpectedly: %v", err)
		}
	}
}
