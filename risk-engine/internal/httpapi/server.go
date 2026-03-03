package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	riskmodels "unifiedsecurityscanner/control-plane/risk-engine/internal/models"
	"unifiedsecurityscanner/control-plane/risk-engine/internal/scoring"
)

type Server struct {
	httpServer *http.Server
}

func New(bindAddress string) *Server {
	mux := http.NewServeMux()
	server := &Server{
		httpServer: &http.Server{
			Addr:              bindAddress,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		},
	}

	mux.HandleFunc("/healthz", server.handleHealth)
	mux.HandleFunc("/v1/score", server.handleScore)
	mux.HandleFunc("/v1/score/batch", server.handleBatchScore)
	mux.HandleFunc("/v1/queues", server.handleQueues)

	return server
}

func (s *Server) ListenAndServe() error {
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "the requested method is not supported")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "risk-engine-api",
	})
}

func (s *Server) handleScore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "the requested method is not supported")
		return
	}
	defer r.Body.Close()

	var request riskmodels.ScoreRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}
	if request.Finding.Category == "" || request.Finding.Title == "" {
		writeError(w, http.StatusBadRequest, "validation_error", "finding.category and finding.title are required")
		return
	}

	writeJSON(w, http.StatusOK, scoring.Score(request))
}

func (s *Server) handleBatchScore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "the requested method is not supported")
		return
	}
	defer r.Body.Close()

	var request riskmodels.BatchScoreRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	writeJSON(w, http.StatusOK, scoring.BatchScore(request))
}

func (s *Server) handleQueues(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "the requested method is not supported")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"items": scoring.QueueCatalog(),
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, code string, message string) {
	writeJSON(w, status, map[string]string{
		"code":    code,
		"message": message,
	})
}
