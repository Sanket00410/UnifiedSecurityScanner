package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"encoding/json"

	"unifiedsecurityscanner/control-plane/internal/auth"
	"unifiedsecurityscanner/control-plane/internal/jobs"
	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Server) handleAIPolicy(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		item, _, err := s.store.GetAIGatewayPolicyForTenant(r.Context(), principal.OrganizationID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "get_ai_policy_failed", "ai policy could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
	case http.MethodPut:
		defer r.Body.Close()

		var request models.UpsertAIGatewayPolicyRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		item, err := s.store.UpsertAIGatewayPolicyForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
		if err != nil {
			if s.writeAIGatewayMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "upsert_ai_policy_failed", "ai policy could not be saved")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleAITriageRequests(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	limit := 200
	if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
		parsed, err := strconv.Atoi(rawLimit)
		if err != nil || parsed <= 0 {
			s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
			return
		}
		limit = parsed
	}

	items, err := s.store.ListAITriageRequestsForTenant(r.Context(), principal.OrganizationID, strings.TrimSpace(r.URL.Query().Get("request_kind")), limit)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_ai_triage_requests_failed", "ai triage requests could not be loaded")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleAITriageSummaries(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	defer r.Body.Close()

	var request models.CreateAITriageSummaryRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}
	if strings.TrimSpace(request.InputText) == "" {
		s.writeError(w, http.StatusBadRequest, "validation_error", "input_text is required")
		return
	}

	item, err := s.store.CreateAITriageSummaryForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
	if err != nil {
		if s.writeAIGatewayMutationError(w, err) {
			return
		}
		s.writeError(w, http.StatusInternalServerError, "create_ai_triage_summary_failed", "ai triage summary could not be created")
		return
	}
	s.writeJSON(w, http.StatusCreated, item)
}

func (s *Server) handleAITriageEvaluations(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		limit := 200
		if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
			parsed, err := strconv.Atoi(rawLimit)
			if err != nil || parsed <= 0 {
				s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
				return
			}
			limit = parsed
		}
		items, err := s.store.ListAITriageEvaluationsForTenant(
			r.Context(),
			principal.OrganizationID,
			strings.TrimSpace(r.URL.Query().Get("verdict")),
			strings.TrimSpace(r.URL.Query().Get("triage_request_id")),
			limit,
		)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_ai_triage_evaluations_failed", "ai triage evaluations could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.RecordAITriageEvaluationRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		if strings.TrimSpace(request.TriageRequestID) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "triage_request_id is required")
			return
		}

		item, err := s.store.RecordAITriageEvaluationForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
		if err != nil {
			if s.writeAIGatewayMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "create_ai_triage_evaluation_failed", "ai triage evaluation could not be recorded")
			return
		}
		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) writeAIGatewayMutationError(w http.ResponseWriter, err error) bool {
	switch {
	case errors.Is(err, jobs.ErrAIPolicyModelDenied):
		s.writeError(w, http.StatusBadRequest, "ai_model_denied", "the requested ai model is not permitted by policy")
		return true
	case errors.Is(err, jobs.ErrAIPolicyInputTooLarge):
		s.writeError(w, http.StatusBadRequest, "ai_input_too_large", "the ai input exceeds policy size limits")
		return true
	case errors.Is(err, jobs.ErrAIPolicyEvidenceRequired):
		s.writeError(w, http.StatusBadRequest, "ai_evidence_required", "evidence references are required by ai policy")
		return true
	case errors.Is(err, jobs.ErrAITriageRequestNotFound):
		s.writeError(w, http.StatusNotFound, "ai_triage_request_not_found", "the referenced ai triage request was not found")
		return true
	}

	lower := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(lower, "is required"),
		strings.Contains(lower, "must be greater than zero"):
		s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
		return true
	default:
		return false
	}
}
