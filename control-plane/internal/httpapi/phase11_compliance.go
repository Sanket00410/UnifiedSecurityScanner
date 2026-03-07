package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"unifiedsecurityscanner/control-plane/internal/auth"
	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Server) handleComplianceMappings(w http.ResponseWriter, r *http.Request) {
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
		items, err := s.store.ListComplianceControlMappingsForTenant(
			r.Context(),
			principal.OrganizationID,
			strings.TrimSpace(r.URL.Query().Get("framework")),
			strings.TrimSpace(r.URL.Query().Get("source_id")),
			limit,
		)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_compliance_mappings_failed", "compliance mappings could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateComplianceControlMappingRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		if strings.TrimSpace(request.SourceKind) == "" ||
			strings.TrimSpace(request.SourceID) == "" ||
			strings.TrimSpace(request.Framework) == "" ||
			strings.TrimSpace(request.ControlID) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "source_kind, source_id, framework, and control_id are required")
			return
		}
		item, err := s.store.CreateComplianceControlMappingForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
		if err != nil {
			if s.writeComplianceMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "create_compliance_mapping_failed", "compliance mapping could not be created")
			return
		}
		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleComplianceMappingRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	mappingID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/compliance/mappings/"))
	if mappingID == "" {
		s.writeError(w, http.StatusNotFound, "compliance_mapping_not_found", "compliance mapping was not found")
		return
	}

	defer r.Body.Close()

	var request models.UpdateComplianceControlMappingRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	item, found, err := s.store.UpdateComplianceControlMappingForTenant(r.Context(), principal.OrganizationID, mappingID, principal.Email, request)
	if err != nil {
		if s.writeComplianceMutationError(w, err) {
			return
		}
		s.writeError(w, http.StatusInternalServerError, "update_compliance_mapping_failed", "compliance mapping could not be updated")
		return
	}
	if !found {
		s.writeError(w, http.StatusNotFound, "compliance_mapping_not_found", "compliance mapping was not found")
		return
	}
	s.writeJSON(w, http.StatusOK, item)
}

func (s *Server) handleComplianceSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	summary, err := s.store.GetComplianceSummaryForTenant(r.Context(), principal.OrganizationID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "get_compliance_summary_failed", "compliance summary could not be loaded")
		return
	}
	s.writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleComplianceOWASPSync(w http.ResponseWriter, r *http.Request) {
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

	request := models.SyncOWASPMappingRequest{}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil && !errors.Is(err, io.EOF) {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	result, err := s.store.SyncOWASPMappingsForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
	if err != nil {
		if s.writeComplianceMutationError(w, err) {
			return
		}
		s.writeError(w, http.StatusInternalServerError, "sync_owasp_mappings_failed", "owasp mappings could not be synchronized")
		return
	}

	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleComplianceSAMMMetrics(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	metrics, err := s.store.GetSAMMMetricsForTenant(r.Context(), principal.OrganizationID)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "get_samm_metrics_failed", "samm metrics could not be loaded")
		return
	}

	s.writeJSON(w, http.StatusOK, metrics)
}

func (s *Server) writeComplianceMutationError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(lower, "is required"):
		s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
		return true
	case strings.Contains(lower, "duplicate key"),
		strings.Contains(lower, "already exists"),
		strings.Contains(lower, "unique"):
		s.writeError(w, http.StatusConflict, "compliance_mapping_conflict", "a conflicting compliance mapping already exists")
		return true
	default:
		return false
	}
}
