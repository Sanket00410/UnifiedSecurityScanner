package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"unifiedsecurityscanner/control-plane/internal/auth"
	"unifiedsecurityscanner/control-plane/internal/jobs"
	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Server) handleDesignReviews(w http.ResponseWriter, r *http.Request) {
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

		items, err := s.store.ListDesignReviewsForTenant(r.Context(), principal.OrganizationID, strings.TrimSpace(r.URL.Query().Get("status")), limit)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_design_reviews_failed", "design reviews could not be loaded")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{
			"items": items,
		})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateDesignReviewRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		if strings.TrimSpace(request.Title) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "title is required")
			return
		}

		item, err := s.store.CreateDesignReviewForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
		if err != nil {
			if s.writeDesignReviewMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "create_design_review_failed", "design review could not be created")
			return
		}

		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleDesignReviewRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/design-reviews/"))
	parts := strings.Split(path, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "design_review_route_not_found", "the requested design review route was not found")
		return
	}
	reviewID := strings.TrimSpace(parts[0])

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			item, found, err := s.store.GetDesignReviewForTenant(r.Context(), principal.OrganizationID, reviewID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "get_design_review_failed", "design review could not be loaded")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "design_review_not_found", "design review was not found")
				return
			}

			s.writeJSON(w, http.StatusOK, item)
		case http.MethodPut:
			defer r.Body.Close()

			var request models.UpdateDesignReviewRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}

			item, found, err := s.store.UpdateDesignReviewForTenant(r.Context(), principal.OrganizationID, reviewID, principal.Email, request)
			if err != nil {
				if s.writeDesignReviewMutationError(w, err) {
					return
				}
				s.writeError(w, http.StatusInternalServerError, "update_design_review_failed", "design review could not be updated")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "design_review_not_found", "design review was not found")
				return
			}

			s.writeJSON(w, http.StatusOK, item)
		default:
			s.writeMethodNotAllowed(w)
		}
		return
	}

	segment := strings.TrimSpace(parts[1])
	if segment == "" {
		s.writeError(w, http.StatusNotFound, "design_review_route_not_found", "the requested design review route was not found")
		return
	}

	if len(parts) == 2 && r.Method == http.MethodPost && (segment == "submit" || segment == "approve" || segment == "close") {
		defer r.Body.Close()
		var request models.DesignReviewDecisionRequest
		_ = json.NewDecoder(r.Body).Decode(&request)

		var (
			item  models.DesignReview
			found bool
			err   error
		)
		switch segment {
		case "submit":
			item, found, err = s.store.SubmitDesignReviewForTenant(r.Context(), principal.OrganizationID, reviewID, principal.Email, request.Reason)
		case "approve":
			item, found, err = s.store.ApproveDesignReviewForTenant(r.Context(), principal.OrganizationID, reviewID, principal.Email, request.Reason)
		case "close":
			item, found, err = s.store.CloseDesignReviewForTenant(r.Context(), principal.OrganizationID, reviewID, principal.Email, request.Reason)
		}
		if err != nil {
			if s.writeDesignReviewMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "transition_design_review_failed", "design review state transition failed")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "design_review_not_found", "design review was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
		return
	}

	switch segment {
	case "threats":
		s.handleDesignThreatRoute(w, r, principal, reviewID, parts[2:])
	case "data-flow":
		s.handleDesignDataFlowRoute(w, r, principal, reviewID, parts[2:])
	case "control-mappings":
		s.handleDesignControlMappingRoute(w, r, principal, reviewID, parts[2:])
	default:
		s.writeError(w, http.StatusNotFound, "design_review_route_not_found", "the requested design review route was not found")
	}
}

func (s *Server) handleDesignThreatRoute(w http.ResponseWriter, r *http.Request, principal models.AuthPrincipal, reviewID string, tail []string) {
	if len(tail) == 0 {
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
			items, err := s.store.ListDesignThreatsForTenant(r.Context(), principal.OrganizationID, reviewID, strings.TrimSpace(r.URL.Query().Get("status")), limit)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "list_design_threats_failed", "design threats could not be loaded")
				return
			}
			s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
		case http.MethodPost:
			defer r.Body.Close()

			var request models.CreateDesignThreatRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}
			if strings.TrimSpace(request.Title) == "" {
				s.writeError(w, http.StatusBadRequest, "validation_error", "title is required")
				return
			}

			item, err := s.store.CreateDesignThreatForTenant(r.Context(), principal.OrganizationID, reviewID, principal.Email, request)
			if err != nil {
				if errors.Is(err, jobs.ErrDesignReviewNotFound) {
					s.writeError(w, http.StatusNotFound, "design_review_not_found", "design review was not found")
					return
				}
				if s.writeDesignReviewMutationError(w, err) {
					return
				}
				s.writeError(w, http.StatusInternalServerError, "create_design_threat_failed", "design threat could not be created")
				return
			}
			s.writeJSON(w, http.StatusCreated, item)
		default:
			s.writeMethodNotAllowed(w)
		}
		return
	}

	if len(tail) == 1 && r.Method == http.MethodPut {
		threatID := strings.TrimSpace(tail[0])
		if threatID == "" {
			s.writeError(w, http.StatusNotFound, "design_threat_not_found", "design threat was not found")
			return
		}

		defer r.Body.Close()
		var request models.UpdateDesignThreatRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		item, found, err := s.store.UpdateDesignThreatForTenant(r.Context(), principal.OrganizationID, reviewID, threatID, principal.Email, request)
		if err != nil {
			if s.writeDesignReviewMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "update_design_threat_failed", "design threat could not be updated")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "design_threat_not_found", "design threat was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
		return
	}

	s.writeError(w, http.StatusNotFound, "design_threat_route_not_found", "the requested design threat route was not found")
}

func (s *Server) handleDesignDataFlowRoute(w http.ResponseWriter, r *http.Request, principal models.AuthPrincipal, reviewID string, tail []string) {
	if len(tail) != 0 {
		s.writeError(w, http.StatusNotFound, "design_data_flow_route_not_found", "the requested design data flow route was not found")
		return
	}

	switch r.Method {
	case http.MethodGet:
		item, found, err := s.store.GetDesignDataFlowForTenant(r.Context(), principal.OrganizationID, reviewID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "get_design_data_flow_failed", "design data flow could not be loaded")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "design_data_flow_not_found", "design data flow model was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
	case http.MethodPut:
		defer r.Body.Close()

		var request models.UpsertDesignDataFlowRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		item, err := s.store.UpsertDesignDataFlowForTenant(r.Context(), principal.OrganizationID, reviewID, principal.Email, request)
		if err != nil {
			if errors.Is(err, jobs.ErrDesignReviewNotFound) {
				s.writeError(w, http.StatusNotFound, "design_review_not_found", "design review was not found")
				return
			}
			if s.writeDesignReviewMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "upsert_design_data_flow_failed", "design data flow model could not be saved")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleDesignControlMappingRoute(w http.ResponseWriter, r *http.Request, principal models.AuthPrincipal, reviewID string, tail []string) {
	if len(tail) == 0 {
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
			items, err := s.store.ListDesignControlMappingsForTenant(r.Context(), principal.OrganizationID, reviewID, strings.TrimSpace(r.URL.Query().Get("framework")), limit)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "list_design_control_mappings_failed", "design control mappings could not be loaded")
				return
			}
			s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
		case http.MethodPost:
			defer r.Body.Close()

			var request models.CreateDesignControlMappingRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}
			if strings.TrimSpace(request.Framework) == "" || strings.TrimSpace(request.ControlID) == "" {
				s.writeError(w, http.StatusBadRequest, "validation_error", "framework and control_id are required")
				return
			}
			item, err := s.store.CreateDesignControlMappingForTenant(r.Context(), principal.OrganizationID, reviewID, principal.Email, request)
			if err != nil {
				if errors.Is(err, jobs.ErrDesignReviewNotFound) {
					s.writeError(w, http.StatusNotFound, "design_review_not_found", "design review was not found")
					return
				}
				if errors.Is(err, jobs.ErrDesignThreatNotFound) {
					s.writeError(w, http.StatusNotFound, "design_threat_not_found", "design threat was not found")
					return
				}
				if s.writeDesignReviewMutationError(w, err) {
					return
				}
				s.writeError(w, http.StatusInternalServerError, "create_design_control_mapping_failed", "design control mapping could not be created")
				return
			}
			s.writeJSON(w, http.StatusCreated, item)
		default:
			s.writeMethodNotAllowed(w)
		}
		return
	}

	if len(tail) == 1 && r.Method == http.MethodPut {
		mappingID := strings.TrimSpace(tail[0])
		if mappingID == "" {
			s.writeError(w, http.StatusNotFound, "design_control_mapping_not_found", "design control mapping was not found")
			return
		}
		defer r.Body.Close()

		var request models.UpdateDesignControlMappingRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		item, found, err := s.store.UpdateDesignControlMappingForTenant(r.Context(), principal.OrganizationID, reviewID, mappingID, principal.Email, request)
		if err != nil {
			if errors.Is(err, jobs.ErrDesignThreatNotFound) {
				s.writeError(w, http.StatusNotFound, "design_threat_not_found", "design threat was not found")
				return
			}
			if s.writeDesignReviewMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "update_design_control_mapping_failed", "design control mapping could not be updated")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "design_control_mapping_not_found", "design control mapping was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
		return
	}

	s.writeError(w, http.StatusNotFound, "design_control_mapping_route_not_found", "the requested design control mapping route was not found")
}

func (s *Server) writeDesignReviewMutationError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(lower, "is required"):
		s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
		return true
	case strings.Contains(lower, "must be"),
		strings.Contains(lower, "cannot"),
		strings.Contains(lower, "transition"):
		s.writeError(w, http.StatusConflict, "design_review_state_invalid", err.Error())
		return true
	case strings.Contains(lower, "duplicate key"),
		strings.Contains(lower, "already exists"),
		strings.Contains(lower, "unique"):
		s.writeError(w, http.StatusConflict, "design_review_conflict", "a conflicting design review resource already exists")
		return true
	default:
		return false
	}
}
