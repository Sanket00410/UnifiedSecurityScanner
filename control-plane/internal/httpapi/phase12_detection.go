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

func (s *Server) handleDetectionRulepacks(w http.ResponseWriter, r *http.Request) {
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
		items, err := s.store.ListDetectionRulepacksForTenant(
			r.Context(),
			principal.OrganizationID,
			strings.TrimSpace(r.URL.Query().Get("engine")),
			strings.TrimSpace(r.URL.Query().Get("status")),
			limit,
		)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_detection_rulepacks_failed", "detection rulepacks could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateDetectionRulepackRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		if strings.TrimSpace(request.Name) == "" || strings.TrimSpace(request.Engine) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "name and engine are required")
			return
		}

		item, err := s.store.CreateDetectionRulepackForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
		if err != nil {
			if s.writeDetectionMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "create_detection_rulepack_failed", "detection rulepack could not be created")
			return
		}
		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleDetectionRulepackRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/detection/rulepacks/"))
	parts := strings.Split(path, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "detection_rulepack_route_not_found", "the requested detection rulepack route was not found")
		return
	}
	rulepackID := strings.TrimSpace(parts[0])

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			item, found, err := s.store.GetDetectionRulepackForTenant(r.Context(), principal.OrganizationID, rulepackID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "get_detection_rulepack_failed", "detection rulepack could not be loaded")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "detection_rulepack_not_found", "detection rulepack was not found")
				return
			}
			s.writeJSON(w, http.StatusOK, item)
		case http.MethodPut:
			defer r.Body.Close()
			var request models.UpdateDetectionRulepackRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}
			item, found, err := s.store.UpdateDetectionRulepackForTenant(r.Context(), principal.OrganizationID, rulepackID, principal.Email, request)
			if err != nil {
				if s.writeDetectionMutationError(w, err) {
					return
				}
				s.writeError(w, http.StatusInternalServerError, "update_detection_rulepack_failed", "detection rulepack could not be updated")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "detection_rulepack_not_found", "detection rulepack was not found")
				return
			}
			s.writeJSON(w, http.StatusOK, item)
		default:
			s.writeMethodNotAllowed(w)
		}
		return
	}

	segment := strings.TrimSpace(parts[1])
	switch segment {
	case "versions":
		s.handleDetectionRulepackVersionsRoute(w, r, principal, rulepackID, parts[2:])
	case "rollouts":
		s.handleDetectionRulepackRolloutsRoute(w, r, principal, rulepackID, parts[2:])
	default:
		s.writeError(w, http.StatusNotFound, "detection_rulepack_route_not_found", "the requested detection rulepack route was not found")
	}
}

func (s *Server) handleDetectionRulepackVersionsRoute(w http.ResponseWriter, r *http.Request, principal models.AuthPrincipal, rulepackID string, tail []string) {
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
			items, err := s.store.ListDetectionRulepackVersionsForTenant(r.Context(), principal.OrganizationID, rulepackID, limit)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "list_detection_rulepack_versions_failed", "detection rulepack versions could not be loaded")
				return
			}
			s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
		case http.MethodPost:
			defer r.Body.Close()
			var request models.CreateDetectionRulepackVersionRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}
			if strings.TrimSpace(request.VersionTag) == "" {
				s.writeError(w, http.StatusBadRequest, "validation_error", "version_tag is required")
				return
			}
			item, err := s.store.CreateDetectionRulepackVersionForTenant(r.Context(), principal.OrganizationID, rulepackID, principal.Email, request)
			if err != nil {
				if errors.Is(err, jobs.ErrDetectionRulepackNotFound) {
					s.writeError(w, http.StatusNotFound, "detection_rulepack_not_found", "detection rulepack was not found")
					return
				}
				if s.writeDetectionMutationError(w, err) {
					return
				}
				s.writeError(w, http.StatusInternalServerError, "create_detection_rulepack_version_failed", "detection rulepack version could not be created")
				return
			}
			s.writeJSON(w, http.StatusCreated, item)
		default:
			s.writeMethodNotAllowed(w)
		}
		return
	}

	if len(tail) == 2 && r.Method == http.MethodPost && strings.EqualFold(strings.TrimSpace(tail[1]), "promote") {
		versionID := strings.TrimSpace(tail[0])
		if versionID == "" {
			s.writeError(w, http.StatusNotFound, "detection_rulepack_version_not_found", "detection rulepack version was not found")
			return
		}

		defer r.Body.Close()
		var request models.PromoteDetectionRulepackVersionRequest
		_ = json.NewDecoder(r.Body).Decode(&request)

		item, found, err := s.store.PromoteDetectionRulepackVersionForTenant(r.Context(), principal.OrganizationID, rulepackID, versionID, principal.Email, request)
		if err != nil {
			if s.writeDetectionMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "promote_detection_rulepack_version_failed", "detection rulepack version promotion failed")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "detection_rulepack_version_not_found", "detection rulepack version was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
		return
	}

	s.writeError(w, http.StatusNotFound, "detection_rulepack_versions_route_not_found", "the requested detection rulepack versions route was not found")
}

func (s *Server) handleDetectionRulepackRolloutsRoute(w http.ResponseWriter, r *http.Request, principal models.AuthPrincipal, rulepackID string, tail []string) {
	if len(tail) != 0 {
		s.writeError(w, http.StatusNotFound, "detection_rulepack_rollouts_route_not_found", "the requested detection rulepack rollouts route was not found")
		return
	}
	if r.Method != http.MethodGet {
		s.writeMethodNotAllowed(w)
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

	items, err := s.store.ListDetectionRulepackRolloutsForTenant(r.Context(), principal.OrganizationID, rulepackID, limit)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "list_detection_rulepack_rollouts_failed", "detection rulepack rollouts could not be loaded")
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) writeDetectionMutationError(w http.ResponseWriter, err error) bool {
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
		s.writeError(w, http.StatusConflict, "detection_rulepack_conflict", "a conflicting detection rulepack resource already exists")
		return true
	default:
		return false
	}
}
