package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"unifiedsecurityscanner/control-plane/internal/auth"
	"unifiedsecurityscanner/control-plane/internal/jobs"
	"unifiedsecurityscanner/control-plane/internal/models"
)

func (s *Server) handleWebhookIntegrations(w http.ResponseWriter, r *http.Request) {
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

		items, err := s.store.ListWebhookIntegrationsForTenant(
			r.Context(),
			principal.OrganizationID,
			strings.TrimSpace(r.URL.Query().Get("status")),
			strings.TrimSpace(r.URL.Query().Get("event_type")),
			limit,
		)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_webhook_integrations_failed", "webhook integrations could not be loaded")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateWebhookIntegrationRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		if strings.TrimSpace(request.Name) == "" || strings.TrimSpace(request.EndpointURL) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "name and endpoint_url are required")
			return
		}

		item, err := s.store.CreateWebhookIntegrationForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
		if err != nil {
			if s.writeWebhookIntegrationMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "create_webhook_integration_failed", "webhook integration could not be created")
			return
		}

		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleWebhookIntegrationRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	path := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/integrations/webhooks/"))
	parts := strings.Split(path, "/")
	if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
		s.writeError(w, http.StatusNotFound, "webhook_integration_route_not_found", "the requested webhook integration route was not found")
		return
	}
	webhookID := strings.TrimSpace(parts[0])

	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			item, found, err := s.store.GetWebhookIntegrationForTenant(r.Context(), principal.OrganizationID, webhookID)
			if err != nil {
				s.writeError(w, http.StatusInternalServerError, "get_webhook_integration_failed", "webhook integration could not be loaded")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "webhook_integration_not_found", "webhook integration was not found")
				return
			}

			s.writeJSON(w, http.StatusOK, item)
		case http.MethodPut:
			defer r.Body.Close()

			var request models.UpdateWebhookIntegrationRequest
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
				return
			}

			item, found, err := s.store.UpdateWebhookIntegrationForTenant(r.Context(), principal.OrganizationID, webhookID, principal.Email, request)
			if err != nil {
				if s.writeWebhookIntegrationMutationError(w, err) {
					return
				}
				s.writeError(w, http.StatusInternalServerError, "update_webhook_integration_failed", "webhook integration could not be updated")
				return
			}
			if !found {
				s.writeError(w, http.StatusNotFound, "webhook_integration_not_found", "webhook integration was not found")
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
	case "deliveries":
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

		items, err := s.store.ListWebhookDeliveriesForTenant(
			r.Context(),
			principal.OrganizationID,
			webhookID,
			strings.TrimSpace(r.URL.Query().Get("status")),
			limit,
		)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_webhook_deliveries_failed", "webhook deliveries could not be loaded")
			return
		}

		s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case "dispatch":
		if r.Method != http.MethodPost {
			s.writeMethodNotAllowed(w)
			return
		}

		request := models.DispatchWebhookDeliveriesRequest{WebhookID: webhookID}
		if err := decodeOptionalDispatchRequest(r, &request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		request.WebhookID = webhookID

		result, err := s.store.DispatchWebhookDeliveriesForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
		if err != nil {
			if s.writeWebhookIntegrationMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "dispatch_webhook_deliveries_failed", "webhook deliveries could not be dispatched")
			return
		}

		s.writeJSON(w, http.StatusOK, result)
	default:
		s.writeError(w, http.StatusNotFound, "webhook_integration_route_not_found", "the requested webhook integration route was not found")
	}
}

func (s *Server) handleWebhookDispatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeMethodNotAllowed(w)
		return
	}

	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	var request models.DispatchWebhookDeliveriesRequest
	if err := decodeOptionalDispatchRequest(r, &request); err != nil {
		s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
		return
	}

	result, err := s.store.DispatchWebhookDeliveriesForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
	if err != nil {
		if s.writeWebhookIntegrationMutationError(w, err) {
			return
		}
		s.writeError(w, http.StatusInternalServerError, "dispatch_webhook_deliveries_failed", "webhook deliveries could not be dispatched")
		return
	}

	s.writeJSON(w, http.StatusOK, result)
}

func decodeOptionalDispatchRequest(r *http.Request, target *models.DispatchWebhookDeliveriesRequest) error {
	if target == nil {
		return nil
	}
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(target); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	}
	return nil
}

func (s *Server) writeWebhookIntegrationMutationError(w http.ResponseWriter, err error) bool {
	if err == nil {
		return false
	}

	switch {
	case errors.Is(err, jobs.ErrWebhookIntegrationNotFound):
		s.writeError(w, http.StatusNotFound, "webhook_integration_not_found", "webhook integration was not found")
		return true
	}

	lower := strings.ToLower(strings.TrimSpace(err.Error()))
	switch {
	case strings.Contains(lower, "is required"),
		strings.Contains(lower, "must be a valid url"),
		strings.Contains(lower, "must use http or https"),
		strings.Contains(lower, "must include a host"):
		s.writeError(w, http.StatusBadRequest, "validation_error", err.Error())
		return true
	case strings.Contains(lower, "duplicate key"),
		strings.Contains(lower, "already exists"),
		strings.Contains(lower, "unique"):
		s.writeError(w, http.StatusConflict, "webhook_integration_conflict", "a conflicting webhook integration resource already exists")
		return true
	default:
		return false
	}
}
