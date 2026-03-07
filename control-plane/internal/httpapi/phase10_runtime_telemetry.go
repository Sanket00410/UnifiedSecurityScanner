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

func (s *Server) handleRuntimeTelemetryConnectors(w http.ResponseWriter, r *http.Request) {
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
		items, err := s.store.ListRuntimeTelemetryConnectorsForTenant(r.Context(), principal.OrganizationID, strings.TrimSpace(r.URL.Query().Get("connector_type")), limit)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_runtime_telemetry_connectors_failed", "runtime telemetry connectors could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.CreateRuntimeTelemetryConnectorRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		if strings.TrimSpace(request.Name) == "" || strings.TrimSpace(request.ConnectorType) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "name and connector_type are required")
			return
		}

		item, err := s.store.CreateRuntimeTelemetryConnectorForTenant(r.Context(), principal.OrganizationID, principal.Email, request)
		if err != nil {
			if s.writeRuntimeTelemetryMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "create_runtime_telemetry_connector_failed", "runtime telemetry connector could not be created")
			return
		}
		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleRuntimeTelemetryConnectorRoute(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	connectorID := strings.TrimSpace(strings.TrimPrefix(r.URL.Path, "/v1/runtime/telemetry/connectors/"))
	if connectorID == "" {
		s.writeError(w, http.StatusNotFound, "runtime_telemetry_connector_not_found", "runtime telemetry connector was not found")
		return
	}

	switch r.Method {
	case http.MethodGet:
		item, found, err := s.store.GetRuntimeTelemetryConnectorForTenant(r.Context(), principal.OrganizationID, connectorID)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "get_runtime_telemetry_connector_failed", "runtime telemetry connector could not be loaded")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "runtime_telemetry_connector_not_found", "runtime telemetry connector was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
	case http.MethodPut:
		defer r.Body.Close()

		var request models.UpdateRuntimeTelemetryConnectorRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}

		item, found, err := s.store.UpdateRuntimeTelemetryConnectorForTenant(r.Context(), principal.OrganizationID, connectorID, principal.Email, request)
		if err != nil {
			if s.writeRuntimeTelemetryMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "update_runtime_telemetry_connector_failed", "runtime telemetry connector could not be updated")
			return
		}
		if !found {
			s.writeError(w, http.StatusNotFound, "runtime_telemetry_connector_not_found", "runtime telemetry connector was not found")
			return
		}
		s.writeJSON(w, http.StatusOK, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) handleRuntimeTelemetryEvents(w http.ResponseWriter, r *http.Request) {
	principal, ok := auth.PrincipalFromContext(r.Context())
	if !ok {
		s.writeError(w, http.StatusUnauthorized, "unauthorized", "authentication is required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		query := models.RuntimeTelemetryEventQuery{
			ConnectorID: strings.TrimSpace(r.URL.Query().Get("connector_id")),
			EventType:   strings.TrimSpace(r.URL.Query().Get("event_type")),
			AssetID:     strings.TrimSpace(r.URL.Query().Get("asset_id")),
			FindingID:   strings.TrimSpace(r.URL.Query().Get("finding_id")),
			Limit:       200,
		}
		if rawLimit := strings.TrimSpace(r.URL.Query().Get("limit")); rawLimit != "" {
			parsed, err := strconv.Atoi(rawLimit)
			if err != nil || parsed <= 0 {
				s.writeError(w, http.StatusBadRequest, "validation_error", "limit must be a positive integer")
				return
			}
			query.Limit = parsed
		}

		items, err := s.store.ListRuntimeTelemetryEventsForTenant(r.Context(), principal.OrganizationID, query)
		if err != nil {
			s.writeError(w, http.StatusInternalServerError, "list_runtime_telemetry_events_failed", "runtime telemetry events could not be loaded")
			return
		}
		s.writeJSON(w, http.StatusOK, map[string]any{"items": items})
	case http.MethodPost:
		defer r.Body.Close()

		var request models.IngestRuntimeTelemetryEventRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			s.writeError(w, http.StatusBadRequest, "invalid_json", "request body must be valid JSON")
			return
		}
		if strings.TrimSpace(request.EventType) == "" {
			s.writeError(w, http.StatusBadRequest, "validation_error", "event_type is required")
			return
		}

		item, err := s.store.IngestRuntimeTelemetryEventForTenant(r.Context(), principal.OrganizationID, request)
		if err != nil {
			if errors.Is(err, jobs.ErrTelemetryConnectorNotFound) {
				s.writeError(w, http.StatusBadRequest, "runtime_telemetry_connector_not_found", "runtime telemetry connector was not found")
				return
			}
			if s.writeRuntimeTelemetryMutationError(w, err) {
				return
			}
			s.writeError(w, http.StatusInternalServerError, "ingest_runtime_telemetry_event_failed", "runtime telemetry event could not be ingested")
			return
		}
		s.writeJSON(w, http.StatusCreated, item)
	default:
		s.writeMethodNotAllowed(w)
	}
}

func (s *Server) writeRuntimeTelemetryMutationError(w http.ResponseWriter, err error) bool {
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
		s.writeError(w, http.StatusConflict, "runtime_telemetry_conflict", "a conflicting runtime telemetry resource already exists")
		return true
	default:
		return false
	}
}
