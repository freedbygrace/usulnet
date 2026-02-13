// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// ============================================================================
// Compliance Frameworks
// ============================================================================

// ComplianceFrameworksTempl returns the list of compliance frameworks as JSON.
func (h *Handler) ComplianceFrameworksTempl(w http.ResponseWriter, r *http.Request) {
	if h.complianceFrameworkSvc == nil {
		http.Error(w, "Compliance frameworks not configured", http.StatusServiceUnavailable)
		return
	}

	frameworks, err := h.complianceFrameworkSvc.ListFrameworks(r.Context())
	if err != nil {
		http.Error(w, "Failed to list frameworks: "+err.Error(), http.StatusInternalServerError)
		return
	}

	type frameworkView struct {
		ID          string  `json:"id"`
		Name        string  `json:"name"`
		DisplayName string  `json:"display_name"`
		Description string  `json:"description"`
		Version     string  `json:"version"`
		IsEnabled   bool    `json:"is_enabled"`
		Score       float64 `json:"score"`
		Controls    int     `json:"controls"`
	}

	views := make([]frameworkView, 0, len(frameworks))
	for _, f := range frameworks {
		views = append(views, frameworkView{
			ID:          f.ID.String(),
			Name:        f.Name,
			DisplayName: f.DisplayName,
			Description: f.Description,
			Version:     f.Version,
			IsEnabled:   f.IsEnabled,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(views) //nolint:errcheck
}

// ComplianceFrameworkAssess runs an assessment for a framework.
func (h *Handler) ComplianceFrameworkAssess(w http.ResponseWriter, r *http.Request) {
	if h.complianceFrameworkSvc == nil {
		http.Error(w, "Compliance frameworks not configured", http.StatusServiceUnavailable)
		return
	}

	frameworkID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid framework ID", http.StatusBadRequest)
		return
	}

	userID := h.getUserID(r)
	assessment, err := h.complianceFrameworkSvc.RunAssessment(r.Context(), frameworkID, userID)
	if err != nil {
		http.Error(w, "Assessment failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(assessment) //nolint:errcheck
}

// ComplianceFrameworkReport generates a compliance report.
func (h *Handler) ComplianceFrameworkReport(w http.ResponseWriter, r *http.Request) {
	if h.complianceFrameworkSvc == nil {
		http.Error(w, "Compliance frameworks not configured", http.StatusServiceUnavailable)
		return
	}

	assessmentID, err := uuid.Parse(chi.URLParam(r, "assessmentId"))
	if err != nil {
		http.Error(w, "Invalid assessment ID", http.StatusBadRequest)
		return
	}

	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	data, err := h.complianceFrameworkSvc.GenerateReport(r.Context(), assessmentID, format)
	if err != nil {
		http.Error(w, "Report generation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	switch format {
	case "html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	default:
		w.Header().Set("Content-Type", "application/json")
	}
	w.Write(data) //nolint:errcheck
}

// ComplianceFrameworkSeed seeds default frameworks.
func (h *Handler) ComplianceFrameworkSeed(w http.ResponseWriter, r *http.Request) {
	if h.complianceFrameworkSvc == nil {
		http.Error(w, "Compliance frameworks not configured", http.StatusServiceUnavailable)
		return
	}

	if err := h.complianceFrameworkSvc.SeedFrameworks(r.Context()); err != nil {
		http.Error(w, "Failed to seed frameworks: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Frameworks seeded successfully"}) //nolint:errcheck
}

// ============================================================================
// OPA Policies
// ============================================================================

// OPAPoliciesJSON returns OPA policies as JSON.
func (h *Handler) OPAPoliciesJSON(w http.ResponseWriter, r *http.Request) {
	if h.opaSvc == nil {
		http.Error(w, "OPA policy engine not configured", http.StatusServiceUnavailable)
		return
	}

	category := r.URL.Query().Get("category")
	policies, err := h.opaSvc.ListPolicies(r.Context(), category)
	if err != nil {
		http.Error(w, "Failed to list policies: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policies) //nolint:errcheck
}

// OPAPolicyEvaluateContainer evaluates OPA policies against a container.
func (h *Handler) OPAPolicyEvaluateContainer(w http.ResponseWriter, r *http.Request) {
	if h.opaSvc == nil {
		http.Error(w, "OPA policy engine not configured", http.StatusServiceUnavailable)
		return
	}

	containerID := chi.URLParam(r, "id")
	if containerID == "" {
		http.Error(w, "Container ID required", http.StatusBadRequest)
		return
	}

	container, err := h.services.Containers().Get(r.Context(), containerID)
	if err != nil {
		http.Error(w, "Failed to get container: "+err.Error(), http.StatusInternalServerError)
		return
	}

	inputData := map[string]interface{}{
		"id":    container.ID,
		"name":  container.Name,
		"image": container.Image,
		"state": container.State,
	}

	results, err := h.opaSvc.EvaluateContainer(r.Context(), inputData)
	if err != nil {
		http.Error(w, "Policy evaluation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results) //nolint:errcheck
}

// OPAPolicySeed seeds default OPA policies.
func (h *Handler) OPAPolicySeed(w http.ResponseWriter, r *http.Request) {
	if h.opaSvc == nil {
		http.Error(w, "OPA policy engine not configured", http.StatusServiceUnavailable)
		return
	}

	if err := h.opaSvc.SeedDefaultPolicies(r.Context()); err != nil {
		http.Error(w, "Failed to seed OPA policies: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "OPA policies seeded"}) //nolint:errcheck
}

// ============================================================================
// Log Aggregation & Search
// ============================================================================

// LogSearchJSON handles log search requests.
func (h *Handler) LogSearchJSON(w http.ResponseWriter, r *http.Request) {
	if h.logAggSvc == nil {
		http.Error(w, "Log aggregation not configured", http.StatusServiceUnavailable)
		return
	}

	query := r.URL.Query().Get("q")
	containerID := r.URL.Query().Get("container_id")
	source := r.URL.Query().Get("source")
	severity := r.URL.Query().Get("severity")
	limitStr := r.URL.Query().Get("limit")

	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	opts := models.AggregatedLogSearchOptions{
		Query:       query,
		ContainerID: containerID,
		Source:      source,
		Severity:    severity,
		Limit:       limit,
	}

	logs, total, err := h.logAggSvc.Search(r.Context(), opts)
	if err != nil {
		http.Error(w, "Log search failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"logs":  logs,
		"total": total,
	}) //nolint:errcheck
}

// LogStatsJSON returns log aggregation statistics.
func (h *Handler) LogStatsJSON(w http.ResponseWriter, r *http.Request) {
	if h.logAggSvc == nil {
		http.Error(w, "Log aggregation not configured", http.StatusServiceUnavailable)
		return
	}

	since := time.Now().Add(-24 * time.Hour)
	if s := r.URL.Query().Get("since"); s != "" {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			since = t
		}
	}

	stats, err := h.logAggSvc.GetStats(r.Context(), since)
	if err != nil {
		http.Error(w, "Failed to get log stats: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats) //nolint:errcheck
}

// ============================================================================
// Image Signing & Verification
// ============================================================================

// ImageSignaturesJSON returns signatures for an image.
func (h *Handler) ImageSignaturesJSON(w http.ResponseWriter, r *http.Request) {
	if h.imageSignSvc == nil {
		http.Error(w, "Image signing not configured", http.StatusServiceUnavailable)
		return
	}

	imageRef := r.URL.Query().Get("image")
	if imageRef == "" {
		http.Error(w, "image parameter required", http.StatusBadRequest)
		return
	}

	sigs, err := h.imageSignSvc.GetImageSignatures(r.Context(), imageRef)
	if err != nil {
		http.Error(w, "Failed to get signatures: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(sigs) //nolint:errcheck
}

// ImageVerifyJSON verifies an image's signatures against trust policies.
func (h *Handler) ImageVerifyJSON(w http.ResponseWriter, r *http.Request) {
	if h.imageSignSvc == nil {
		http.Error(w, "Image signing not configured", http.StatusServiceUnavailable)
		return
	}

	imageRef := r.URL.Query().Get("image")
	if imageRef == "" {
		http.Error(w, "image parameter required", http.StatusBadRequest)
		return
	}

	result, err := h.imageSignSvc.VerifyImageAgainstPolicies(r.Context(), imageRef)
	if err != nil {
		http.Error(w, "Verification failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result) //nolint:errcheck
}

// ImageTrustPoliciesJSON lists trust policies.
func (h *Handler) ImageTrustPoliciesJSON(w http.ResponseWriter, r *http.Request) {
	if h.imageSignSvc == nil {
		http.Error(w, "Image signing not configured", http.StatusServiceUnavailable)
		return
	}

	policies, err := h.imageSignSvc.ListTrustPolicies(r.Context())
	if err != nil {
		http.Error(w, "Failed to list trust policies: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(policies) //nolint:errcheck
}

// ImageSignSeed seeds default trust policies.
func (h *Handler) ImageSignSeed(w http.ResponseWriter, r *http.Request) {
	if h.imageSignSvc == nil {
		http.Error(w, "Image signing not configured", http.StatusServiceUnavailable)
		return
	}

	if err := h.imageSignSvc.SeedDefaultPolicies(r.Context()); err != nil {
		http.Error(w, "Failed to seed trust policies: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Trust policies seeded"}) //nolint:errcheck
}

// ============================================================================
// Runtime Threat Detection
// ============================================================================

// RuntimeEventsJSON lists runtime security events.
func (h *Handler) RuntimeEventsJSON(w http.ResponseWriter, r *http.Request) {
	if h.runtimeSecSvc == nil {
		http.Error(w, "Runtime security not configured", http.StatusServiceUnavailable)
		return
	}

	containerID := r.URL.Query().Get("container_id")
	severity := r.URL.Query().Get("severity")
	eventType := r.URL.Query().Get("event_type")
	limitStr := r.URL.Query().Get("limit")

	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 1000 {
			limit = l
		}
	}

	events, total, err := h.runtimeSecSvc.ListEvents(r.Context(), postgres.RuntimeEventListOptions{
		ContainerID: containerID,
		Severity:    severity,
		EventType:   eventType,
		Limit:       limit,
	})
	if err != nil {
		http.Error(w, "Failed to list events: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"total":  total,
	}) //nolint:errcheck
}

// RuntimeDashboardJSON returns the runtime security dashboard data.
func (h *Handler) RuntimeDashboardJSON(w http.ResponseWriter, r *http.Request) {
	if h.runtimeSecSvc == nil {
		http.Error(w, "Runtime security not configured", http.StatusServiceUnavailable)
		return
	}

	dashboard, err := h.runtimeSecSvc.GetDashboardData(r.Context())
	if err != nil {
		http.Error(w, "Failed to get dashboard: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(dashboard) //nolint:errcheck
}

// RuntimeRulesJSON lists runtime detection rules.
func (h *Handler) RuntimeRulesJSON(w http.ResponseWriter, r *http.Request) {
	if h.runtimeSecSvc == nil {
		http.Error(w, "Runtime security not configured", http.StatusServiceUnavailable)
		return
	}

	rules, err := h.runtimeSecSvc.ListRules(r.Context())
	if err != nil {
		http.Error(w, "Failed to list rules: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(rules) //nolint:errcheck
}

// RuntimeEventAcknowledge acknowledges a runtime event.
func (h *Handler) RuntimeEventAcknowledge(w http.ResponseWriter, r *http.Request) {
	if h.runtimeSecSvc == nil {
		http.Error(w, "Runtime security not configured", http.StatusServiceUnavailable)
		return
	}

	eventIDStr := chi.URLParam(r, "id")
	eventID, err := strconv.ParseInt(eventIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid event ID", http.StatusBadRequest)
		return
	}

	userID := h.getUserID(r)
	if userID == nil {
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return
	}

	if err := h.runtimeSecSvc.AcknowledgeEvent(r.Context(), eventID, *userID); err != nil {
		http.Error(w, "Failed to acknowledge event: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"}) //nolint:errcheck
}

// RuntimeSeedRules seeds default detection rules.
func (h *Handler) RuntimeSeedRules(w http.ResponseWriter, r *http.Request) {
	if h.runtimeSecSvc == nil {
		http.Error(w, "Runtime security not configured", http.StatusServiceUnavailable)
		return
	}

	if err := h.runtimeSecSvc.SeedDefaultRules(r.Context()); err != nil {
		http.Error(w, "Failed to seed rules: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Runtime rules seeded"}) //nolint:errcheck
}

// RuntimeMonitorAll triggers runtime monitoring for all containers.
func (h *Handler) RuntimeMonitorAll(w http.ResponseWriter, r *http.Request) {
	if h.runtimeSecSvc == nil {
		http.Error(w, "Runtime security not configured", http.StatusServiceUnavailable)
		return
	}

	hostID := h.services.Containers().GetHostID()
	if err := h.runtimeSecSvc.MonitorAllContainers(r.Context(), hostID); err != nil {
		http.Error(w, "Monitoring failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Monitoring completed"}) //nolint:errcheck
}

// ============================================================================
// Dashboard Layouts
// ============================================================================

// DashboardLayoutsJSON returns the user's dashboard layouts.
func (h *Handler) DashboardLayoutsJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"layouts": []interface{}{},
		"message": "Dashboard layout system initialized",
	}) //nolint:errcheck
}

// ============================================================================
// Helper: getUserID extracts the user UUID from the request context.
// ============================================================================

func (h *Handler) getUserID(r *http.Request) *uuid.UUID {
	user := GetUserFromContext(r.Context())
	if user == nil || user.ID == "" {
		return nil
	}
	id, err := uuid.Parse(user.ID)
	if err != nil {
		return nil
	}
	return &id
}
