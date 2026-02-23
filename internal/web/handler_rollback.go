// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	rollbacksvc "github.com/fr4nsys/usulnet/internal/services/rollback"
	rbtpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/rollback"
)

// requireRollbackSvc returns the rollback service or renders a "not configured" error.
func (h *Handler) requireRollbackSvc(w http.ResponseWriter, r *http.Request) *rollbacksvc.Service {
	svc := h.services.Rollback()
	if svc == nil {
		h.RenderErrorTempl(w, r, http.StatusServiceUnavailable, "Rollback Not Configured", "The rollback service is not enabled.")
		return nil
	}
	return svc
}

// getRBHostID resolves the active host ID for rollback operations.
func (h *Handler) getRBHostID(r *http.Request) uuid.UUID {
	if reg, ok := h.services.(*ServiceRegistry); ok {
		return resolveHostID(r.Context(), reg.defaultHostID)
	}
	return uuid.Nil
}

// ============================================================================
// Execution List
// ============================================================================

// RollbackListTempl renders the rollback executions list page.
func (h *Handler) RollbackListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getRBHostID(r)
	pageData := h.prepareTemplPageData(r, "Automated Rollback", "rollback")

	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	pageSize := 50
	offset := (page - 1) * pageSize

	executions, total, err := svc.ListExecutions(ctx, hostID, pageSize, offset)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load rollback history: "+err.Error())
		return
	}

	stats, _ := svc.GetStats(ctx, hostID)

	var views []rbtpl.ExecutionView
	for _, e := range executions {
		views = append(views, executionToView(e))
	}

	statsView := rbtpl.StatsView{}
	if stats != nil {
		statsView.TotalRollbacks = stats.TotalRollbacks
		statsView.Successful = stats.Successful
		statsView.Failed = stats.Failed
		statsView.AutoTriggered = stats.AutoTriggered
		statsView.ManualTriggers = stats.ManualTriggers
	}

	data := rbtpl.ListData{
		PageData:   pageData,
		Executions: views,
		Stats:      statsView,
		Total:      total,
		Page:       page,
		PageSize:   pageSize,
	}

	h.renderTempl(w, r, rbtpl.List(data))
}

// ============================================================================
// Execution Detail
// ============================================================================

// RollbackDetailTempl renders a rollback execution detail page.
func (h *Handler) RollbackDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}

	execID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The execution ID is not valid.")
		return
	}

	e, err := svc.GetExecution(r.Context(), execID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "The requested rollback execution was not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Rollback Detail", "rollback")

	data := rbtpl.DetailData{
		PageData:  pageData,
		Execution: executionToView(*e),
	}

	h.renderTempl(w, r, rbtpl.Detail(data))
}

// ============================================================================
// Manual Rollback
// ============================================================================

// RollbackExecuteTempl handles POST /rollback/{stackID}/execute — triggers a manual rollback.
func (h *Handler) RollbackExecuteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}

	stackID, err := uuid.Parse(chi.URLParam(r, "stackID"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The stack ID is not valid.")
		return
	}

	userID := h.getUserUUID(r)

	if _, err := svc.ExecuteRollback(r.Context(), stackID, models.RollbackTriggerManual, userID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Rollback Failed", "Failed to execute rollback: "+err.Error())
		return
	}

	http.Redirect(w, r, "/rollback", http.StatusSeeOther)
}

// ============================================================================
// Policies
// ============================================================================

// RollbackPolicyListTempl renders the rollback policies page.
func (h *Handler) RollbackPolicyListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getRBHostID(r)
	pageData := h.prepareTemplPageData(r, "Rollback Policies", "rollback")

	policies, err := svc.ListPolicies(ctx, hostID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load policies: "+err.Error())
		return
	}

	var views []rbtpl.PolicyView
	for _, p := range policies {
		views = append(views, policyToView(p))
	}

	data := rbtpl.PolicyListData{
		PageData: pageData,
		Policies: views,
	}

	h.renderTempl(w, r, rbtpl.PolicyList(data))
}

// RollbackPolicyNewTempl renders the new policy form.
func (h *Handler) RollbackPolicyNewTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}
	pageData := h.prepareTemplPageData(r, "New Rollback Policy", "rollback")
	h.renderTempl(w, r, rbtpl.PolicyNew(rbtpl.PolicyNewData{PageData: pageData}))
}

// RollbackPolicyCreateTempl handles POST /rollback/policies.
func (h *Handler) RollbackPolicyCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	hostID := h.getRBHostID(r)

	stackID, err := uuid.Parse(r.FormValue("stack_id"))
	if err != nil {
		pageData := h.prepareTemplPageData(r, "New Rollback Policy", "rollback")
		h.renderTempl(w, r, rbtpl.PolicyNew(rbtpl.PolicyNewData{
			PageData: pageData,
			Error:    "Please select a stack.",
		}))
		return
	}

	triggerOn := r.FormValue("trigger_on")
	healthCheckURL := r.FormValue("health_check_url")
	maxRetries := 3
	if mr := r.FormValue("max_retries"); mr != "" {
		if v, err := strconv.Atoi(mr); err == nil && v > 0 {
			maxRetries = v
		}
	}
	cooldownMinutes := 5
	if cd := r.FormValue("cooldown_minutes"); cd != "" {
		if v, err := strconv.Atoi(cd); err == nil && v > 0 {
			cooldownMinutes = v
		}
	}

	userID := h.getUserUUID(r)

	if _, err := svc.CreatePolicy(r.Context(), hostID, stackID, triggerOn, healthCheckURL, maxRetries, cooldownMinutes, userID); err != nil {
		pageData := h.prepareTemplPageData(r, "New Rollback Policy", "rollback")
		h.renderTempl(w, r, rbtpl.PolicyNew(rbtpl.PolicyNewData{
			PageData: pageData,
			Error:    "Failed to create policy: " + err.Error(),
		}))
		return
	}

	http.Redirect(w, r, "/rollback/policies", http.StatusSeeOther)
}

// RollbackPolicyEditTempl renders the edit policy form.
func (h *Handler) RollbackPolicyEditTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}

	policyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The policy ID is not valid.")
		return
	}

	p, err := svc.GetPolicy(r.Context(), policyID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "The requested policy was not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Edit Rollback Policy", "rollback")

	data := rbtpl.PolicyEditData{
		PageData: pageData,
		Policy:   policyToView(*p),
	}

	h.renderTempl(w, r, rbtpl.PolicyEdit(data))
}

// RollbackPolicyUpdateTempl handles POST /rollback/policies/{id}.
func (h *Handler) RollbackPolicyUpdateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	policyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The policy ID is not valid.")
		return
	}

	enabled := r.FormValue("enabled") == "true"
	triggerOn := r.FormValue("trigger_on")
	healthCheckURL := r.FormValue("health_check_url")
	maxRetries := 3
	if mr := r.FormValue("max_retries"); mr != "" {
		if v, err := strconv.Atoi(mr); err == nil && v > 0 {
			maxRetries = v
		}
	}
	cooldownMinutes := 5
	if cd := r.FormValue("cooldown_minutes"); cd != "" {
		if v, err := strconv.Atoi(cd); err == nil && v > 0 {
			cooldownMinutes = v
		}
	}

	if err := svc.UpdatePolicy(r.Context(), policyID, enabled, triggerOn, healthCheckURL, maxRetries, cooldownMinutes); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to update policy: "+err.Error())
		return
	}

	http.Redirect(w, r, "/rollback/policies", http.StatusSeeOther)
}

// RollbackPolicyDeleteTempl handles DELETE /rollback/policies/{id}.
func (h *Handler) RollbackPolicyDeleteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireRollbackSvc(w, r)
	if svc == nil {
		return
	}

	policyID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if err := svc.DeletePolicy(r.Context(), policyID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to delete policy: "+err.Error())
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/rollback/policies")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/rollback/policies", http.StatusSeeOther)
}

// ============================================================================
// Helpers
// ============================================================================

func executionToView(e models.RollbackExecution) rbtpl.ExecutionView {
	view := rbtpl.ExecutionView{
		ID:            e.ID.String(),
		StackID:       e.StackID.String(),
		StackName:     e.StackID.String()[:8],
		TriggerReason: string(e.TriggerReason),
		FromVersion:   e.FromVersion,
		ToVersion:     e.ToVersion,
		Status:        string(e.Status),
		Output:        e.Output,
		ErrorMessage:  e.ErrorMessage,
		DurationMs:    e.DurationMs,
		CreatedAt:     e.CreatedAt.Format("2006-01-02 15:04"),
	}
	if e.CompletedAt != nil {
		view.CompletedAt = e.CompletedAt.Format("2006-01-02 15:04")
	}
	return view
}

func policyToView(p models.RollbackPolicy) rbtpl.PolicyView {
	return rbtpl.PolicyView{
		ID:                  p.ID.String(),
		StackID:             p.StackID.String(),
		StackName:           p.StackID.String()[:8],
		Enabled:             p.Enabled,
		TriggerOn:           string(p.TriggerOn),
		HealthCheckURL:      p.HealthCheckURL,
		HealthCheckInterval: p.HealthCheckInterval,
		HealthCheckTimeout:  p.HealthCheckTimeout,
		MaxRetries:          p.MaxRetries,
		CooldownMinutes:     p.CooldownMinutes,
		NotifyOnRollback:    p.NotifyOnRollback,
		CreatedAt:           p.CreatedAt.Format("2006-01-02 15:04"),
	}
}
