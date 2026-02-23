// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	crontabsvc "github.com/fr4nsys/usulnet/internal/services/crontab"
	crontabtpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/crontab"
)

// requireCrontabSvc returns the crontab service or renders a "not configured" error.
func (h *Handler) requireCrontabSvc(w http.ResponseWriter, r *http.Request) *crontabsvc.Service {
	svc := h.services.Crontab()
	if svc == nil {
		h.RenderErrorTempl(w, r, http.StatusServiceUnavailable, "Crontab Not Configured", "The crontab manager is not enabled.")
		return nil
	}
	return svc
}

// getCrontabHostID resolves the active host ID for crontab operations.
func (h *Handler) getCrontabHostID(r *http.Request) uuid.UUID {
	if reg, ok := h.services.(*ServiceRegistry); ok {
		return resolveHostID(r.Context(), reg.defaultHostID)
	}
	return uuid.Nil
}

// ============================================================================
// List
// ============================================================================

// CrontabListTempl renders the crontab entries list page.
func (h *Handler) CrontabListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCrontabSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getCrontabHostID(r)
	pageData := h.prepareTemplPageData(r, "Crontab Manager", "crontab")

	entries, err := svc.List(ctx, hostID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load crontab entries: "+err.Error())
		return
	}

	stats, _ := svc.GetStats(ctx, hostID)

	var entryViews []crontabtpl.EntryView
	for _, e := range entries {
		ev := crontabtpl.EntryView{
			ID:          e.ID.String(),
			Name:        e.Name,
			Description: e.Description,
			Schedule:    e.Schedule,
			CommandType: string(e.CommandType),
			Command:     e.Command,
			Enabled:     e.Enabled,
			RunCount:    e.RunCount,
			FailCount:   e.FailCount,
			CreatedAt:   e.CreatedAt.Format("2006-01-02 15:04"),
		}
		if e.LastRunAt != nil {
			s := e.LastRunAt.Format("2006-01-02 15:04:05")
			ev.LastRunAt = &s
		}
		if e.LastRunStatus != nil {
			ev.LastRunStatus = e.LastRunStatus
		}
		if e.NextRunAt != nil {
			s := e.NextRunAt.Format("2006-01-02 15:04:05")
			ev.NextRunAt = &s
		}
		entryViews = append(entryViews, ev)
	}

	var statsView crontabtpl.StatsView
	if stats != nil {
		statsView = crontabtpl.StatsView{
			Total:    stats.Total,
			Enabled:  stats.Enabled,
			Disabled: stats.Disabled,
			Running:  stats.Running,
		}
	}

	data := crontabtpl.ListData{
		PageData: pageData,
		Entries:  entryViews,
		Stats:    statsView,
	}

	h.renderTempl(w, r, crontabtpl.List(data))
}

// ============================================================================
// Create
// ============================================================================

// CrontabNewTempl renders the new crontab entry form.
func (h *Handler) CrontabNewTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCrontabSvc(w, r)
	if svc == nil {
		return
	}
	pageData := h.prepareTemplPageData(r, "New Cron Job", "crontab")
	h.renderTempl(w, r, crontabtpl.New(crontabtpl.NewData{PageData: pageData}))
}

// CrontabCreateTempl handles POST /crontab — creates a new crontab entry.
func (h *Handler) CrontabCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCrontabSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	hostID := h.getCrontabHostID(r)
	userID := h.getUserUUID(r)

	cmdType := models.CrontabCommandType(r.FormValue("command_type"))
	if cmdType == "" {
		cmdType = models.CrontabCommandShell
	}

	input := models.CreateCrontabInput{
		Name:        r.FormValue("name"),
		Description: r.FormValue("description"),
		Schedule:    r.FormValue("schedule"),
		CommandType: cmdType,
		Command:     r.FormValue("command"),
		Enabled:     r.FormValue("enabled") == "on" || r.FormValue("enabled") == "true",
	}

	if v := r.FormValue("container_id"); v != "" {
		input.ContainerID = &v
	}
	if v := r.FormValue("working_dir"); v != "" {
		input.WorkingDir = &v
	}
	if v := r.FormValue("http_method"); v != "" {
		input.HTTPMethod = &v
	}
	if v := r.FormValue("http_url"); v != "" {
		input.HTTPURL = &v
	}

	if _, err := svc.Create(r.Context(), hostID, input, userID); err != nil {
		pageData := h.prepareTemplPageData(r, "New Cron Job", "crontab")
		h.renderTempl(w, r, crontabtpl.New(crontabtpl.NewData{
			PageData: pageData,
			Error:    "Failed to create cron job: " + err.Error(),
		}))
		return
	}

	http.Redirect(w, r, "/crontab", http.StatusSeeOther)
}

// ============================================================================
// Detail
// ============================================================================

// CrontabDetailTempl renders the crontab entry detail page with execution history.
func (h *Handler) CrontabDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCrontabSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()

	entryID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The cron job ID is not valid.")
		return
	}

	entry, err := svc.Get(ctx, entryID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "The requested cron job was not found.")
		return
	}

	executions, _ := svc.ListExecutions(ctx, entryID, 50)

	pageData := h.prepareTemplPageData(r, "Cron Job: "+entry.Name, "crontab")

	ev := crontabtpl.EntryView{
		ID:          entry.ID.String(),
		Name:        entry.Name,
		Description: entry.Description,
		Schedule:    entry.Schedule,
		CommandType: string(entry.CommandType),
		Command:     entry.Command,
		Enabled:     entry.Enabled,
		RunCount:    entry.RunCount,
		FailCount:   entry.FailCount,
		CreatedAt:   entry.CreatedAt.Format("2006-01-02 15:04"),
	}
	if entry.LastRunAt != nil {
		s := entry.LastRunAt.Format("2006-01-02 15:04:05")
		ev.LastRunAt = &s
	}
	if entry.LastRunStatus != nil {
		ev.LastRunStatus = entry.LastRunStatus
	}
	if entry.NextRunAt != nil {
		s := entry.NextRunAt.Format("2006-01-02 15:04:05")
		ev.NextRunAt = &s
	}
	if entry.ContainerID != nil {
		ev.ContainerID = entry.ContainerID
	}
	if entry.WorkingDir != nil {
		ev.WorkingDir = entry.WorkingDir
	}
	if entry.HTTPMethod != nil {
		ev.HTTPMethod = entry.HTTPMethod
	}
	if entry.HTTPURL != nil {
		ev.HTTPURL = entry.HTTPURL
	}

	var execViews []crontabtpl.ExecutionView
	for _, ex := range executions {
		exv := crontabtpl.ExecutionView{
			ID:         ex.ID.String(),
			Status:     ex.Status,
			Output:     ex.Output,
			Error:      ex.Error,
			DurationMs: ex.DurationMs,
			StartedAt:  ex.StartedAt.Format("2006-01-02 15:04:05"),
			FinishedAt: ex.FinishedAt.Format("2006-01-02 15:04:05"),
		}
		if ex.ExitCode != nil {
			exv.ExitCode = ex.ExitCode
		}
		execViews = append(execViews, exv)
	}

	data := crontabtpl.DetailData{
		PageData:   pageData,
		Entry:      ev,
		Executions: execViews,
	}

	h.renderTempl(w, r, crontabtpl.Detail(data))
}

// ============================================================================
// Edit / Update
// ============================================================================

// CrontabEditTempl renders the crontab entry edit form.
func (h *Handler) CrontabEditTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCrontabSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()

	entryID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The cron job ID is not valid.")
		return
	}

	entry, err := svc.Get(ctx, entryID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "The requested cron job was not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Edit: "+entry.Name, "crontab")

	ev := crontabtpl.EntryView{
		ID:          entry.ID.String(),
		Name:        entry.Name,
		Description: entry.Description,
		Schedule:    entry.Schedule,
		CommandType: string(entry.CommandType),
		Command:     entry.Command,
		Enabled:     entry.Enabled,
	}
	if entry.ContainerID != nil {
		ev.ContainerID = entry.ContainerID
	}
	if entry.WorkingDir != nil {
		ev.WorkingDir = entry.WorkingDir
	}
	if entry.HTTPMethod != nil {
		ev.HTTPMethod = entry.HTTPMethod
	}
	if entry.HTTPURL != nil {
		ev.HTTPURL = entry.HTTPURL
	}

	data := crontabtpl.EditData{
		PageData: pageData,
		Entry:    ev,
	}

	h.renderTempl(w, r, crontabtpl.Edit(data))
}

// CrontabUpdateTempl handles POST /crontab/{id} — updates a crontab entry.
func (h *Handler) CrontabUpdateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCrontabSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	entryID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The cron job ID is not valid.")
		return
	}

	name := r.FormValue("name")
	desc := r.FormValue("description")
	schedule := r.FormValue("schedule")
	command := r.FormValue("command")
	cmdTypeStr := r.FormValue("command_type")
	cmdType := models.CrontabCommandType(cmdTypeStr)
	enabled := r.FormValue("enabled") == "on" || r.FormValue("enabled") == "true"

	input := models.UpdateCrontabInput{
		Name:        &name,
		Description: &desc,
		Schedule:    &schedule,
		Command:     &command,
		CommandType: &cmdType,
		Enabled:     &enabled,
	}

	if v := r.FormValue("container_id"); v != "" {
		input.ContainerID = &v
	}
	if v := r.FormValue("working_dir"); v != "" {
		input.WorkingDir = &v
	}
	if v := r.FormValue("http_method"); v != "" {
		input.HTTPMethod = &v
	}
	if v := r.FormValue("http_url"); v != "" {
		input.HTTPURL = &v
	}

	if _, err := svc.Update(r.Context(), entryID, input); err != nil {
		pageData := h.prepareTemplPageData(r, "Edit Cron Job", "crontab")
		ev := crontabtpl.EntryView{
			ID:          entryID.String(),
			Name:        name,
			Description: desc,
			Schedule:    schedule,
			CommandType: cmdTypeStr,
			Command:     command,
			Enabled:     enabled,
		}
		h.renderTempl(w, r, crontabtpl.Edit(crontabtpl.EditData{
			PageData: pageData,
			Entry:    ev,
			Error:    "Failed to update cron job: " + err.Error(),
		}))
		return
	}

	http.Redirect(w, r, "/crontab/"+entryID.String(), http.StatusSeeOther)
}

// ============================================================================
// Delete
// ============================================================================

// CrontabDeleteTempl handles DELETE /crontab/{id}.
func (h *Handler) CrontabDeleteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCrontabSvc(w, r)
	if svc == nil {
		return
	}

	entryID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if err := svc.Delete(r.Context(), entryID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to delete cron job: "+err.Error())
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/crontab")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/crontab", http.StatusSeeOther)
}

// ============================================================================
// Toggle + Run Now
// ============================================================================

// CrontabToggleTempl handles POST /crontab/{id}/toggle — enables or disables.
func (h *Handler) CrontabToggleTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCrontabSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	entryID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	enabled := r.FormValue("enabled") == "on" || r.FormValue("enabled") == "true"

	if err := svc.ToggleEnabled(r.Context(), entryID, enabled); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to toggle cron job: "+err.Error())
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/crontab/"+entryID.String())
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/crontab/"+entryID.String(), http.StatusSeeOther)
}

// CrontabRunNowTempl handles POST /crontab/{id}/run — executes immediately.
func (h *Handler) CrontabRunNowTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireCrontabSvc(w, r)
	if svc == nil {
		return
	}

	entryID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if err := svc.RunNow(r.Context(), entryID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to run cron job: "+err.Error())
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/crontab/"+entryID.String())
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/crontab/"+entryID.String(), http.StatusSeeOther)
}
