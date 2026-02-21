// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
)

// AutoUpdatePolicyCreate creates a new auto-update policy.
func (h *Handler) AutoUpdatePolicyCreate(w http.ResponseWriter, r *http.Request) {
	updatesSvc := h.services.Updates()
	if updatesSvc == nil {
		h.setFlash(w, r, "error", "Updates service is not configured")
		http.Redirect(w, r, "/updates?tab=policies", http.StatusSeeOther)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/updates?tab=policies", http.StatusSeeOther)
		return
	}

	containerID := r.FormValue("container_id")
	containerName := r.FormValue("container_name")
	if containerID == "" {
		h.setFlash(w, r, "error", "Container is required")
		http.Redirect(w, r, "/updates?tab=policies", http.StatusSeeOther)
		return
	}

	maxRetries, _ := strconv.Atoi(r.FormValue("max_retries"))
	if maxRetries == 0 {
		maxRetries = 3
	}
	healthCheckWait, _ := strconv.Atoi(r.FormValue("health_check_wait"))
	if healthCheckWait == 0 {
		healthCheckWait = 30
	}

	policy := UpdatePolicyView{
		TargetType:        "container",
		TargetID:          containerID,
		TargetName:        containerName,
		IsEnabled:         true,
		AutoUpdate:        r.FormValue("auto_update") == "on",
		AutoBackup:        r.FormValue("auto_backup") == "on",
		IncludePrerelease: r.FormValue("include_prerelease") == "on",
		Schedule:          strings.TrimSpace(r.FormValue("schedule")),
		NotifyOnUpdate:    r.FormValue("notify_update") == "on",
		NotifyOnFailure:   r.FormValue("notify_failure") == "on",
		MaxRetries:        maxRetries,
		HealthCheckWait:   healthCheckWait,
	}

	if err := updatesSvc.SetPolicy(r.Context(), policy); err != nil {
		h.logger.Error("failed to create auto-update policy", "error", err)
		h.setFlash(w, r, "error", "Failed to create policy: "+err.Error())
	} else {
		h.setFlash(w, r, "success", "Auto-update policy created for "+containerName)
	}

	http.Redirect(w, r, "/updates?tab=policies", http.StatusSeeOther)
}

// AutoUpdatePolicyToggle toggles an auto-update policy on/off.
func (h *Handler) AutoUpdatePolicyToggle(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	updatesSvc := h.services.Updates()
	if updatesSvc != nil {
		policies, _ := updatesSvc.ListPolicies(r.Context())
		for _, p := range policies {
			if p.ID == id {
				p.IsEnabled = !p.IsEnabled
				if err := updatesSvc.SetPolicy(r.Context(), p); err != nil {
					h.setFlash(w, r, "error", "Failed to toggle policy")
				} else {
					status := "disabled"
					if p.IsEnabled {
						status = "enabled"
					}
					h.setFlash(w, r, "success", "Policy "+status+" for "+p.TargetName)
				}
				break
			}
		}
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/updates?tab=policies")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/updates?tab=policies", http.StatusSeeOther)
}

// AutoUpdatePolicyDelete deletes an auto-update policy.
func (h *Handler) AutoUpdatePolicyDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if updatesSvc := h.services.Updates(); updatesSvc != nil {
		if err := updatesSvc.DeletePolicy(r.Context(), id); err != nil {
			h.setFlash(w, r, "error", "Failed to delete policy: "+err.Error())
		} else {
			h.setFlash(w, r, "success", "Auto-update policy removed")
		}
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/updates?tab=policies")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/updates?tab=policies", http.StatusSeeOther)
}
