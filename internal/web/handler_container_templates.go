// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	tmplpkg "github.com/fr4nsys/usulnet/internal/web/templates/pages/templates"
)

// templateEnvVar represents an environment variable in a container template.
type templateEnvVar struct {
	Key         string `json:"key"`
	Value       string `json:"value"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// ContainerTemplatesTempl renders the container templates page.
func (h *Handler) ContainerTemplatesTempl(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Container Templates", "container-templates")

	var templates []tmplpkg.ContainerTemplateView
	stats := tmplpkg.TemplateStats{}
	var categories []string

	if h.containerTemplateRepo != nil {
		dbTemplates, err := h.containerTemplateRepo.List(ctx)
		if err == nil {
			categorySet := make(map[string]bool)
			for _, t := range dbTemplates {
				var envVars []tmplpkg.EnvVarView
				if len(t.EnvVars) > 0 {
					var evList []templateEnvVar
					if json.Unmarshal(t.EnvVars, &evList) == nil {
						for _, ev := range evList {
							envVars = append(envVars, tmplpkg.EnvVarView{
								Key:         ev.Key,
								Value:       ev.Value,
								Description: ev.Description,
								Required:    ev.Required,
							})
						}
					}
				}

				tv := tmplpkg.ContainerTemplateView{
					ID:            t.ID.String(),
					Name:          t.Name,
					Description:   t.Description,
					Category:      t.Category,
					Image:         t.Image,
					Tag:           t.Tag,
					Ports:         t.Ports,
					Volumes:       t.Volumes,
					EnvVars:       envVars,
					Network:       t.Network,
					RestartPolicy: t.RestartPolicy,
					Command:       t.Command,
					IsPublic:      t.IsPublic,
					UsageCount:    t.UsageCount,
					CreatedAt:     t.CreatedAt.Format("Jan 02 15:04"),
				}
				if t.CreatedBy != nil {
					tv.CreatedBy = t.CreatedBy.String()
				}
				templates = append(templates, tv)
				stats.TotalTemplates++
				if t.IsPublic {
					stats.PublicTemplates++
				}
				stats.TotalDeploys += t.UsageCount
				categorySet[t.Category] = true
			}

			for cat := range categorySet {
				categories = append(categories, cat)
			}
			stats.Categories = len(categories)
		}
	}

	data := tmplpkg.ContainerTemplatesData{
		PageData:   pageData,
		Templates:  templates,
		Categories: categories,
		Stats:      stats,
	}

	h.renderTempl(w, r, tmplpkg.ContainerTemplates(data))
}

// ContainerTemplateCreate creates a new container template.
func (h *Handler) ContainerTemplateCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
		return
	}

	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		h.setFlash(w, r, "error", "Template name is required")
		http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
		return
	}

	image := strings.TrimSpace(r.FormValue("image"))
	if image == "" {
		h.setFlash(w, r, "error", "Docker image is required")
		http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
		return
	}

	tag := strings.TrimSpace(r.FormValue("tag"))
	if tag == "" {
		tag = "latest"
	}

	// Parse ports (one per line)
	var ports []string
	if portsRaw := strings.TrimSpace(r.FormValue("ports")); portsRaw != "" {
		for _, line := range strings.Split(portsRaw, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				ports = append(ports, line)
			}
		}
	}

	// Parse volumes (one per line)
	var volumes []string
	if volsRaw := strings.TrimSpace(r.FormValue("volumes")); volsRaw != "" {
		for _, line := range strings.Split(volsRaw, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				volumes = append(volumes, line)
			}
		}
	}

	// Parse environment variables (KEY=VALUE per line)
	var envVars []templateEnvVar
	if envsRaw := strings.TrimSpace(r.FormValue("env_vars")); envsRaw != "" {
		for _, line := range strings.Split(envsRaw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			ev := templateEnvVar{Key: parts[0]}
			if len(parts) > 1 {
				ev.Value = parts[1]
			}
			envVars = append(envVars, ev)
		}
	}

	envVarsJSON, _ := json.Marshal(envVars)

	if h.containerTemplateRepo != nil {
		t := &ContainerTemplateRecord{
			ID:            uuid.New(),
			Name:          name,
			Description:   strings.TrimSpace(r.FormValue("description")),
			Category:      r.FormValue("category"),
			Image:         image,
			Tag:           tag,
			Ports:         ports,
			Volumes:       volumes,
			EnvVars:       envVarsJSON,
			Network:       strings.TrimSpace(r.FormValue("network")),
			RestartPolicy: r.FormValue("restart_policy"),
			Command:       strings.TrimSpace(r.FormValue("command")),
			IsPublic:      r.FormValue("is_public") == "on",
		}
		if err := h.containerTemplateRepo.Create(r.Context(), t); err != nil {
			h.setFlash(w, r, "error", "Failed to create template: "+err.Error())
			http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
			return
		}
	}

	h.setFlash(w, r, "success", "Container template '"+name+"' created")
	http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
}

// ContainerTemplateDelete deletes a container template.
func (h *Handler) ContainerTemplateDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	if h.containerTemplateRepo != nil {
		uid, err := uuid.Parse(id)
		if err == nil {
			h.containerTemplateRepo.Delete(r.Context(), uid)
		}
	}

	h.setFlash(w, r, "success", "Container template deleted")

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/container-templates")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
}

// ContainerTemplateDeploy deploys a container from a template.
func (h *Handler) ContainerTemplateDeploy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx := r.Context()

	if h.containerTemplateRepo == nil {
		h.setFlash(w, r, "error", "Template repository unavailable")
		http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
		return
	}

	uid, err := uuid.Parse(id)
	if err != nil {
		h.setFlash(w, r, "error", "Invalid template ID")
		http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
		return
	}

	t, err := h.containerTemplateRepo.GetByID(ctx, uid)
	if err != nil {
		h.setFlash(w, r, "error", "Template not found")
		http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
		return
	}

	// Deploy the container using the container service
	containerSvc := h.services.Containers()
	if containerSvc == nil {
		h.setFlash(w, r, "error", "Container service unavailable")
		http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
		return
	}

	// Build environment variables as KEY=value lines
	var envLines []string
	if len(t.EnvVars) > 0 {
		var evList []templateEnvVar
		if json.Unmarshal(t.EnvVars, &evList) == nil {
			for _, ev := range evList {
				envLines = append(envLines, ev.Key+"="+ev.Value)
			}
		}
	}

	// Create container using the service
	containerName := strings.ReplaceAll(strings.ToLower(t.Name), " ", "-")
	imageRef := t.Image + ":" + t.Tag

	input := &ContainerCreateInput{
		Name:          containerName,
		Image:         imageRef,
		Ports:         t.Ports,
		Volumes:       t.Volumes,
		Environment:   strings.Join(envLines, "\n"),
		Network:       t.Network,
		Command:       t.Command,
		RestartPolicy: t.RestartPolicy,
	}

	containerID, err := containerSvc.Create(ctx, input)
	if err != nil {
		h.setFlash(w, r, "error", "Failed to create container: "+err.Error())
		http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
		return
	}

	// Start the container
	if err := containerSvc.Start(ctx, containerID); err != nil {
		h.setFlash(w, r, "warning", fmt.Sprintf("Container created (%s) but failed to start: %s", containerID[:12], err.Error()))
		http.Redirect(w, r, "/container-templates", http.StatusSeeOther)
		return
	}

	// Increment usage count in DB
	h.containerTemplateRepo.IncrementUsage(ctx, uid)

	h.setFlash(w, r, "success", fmt.Sprintf("Container '%s' deployed from template '%s'", containerName, t.Name))

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/containers")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/containers", http.StatusSeeOther)
}
