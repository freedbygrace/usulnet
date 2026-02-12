// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/web/templates/pages/registries"
)

// RegistriesTempl renders the registries management page.
func (h *Handler) RegistriesTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "Registries", "registries")

	var items []registries.RegistryItem
	if h.registryRepo != nil {
		regs, err := h.registryRepo.List(r.Context())
		if err != nil {
			slog.Error("Failed to list registries", "error", err)
		} else {
			for _, reg := range regs {
				item := registries.RegistryItem{
					ID:        reg.ID.String(),
					Name:      reg.Name,
					URL:       reg.URL,
					IsDefault: reg.IsDefault,
					CreatedAt: reg.CreatedAt.Format("2006-01-02 15:04"),
				}
				if reg.Username != nil {
					item.Username = *reg.Username
				}
				items = append(items, item)
			}
		}
	}

	data := registries.RegistriesData{
		PageData:   pageData,
		Registries: items,
	}
	h.renderTempl(w, r, registries.List(data))
}

// RegistryCreate handles creation of a new registry.
func (h *Handler) RegistryCreate(w http.ResponseWriter, r *http.Request) {
	if h.registryRepo == nil {
		h.setFlash(w, r, "error", "Registry service not configured")
		h.redirect(w, r, "/registries")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		h.redirect(w, r, "/registries")
		return
	}

	name := r.FormValue("name")
	registryURL := r.FormValue("url")
	if name == "" || registryURL == "" {
		h.setFlash(w, r, "error", "Name and URL are required")
		h.redirect(w, r, "/registries")
		return
	}

	input := models.CreateRegistryInput{
		Name:      name,
		URL:       registryURL,
		IsDefault: r.FormValue("is_default") == "on",
	}

	if username := r.FormValue("username"); username != "" {
		input.Username = &username
	}
	if password := r.FormValue("password"); password != "" {
		if h.encryptor != nil {
			encrypted, err := h.encryptor.Encrypt(password)
			if err == nil {
				input.Password = &encrypted
			} else {
				slog.Error("Failed to encrypt registry password", "error", err)
				h.setFlash(w, r, "error", "Failed to encrypt password")
				h.redirect(w, r, "/registries")
				return
			}
		} else {
			input.Password = &password
		}
	}

	_, err := h.registryRepo.Create(r.Context(), input)
	if err != nil {
		slog.Error("Failed to create registry", "name", input.Name, "error", err)
		h.setFlash(w, r, "error", "Failed to create registry: "+err.Error())
		h.redirect(w, r, "/registries")
		return
	}

	h.setFlash(w, r, "success", "Registry created successfully")
	h.redirect(w, r, "/registries")
}

// RegistryUpdate handles updating a registry.
func (h *Handler) RegistryUpdate(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/registries")
		return
	}

	if h.registryRepo == nil {
		h.setFlash(w, r, "error", "Registry service not configured")
		h.redirect(w, r, "/registries")
		return
	}

	if err := r.ParseForm(); err != nil {
		h.setFlash(w, r, "error", "Invalid form data")
		h.redirect(w, r, "/registries")
		return
	}

	name := r.FormValue("name")
	registryURL := r.FormValue("url")
	if name == "" || registryURL == "" {
		h.setFlash(w, r, "error", "Name and URL are required")
		h.redirect(w, r, "/registries")
		return
	}

	input := models.CreateRegistryInput{
		Name:      name,
		URL:       registryURL,
		IsDefault: r.FormValue("is_default") == "on",
	}

	if username := r.FormValue("username"); username != "" {
		input.Username = &username
	}
	if password := r.FormValue("password"); password != "" {
		if h.encryptor != nil {
			encrypted, err := h.encryptor.Encrypt(password)
			if err == nil {
				input.Password = &encrypted
			} else {
				slog.Error("Failed to encrypt registry password", "error", err)
				h.setFlash(w, r, "error", "Failed to encrypt password")
				h.redirect(w, r, "/registries")
				return
			}
		} else {
			input.Password = &password
		}
	}

	_, err = h.registryRepo.Update(r.Context(), id, input)
	if err != nil {
		slog.Error("Failed to update registry", "id", id, "error", err)
		h.setFlash(w, r, "error", "Failed to update registry: "+err.Error())
		h.redirect(w, r, "/registries")
		return
	}

	h.setFlash(w, r, "success", "Registry updated successfully")
	h.redirect(w, r, "/registries")
}

// RegistryDelete handles deletion of a registry.
func (h *Handler) RegistryDelete(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		h.redirect(w, r, "/registries")
		return
	}

	if h.registryRepo != nil {
		if err := h.registryRepo.Delete(r.Context(), id); err != nil {
			slog.Error("Failed to delete registry", "id", id, "error", err)
			h.setFlash(w, r, "error", "Failed to delete registry: "+err.Error())
			h.redirect(w, r, "/registries")
			return
		}
	}

	h.setFlash(w, r, "success", "Registry deleted")
	h.redirect(w, r, "/registries")
}
