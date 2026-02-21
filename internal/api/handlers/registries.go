// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/services/registry"
)

// RegistryHandler handles registry browsing HTTP requests.
type RegistryHandler struct {
	BaseHandler
	registrySvc *registry.Service
}

// NewRegistryHandler creates a new registry handler.
func NewRegistryHandler(registrySvc *registry.Service, log *logger.Logger) *RegistryHandler {
	return &RegistryHandler{
		BaseHandler: NewBaseHandler(log),
		registrySvc: registrySvc,
	}
}

// Routes returns the router for registry browsing endpoints.
func (h *RegistryHandler) Routes() chi.Router {
	r := chi.NewRouter()

	// All browsing endpoints require viewer+
	r.Get("/", h.ListRegistries)

	r.Route("/{registryID}", func(r chi.Router) {
		r.Get("/repositories", h.ListRepositories)
		r.Get("/repositories/*", h.RepositoryAction)
	})

	// CRUD requires operator+
	r.Group(func(r chi.Router) {
		r.Use(middleware.RequireOperator)
		r.Post("/", h.CreateRegistry)
		r.Put("/{registryID}", h.UpdateRegistry)
		r.Delete("/{registryID}", h.DeleteRegistry)
	})

	return r
}

// ListRegistries returns all stored registries (passwords excluded).
func (h *RegistryHandler) ListRegistries(w http.ResponseWriter, r *http.Request) {
	registries, err := h.registrySvc.ListRegistries(r.Context())
	if err != nil {
		h.InternalError(w, err)
		return
	}
	h.OK(w, registries)
}

// CreateRegistry creates a new registry.
func (h *RegistryHandler) CreateRegistry(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Name      string  `json:"name" validate:"required,min=1,max=100"`
		URL       string  `json:"url" validate:"required,url"`
		Username  *string `json:"username,omitempty"`
		Password  *string `json:"password,omitempty"`
		IsDefault bool    `json:"is_default,omitempty"`
	}

	if err := h.ParseJSON(r, &input); err != nil {
		h.HandleError(w, err)
		return
	}

	reg, err := h.registrySvc.CreateRegistry(r.Context(), input.Name, input.URL, input.Username, input.Password, input.IsDefault)
	if err != nil {
		h.InternalError(w, err)
		return
	}

	h.Created(w, reg)
}

// UpdateRegistry updates an existing registry.
func (h *RegistryHandler) UpdateRegistry(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "registryID"))
	if err != nil {
		h.BadRequest(w, "invalid registry ID")
		return
	}

	var input struct {
		Name      string  `json:"name" validate:"required,min=1,max=100"`
		URL       string  `json:"url" validate:"required,url"`
		Username  *string `json:"username,omitempty"`
		Password  *string `json:"password,omitempty"`
		IsDefault bool    `json:"is_default,omitempty"`
	}

	if err := h.ParseJSON(r, &input); err != nil {
		h.HandleError(w, err)
		return
	}

	reg, err := h.registrySvc.UpdateRegistry(r.Context(), id, input.Name, input.URL, input.Username, input.Password, input.IsDefault)
	if err != nil {
		h.InternalError(w, err)
		return
	}

	h.OK(w, reg)
}

// DeleteRegistry deletes a registry.
func (h *RegistryHandler) DeleteRegistry(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "registryID"))
	if err != nil {
		h.BadRequest(w, "invalid registry ID")
		return
	}

	if err := h.registrySvc.DeleteRegistry(r.Context(), id); err != nil {
		h.InternalError(w, err)
		return
	}

	h.NoContent(w)
}

// ListRepositories lists repos in a registry.
func (h *RegistryHandler) ListRepositories(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "registryID"))
	if err != nil {
		h.BadRequest(w, "invalid registry ID")
		return
	}

	namespace := r.URL.Query().Get("namespace")
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))

	repos, err := h.registrySvc.ListRepositories(r.Context(), id, namespace, page, perPage)
	if err != nil {
		h.InternalError(w, err)
		return
	}

	h.OK(w, repos)
}

// RepositoryAction handles tag listing and manifest retrieval using a wildcard
// route pattern. This allows repository names with slashes (e.g., "library/nginx").
//
// Routes resolved:
//
//	GET /{registryID}/repositories/{repo...}/tags       → ListTags
//	GET /{registryID}/repositories/{repo...}/tags/{ref} → GetManifest
func (h *RegistryHandler) RepositoryAction(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "registryID"))
	if err != nil {
		h.BadRequest(w, "invalid registry ID")
		return
	}

	// The wildcard captures everything after /repositories/
	wildcard := chi.URLParam(r, "*")

	// Parse: "{repo}/tags" or "{repo}/tags/{reference}"
	repo, action, ref := parseRepoPath(wildcard)
	if repo == "" || action != "tags" {
		h.NotFound(w, "registry endpoint")
		return
	}

	if ref != "" {
		// Get manifest for a specific tag/digest
		manifest, err := h.registrySvc.GetManifest(r.Context(), id, repo, ref)
		if err != nil {
			h.InternalError(w, err)
			return
		}
		h.OK(w, manifest)
		return
	}

	// List tags
	tags, err := h.registrySvc.ListTags(r.Context(), id, repo)
	if err != nil {
		h.InternalError(w, err)
		return
	}
	h.OK(w, tags)
}

// parseRepoPath splits a wildcard path like "library/nginx/tags" or
// "library/nginx/tags/latest" into (repo, action, reference).
func parseRepoPath(path string) (repo, action, ref string) {
	// Find the last segment that is "tags" — everything before it is the repo name
	parts := splitPath(path)
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == "tags" {
			repo = joinPath(parts[:i])
			action = "tags"
			if i+1 < len(parts) {
				ref = joinPath(parts[i+1:])
			}
			return
		}
	}
	return path, "", ""
}

func splitPath(p string) []string {
	var parts []string
	for _, s := range split(p, '/') {
		if s != "" {
			parts = append(parts, s)
		}
	}
	return parts
}

func split(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func joinPath(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += "/"
		}
		result += p
	}
	return result
}
