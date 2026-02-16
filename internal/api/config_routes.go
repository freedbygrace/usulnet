// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package api

import (
	"github.com/go-chi/chi/v5"

	"github.com/fr4nsys/usulnet/internal/api/handlers"
)

// RegisterConfigRoutes registers all config-related routes
func RegisterConfigRoutes(r chi.Router, h *handlers.ConfigHandler) {
	r.Route("/config", func(r chi.Router) {
		// Variables
		r.Route("/variables", func(r chi.Router) {
			r.Get("/", h.ListVariables)
			r.Post("/", h.CreateVariable)
			r.Route("/{id}", func(r chi.Router) {
				r.Get("/", h.GetVariable)
				r.Put("/", h.UpdateVariable)
				r.Delete("/", h.DeleteVariable)
				r.Get("/usage", h.GetVariableUsage)
				r.Get("/history", h.GetVariableHistory)
				r.Post("/rollback/{version}", h.RollbackVariable)
			})
		})

		// Templates
		r.Route("/templates", func(r chi.Router) {
			r.Get("/", h.ListTemplates)
			r.Post("/", h.CreateTemplate)
			r.Route("/{id}", func(r chi.Router) {
				r.Get("/", h.GetTemplate)
				r.Put("/", h.UpdateTemplate)
				r.Delete("/", h.DeleteTemplate)
				r.Post("/default", h.SetDefaultTemplate)
			})
		})

		// Sync - Configuration synchronization to containers
		r.Route("/sync", func(r chi.Router) {
			r.Post("/", h.SyncConfig)
			r.Post("/preview", h.PreviewSync)
			r.Post("/bulk", h.BulkSyncConfig)
			r.Get("/outdated", h.ListOutdatedSyncs)
			r.Get("/stats", h.GetSyncStats)
			r.Get("/{hostID}/{containerID}", h.GetSyncStatus)
			r.Delete("/{hostID}/{containerID}", h.RemoveSync)
		})

		// Export/Import
		r.Get("/export", h.ExportConfig)
		r.Post("/import", h.ImportConfig)

		// Audit
		r.Get("/audit", h.GetAuditLog)
	})
}
