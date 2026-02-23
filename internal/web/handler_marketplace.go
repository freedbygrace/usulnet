// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	marketplacesvc "github.com/fr4nsys/usulnet/internal/services/marketplace"
	mktpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/marketplace"
)

// requireMarketplaceSvc returns the marketplace service or renders a "not configured" error.
func (h *Handler) requireMarketplaceSvc(w http.ResponseWriter, r *http.Request) *marketplacesvc.Service {
	svc := h.services.Marketplace()
	if svc == nil {
		h.RenderErrorTempl(w, r, http.StatusServiceUnavailable, "Marketplace Not Configured", "The marketplace service is not enabled.")
		return nil
	}
	return svc
}

// getMKHostID resolves the active host ID for marketplace operations.
func (h *Handler) getMKHostID(r *http.Request) uuid.UUID {
	if reg, ok := h.services.(*ServiceRegistry); ok {
		return resolveHostID(r.Context(), reg.defaultHostID)
	}
	return uuid.Nil
}

// marketplace categories for form options
var marketplaceCategories = []string{
	"networking", "storage", "development", "monitoring",
	"security", "communication", "productivity", "database", "other",
}

// ============================================================================
// Browse
// ============================================================================

// MarketplaceListTempl renders the marketplace browse page.
func (h *Handler) MarketplaceListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireMarketplaceSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "Marketplace", "marketplace")

	query := r.URL.Query().Get("q")
	category := r.URL.Query().Get("category")
	page := 1
	if p := r.URL.Query().Get("page"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 {
			page = v
		}
	}
	pageSize := 24
	offset := (page - 1) * pageSize

	apps, total, err := svc.SearchApps(ctx, query, category, pageSize, offset)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load apps: "+err.Error())
		return
	}

	var featured []mktpl.AppView
	if query == "" && category == "" {
		featuredApps, _ := svc.ListFeatured(ctx, 3)
		for _, a := range featuredApps {
			featured = append(featured, appToView(a))
		}
	}

	var views []mktpl.AppView
	for _, a := range apps {
		views = append(views, appToView(a))
	}

	data := mktpl.ListData{
		PageData:   pageData,
		Featured:   featured,
		Apps:       views,
		Categories: marketplaceCategories,
		Query:      query,
		Category:   category,
		Total:      total,
	}
	mktpl.List(data).Render(ctx, w)
}

// ============================================================================
// App Detail
// ============================================================================

// MarketplaceDetailTempl renders the app detail page.
func (h *Handler) MarketplaceDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireMarketplaceSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	slug := chi.URLParam(r, "slug")

	app, err := svc.GetAppBySlug(ctx, slug)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "App not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, app.Name, "marketplace")

	reviews, _ := svc.ListReviews(ctx, app.ID)
	var reviewViews []mktpl.ReviewView
	for _, rv := range reviews {
		reviewViews = append(reviewViews, mktpl.ReviewView{
			ID:        rv.ID.String(),
			Rating:    rv.Rating,
			Title:     rv.Title,
			Comment:   rv.Comment,
			CreatedAt: rv.CreatedAt.Format("2006-01-02"),
		})
	}

	var tags []string
	if app.Tags != nil {
		tags = app.Tags
	}

	data := mktpl.DetailData{
		PageData: pageData,
		App: mktpl.AppDetailView{
			AppView:         appToView(app),
			LongDescription: app.LongDescription,
			ComposeTemplate: app.ComposeTemplate,
			Website:         app.Website,
			Source:          app.Source,
			License:         app.License,
			MinMemoryMB:     app.MinMemoryMB,
			MinCPUCores:     app.MinCPUCores,
			Tags:            tags,
		},
		Reviews: reviewViews,
	}
	mktpl.Detail(data).Render(ctx, w)
}

// ============================================================================
// Install
// ============================================================================

// MarketplaceInstallTempl renders the app install form.
func (h *Handler) MarketplaceInstallTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireMarketplaceSvc(w, r)
	if svc == nil {
		return
	}
	slug := chi.URLParam(r, "slug")

	app, err := svc.GetAppBySlug(r.Context(), slug)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "App not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Install "+app.Name, "marketplace")

	var fields []mktpl.FieldView
	if app.Fields != nil {
		var mFields []models.MarketplaceField
		if err := json.Unmarshal(app.Fields, &mFields); err == nil {
			for _, f := range mFields {
				fields = append(fields, mktpl.FieldView{
					Key:         f.Key,
					Label:       f.Label,
					Description: f.Description,
					Type:        f.Type,
					Default:     f.Default,
					Required:    f.Required,
					Options:     f.Options,
					Placeholder: f.Placeholder,
				})
			}
		}
	}

	data := mktpl.InstallData{
		PageData: pageData,
		App:      appToView(app),
		Fields:   fields,
	}
	mktpl.Install(data).Render(r.Context(), w)
}

// MarketplaceInstallCreateTempl handles the install form submission.
func (h *Handler) MarketplaceInstallCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireMarketplaceSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/marketplace", http.StatusSeeOther)
		return
	}

	slug := chi.URLParam(r, "slug")
	app, err := svc.GetAppBySlug(r.Context(), slug)
	if err != nil {
		http.Redirect(w, r, "/marketplace", http.StatusSeeOther)
		return
	}

	hostID := h.getMKHostID(r)
	name := r.FormValue("name")
	if name == "" {
		name = app.Name
	}

	// Collect field values
	configValues := make(map[string]string)
	for key, values := range r.Form {
		if strings.HasPrefix(key, "field_") && len(values) > 0 {
			configValues[strings.TrimPrefix(key, "field_")] = values[0]
		}
	}

	_, err = svc.InstallApp(r.Context(), app.ID, hostID, name, configValues, nil)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to install app: "+err.Error())
		return
	}

	http.Redirect(w, r, "/marketplace/installed", http.StatusSeeOther)
}

// ============================================================================
// Installed
// ============================================================================

// MarketplaceInstalledTempl renders the installed apps page.
func (h *Handler) MarketplaceInstalledTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireMarketplaceSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getMKHostID(r)
	pageData := h.prepareTemplPageData(r, "Installed Apps", "marketplace")

	installations, total, err := svc.ListInstallations(ctx, hostID, 100, 0)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load installations: "+err.Error())
		return
	}

	var views []mktpl.InstallationView
	for _, inst := range installations {
		v := mktpl.InstallationView{
			ID:          inst.ID.String(),
			Name:        inst.Name,
			Status:      string(inst.Status),
			Version:     inst.Version,
			InstalledAt: inst.InstalledAt.Format("2006-01-02 15:04"),
		}
		// Look up app info
		app, err := svc.GetApp(ctx, inst.AppID)
		if err == nil {
			v.AppName = app.Name
			v.AppSlug = app.Slug
			v.AppIcon = app.Icon
			v.AppIconColor = app.IconColor
		}
		views = append(views, v)
	}

	data := mktpl.InstalledData{
		PageData:      pageData,
		Installations: views,
		Total:         total,
	}
	mktpl.Installed(data).Render(ctx, w)
}

// MarketplaceUninstallTempl handles uninstalling an app.
func (h *Handler) MarketplaceUninstallTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireMarketplaceSvc(w, r)
	if svc == nil {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Redirect(w, r, "/marketplace/installed", http.StatusSeeOther)
		return
	}
	_ = svc.UninstallApp(r.Context(), id)
	http.Redirect(w, r, "/marketplace/installed", http.StatusSeeOther)
}

// ============================================================================
// Submit App
// ============================================================================

// MarketplaceSubmitTempl renders the submit app form.
func (h *Handler) MarketplaceSubmitTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireMarketplaceSvc(w, r)
	if svc == nil {
		return
	}
	pageData := h.prepareTemplPageData(r, "Submit App", "marketplace")
	data := mktpl.SubmitData{
		PageData:   pageData,
		Categories: marketplaceCategories,
	}
	mktpl.Submit(data).Render(r.Context(), w)
}

// MarketplaceSubmitCreateTempl handles the submit app form submission.
func (h *Handler) MarketplaceSubmitCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireMarketplaceSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/marketplace", http.StatusSeeOther)
		return
	}

	var tags []string
	if t := r.FormValue("tags"); t != "" {
		for _, tag := range strings.Split(t, ",") {
			tag = strings.TrimSpace(tag)
			if tag != "" {
				tags = append(tags, tag)
			}
		}
	}

	app := &models.MarketplaceApp{
		Name:            r.FormValue("name"),
		Description:     r.FormValue("description"),
		LongDescription: r.FormValue("long_description"),
		Category:        models.MarketplaceAppCategory(r.FormValue("category")),
		ComposeTemplate: r.FormValue("compose_template"),
		Version:         r.FormValue("version"),
		License:         r.FormValue("license"),
		Website:         r.FormValue("website"),
		Source:          r.FormValue("source"),
		Tags:            tags,
	}

	if err := svc.CreateApp(r.Context(), app); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to submit app: "+err.Error())
		return
	}

	http.Redirect(w, r, "/marketplace/"+app.Slug, http.StatusSeeOther)
}

// ============================================================================
// View helpers
// ============================================================================

func appToView(a *models.MarketplaceApp) mktpl.AppView {
	return mktpl.AppView{
		ID:           a.ID.String(),
		Slug:         a.Slug,
		Name:         a.Name,
		Description:  a.Description,
		Icon:         a.Icon,
		IconColor:    a.IconColor,
		Category:     string(a.Category),
		Version:      a.Version,
		Author:       a.Author,
		IsOfficial:   a.IsOfficial,
		IsVerified:   a.IsVerified,
		InstallCount: a.InstallCount,
		AvgRating:    a.AvgRating,
		RatingCount:  a.RatingCount,
	}
}
