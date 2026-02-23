// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	sslobssvc "github.com/fr4nsys/usulnet/internal/services/sslobservatory"
	ssltpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/sslobservatory"
)

// requireSSLObsSvc returns the SSL observatory service or renders a "not configured" error.
func (h *Handler) requireSSLObsSvc(w http.ResponseWriter, r *http.Request) *sslobssvc.Service {
	svc := h.services.SSLObservatory()
	if svc == nil {
		h.RenderErrorTempl(w, r, http.StatusServiceUnavailable, "SSL Observatory Not Configured", "The SSL observatory service is not enabled.")
		return nil
	}
	return svc
}

// getSSLHostID resolves the active host ID for SSL observatory operations.
func (h *Handler) getSSLHostID(r *http.Request) uuid.UUID {
	if reg, ok := h.services.(*ServiceRegistry); ok {
		return resolveHostID(r.Context(), reg.defaultHostID)
	}
	return uuid.Nil
}

func scanResultToView(result models.SSLScanResult) ssltpl.ScanView {
	view := ssltpl.ScanView{
		ID:           result.ID.String(),
		Grade:        result.Grade,
		Score:        result.Score,
		CertCN:       result.CertificateCN,
		CertIssuer:   result.CertificateIssuer,
		CertKeyType:  result.CertKeyType,
		CertKeyBits:  result.CertKeyBits,
		ChainValid:   result.CertChainValid,
		ChainLength:  result.CertChainLength,
		HasHSTS:      result.HasHSTS,
		HasOCSP:      result.HasOCSPStapling,
		HasSCT:       result.HasSCT,
		ErrorMessage: result.ErrorMessage,
		ScanDuration: fmt.Sprintf("%dms", result.ScanDurationMs),
		ScannedAt:    result.ScannedAt.Format("2006-01-02 15:04"),
	}

	if len(result.ProtocolVersions) > 0 {
		view.ProtocolVersions = strings.Join(result.ProtocolVersions, ", ")
	}

	if result.CipherSuites != nil {
		var ciphers []struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(result.CipherSuites, &ciphers) == nil && len(ciphers) > 0 {
			view.CipherSuite = ciphers[0].Name
		}
	}

	if result.CertificateSANs != nil {
		view.CertSANs = strings.Join(result.CertificateSANs, ", ")
	}

	if result.CertNotBefore != nil {
		view.CertNotBefore = result.CertNotBefore.Format("2006-01-02 15:04")
	}
	if result.CertNotAfter != nil {
		view.CertNotAfter = result.CertNotAfter.Format("2006-01-02 15:04")
	}

	return view
}

func targetToView(target models.SSLTarget, latestScan *models.SSLScanResult) ssltpl.TargetView {
	view := ssltpl.TargetView{
		ID:       target.ID.String(),
		Name:     target.Name,
		Hostname: target.Hostname,
		Port:     target.Port,
		Enabled:  target.Enabled,
	}

	if latestScan != nil {
		view.LatestGrade = latestScan.Grade
		view.LatestScore = fmt.Sprintf("%d", latestScan.Score)
		view.LastScan = latestScan.ScannedAt.Format("2006-01-02 15:04")
		if latestScan.CertNotAfter != nil {
			view.CertExpires = latestScan.CertNotAfter.Format("2006-01-02")
		}
	}

	return view
}

// ============================================================================
// Dashboard
// ============================================================================

// SSLDashboardTempl renders the SSL observatory dashboard.
func (h *Handler) SSLDashboardTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireSSLObsSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getSSLHostID(r)
	pageData := h.prepareTemplPageData(r, "SSL Observatory", "ssl")

	stats, err := svc.GetDashboardStats(ctx, hostID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load dashboard stats: "+err.Error())
		return
	}

	expiring, err := svc.GetExpiringCerts(ctx, hostID, 30)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load expiring certs: "+err.Error())
		return
	}

	// Build expiring cert views, looking up target info for each
	var expiringViews []ssltpl.ExpiringCertView
	for _, scan := range expiring {
		target, tErr := svc.GetTarget(ctx, scan.TargetID)
		targetName := ""
		hostname := ""
		if tErr == nil && target != nil {
			targetName = target.Name
			hostname = target.Hostname
		}

		daysLeft := 0
		expiresAt := ""
		if scan.CertNotAfter != nil {
			daysLeft = int(time.Until(*scan.CertNotAfter).Hours() / 24)
			expiresAt = scan.CertNotAfter.Format("2006-01-02")
		}

		expiringViews = append(expiringViews, ssltpl.ExpiringCertView{
			TargetName: targetName,
			Hostname:   hostname,
			Grade:      scan.Grade,
			CertCN:     scan.CertificateCN,
			ExpiresAt:  expiresAt,
			DaysLeft:   daysLeft,
		})
	}

	lastScanTime := ""
	if stats.LastScanTime != nil {
		lastScanTime = stats.LastScanTime.Format("2006-01-02 15:04")
	}

	data := ssltpl.DashboardData{
		PageData:          pageData,
		TotalTargets:      stats.TotalTargets,
		GradeDistribution: stats.GradeDistribution,
		ExpiringSoon:      expiringViews,
		LastScanTime:      lastScanTime,
	}

	h.renderTempl(w, r, ssltpl.Dashboard(data))
}

// ============================================================================
// Target List
// ============================================================================

// SSLTargetListTempl renders the SSL targets list page.
func (h *Handler) SSLTargetListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireSSLObsSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getSSLHostID(r)
	pageData := h.prepareTemplPageData(r, "SSL Targets", "ssl")

	targets, err := svc.ListTargets(ctx, hostID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load SSL targets: "+err.Error())
		return
	}

	var targetViews []ssltpl.TargetView
	for _, t := range targets {
		latest, _ := svc.GetLatestScan(ctx, t.ID)
		targetViews = append(targetViews, targetToView(t, latest))
	}

	data := ssltpl.TargetListData{
		PageData: pageData,
		Targets:  targetViews,
	}

	h.renderTempl(w, r, ssltpl.TargetList(data))
}

// ============================================================================
// Create
// ============================================================================

// SSLTargetNewTempl renders the new SSL target form.
func (h *Handler) SSLTargetNewTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireSSLObsSvc(w, r)
	if svc == nil {
		return
	}
	pageData := h.prepareTemplPageData(r, "New SSL Target", "ssl")
	h.renderTempl(w, r, ssltpl.NewTarget(ssltpl.NewTargetData{PageData: pageData}))
}

// SSLTargetCreateTempl handles POST /ssl/targets -- creates a new SSL target.
func (h *Handler) SSLTargetCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireSSLObsSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	hostID := h.getSSLHostID(r)

	port := 443
	if p := r.FormValue("port"); p != "" {
		if v, err := strconv.Atoi(p); err == nil && v > 0 && v <= 65535 {
			port = v
		}
	}

	input := models.CreateSSLTargetInput{
		Name:     r.FormValue("name"),
		Hostname: r.FormValue("hostname"),
		Port:     port,
	}

	if _, err := svc.CreateTarget(r.Context(), hostID, input); err != nil {
		pageData := h.prepareTemplPageData(r, "New SSL Target", "ssl")
		h.renderTempl(w, r, ssltpl.NewTarget(ssltpl.NewTargetData{
			PageData: pageData,
			Error:    "Failed to create target: " + err.Error(),
		}))
		return
	}

	http.Redirect(w, r, "/ssl/targets", http.StatusSeeOther)
}

// ============================================================================
// Detail
// ============================================================================

// SSLTargetDetailTempl renders the SSL target detail page.
func (h *Handler) SSLTargetDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireSSLObsSvc(w, r)
	if svc == nil {
		return
	}

	targetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The target ID is not valid.")
		return
	}

	target, err := svc.GetTarget(r.Context(), targetID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "The requested SSL target was not found.")
		return
	}

	latest, _ := svc.GetLatestScan(r.Context(), targetID)
	scans, _, _ := svc.ListScans(r.Context(), targetID, 20, 0)

	var latestView *ssltpl.ScanView
	if latest != nil {
		v := scanResultToView(*latest)
		latestView = &v
	}

	var historyViews []ssltpl.ScanView
	for _, s := range scans {
		historyViews = append(historyViews, scanResultToView(s))
	}

	pageData := h.prepareTemplPageData(r, "SSL: "+target.Name, "ssl")

	data := ssltpl.TargetDetailData{
		PageData:    pageData,
		Target:      targetToView(*target, latest),
		LatestScan:  latestView,
		ScanHistory: historyViews,
	}

	h.renderTempl(w, r, ssltpl.TargetDetail(data))
}

// ============================================================================
// Delete
// ============================================================================

// SSLTargetDeleteTempl handles DELETE /ssl/targets/{id}.
func (h *Handler) SSLTargetDeleteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireSSLObsSvc(w, r)
	if svc == nil {
		return
	}

	targetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid ID", http.StatusBadRequest)
		return
	}

	if err := svc.DeleteTarget(r.Context(), targetID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to delete target: "+err.Error())
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/ssl/targets")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/ssl/targets", http.StatusSeeOther)
}

// ============================================================================
// Scanning
// ============================================================================

// SSLScanTargetTempl handles POST /ssl/targets/{id}/scan.
func (h *Handler) SSLScanTargetTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireSSLObsSvc(w, r)
	if svc == nil {
		return
	}

	targetID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The target ID is not valid.")
		return
	}

	if _, err := svc.ScanTarget(r.Context(), targetID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Scan Failed", "Failed to scan target: "+err.Error())
		return
	}

	http.Redirect(w, r, "/ssl/targets/"+targetID.String(), http.StatusSeeOther)
}

// SSLScanAllTempl handles POST /ssl/scan-all.
func (h *Handler) SSLScanAllTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireSSLObsSvc(w, r)
	if svc == nil {
		return
	}

	hostID := h.getSSLHostID(r)

	if _, err := svc.ScanAll(r.Context(), hostID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Scan Failed", "Failed to scan all targets: "+err.Error())
		return
	}

	http.Redirect(w, r, "/ssl", http.StatusSeeOther)
}
