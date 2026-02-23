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
	dnssvc "github.com/fr4nsys/usulnet/internal/services/dns"
	dns "github.com/fr4nsys/usulnet/internal/web/templates/pages/dns"
)

// requireDNSSvc returns the DNS service or renders a "not configured" error.
func (h *Handler) requireDNSSvc(w http.ResponseWriter, r *http.Request) *dnssvc.Service {
	svc := h.services.DNS()
	if svc == nil {
		h.RenderErrorTempl(w, r, http.StatusServiceUnavailable, "DNS Not Configured", "The DNS server is not enabled. Set dns.enabled=true in your configuration.")
		return nil
	}
	return svc
}

// getDNSHostID resolves the active host ID for DNS operations.
func (h *Handler) getDNSHostID(r *http.Request) uuid.UUID {
	if reg, ok := h.services.(*ServiceRegistry); ok {
		return resolveHostID(r.Context(), reg.defaultHostID)
	}
	return uuid.Nil
}

// getUserUUID extracts the user UUID from context.
func (h *Handler) getUserUUID(r *http.Request) *uuid.UUID {
	user := GetUserFromContext(r.Context())
	if user == nil {
		return nil
	}
	id, err := uuid.Parse(user.ID)
	if err != nil {
		return nil
	}
	return &id
}

// ============================================================================
// Zone list
// ============================================================================

// DNSZonesTempl renders the DNS zones list page.
func (h *Handler) DNSZonesTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getDNSHostID(r)
	pageData := h.prepareTemplPageData(r, "DNS Server", "dns")

	zones, err := svc.ListZones(ctx, hostID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load DNS zones: "+err.Error())
		return
	}

	stats := svc.Stats()
	healthy, _ := svc.Healthy(ctx)

	var zoneViews []dns.ZoneView
	for _, z := range zones {
		records, _ := svc.ListRecords(ctx, z.ID)
		zoneViews = append(zoneViews, dns.ZoneView{
			ID:          z.ID.String(),
			Name:        z.Name,
			Kind:        string(z.Kind),
			Enabled:     z.Enabled,
			RecordCount: len(records),
			Serial:      z.Serial,
			TTL:         z.TTL,
			CreatedAt:   z.CreatedAt.Format("2006-01-02 15:04"),
		})
	}

	data := dns.ZoneListData{
		PageData: pageData,
		Zones:    zoneViews,
		Stats: dns.DNSStatsView{
			QueriesTotal:   stats.QueriesTotal,
			QueriesSuccess: stats.QueriesSuccess,
			QueriesFailed:  stats.QueriesFailed,
			ZonesLoaded:    stats.ZonesLoaded,
			Uptime:         stats.Uptime,
			Healthy:        healthy,
		},
	}

	h.renderTempl(w, r, dns.ZoneList(data))
}

// ============================================================================
// Zone CRUD
// ============================================================================

// DNSZoneNewTempl renders the new zone form.
func (h *Handler) DNSZoneNewTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	pageData := h.prepareTemplPageData(r, "New DNS Zone", "dns")
	h.renderTempl(w, r, dns.ZoneNew(dns.ZoneNewData{PageData: pageData}))
}

// DNSZoneCreateTempl handles POST /dns/zones — creates a new zone.
func (h *Handler) DNSZoneCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	hostID := h.getDNSHostID(r)
	userID := h.getUserUUID(r)

	ttl, _ := strconv.Atoi(r.FormValue("ttl"))
	if ttl <= 0 {
		ttl = 3600
	}

	zone := &models.DNSZone{
		HostID:      hostID,
		Name:        r.FormValue("name"),
		Kind:        models.DNSZoneKind(r.FormValue("kind")),
		Enabled:     true,
		TTL:         ttl,
		Serial:      1,
		Refresh:     3600,
		Retry:       900,
		Expire:      604800,
		MinimumTTL:  300,
		PrimaryNS:   r.FormValue("primary_ns"),
		AdminEmail:  r.FormValue("admin_email"),
		Description: r.FormValue("description"),
		CreatedBy:   userID,
		UpdatedBy:   userID,
	}

	if err := svc.CreateZone(ctx, zone); err != nil {
		pageData := h.prepareTemplPageData(r, "New DNS Zone", "dns")
		h.renderTempl(w, r, dns.ZoneNew(dns.ZoneNewData{
			PageData: pageData,
			Error:    "Failed to create zone: " + err.Error(),
		}))
		return
	}

	http.Redirect(w, r, "/dns", http.StatusSeeOther)
}

// DNSZoneDetailTempl renders the zone detail page with records.
func (h *Handler) DNSZoneDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()

	zoneID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The zone ID is not valid.")
		return
	}

	zone, err := svc.GetZone(ctx, zoneID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Zone Not Found", "The requested DNS zone was not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Zone: "+zone.Name, "dns")

	var recordViews []dns.RecordView
	for _, rec := range zone.Records {
		recordViews = append(recordViews, dns.RecordView{
			ID:       rec.ID.String(),
			Name:     rec.Name,
			Type:     string(rec.Type),
			TTL:      rec.TTL,
			Content:  rec.Content,
			Priority: rec.Priority,
			Weight:   rec.Weight,
			Port:     rec.Port,
			Enabled:  rec.Enabled,
			Comment:  rec.Comment,
		})
	}

	data := dns.ZoneDetailData{
		PageData: pageData,
		Zone: dns.ZoneFormView{
			ID:          zone.ID.String(),
			Name:        zone.Name,
			Kind:        string(zone.Kind),
			Enabled:     zone.Enabled,
			TTL:         zone.TTL,
			Refresh:     zone.Refresh,
			Retry:       zone.Retry,
			Expire:      zone.Expire,
			MinimumTTL:  zone.MinimumTTL,
			PrimaryNS:   zone.PrimaryNS,
			AdminEmail:  zone.AdminEmail,
			Description: zone.Description,
			Serial:      zone.Serial,
		},
		Records: recordViews,
	}

	h.renderTempl(w, r, dns.ZoneDetail(data))
}

// DNSZoneEditTempl renders the zone edit form.
func (h *Handler) DNSZoneEditTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()

	zoneID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The zone ID is not valid.")
		return
	}

	zone, err := svc.GetZone(ctx, zoneID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Zone Not Found", "The requested DNS zone was not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Edit Zone: "+zone.Name, "dns")

	data := dns.ZoneEditData{
		PageData: pageData,
		Zone: dns.ZoneFormView{
			ID:          zone.ID.String(),
			Name:        zone.Name,
			Kind:        string(zone.Kind),
			Enabled:     zone.Enabled,
			TTL:         zone.TTL,
			Refresh:     zone.Refresh,
			Retry:       zone.Retry,
			Expire:      zone.Expire,
			MinimumTTL:  zone.MinimumTTL,
			PrimaryNS:   zone.PrimaryNS,
			AdminEmail:  zone.AdminEmail,
			Description: zone.Description,
			Serial:      zone.Serial,
		},
	}

	h.renderTempl(w, r, dns.ZoneEdit(data))
}

// DNSZoneUpdateTempl handles POST /dns/zones/{id} — updates a zone.
func (h *Handler) DNSZoneUpdateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	zoneID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "The zone ID is not valid.")
		return
	}

	zone, err := svc.GetZone(ctx, zoneID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Zone Not Found", "The requested DNS zone was not found.")
		return
	}

	userID := h.getUserUUID(r)

	zone.Name = r.FormValue("name")
	zone.Kind = models.DNSZoneKind(r.FormValue("kind"))
	zone.Enabled = r.FormValue("enabled") == "on" || r.FormValue("enabled") == "true"
	zone.PrimaryNS = r.FormValue("primary_ns")
	zone.AdminEmail = r.FormValue("admin_email")
	zone.Description = r.FormValue("description")
	zone.UpdatedBy = userID

	if v, err := strconv.Atoi(r.FormValue("ttl")); err == nil && v > 0 {
		zone.TTL = v
	}
	if v, err := strconv.Atoi(r.FormValue("refresh")); err == nil && v > 0 {
		zone.Refresh = v
	}
	if v, err := strconv.Atoi(r.FormValue("retry")); err == nil && v > 0 {
		zone.Retry = v
	}
	if v, err := strconv.Atoi(r.FormValue("expire")); err == nil && v > 0 {
		zone.Expire = v
	}
	if v, err := strconv.Atoi(r.FormValue("minimum_ttl")); err == nil && v > 0 {
		zone.MinimumTTL = v
	}

	if err := svc.UpdateZone(ctx, zone); err != nil {
		pageData := h.prepareTemplPageData(r, "Edit Zone: "+zone.Name, "dns")
		h.renderTempl(w, r, dns.ZoneEdit(dns.ZoneEditData{
			PageData: pageData,
			Zone: dns.ZoneFormView{
				ID:          zone.ID.String(),
				Name:        zone.Name,
				Kind:        string(zone.Kind),
				Enabled:     zone.Enabled,
				TTL:         zone.TTL,
				Refresh:     zone.Refresh,
				Retry:       zone.Retry,
				Expire:      zone.Expire,
				MinimumTTL:  zone.MinimumTTL,
				PrimaryNS:   zone.PrimaryNS,
				AdminEmail:  zone.AdminEmail,
				Description: zone.Description,
				Serial:      zone.Serial,
			},
			Error: "Failed to update zone: " + err.Error(),
		}))
		return
	}

	http.Redirect(w, r, "/dns/zones/"+zoneID.String(), http.StatusSeeOther)
}

// DNSZoneDeleteTempl handles DELETE /dns/zones/{id}.
func (h *Handler) DNSZoneDeleteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()

	zoneID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid zone ID", http.StatusBadRequest)
		return
	}

	hostID := h.getDNSHostID(r)
	userID := h.getUserUUID(r)

	if err := svc.DeleteZone(ctx, hostID, zoneID, userID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to delete zone: "+err.Error())
		return
	}

	// For htmx DELETE requests, redirect via HX-Redirect header
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/dns")
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/dns", http.StatusSeeOther)
}

// ============================================================================
// Record CRUD
// ============================================================================

// DNSRecordCreateTempl handles POST /dns/zones/{zoneID}/records.
func (h *Handler) DNSRecordCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	zoneID, err := uuid.Parse(chi.URLParam(r, "zoneID"))
	if err != nil {
		http.Error(w, "Invalid zone ID", http.StatusBadRequest)
		return
	}

	hostID := h.getDNSHostID(r)
	userID := h.getUserUUID(r)

	ttl, _ := strconv.Atoi(r.FormValue("ttl"))
	if ttl <= 0 {
		ttl = 300
	}

	rec := &models.DNSRecord{
		ZoneID:  zoneID,
		HostID:  hostID,
		Name:    r.FormValue("name"),
		Type:    models.DNSRecordType(r.FormValue("type")),
		TTL:     ttl,
		Content: r.FormValue("content"),
		Enabled: true,
		Comment: r.FormValue("comment"),
	}

	if v := r.FormValue("priority"); v != "" {
		if prio, err := strconv.Atoi(v); err == nil {
			rec.Priority = &prio
		}
	}
	if v := r.FormValue("weight"); v != "" {
		if w, err := strconv.Atoi(v); err == nil {
			rec.Weight = &w
		}
	}
	if v := r.FormValue("port"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			rec.Port = &p
		}
	}

	if err := svc.CreateRecord(ctx, rec, userID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to create record: "+err.Error())
		return
	}

	http.Redirect(w, r, "/dns/zones/"+zoneID.String(), http.StatusSeeOther)
}

// DNSRecordEditTempl renders the record edit form.
func (h *Handler) DNSRecordEditTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()

	zoneID, err := uuid.Parse(chi.URLParam(r, "zoneID"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "Invalid zone ID.")
		return
	}

	recID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "Invalid record ID.")
		return
	}

	zone, err := svc.GetZone(ctx, zoneID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Zone Not Found", "The zone was not found.")
		return
	}

	rec, err := svc.GetRecord(ctx, recID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Record Not Found", "The record was not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Edit Record", "dns")

	data := dns.RecordEditData{
		PageData: pageData,
		ZoneID:   zoneID.String(),
		ZoneName: zone.Name,
		Record: dns.RecordView{
			ID:       rec.ID.String(),
			Name:     rec.Name,
			Type:     string(rec.Type),
			TTL:      rec.TTL,
			Content:  rec.Content,
			Priority: rec.Priority,
			Weight:   rec.Weight,
			Port:     rec.Port,
			Enabled:  rec.Enabled,
			Comment:  rec.Comment,
		},
	}

	h.renderTempl(w, r, dns.RecordEdit(data))
}

// DNSRecordUpdateTempl handles POST /dns/zones/{zoneID}/records/{id}.
func (h *Handler) DNSRecordUpdateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Error parsing form", http.StatusBadRequest)
		return
	}

	zoneID, err := uuid.Parse(chi.URLParam(r, "zoneID"))
	if err != nil {
		http.Error(w, "Invalid zone ID", http.StatusBadRequest)
		return
	}

	recID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid record ID", http.StatusBadRequest)
		return
	}

	rec, err := svc.GetRecord(ctx, recID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Record Not Found", "The record was not found.")
		return
	}

	userID := h.getUserUUID(r)

	rec.Name = r.FormValue("name")
	rec.Type = models.DNSRecordType(r.FormValue("type"))
	rec.Content = r.FormValue("content")
	rec.Comment = r.FormValue("comment")
	rec.Enabled = r.FormValue("enabled") == "on" || r.FormValue("enabled") == "true"

	if v, err := strconv.Atoi(r.FormValue("ttl")); err == nil && v > 0 {
		rec.TTL = v
	}

	rec.Priority = nil
	rec.Weight = nil
	rec.Port = nil

	if v := r.FormValue("priority"); v != "" {
		if prio, err := strconv.Atoi(v); err == nil {
			rec.Priority = &prio
		}
	}
	if v := r.FormValue("weight"); v != "" {
		if w, err := strconv.Atoi(v); err == nil {
			rec.Weight = &w
		}
	}
	if v := r.FormValue("port"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			rec.Port = &p
		}
	}

	if err := svc.UpdateRecord(ctx, rec, userID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to update record: "+err.Error())
		return
	}

	http.Redirect(w, r, "/dns/zones/"+zoneID.String(), http.StatusSeeOther)
}

// DNSRecordDeleteTempl handles DELETE /dns/zones/{zoneID}/records/{id}.
func (h *Handler) DNSRecordDeleteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()

	zoneID, err := uuid.Parse(chi.URLParam(r, "zoneID"))
	if err != nil {
		http.Error(w, "Invalid zone ID", http.StatusBadRequest)
		return
	}

	recID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Error(w, "Invalid record ID", http.StatusBadRequest)
		return
	}

	hostID := h.getDNSHostID(r)
	userID := h.getUserUUID(r)

	if err := svc.DeleteRecord(ctx, hostID, zoneID, recID, userID); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to delete record: "+err.Error())
		return
	}

	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", "/dns/zones/"+zoneID.String())
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, "/dns/zones/"+zoneID.String(), http.StatusSeeOther)
}

// ============================================================================
// Settings & Audit
// ============================================================================

// DNSSettingsTempl renders the DNS server settings page.
func (h *Handler) DNSSettingsTempl(w http.ResponseWriter, r *http.Request) {
	pageData := h.prepareTemplPageData(r, "DNS Settings", "dns")

	svc := h.services.DNS()
	if svc == nil {
		h.renderTempl(w, r, dns.Settings(dns.SettingsData{
			PageData: pageData,
			Enabled:  false,
		}))
		return
	}

	stats := svc.Stats()
	healthy, _ := svc.Healthy(r.Context())

	data := dns.SettingsData{
		PageData:   pageData,
		Enabled:    true,
		ListenAddr: svc.Backend().Mode(),
		Mode:       svc.Backend().Mode(),
		Stats: dns.DNSStatsView{
			QueriesTotal:   stats.QueriesTotal,
			QueriesSuccess: stats.QueriesSuccess,
			QueriesFailed:  stats.QueriesFailed,
			ZonesLoaded:    stats.ZonesLoaded,
			Uptime:         stats.Uptime,
			Healthy:        healthy,
		},
	}

	// Populate service discovery stats
	if discSvc := h.services.DNSDiscovery(); discSvc != nil {
		discStats := discSvc.Stats()
		data.Discovery = dns.DiscoveryView{
			Enabled:           discStats.Enabled,
			Domain:            discStats.Domain,
			TTL:               30, // from config
			CreateSRV:         true,
			TrackedContainers: discStats.TrackedContainers,
			TrackedRecords:    discStats.TrackedRecords,
		}
	}

	h.renderTempl(w, r, dns.Settings(data))
}

// DNSAuditTempl renders the DNS audit log page.
func (h *Handler) DNSAuditTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireDNSSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getDNSHostID(r)
	pageData := h.prepareTemplPageData(r, "DNS Audit Log", "dns")

	page := 1
	pageSize := 50
	if v := r.URL.Query().Get("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			page = p
		}
	}

	offset := (page - 1) * pageSize
	entries, total, err := svc.ListAuditLogs(ctx, hostID, pageSize, offset)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load audit logs: "+err.Error())
		return
	}

	var auditViews []dns.AuditEntry
	for _, e := range entries {
		userStr := ""
		if e.UserID != nil {
			userStr = e.UserID.String()
		}
		auditViews = append(auditViews, dns.AuditEntry{
			ID:           e.ID.String(),
			Action:       e.Action,
			ResourceType: e.ResourceType,
			ResourceName: e.ResourceName,
			Details:      e.Details,
			CreatedAt:    e.CreatedAt.Format("2006-01-02 15:04:05"),
			UserID:       userStr,
		})
	}

	data := dns.AuditData{
		PageData: pageData,
		Entries:  auditViews,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}

	h.renderTempl(w, r, dns.Audit(data))
}
