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
	wireguardsvc "github.com/fr4nsys/usulnet/internal/services/wireguard"
	wgtpl "github.com/fr4nsys/usulnet/internal/web/templates/pages/wireguard"
)

// requireWireGuardSvc returns the WireGuard service or renders a "not configured" error.
func (h *Handler) requireWireGuardSvc(w http.ResponseWriter, r *http.Request) *wireguardsvc.Service {
	svc := h.services.WireGuard()
	if svc == nil {
		h.RenderErrorTempl(w, r, http.StatusServiceUnavailable, "WireGuard Not Configured", "The WireGuard VPN service is not enabled.")
		return nil
	}
	return svc
}

// getWGHostID resolves the active host ID for WireGuard operations.
func (h *Handler) getWGHostID(r *http.Request) uuid.UUID {
	if reg, ok := h.services.(*ServiceRegistry); ok {
		return resolveHostID(r.Context(), reg.defaultHostID)
	}
	return uuid.Nil
}

// ============================================================================
// Interface List
// ============================================================================

// WireGuardListTempl renders the WireGuard interfaces list page.
func (h *Handler) WireGuardListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getWGHostID(r)
	pageData := h.prepareTemplPageData(r, "WireGuard VPN", "wireguard")

	interfaces, err := svc.ListInterfaces(ctx, hostID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load interfaces: "+err.Error())
		return
	}

	stats, _ := svc.GetStats(ctx, hostID)

	var views []wgtpl.InterfaceView
	for _, iface := range interfaces {
		views = append(views, interfaceToView(iface))
	}

	statsView := wgtpl.StatsView{}
	if stats != nil {
		statsView.TotalInterfaces = stats.TotalInterfaces
		statsView.ActiveInterfaces = stats.ActiveInterfaces
		statsView.TotalPeers = stats.TotalPeers
		statsView.ConnectedPeers = stats.ConnectedPeers
		statsView.TotalRx = formatBytes(stats.TotalRx)
		statsView.TotalTx = formatBytes(stats.TotalTx)
	}

	data := wgtpl.ListData{
		PageData:   pageData,
		Interfaces: views,
		Stats:      statsView,
	}
	wgtpl.List(data).Render(ctx, w)
}

// ============================================================================
// Interface Detail
// ============================================================================

// WireGuardDetailTempl renders the WireGuard interface detail page.
func (h *Handler) WireGuardDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	pageData := h.prepareTemplPageData(r, "WireGuard VPN", "wireguard")

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusBadRequest, "Invalid ID", "")
		return
	}

	iface, err := svc.GetInterface(ctx, id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Interface not found.")
		return
	}

	peers, err := svc.ListPeers(ctx, id)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load peers: "+err.Error())
		return
	}

	var peerViews []wgtpl.PeerView
	for _, p := range peers {
		peerViews = append(peerViews, peerToView(p))
	}

	data := wgtpl.DetailData{
		PageData:  pageData,
		Interface: interfaceToView(iface),
		Peers:     peerViews,
	}
	wgtpl.Detail(data).Render(ctx, w)
}

// ============================================================================
// New Interface
// ============================================================================

// WireGuardNewTempl renders the new WireGuard interface form.
func (h *Handler) WireGuardNewTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}
	pageData := h.prepareTemplPageData(r, "New WireGuard Interface", "wireguard")
	wgtpl.New(wgtpl.NewData{PageData: pageData}).Render(r.Context(), w)
}

// WireGuardCreateTempl handles the new WireGuard interface form submission.
func (h *Handler) WireGuardCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/wireguard", http.StatusSeeOther)
		return
	}

	hostID := h.getWGHostID(r)
	port := 51820
	if p, err := strconv.Atoi(r.FormValue("listen_port")); err == nil && p > 0 {
		port = p
	}
	mtu := 1420
	if m, err := strconv.Atoi(r.FormValue("mtu")); err == nil && m > 0 {
		mtu = m
	}

	iface := &models.WireGuardInterface{
		HostID:      hostID,
		Name:        r.FormValue("name"),
		DisplayName: r.FormValue("display_name"),
		Description: r.FormValue("description"),
		ListenPort:  port,
		Address:     r.FormValue("address"),
		DNS:         r.FormValue("dns"),
		MTU:         mtu,
		PostUp:      r.FormValue("post_up"),
		PostDown:    r.FormValue("post_down"),
	}

	if err := svc.CreateInterface(r.Context(), iface); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to create interface: "+err.Error())
		return
	}

	http.Redirect(w, r, "/wireguard/"+iface.ID.String(), http.StatusSeeOther)
}

// WireGuardDeleteTempl handles deleting a WireGuard interface.
func (h *Handler) WireGuardDeleteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Redirect(w, r, "/wireguard", http.StatusSeeOther)
		return
	}
	_ = svc.DeleteInterface(r.Context(), id)
	http.Redirect(w, r, "/wireguard", http.StatusSeeOther)
}

// ============================================================================
// Peers
// ============================================================================

// WireGuardPeerListTempl renders all peers across interfaces.
func (h *Handler) WireGuardPeerListTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}
	ctx := r.Context()
	hostID := h.getWGHostID(r)
	pageData := h.prepareTemplPageData(r, "WireGuard Peers", "wireguard")

	peers, total, err := svc.ListHostPeers(ctx, hostID, 100, 0)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to load peers: "+err.Error())
		return
	}

	var views []wgtpl.PeerView
	for _, p := range peers {
		views = append(views, peerToView(p))
	}

	data := wgtpl.PeerListData{
		PageData: pageData,
		Peers:    views,
		Total:    total,
	}
	wgtpl.PeerList(data).Render(ctx, w)
}

// WireGuardPeerNewTempl renders the new peer form.
func (h *Handler) WireGuardPeerNewTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}

	ifaceID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Redirect(w, r, "/wireguard", http.StatusSeeOther)
		return
	}

	iface, err := svc.GetInterface(r.Context(), ifaceID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Interface not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Add Peer", "wireguard")
	data := wgtpl.PeerNewData{
		PageData:      pageData,
		InterfaceID:   ifaceID.String(),
		InterfaceName: iface.DisplayName,
	}
	wgtpl.PeerNew(data).Render(r.Context(), w)
}

// WireGuardPeerCreateTempl handles the new peer form submission.
func (h *Handler) WireGuardPeerCreateTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/wireguard", http.StatusSeeOther)
		return
	}

	ifaceID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		http.Redirect(w, r, "/wireguard", http.StatusSeeOther)
		return
	}

	hostID := h.getWGHostID(r)
	keepalive := 25
	if k, err := strconv.Atoi(r.FormValue("persistent_keepalive")); err == nil {
		keepalive = k
	}

	peer := &models.WireGuardPeer{
		InterfaceID:         ifaceID,
		HostID:              hostID,
		Name:                r.FormValue("name"),
		Description:         r.FormValue("description"),
		PublicKey:           r.FormValue("public_key"),
		AllowedIPs:          r.FormValue("allowed_ips"),
		Endpoint:            r.FormValue("endpoint"),
		PersistentKeepalive: keepalive,
		Enabled:             true,
	}

	if err := svc.CreatePeer(r.Context(), peer); err != nil {
		h.RenderErrorTempl(w, r, http.StatusInternalServerError, "Error", "Failed to create peer: "+err.Error())
		return
	}

	http.Redirect(w, r, "/wireguard/"+ifaceID.String(), http.StatusSeeOther)
}

// WireGuardPeerDetailTempl renders a peer's detail/config page.
func (h *Handler) WireGuardPeerDetailTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}

	peerID, err := uuid.Parse(chi.URLParam(r, "peerID"))
	if err != nil {
		http.Redirect(w, r, "/wireguard/peers", http.StatusSeeOther)
		return
	}

	peer, err := svc.GetPeer(r.Context(), peerID)
	if err != nil {
		h.RenderErrorTempl(w, r, http.StatusNotFound, "Not Found", "Peer not found.")
		return
	}

	pageData := h.prepareTemplPageData(r, "Peer: "+peer.Name, "wireguard")
	data := wgtpl.PeerDetailData{
		PageData: pageData,
		Peer:     peerToView(peer),
	}
	wgtpl.PeerDetail(data).Render(r.Context(), w)
}

// WireGuardPeerDeleteTempl handles deleting a peer.
func (h *Handler) WireGuardPeerDeleteTempl(w http.ResponseWriter, r *http.Request) {
	svc := h.requireWireGuardSvc(w, r)
	if svc == nil {
		return
	}
	peerID, err := uuid.Parse(chi.URLParam(r, "peerID"))
	if err != nil {
		http.Redirect(w, r, "/wireguard", http.StatusSeeOther)
		return
	}
	_ = svc.DeletePeer(r.Context(), peerID)
	http.Redirect(w, r, "/wireguard", http.StatusSeeOther)
}

// ============================================================================
// View helpers
// ============================================================================

func interfaceToView(iface *models.WireGuardInterface) wgtpl.InterfaceView {
	return wgtpl.InterfaceView{
		ID:          iface.ID.String(),
		Name:        iface.Name,
		DisplayName: iface.DisplayName,
		Address:     iface.Address,
		ListenPort:  iface.ListenPort,
		PublicKey:   iface.PublicKey,
		Status:      string(iface.Status),
		PeerCount:   iface.PeerCount,
		TransferRx:  formatBytes(iface.TransferRx),
		TransferTx:  formatBytes(iface.TransferTx),
		CreatedAt:   iface.CreatedAt.Format("2006-01-02 15:04"),
	}
}

func peerToView(p *models.WireGuardPeer) wgtpl.PeerView {
	v := wgtpl.PeerView{
		ID:                  p.ID.String(),
		Name:                p.Name,
		PublicKey:           p.PublicKey,
		AllowedIPs:          p.AllowedIPs,
		Endpoint:            p.Endpoint,
		PersistentKeepalive: p.PersistentKeepalive,
		Enabled:             p.Enabled,
		TransferRx:          formatBytes(p.TransferRx),
		TransferTx:          formatBytes(p.TransferTx),
		ConfigQR:            p.ConfigQR,
		CreatedAt:           p.CreatedAt.Format("2006-01-02 15:04"),
	}
	if p.LastHandshake != nil {
		v.LastHandshake = p.LastHandshake.Format("2006-01-02 15:04:05")
	}
	return v
}
