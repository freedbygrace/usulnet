// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	proxysvc "github.com/fr4nsys/usulnet/internal/services/proxy"
)

// proxyServiceAdapter implements ProxyService using the nginx-backed proxy service.
type proxyServiceAdapter struct {
	svc *proxysvc.Service
}

// newProxyServiceAdapter creates a new proxy service adapter.
func newProxyServiceAdapter(svc *proxysvc.Service) *proxyServiceAdapter {
	return &proxyServiceAdapter{svc: svc}
}

// ---- Proxy Hosts ----

func (a *proxyServiceAdapter) ListHosts(ctx context.Context) ([]ProxyHostView, error) {
	if a.svc == nil {
		return nil, fmt.Errorf("proxy service not configured")
	}

	hosts, err := a.svc.ListHosts(ctx)
	if err != nil {
		return nil, err
	}

	views := make([]ProxyHostView, 0, len(hosts))
	for _, h := range hosts {
		views = append(views, proxyHostToView(h))
	}
	return views, nil
}

func (a *proxyServiceAdapter) GetHost(ctx context.Context, id int) (*ProxyHostView, error) {
	// The web layer uses int IDs (legacy). We resolve UUID from hash.
	uid, err := a.resolveHostID(ctx, id)
	if err != nil {
		return nil, err
	}

	h, err := a.svc.GetHost(ctx, uid)
	if err != nil {
		return nil, err
	}

	v := proxyHostToView(h)
	return &v, nil
}

func (a *proxyServiceAdapter) CreateHost(ctx context.Context, v *ProxyHostView) error {
	// Resolve domains: use DomainNames if provided, else single Domain
	domains := v.DomainNames
	if len(domains) == 0 && v.Domain != "" {
		domains = []string{v.Domain}
	}

	// Map upstream scheme
	scheme := mapUpstreamScheme(v.ForwardScheme)

	// SSL mode
	sslMode := models.ProxySSLModeNone
	if v.SSLEnabled {
		sslMode = models.ProxySSLModeAuto
	}

	input := &models.CreateProxyHostInput{
		Name:              domains[0],
		Domains:           domains,
		UpstreamScheme:    scheme,
		UpstreamHost:      v.ForwardHost,
		UpstreamPort:      v.ForwardPort,
		SSLMode:           sslMode,
		SSLForceHTTPS:     v.SSLForced,
		EnableWebSocket:   v.AllowWebsocketUpgrade,
		EnableCompression: true,
		EnableHSTS:        v.HSTSEnabled,
		EnableHTTP2:       v.HTTP2Support,
		BlockExploits:     v.BlockExploits,
		CachingEnabled:    v.CachingEnabled,
		CustomNginxConfig: v.AdvancedConfig,
		HSTSSubdomains:    v.HSTSSubdomains,
		ContainerID:       v.ContainerID,
		ContainerName:     v.Container,
	}

	// Certificate ID
	if v.CertificateID > 0 {
		certUUID := a.resolveCertID(ctx, v.CertificateID)
		if certUUID != uuid.Nil {
			input.CertificateID = &certUUID
			input.SSLMode = models.ProxySSLModeCustom
		}
	}

	// Access list
	if v.AccessListID > 0 {
		aclUUID := a.resolveACLID(ctx, v.AccessListID)
		if aclUUID != uuid.Nil {
			input.AccessListID = &aclUUID
		}
	}

	_, err := a.svc.CreateHost(ctx, input, nil)
	if err != nil {
		return fmt.Errorf("createHost: create proxy host %q: %w", input.Name, err)
	}
	return nil
}

func (a *proxyServiceAdapter) UpdateHost(ctx context.Context, v *ProxyHostView) error {
	uid, err := a.resolveHostID(ctx, v.ID)
	if err != nil {
		return fmt.Errorf("updateHost: resolve host id %d: %w", v.ID, err)
	}

	// Resolve domains
	domains := v.DomainNames
	if len(domains) == 0 && v.Domain != "" {
		domains = []string{v.Domain}
	}

	scheme := mapUpstreamScheme(v.ForwardScheme)
	sslMode := models.ProxySSLModeNone
	if v.SSLEnabled {
		sslMode = models.ProxySSLModeAuto
	}

	// Certificate
	if v.CertificateID > 0 {
		certUUID := a.resolveCertID(ctx, v.CertificateID)
		if certUUID != uuid.Nil {
			sslMode = models.ProxySSLModeCustom
		}
	}

	name := domains[0]
	input := &models.UpdateProxyHostInput{
		Name:              &name,
		Domains:           domains,
		UpstreamScheme:    &scheme,
		UpstreamHost:      &v.ForwardHost,
		UpstreamPort:      &v.ForwardPort,
		SSLMode:           &sslMode,
		SSLForceHTTPS:     &v.SSLForced,
		Enabled:           &v.Enabled,
		EnableWebSocket:   &v.AllowWebsocketUpgrade,
		EnableHSTS:        &v.HSTSEnabled,
		EnableHTTP2:       &v.HTTP2Support,
		BlockExploits:     &v.BlockExploits,
		CachingEnabled:    &v.CachingEnabled,
		CustomNginxConfig: &v.AdvancedConfig,
		HSTSSubdomains:    &v.HSTSSubdomains,
	}

	// Access list
	if v.AccessListID > 0 {
		aclUUID := a.resolveACLID(ctx, v.AccessListID)
		if aclUUID != uuid.Nil {
			input.AccessListID = &aclUUID
		}
	}

	_, err = a.svc.UpdateHost(ctx, uid, input, nil)
	if err != nil {
		return fmt.Errorf("updateHost: update proxy host %q: %w", name, err)
	}
	return nil
}

func (a *proxyServiceAdapter) RemoveHost(ctx context.Context, id int) error {
	uid, err := a.resolveHostID(ctx, id)
	if err != nil {
		return fmt.Errorf("removeHost: resolve host id %d: %w", id, err)
	}
	return a.svc.DeleteHost(ctx, uid, nil)
}

func (a *proxyServiceAdapter) EnableHost(ctx context.Context, id int) error {
	uid, err := a.resolveHostID(ctx, id)
	if err != nil {
		return fmt.Errorf("enableHost: resolve host id %d: %w", id, err)
	}
	return a.svc.EnableHost(ctx, uid, nil)
}

func (a *proxyServiceAdapter) DisableHost(ctx context.Context, id int) error {
	uid, err := a.resolveHostID(ctx, id)
	if err != nil {
		return fmt.Errorf("disableHost: resolve host id %d: %w", id, err)
	}
	return a.svc.DisableHost(ctx, uid, nil)
}

func (a *proxyServiceAdapter) Sync(ctx context.Context) error {
	return a.svc.Sync(ctx)
}

// ---- Redirections ----

func (a *proxyServiceAdapter) ListRedirections(ctx context.Context) ([]RedirectionHostView, error) {
	list, err := a.svc.ListRedirections(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]RedirectionHostView, 0, len(list))
	for _, rd := range list {
		views = append(views, RedirectionHostView{
			ID:              hashUUIDToInt(rd.ID),
			DomainNames:     rd.Domains,
			ForwardScheme:   rd.ForwardScheme,
			ForwardDomain:   rd.ForwardDomain,
			ForwardHTTPCode: rd.ForwardHTTPCode,
			PreservePath:    rd.PreservePath,
			SSLForced:       rd.SSLForceHTTPS,
			CertificateID:   a.certUUIDToInt(rd.CertificateID),
			Enabled:         rd.Enabled,
		})
	}
	return views, nil
}

func (a *proxyServiceAdapter) GetRedirection(ctx context.Context, id int) (*RedirectionHostView, error) {
	uid, err := a.resolveRedirectionID(ctx, id)
	if err != nil {
		return nil, err
	}
	rd, err := a.svc.GetRedirection(ctx, uid)
	if err != nil {
		return nil, err
	}
	v := &RedirectionHostView{
		ID:              hashUUIDToInt(rd.ID),
		DomainNames:     rd.Domains,
		ForwardScheme:   rd.ForwardScheme,
		ForwardDomain:   rd.ForwardDomain,
		ForwardHTTPCode: rd.ForwardHTTPCode,
		PreservePath:    rd.PreservePath,
		SSLForced:       rd.SSLForceHTTPS,
		CertificateID:   a.certUUIDToInt(rd.CertificateID),
		Enabled:         rd.Enabled,
	}
	return v, nil
}

func (a *proxyServiceAdapter) CreateRedirection(ctx context.Context, r *RedirectionHostView) error {
	sslMode := models.ProxySSLModeNone
	if r.SSLForced {
		sslMode = models.ProxySSLModeAuto
	}
	rd := &models.ProxyRedirection{
		Domains:         r.DomainNames,
		ForwardScheme:   r.ForwardScheme,
		ForwardDomain:   r.ForwardDomain,
		ForwardHTTPCode: r.ForwardHTTPCode,
		PreservePath:    r.PreservePath,
		SSLMode:         sslMode,
		SSLForceHTTPS:   r.SSLForced,
		Enabled:         true,
	}
	return a.svc.CreateRedirection(ctx, rd, nil)
}

func (a *proxyServiceAdapter) UpdateRedirection(ctx context.Context, r *RedirectionHostView) error {
	uid, err := a.resolveRedirectionID(ctx, r.ID)
	if err != nil {
		return err
	}
	sslMode := models.ProxySSLModeNone
	if r.SSLForced {
		sslMode = models.ProxySSLModeAuto
	}
	existing, err := a.svc.GetRedirection(ctx, uid)
	if err != nil {
		return err
	}
	existing.Domains = r.DomainNames
	existing.ForwardScheme = r.ForwardScheme
	existing.ForwardDomain = r.ForwardDomain
	existing.ForwardHTTPCode = r.ForwardHTTPCode
	existing.PreservePath = r.PreservePath
	existing.SSLMode = sslMode
	existing.SSLForceHTTPS = r.SSLForced
	existing.Enabled = r.Enabled
	return a.svc.UpdateRedirection(ctx, existing, nil)
}

func (a *proxyServiceAdapter) DeleteRedirection(ctx context.Context, id int) error {
	uid, err := a.resolveRedirectionID(ctx, id)
	if err != nil {
		return err
	}
	return a.svc.DeleteRedirection(ctx, uid, nil)
}

// ---- Streams ----

func (a *proxyServiceAdapter) ListStreams(ctx context.Context) ([]StreamView, error) {
	list, err := a.svc.ListStreams(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]StreamView, 0, len(list))
	for _, s := range list {
		views = append(views, StreamView{
			ID:             hashUUIDToInt(s.ID),
			IncomingPort:   s.IncomingPort,
			ForwardingHost: s.ForwardingHost,
			ForwardingPort: s.ForwardingPort,
			TCPForwarding:  s.TCPForwarding,
			UDPForwarding:  s.UDPForwarding,
			Enabled:        s.Enabled,
		})
	}
	return views, nil
}

func (a *proxyServiceAdapter) GetStream(ctx context.Context, id int) (*StreamView, error) {
	uid, err := a.resolveStreamID(ctx, id)
	if err != nil {
		return nil, err
	}
	s, err := a.svc.GetStream(ctx, uid)
	if err != nil {
		return nil, err
	}
	v := &StreamView{
		ID:             hashUUIDToInt(s.ID),
		IncomingPort:   s.IncomingPort,
		ForwardingHost: s.ForwardingHost,
		ForwardingPort: s.ForwardingPort,
		TCPForwarding:  s.TCPForwarding,
		UDPForwarding:  s.UDPForwarding,
		Enabled:        s.Enabled,
	}
	return v, nil
}

func (a *proxyServiceAdapter) CreateStream(ctx context.Context, sv *StreamView) error {
	st := &models.ProxyStream{
		IncomingPort:   sv.IncomingPort,
		ForwardingHost: sv.ForwardingHost,
		ForwardingPort: sv.ForwardingPort,
		TCPForwarding:  sv.TCPForwarding,
		UDPForwarding:  sv.UDPForwarding,
		Enabled:        true,
	}
	return a.svc.CreateStream(ctx, st, nil)
}

func (a *proxyServiceAdapter) UpdateStream(ctx context.Context, sv *StreamView) error {
	uid, err := a.resolveStreamID(ctx, sv.ID)
	if err != nil {
		return err
	}
	existing, err := a.svc.GetStream(ctx, uid)
	if err != nil {
		return err
	}
	existing.IncomingPort = sv.IncomingPort
	existing.ForwardingHost = sv.ForwardingHost
	existing.ForwardingPort = sv.ForwardingPort
	existing.TCPForwarding = sv.TCPForwarding
	existing.UDPForwarding = sv.UDPForwarding
	existing.Enabled = sv.Enabled
	return a.svc.UpdateStream(ctx, existing, nil)
}

func (a *proxyServiceAdapter) DeleteStream(ctx context.Context, id int) error {
	uid, err := a.resolveStreamID(ctx, id)
	if err != nil {
		return err
	}
	return a.svc.DeleteStream(ctx, uid, nil)
}

// ---- Dead Hosts ----

func (a *proxyServiceAdapter) ListDeadHosts(ctx context.Context) ([]DeadHostView, error) {
	list, err := a.svc.ListDeadHosts(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]DeadHostView, 0, len(list))
	for _, d := range list {
		views = append(views, DeadHostView{
			ID:          hashUUIDToInt(d.ID),
			DomainNames: d.Domains,
			SSLForced:   d.SSLForceHTTPS,
			CertID:      a.certUUIDToInt(d.CertificateID),
			Enabled:     d.Enabled,
		})
	}
	return views, nil
}

func (a *proxyServiceAdapter) CreateDeadHost(ctx context.Context, dv *DeadHostView) error {
	sslMode := models.ProxySSLModeNone
	if dv.SSLForced {
		sslMode = models.ProxySSLModeAuto
	}
	d := &models.ProxyDeadHost{
		Domains:       dv.DomainNames,
		SSLMode:       sslMode,
		SSLForceHTTPS: dv.SSLForced,
		Enabled:       true,
	}
	return a.svc.CreateDeadHost(ctx, d, nil)
}

func (a *proxyServiceAdapter) DeleteDeadHost(ctx context.Context, id int) error {
	uid, err := a.resolveDeadHostID(ctx, id)
	if err != nil {
		return err
	}
	return a.svc.DeleteDeadHost(ctx, uid, nil)
}

// ---- Certificates ----

func (a *proxyServiceAdapter) ListCertificates(ctx context.Context) ([]CertificateView, error) {
	certs, err := a.svc.ListCertificates(ctx)
	if err != nil {
		return nil, err
	}

	views := make([]CertificateView, 0, len(certs))
	for i, c := range certs {
		expires := ""
		if c.ExpiresAt != nil {
			expires = c.ExpiresAt.Format("2006-01-02")
		}
		views = append(views, CertificateView{
			ID:          i + 1,
			NiceName:    c.Name,
			Provider:    c.Provider,
			DomainNames: c.Domains,
			ExpiresOn:   expires,
		})
	}
	return views, nil
}

func (a *proxyServiceAdapter) GetCertificate(ctx context.Context, id int) (*CertificateView, error) {
	certs, err := a.svc.ListCertificates(ctx)
	if err != nil {
		return nil, err
	}
	idx := id - 1
	if idx < 0 || idx >= len(certs) {
		return nil, fmt.Errorf("certificate not found")
	}
	c := certs[idx]
	expires := ""
	if c.ExpiresAt != nil {
		expires = c.ExpiresAt.Format("2006-01-02")
	}
	return &CertificateView{
		ID:          id,
		NiceName:    c.Name,
		Provider:    c.Provider,
		DomainNames: c.Domains,
		ExpiresOn:   expires,
	}, nil
}

func (a *proxyServiceAdapter) RequestLECertificate(ctx context.Context, domains []string, email string, agree bool, dnsChallenge bool, dnsProvider, dnsCredentials string, propagation int) error {
	// Resolve DNS provider for DNS-01 challenge (wildcards)
	var dnsProv *models.ProxyDNSProvider
	if dnsChallenge && dnsProvider != "" {
		dnsProv = &models.ProxyDNSProvider{
			Provider:    dnsProvider,
			APIToken:    dnsCredentials,
			Propagation: propagation,
		}
	}

	certPEM, keyPEM, err := a.svc.RequestLECertificate(ctx, domains, email, dnsProv)
	if err != nil {
		return fmt.Errorf("requestLECertificate: request certificate for %v: %w", domains, err)
	}
	// If the backend returned a certificate, store it in the database
	if certPEM != "" && keyPEM != "" {
		_, err = a.svc.UploadCertificate(ctx, domains[0], domains, certPEM, keyPEM, "", nil)
		if err != nil {
			return fmt.Errorf("store LE certificate: %w", err)
		}
	}
	// Sync to apply the new certificate
	return a.svc.Sync(ctx)
}

func (a *proxyServiceAdapter) UploadCustomCertificate(ctx context.Context, niceName string, cert, key, intermediate []byte) error {
	_, err := a.svc.UploadCertificate(ctx, niceName, nil, string(cert), string(key), string(intermediate), nil)
	if err != nil {
		return fmt.Errorf("uploadCustomCertificate: upload certificate %q: %w", niceName, err)
	}
	return nil
}

func (a *proxyServiceAdapter) RenewCertificate(ctx context.Context, id int) error {
	certs, err := a.svc.ListCertificates(ctx)
	if err != nil {
		return fmt.Errorf("renewCertificate: list certificates: %w", err)
	}
	idx := id - 1
	if idx < 0 || idx >= len(certs) {
		return fmt.Errorf("certificate not found")
	}
	cert := certs[idx]
	if cert.Provider == "custom" {
		return fmt.Errorf("cannot auto-renew custom certificates")
	}
	_, _, err = a.svc.RenewLECertificate(ctx, cert.Domains, "", nil)
	if err != nil {
		return fmt.Errorf("renewCertificate: renew certificate %d: %w", id, err)
	}
	return nil
}

func (a *proxyServiceAdapter) DeleteCertificate(ctx context.Context, id int) error {
	certs, err := a.svc.ListCertificates(ctx)
	if err != nil {
		return fmt.Errorf("deleteCertificate: list certificates: %w", err)
	}
	idx := id - 1
	if idx < 0 || idx >= len(certs) {
		return fmt.Errorf("certificate not found")
	}
	return a.svc.DeleteCertificate(ctx, certs[idx].ID, nil)
}

// ---- Access Lists ----

func (a *proxyServiceAdapter) ListAccessLists(ctx context.Context) ([]AccessListView, error) {
	list, err := a.svc.ListAccessLists(ctx)
	if err != nil {
		return nil, err
	}
	views := make([]AccessListView, 0, len(list))
	for _, al := range list {
		views = append(views, AccessListView{
			ID:          hashUUIDToInt(al.ID),
			Name:        al.Name,
			SatisfyAny:  al.SatisfyAny,
			PassAuth:    al.PassAuth,
			ItemCount:   len(al.Items),
			ClientCount: len(al.Clients),
		})
	}
	return views, nil
}

func (a *proxyServiceAdapter) GetAccessList(ctx context.Context, id int) (*AccessListDetailView, error) {
	uid, err := a.resolveACLID2(ctx, id)
	if err != nil {
		return nil, err
	}
	al, err := a.svc.GetAccessList(ctx, uid)
	if err != nil {
		return nil, err
	}
	v := &AccessListDetailView{
		ID:         hashUUIDToInt(al.ID),
		Name:       al.Name,
		SatisfyAny: al.SatisfyAny,
		PassAuth:   al.PassAuth,
	}
	for _, item := range al.Items {
		v.Items = append(v.Items, AccessListItemView{
			Username: item.Username,
			Password: "", // Never expose hash
		})
	}
	for _, c := range al.Clients {
		v.Clients = append(v.Clients, AccessListClientView{
			Address:   c.Address,
			Directive: c.Directive,
		})
	}
	return v, nil
}

func (a *proxyServiceAdapter) CreateAccessList(ctx context.Context, av *AccessListDetailView) error {
	al := &models.ProxyAccessList{
		Name:       av.Name,
		SatisfyAny: av.SatisfyAny,
		PassAuth:   av.PassAuth,
		Enabled:    true,
	}
	for _, item := range av.Items {
		al.Items = append(al.Items, models.ProxyAccessListAuth{
			Username:     item.Username,
			PasswordHash: hashPassword(item.Password),
		})
	}
	for _, c := range av.Clients {
		directive := c.Directive
		if directive == "" {
			directive = "allow"
		}
		al.Clients = append(al.Clients, models.ProxyAccessListClient{
			Address:   c.Address,
			Directive: directive,
		})
	}
	return a.svc.CreateAccessList(ctx, al, nil)
}

func (a *proxyServiceAdapter) UpdateAccessList(ctx context.Context, av *AccessListDetailView) error {
	uid, err := a.resolveACLID2(ctx, av.ID)
	if err != nil {
		return err
	}
	al := &models.ProxyAccessList{
		ID:         uid,
		Name:       av.Name,
		SatisfyAny: av.SatisfyAny,
		PassAuth:   av.PassAuth,
		Enabled:    true,
	}
	for _, item := range av.Items {
		al.Items = append(al.Items, models.ProxyAccessListAuth{
			Username:     item.Username,
			PasswordHash: hashPassword(item.Password),
		})
	}
	for _, c := range av.Clients {
		directive := c.Directive
		if directive == "" {
			directive = "allow"
		}
		al.Clients = append(al.Clients, models.ProxyAccessListClient{
			Address:   c.Address,
			Directive: directive,
		})
	}
	return a.svc.UpdateAccessList(ctx, al, nil)
}

func (a *proxyServiceAdapter) DeleteAccessList(ctx context.Context, id int) error {
	uid, err := a.resolveACLID2(ctx, id)
	if err != nil {
		return err
	}
	return a.svc.DeleteAccessList(ctx, uid, nil)
}

// ---- Audit ----

func (a *proxyServiceAdapter) ListAuditLogs(ctx context.Context, limit, offset int) ([]AuditLogView, int, error) {
	entries, total, err := a.svc.ListAuditLogs(ctx, limit, offset)
	if err != nil {
		return nil, 0, err
	}

	views := make([]AuditLogView, 0, len(entries))
	for _, e := range entries {
		userID := ""
		if e.UserID != nil {
			userID = e.UserID.String()
		}
		views = append(views, AuditLogView{
			ID:           e.ID.String(),
			Operation:    e.Action,
			ResourceType: e.ResourceType,
			ResourceID:   hashUUIDToInt(e.ResourceID),
			ResourceName: e.ResourceName,
			UserName:     userID,
			CreatedAt:    e.CreatedAt.Format("2006-01-02 15:04:05"),
		})
	}
	return views, total, nil
}

// ---- Connection management (nginx: simplified) ----

func (a *proxyServiceAdapter) GetConnection(ctx context.Context) (*ProxyConnection, error) {
	healthy, _ := a.svc.BackendHealthy(ctx)
	status := "unhealthy"
	if healthy {
		status = "healthy"
	}

	mode := a.svc.BackendMode()
	return &ProxyConnection{
		ID:           mode,
		BaseURL:      mode,
		IsEnabled:    true,
		HealthStatus: status,
	}, nil
}

func (a *proxyServiceAdapter) SetupConnection(ctx context.Context, baseURL, email, password, userID string) error {
	return nil
}

func (a *proxyServiceAdapter) UpdateConnectionConfig(ctx context.Context, connID string, baseURL, email, password *string, enabled *bool, userID string) error {
	return nil
}

func (a *proxyServiceAdapter) DeleteConnection(ctx context.Context, connID string) error {
	return nil
}

func (a *proxyServiceAdapter) IsConnected(ctx context.Context) bool {
	healthy, _ := a.svc.BackendHealthy(ctx)
	return healthy
}

func (a *proxyServiceAdapter) Mode() string {
	return a.svc.BackendMode()
}

// ---- UUID resolution helpers ----

// resolveHostID maps a legacy int ID (produced by hashUUIDToInt) back to a UUID.
func (a *proxyServiceAdapter) resolveHostID(ctx context.Context, id int) (uuid.UUID, error) {
	hosts, err := a.svc.ListHosts(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	for _, h := range hosts {
		if hashUUIDToInt(h.ID) == id {
			return h.ID, nil
		}
	}
	return uuid.Nil, fmt.Errorf("proxy host not found: id %d", id)
}

func (a *proxyServiceAdapter) resolveRedirectionID(ctx context.Context, id int) (uuid.UUID, error) {
	list, err := a.svc.ListRedirections(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	for _, rd := range list {
		if hashUUIDToInt(rd.ID) == id {
			return rd.ID, nil
		}
	}
	return uuid.Nil, fmt.Errorf("redirection not found: id %d", id)
}

func (a *proxyServiceAdapter) resolveStreamID(ctx context.Context, id int) (uuid.UUID, error) {
	list, err := a.svc.ListStreams(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	for _, s := range list {
		if hashUUIDToInt(s.ID) == id {
			return s.ID, nil
		}
	}
	return uuid.Nil, fmt.Errorf("stream not found: id %d", id)
}

func (a *proxyServiceAdapter) resolveDeadHostID(ctx context.Context, id int) (uuid.UUID, error) {
	list, err := a.svc.ListDeadHosts(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	for _, d := range list {
		if hashUUIDToInt(d.ID) == id {
			return d.ID, nil
		}
	}
	return uuid.Nil, fmt.Errorf("dead host not found: id %d", id)
}

func (a *proxyServiceAdapter) resolveACLID(ctx context.Context, id int) uuid.UUID {
	list, err := a.svc.ListAccessLists(ctx)
	if err != nil {
		return uuid.Nil
	}
	for _, al := range list {
		if hashUUIDToInt(al.ID) == id {
			return al.ID
		}
	}
	return uuid.Nil
}

func (a *proxyServiceAdapter) resolveACLID2(ctx context.Context, id int) (uuid.UUID, error) {
	uid := a.resolveACLID(ctx, id)
	if uid == uuid.Nil {
		return uuid.Nil, fmt.Errorf("access list not found: id %d", id)
	}
	return uid, nil
}

func (a *proxyServiceAdapter) resolveCertID(ctx context.Context, id int) uuid.UUID {
	certs, err := a.svc.ListCertificates(ctx)
	if err != nil {
		return uuid.Nil
	}
	idx := id - 1
	if idx < 0 || idx >= len(certs) {
		return uuid.Nil
	}
	return certs[idx].ID
}

func (a *proxyServiceAdapter) certUUIDToInt(id *uuid.UUID) int {
	if id == nil {
		return 0
	}
	return hashUUIDToInt(*id)
}

// ---- Conversion helpers ----

// proxyHostToView converts a ProxyHost model to the legacy ProxyHostView.
func proxyHostToView(h *models.ProxyHost) ProxyHostView {
	domain := ""
	if len(h.Domains) > 0 {
		domain = h.Domains[0]
	}

	schemeStr := "http"
	switch h.UpstreamScheme {
	case models.ProxyUpstreamHTTPS:
		schemeStr = "https"
	case models.ProxyUpstreamH2C:
		schemeStr = "h2c"
	}

	return ProxyHostView{
		ID:                    hashUUIDToInt(h.ID),
		DomainNames:          h.Domains,
		Domain:                domain,
		ForwardScheme:         schemeStr,
		ForwardHost:           h.UpstreamHost,
		ForwardPort:           h.UpstreamPort,
		SSLEnabled:            h.SSLMode != models.ProxySSLModeNone,
		SSLForced:             h.SSLForceHTTPS,
		HSTSEnabled:           h.EnableHSTS,
		HSTSSubdomains:        h.HSTSSubdomains,
		HTTP2Support:          h.EnableHTTP2,
		BlockExploits:         h.BlockExploits,
		CachingEnabled:        h.CachingEnabled,
		AllowWebsocketUpgrade: h.EnableWebSocket,
		AdvancedConfig:        h.CustomNginxConfig,
		Enabled:               h.Enabled,
		ContainerID:           h.ContainerID,
		Container:             h.ContainerName,
		CreatedOn:             h.CreatedAt.Format("2006-01-02 15:04:05"),
		ModifiedOn:            h.UpdatedAt.Format("2006-01-02 15:04:05"),
	}
}

// mapUpstreamScheme maps a string scheme to the ProxyUpstreamScheme type.
func mapUpstreamScheme(s string) models.ProxyUpstreamScheme {
	switch strings.ToLower(s) {
	case "https":
		return models.ProxyUpstreamHTTPS
	case "h2c":
		return models.ProxyUpstreamH2C
	default:
		return models.ProxyUpstreamHTTP
	}
}

// hashPassword creates a simple hash for access list passwords.
// In production this should use bcrypt, but for now we store as-is
// and the nginx htpasswd generation will handle proper hashing.
func hashPassword(password string) string {
	if password == "" {
		return ""
	}
	return password // Will be bcrypt-hashed when generating htpasswd file
}

// hashUUIDToInt generates a deterministic positive int from a UUID.
// Used for backwards compatibility with templates that expect int IDs.
func hashUUIDToInt(id uuid.UUID) int {
	// Use first 4 bytes as uint32, ensure positive
	b := id[:]
	n := int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
	if n < 0 {
		n = -n
	}
	if n == 0 {
		n = 1
	}
	return n
}
