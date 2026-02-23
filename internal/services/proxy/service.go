// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package proxy provides the reverse proxy management service.
// It stores configuration in PostgreSQL (source of truth) and pushes
// the full configuration to the nginx backend on each change.
package proxy

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Config holds service configuration.
type Config struct {
	// ACMEEmail is the email used for Let's Encrypt registration.
	ACMEEmail string
	// ListenHTTP is the listen address for HTTP (default ":80").
	ListenHTTP string
	// ListenHTTPS is the listen address for HTTPS (default ":443").
	ListenHTTPS string
	// DefaultHostID is the usulnet host ID used when not multi-host.
	DefaultHostID uuid.UUID

}

// Service manages reverse proxy configuration.
type Service struct {
	hosts        HostRepository
	headers      HeaderRepository
	certs        CertificateRepository
	dns          DNSProviderRepository
	audit        AuditLogRepository
	redirections RedirectionRepository
	streams      StreamRepository
	deadHosts    DeadHostRepository
	accessLists  AccessListRepository
	locations    LocationRepository
	backend      SyncBackend
	enc          Encryptor
	cfg          Config
	logger       *logger.Logger

	// Sync mutex to prevent concurrent config pushes
	syncMu sync.Mutex
}

// NewService creates a new proxy service with the given backend.
func NewService(
	hosts HostRepository,
	headers HeaderRepository,
	certs CertificateRepository,
	dns DNSProviderRepository,
	audit AuditLogRepository,
	enc Encryptor,
	backend SyncBackend,
	cfg Config,
	log *logger.Logger,
) *Service {
	return &Service{
		hosts:   hosts,
		headers: headers,
		certs:   certs,
		dns:     dns,
		audit:   audit,
		backend: backend,
		enc:     enc,
		cfg:     cfg,
		logger:  log.Named("proxy"),
	}
}

// SetExtendedRepositories sets the optional extended repositories (redirections, streams, etc.).
// This allows backwards-compatible initialization — callers that don't have these repos
// can simply skip this call.
func (s *Service) SetExtendedRepositories(
	redirections RedirectionRepository,
	streams StreamRepository,
	deadHosts DeadHostRepository,
	accessLists AccessListRepository,
	locations LocationRepository,
) {
	s.redirections = redirections
	s.streams = streams
	s.deadHosts = deadHosts
	s.accessLists = accessLists
	s.locations = locations
}

// Backend returns the active sync backend.
func (s *Service) Backend() SyncBackend {
	return s.backend
}

// ============================================================================
// Proxy Host CRUD
// ============================================================================

// CreateHost creates a new proxy host and syncs the configuration.
func (s *Service) CreateHost(ctx context.Context, input *models.CreateProxyHostInput, userID *uuid.UUID) (*models.ProxyHost, error) {
	h := &models.ProxyHost{
		ID:                  uuid.New(),
		HostID:              s.cfg.DefaultHostID,
		Name:                input.Name,
		Domains:             input.Domains,
		Enabled:             true,
		Status:              models.ProxyHostStatusPending,
		UpstreamScheme:      input.UpstreamScheme,
		UpstreamHost:        input.UpstreamHost,
		UpstreamPort:        input.UpstreamPort,
		UpstreamPath:        input.UpstreamPath,
		SSLMode:             input.SSLMode,
		SSLForceHTTPS:       input.SSLForceHTTPS,
		CertificateID:       input.CertificateID,
		DNSProviderID:       input.DNSProviderID,
		EnableWebSocket:     input.EnableWebSocket,
		EnableCompression:   input.EnableCompression,
		EnableHSTS:          input.EnableHSTS,
		EnableHTTP2:         input.EnableHTTP2,
		BlockExploits:       input.BlockExploits,
		CachingEnabled:      input.CachingEnabled,
		CustomNginxConfig:   input.CustomNginxConfig,
		HSTSSubdomains:      input.HSTSSubdomains,
		AccessListID:        input.AccessListID,
		HealthCheckEnabled:  input.HealthCheckEnabled,
		HealthCheckPath:     input.HealthCheckPath,
		HealthCheckInterval: input.HealthCheckInterval,
		ContainerID:         input.ContainerID,
		ContainerName:       input.ContainerName,
		CreatedBy:           userID,
		UpdatedBy:           userID,
	}

	if err := s.hosts.Create(ctx, h); err != nil {
		return nil, fmt.Errorf("create proxy host: %w", err)
	}

	s.auditLog(ctx, h.HostID, userID, "create", "proxy_host", h.ID, h.Name, "")

	if err := s.Sync(ctx); err != nil {
		s.logger.Error("Failed to sync after create", "host_id", h.ID, "error", err)
		_ = s.hosts.UpdateStatus(ctx, h.ID, models.ProxyHostStatusError, err.Error())
		return h, nil // Return host even if sync fails
	}

	_ = s.hosts.UpdateStatus(ctx, h.ID, models.ProxyHostStatusActive, "")
	h.Status = models.ProxyHostStatusActive
	return h, nil
}

// GetHost retrieves a proxy host by ID, including custom headers and locations.
func (s *Service) GetHost(ctx context.Context, id uuid.UUID) (*models.ProxyHost, error) {
	h, err := s.hosts.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get proxy host %s: %w", id, err)
	}

	headers, err := s.headers.ListByHost(ctx, id)
	if err != nil {
		s.logger.Error("Failed to load custom headers", "proxy_host_id", id, "error", err)
	} else {
		h.CustomHeaders = headers
	}

	if s.locations != nil {
		locs, err := s.locations.ListByHost(ctx, id)
		if err != nil {
			s.logger.Error("Failed to load custom locations", "proxy_host_id", id, "error", err)
		} else {
			h.Locations = locs
		}
	}

	return h, nil
}

// ListHosts returns all proxy hosts for the default host.
func (s *Service) ListHosts(ctx context.Context) ([]*models.ProxyHost, error) {
	return s.hosts.List(ctx, s.cfg.DefaultHostID, false)
}

// UpdateHost updates a proxy host and syncs the configuration.
func (s *Service) UpdateHost(ctx context.Context, id uuid.UUID, input *models.UpdateProxyHostInput, userID *uuid.UUID) (*models.ProxyHost, error) {
	h, err := s.hosts.GetByID(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get proxy host for update %s: %w", id, err)
	}

	// Apply partial update
	if input.Name != nil {
		h.Name = *input.Name
	}
	if input.Domains != nil {
		h.Domains = input.Domains
	}
	if input.UpstreamScheme != nil {
		h.UpstreamScheme = *input.UpstreamScheme
	}
	if input.UpstreamHost != nil {
		h.UpstreamHost = *input.UpstreamHost
	}
	if input.UpstreamPort != nil {
		h.UpstreamPort = *input.UpstreamPort
	}
	if input.UpstreamPath != nil {
		h.UpstreamPath = *input.UpstreamPath
	}
	if input.SSLMode != nil {
		h.SSLMode = *input.SSLMode
	}
	if input.SSLForceHTTPS != nil {
		h.SSLForceHTTPS = *input.SSLForceHTTPS
	}
	if input.CertificateID != nil {
		h.CertificateID = input.CertificateID
	}
	if input.DNSProviderID != nil {
		h.DNSProviderID = input.DNSProviderID
	}
	if input.Enabled != nil {
		h.Enabled = *input.Enabled
	}
	if input.EnableWebSocket != nil {
		h.EnableWebSocket = *input.EnableWebSocket
	}
	if input.EnableCompression != nil {
		h.EnableCompression = *input.EnableCompression
	}
	if input.EnableHSTS != nil {
		h.EnableHSTS = *input.EnableHSTS
	}
	if input.EnableHTTP2 != nil {
		h.EnableHTTP2 = *input.EnableHTTP2
	}
	if input.BlockExploits != nil {
		h.BlockExploits = *input.BlockExploits
	}
	if input.CachingEnabled != nil {
		h.CachingEnabled = *input.CachingEnabled
	}
	if input.CustomNginxConfig != nil {
		h.CustomNginxConfig = *input.CustomNginxConfig
	}
	if input.HSTSSubdomains != nil {
		h.HSTSSubdomains = *input.HSTSSubdomains
	}
	if input.AccessListID != nil {
		h.AccessListID = input.AccessListID
	}
	if input.HealthCheckEnabled != nil {
		h.HealthCheckEnabled = *input.HealthCheckEnabled
	}
	if input.HealthCheckPath != nil {
		h.HealthCheckPath = *input.HealthCheckPath
	}
	if input.HealthCheckInterval != nil {
		h.HealthCheckInterval = *input.HealthCheckInterval
	}

	h.UpdatedBy = userID

	if err := s.hosts.Update(ctx, h); err != nil {
		return nil, fmt.Errorf("update proxy host: %w", err)
	}

	s.auditLog(ctx, h.HostID, userID, "update", "proxy_host", h.ID, h.Name, "")

	if err := s.Sync(ctx); err != nil {
		s.logger.Error("Failed to sync after update", "host_id", h.ID, "error", err)
		_ = s.hosts.UpdateStatus(ctx, h.ID, models.ProxyHostStatusError, err.Error())
	} else {
		_ = s.hosts.UpdateStatus(ctx, h.ID, models.ProxyHostStatusActive, "")
	}

	return h, nil
}

// DeleteHost removes a proxy host and syncs the configuration.
func (s *Service) DeleteHost(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	h, err := s.hosts.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("get proxy host for delete %s: %w", id, err)
	}

	// Delete headers first (FK cascade should handle this, but be explicit)
	if err := s.headers.ReplaceForHost(ctx, id, nil); err != nil {
		s.logger.Error("Failed to delete headers for proxy host", "id", id, "error", err)
	}

	if err := s.hosts.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete proxy host: %w", err)
	}

	s.auditLog(ctx, h.HostID, userID, "delete", "proxy_host", h.ID, h.Name, "")

	if err := s.Sync(ctx); err != nil {
		s.logger.Error("Failed to sync after delete", "error", err)
	}

	return nil
}

// EnableHost enables a proxy host.
func (s *Service) EnableHost(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	enabled := true
	if _, err := s.UpdateHost(ctx, id, &models.UpdateProxyHostInput{Enabled: &enabled}, userID); err != nil {
		return fmt.Errorf("enable proxy host %s: %w", id, err)
	}
	return nil
}

// DisableHost disables a proxy host.
func (s *Service) DisableHost(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	disabled := false
	if _, err := s.UpdateHost(ctx, id, &models.UpdateProxyHostInput{Enabled: &disabled}, userID); err != nil {
		return fmt.Errorf("disable proxy host %s: %w", id, err)
	}
	return nil
}

// SetCustomHeaders replaces all custom headers for a proxy host and syncs.
func (s *Service) SetCustomHeaders(ctx context.Context, proxyHostID uuid.UUID, headers []models.ProxyHeader) error {
	if err := s.headers.ReplaceForHost(ctx, proxyHostID, headers); err != nil {
		return fmt.Errorf("replace custom headers for proxy host %s: %w", proxyHostID, err)
	}
	return s.Sync(ctx)
}

// ============================================================================
// Certificates
// ============================================================================

// ListCertificates returns all certificates for the default host.
func (s *Service) ListCertificates(ctx context.Context) ([]*models.ProxyCertificate, error) {
	return s.certs.List(ctx, s.cfg.DefaultHostID)
}

// UploadCertificate stores a custom certificate.
func (s *Service) UploadCertificate(ctx context.Context, name string, domains []string, certPEM, keyPEM, chainPEM string, userID *uuid.UUID) (*models.ProxyCertificate, error) {
	// Encrypt the private key at rest
	encKey, err := s.enc.EncryptString(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("encrypt certificate key: %w", err)
	}

	c := &models.ProxyCertificate{
		ID:       uuid.New(),
		HostID:   s.cfg.DefaultHostID,
		Name:     name,
		Domains:  domains,
		Provider: "custom",
		CertPEM:  certPEM,
		KeyPEM:   encKey,
		ChainPEM: chainPEM,
	}

	if err := s.certs.Create(ctx, c); err != nil {
		return nil, fmt.Errorf("store certificate: %w", err)
	}

	s.auditLog(ctx, c.HostID, userID, "create", "certificate", c.ID, c.Name, "")
	return c, nil
}

// DeleteCertificate removes a certificate.
func (s *Service) DeleteCertificate(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	c, err := s.certs.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("get certificate %s: %w", id, err)
	}
	if err := s.certs.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete certificate %s: %w", id, err)
	}
	s.auditLog(ctx, c.HostID, userID, "delete", "certificate", c.ID, c.Name, "")
	return nil
}

// RequestLECertificate requests a Let's Encrypt certificate via the active backend.
// If dnsProvider is non-nil, DNS-01 challenge is used (required for wildcards).
func (s *Service) RequestLECertificate(ctx context.Context, domains []string, email string, dnsProvider *models.ProxyDNSProvider) (certPEM, keyPEM string, err error) {
	return s.backend.RequestCertificate(ctx, domains, email, dnsProvider)
}

// RenewLECertificate renews a Let's Encrypt certificate via the active backend.
func (s *Service) RenewLECertificate(ctx context.Context, domains []string, email string, dnsProvider *models.ProxyDNSProvider) (certPEM, keyPEM string, err error) {
	return s.backend.RenewCertificate(ctx, domains, email, dnsProvider)
}

// ============================================================================
// DNS Providers
// ============================================================================

// ListDNSProviders returns all DNS providers for the default host.
func (s *Service) ListDNSProviders(ctx context.Context) ([]*models.ProxyDNSProvider, error) {
	providers, err := s.dns.List(ctx, s.cfg.DefaultHostID)
	if err != nil {
		return nil, fmt.Errorf("list DNS providers: %w", err)
	}
	// Mask API tokens for display
	for _, p := range providers {
		p.APITokenHint = maskToken(p.APIToken)
		p.APIToken = "" // Never expose full token
	}
	return providers, nil
}

// CreateDNSProvider stores a new DNS provider with encrypted API token.
func (s *Service) CreateDNSProvider(ctx context.Context, name, provider, apiToken, zone string, propagation int, isDefault bool, userID *uuid.UUID) (*models.ProxyDNSProvider, error) {
	// Validate provider
	if _, ok := models.SupportedDNSProviders[provider]; !ok {
		return nil, fmt.Errorf("unsupported DNS provider: %s", provider)
	}

	encToken, err := s.enc.EncryptString(apiToken)
	if err != nil {
		return nil, fmt.Errorf("encrypt DNS API token: %w", err)
	}

	p := &models.ProxyDNSProvider{
		ID:          uuid.New(),
		HostID:      s.cfg.DefaultHostID,
		Name:        name,
		Provider:    provider,
		APIToken:    encToken,
		Zone:        zone,
		Propagation: propagation,
		IsDefault:   isDefault,
	}

	if err := s.dns.Create(ctx, p); err != nil {
		return nil, fmt.Errorf("store DNS provider: %w", err)
	}

	s.auditLog(ctx, p.HostID, userID, "create", "dns_provider", p.ID, p.Name, "")

	p.APITokenHint = maskToken(apiToken)
	p.APIToken = ""
	return p, nil
}

// DeleteDNSProvider removes a DNS provider.
func (s *Service) DeleteDNSProvider(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	p, err := s.dns.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("get DNS provider %s: %w", id, err)
	}
	if err := s.dns.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete DNS provider %s: %w", id, err)
	}
	s.auditLog(ctx, p.HostID, userID, "delete", "dns_provider", p.ID, p.Name, "")
	return nil
}

// ============================================================================
// Backend Sync
// ============================================================================

// loadSyncData loads all proxy data from the database into a SyncData struct.
func (s *Service) loadSyncData(ctx context.Context) (*SyncData, error) {
	// 1. Load all enabled hosts
	hosts, err := s.hosts.ListAll(ctx, true)
	if err != nil {
		return nil, fmt.Errorf("list proxy hosts: %w", err)
	}

	// 2. Load custom headers and locations for each host
	for _, h := range hosts {
		headers, err := s.headers.ListByHost(ctx, h.ID)
		if err != nil {
			s.logger.Error("Failed to load headers for host", "id", h.ID, "error", err)
			continue
		}
		h.CustomHeaders = headers

		if s.locations != nil {
			locs, err := s.locations.ListByHost(ctx, h.ID)
			if err != nil {
				s.logger.Error("Failed to load locations for host", "id", h.ID, "error", err)
			} else {
				h.Locations = locs
			}
		}
	}

	// 3. Load DNS providers (for DNS challenge hosts)
	dnsProviders := make(map[string]*models.ProxyDNSProvider)
	allDNS, err := s.dns.List(ctx, s.cfg.DefaultHostID)
	if err != nil {
		s.logger.Error("Failed to load DNS providers", "error", err)
	} else {
		for _, p := range allDNS {
			decrypted, err := s.enc.DecryptString(p.APIToken)
			if err != nil {
				s.logger.Error("Failed to decrypt DNS token", "provider_id", p.ID, "error", err)
				continue
			}
			p.APIToken = decrypted
			dnsProviders[p.ID.String()] = p
		}
	}

	// 4. Load custom certificates
	customCerts := make(map[string]*models.ProxyCertificate)
	allCerts, err := s.certs.List(ctx, s.cfg.DefaultHostID)
	if err != nil {
		s.logger.Error("Failed to load certificates", "error", err)
	} else {
		for _, c := range allCerts {
			if c.KeyPEM != "" {
				decrypted, err := s.enc.DecryptString(c.KeyPEM)
				if err != nil {
					s.logger.Error("Failed to decrypt cert key", "cert_id", c.ID, "error", err)
					continue
				}
				c.KeyPEM = decrypted
			}
			customCerts[c.ID.String()] = c
		}
	}

	// 5. Load redirections, streams, dead hosts, access lists
	var redirections []*models.ProxyRedirection
	if s.redirections != nil {
		redirections, err = s.redirections.List(ctx, s.cfg.DefaultHostID)
		if err != nil {
			s.logger.Error("Failed to load redirections", "error", err)
		}
	}

	var streams []*models.ProxyStream
	if s.streams != nil {
		streams, err = s.streams.List(ctx, s.cfg.DefaultHostID)
		if err != nil {
			s.logger.Error("Failed to load streams", "error", err)
		}
	}

	var deadHosts []*models.ProxyDeadHost
	if s.deadHosts != nil {
		deadHosts, err = s.deadHosts.List(ctx, s.cfg.DefaultHostID)
		if err != nil {
			s.logger.Error("Failed to load dead hosts", "error", err)
		}
	}

	var accessLists []*models.ProxyAccessList
	if s.accessLists != nil {
		accessLists, err = s.accessLists.List(ctx, s.cfg.DefaultHostID)
		if err != nil {
			s.logger.Error("Failed to load access lists", "error", err)
		}
	}

	return &SyncData{
		Hosts:        hosts,
		Redirections: redirections,
		Streams:      streams,
		DeadHosts:    deadHosts,
		AccessLists:  accessLists,
		DNSProviders: dnsProviders,
		CustomCerts:  customCerts,
		ACMEEmail:    s.cfg.ACMEEmail,
		ListenHTTP:   s.cfg.ListenHTTP,
		ListenHTTPS:  s.cfg.ListenHTTPS,
	}, nil
}

// Sync loads all proxy data from the database and pushes it to the active backend.
func (s *Service) Sync(ctx context.Context) error {
	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	data, err := s.loadSyncData(ctx)
	if err != nil {
		return fmt.Errorf("load proxy sync data: %w", err)
	}

	if err := s.backend.Sync(ctx, data); err != nil {
		return fmt.Errorf("proxy sync (%s): %w", s.backend.Mode(), err)
	}

	s.logger.Info("Synced proxy configuration", "backend", s.backend.Mode(), "host_count", len(data.Hosts))

	for _, h := range data.Hosts {
		_ = s.hosts.UpdateStatus(ctx, h.ID, models.ProxyHostStatusActive, "")
	}

	return nil
}

// BackendHealthy checks if the backend process is reachable.
func (s *Service) BackendHealthy(ctx context.Context) (bool, error) {
	return s.backend.Healthy(ctx)
}

// BackendMode returns the active backend mode.
func (s *Service) BackendMode() string {
	return s.backend.Mode()
}

// ============================================================================
// Audit Log
// ============================================================================

// ListAuditLogs returns proxy audit log entries.
func (s *Service) ListAuditLogs(ctx context.Context, limit, offset int) ([]*models.ProxyAuditLog, int, error) {
	return s.audit.List(ctx, s.cfg.DefaultHostID, limit, offset)
}

// ============================================================================
// Auto-proxy from Docker containers
// ============================================================================

// AutoProxyFromLabels checks if a container has proxy labels and creates/updates
// a proxy host accordingly.
func (s *Service) AutoProxyFromLabels(ctx context.Context, containerID, containerName string, labels map[string]string) error {
	domain, ok := labels[models.LabelProxyDomain]
	if !ok || domain == "" {
		return nil // No proxy label, skip
	}

	// Check if we already have a proxy for this container
	existing, err := s.hosts.GetByContainerID(ctx, containerID)
	if err != nil {
		return fmt.Errorf("lookup proxy host by container %s: %w", containerID, err)
	}

	port := 80
	if p, ok := labels[models.LabelProxyPort]; ok {
		fmt.Sscanf(p, "%d", &port)
	}

	sslMode := models.ProxySSLModeAuto
	if v, ok := labels[models.LabelProxySSL]; ok && v == "false" {
		sslMode = models.ProxySSLModeNone
	}

	websocket := false
	if v, ok := labels[models.LabelProxyWebsocket]; ok && v == "true" {
		websocket = true
	}

	if existing != nil {
		// Update existing
		name := containerName
		newDomains := []string{domain}
		newPort := port
		scheme := models.ProxyUpstreamHTTP
		_, err = s.UpdateHost(ctx, existing.ID, &models.UpdateProxyHostInput{
			Name:            &name,
			Domains:         newDomains,
			UpstreamHost:    &containerName,
			UpstreamPort:    &newPort,
			UpstreamScheme:  &scheme,
			SSLMode:         &sslMode,
			EnableWebSocket: &websocket,
		}, nil)
		if err != nil {
			return fmt.Errorf("auto-proxy update for container %s: %w", containerID, err)
		}
		return nil
	}

	// Create new
	_, err = s.CreateHost(ctx, &models.CreateProxyHostInput{
		Name:              containerName,
		Domains:           []string{domain},
		UpstreamScheme:    models.ProxyUpstreamHTTP,
		UpstreamHost:      containerName,
		UpstreamPort:      port,
		SSLMode:           sslMode,
		SSLForceHTTPS:     sslMode != models.ProxySSLModeNone,
		EnableWebSocket:   websocket,
		EnableCompression: true,
		EnableHSTS:        sslMode != models.ProxySSLModeNone,
		EnableHTTP2:       true,
		ContainerID:       containerID,
		ContainerName:     containerName,
	}, nil)
	if err != nil {
		return fmt.Errorf("auto-proxy create for container %s: %w", containerID, err)
	}

	return nil
}

// ============================================================================
// Redirections
// ============================================================================

// ListRedirections returns all redirections for the default host.
func (s *Service) ListRedirections(ctx context.Context) ([]*models.ProxyRedirection, error) {
	if s.redirections == nil {
		return nil, nil
	}
	return s.redirections.List(ctx, s.cfg.DefaultHostID)
}

// GetRedirection retrieves a redirection by ID.
func (s *Service) GetRedirection(ctx context.Context, id uuid.UUID) (*models.ProxyRedirection, error) {
	if s.redirections == nil {
		return nil, fmt.Errorf("redirections not configured")
	}
	return s.redirections.GetByID(ctx, id)
}

// CreateRedirection creates a new redirection and syncs.
func (s *Service) CreateRedirection(ctx context.Context, rd *models.ProxyRedirection, userID *uuid.UUID) error {
	if s.redirections == nil {
		return fmt.Errorf("redirections not configured")
	}
	rd.HostID = s.cfg.DefaultHostID
	if err := s.redirections.Create(ctx, rd); err != nil {
		return fmt.Errorf("create redirection: %w", err)
	}
	s.auditLog(ctx, rd.HostID, userID, "create", "redirection", rd.ID, rd.ForwardDomain, "")
	if err := s.Sync(ctx); err != nil {
		s.logger.Error("Failed to sync after redirection create", "error", err)
	}
	return nil
}

// UpdateRedirection updates a redirection and syncs.
func (s *Service) UpdateRedirection(ctx context.Context, rd *models.ProxyRedirection, userID *uuid.UUID) error {
	if s.redirections == nil {
		return fmt.Errorf("redirections not configured")
	}
	if err := s.redirections.Update(ctx, rd); err != nil {
		return fmt.Errorf("update redirection: %w", err)
	}
	s.auditLog(ctx, rd.HostID, userID, "update", "redirection", rd.ID, rd.ForwardDomain, "")
	if err := s.Sync(ctx); err != nil {
		s.logger.Error("Failed to sync after redirection update", "error", err)
	}
	return nil
}

// DeleteRedirection deletes a redirection and syncs.
func (s *Service) DeleteRedirection(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	if s.redirections == nil {
		return fmt.Errorf("redirections not configured")
	}
	rd, err := s.redirections.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("get redirection for delete: %w", err)
	}
	if err := s.redirections.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete redirection: %w", err)
	}
	s.auditLog(ctx, rd.HostID, userID, "delete", "redirection", rd.ID, rd.ForwardDomain, "")
	if err := s.Sync(ctx); err != nil {
		s.logger.Error("Failed to sync after redirection delete", "error", err)
	}
	return nil
}

// ============================================================================
// Streams
// ============================================================================

// ListStreams returns all streams for the default host.
func (s *Service) ListStreams(ctx context.Context) ([]*models.ProxyStream, error) {
	if s.streams == nil {
		return nil, nil
	}
	return s.streams.List(ctx, s.cfg.DefaultHostID)
}

// GetStream retrieves a stream by ID.
func (s *Service) GetStream(ctx context.Context, id uuid.UUID) (*models.ProxyStream, error) {
	if s.streams == nil {
		return nil, fmt.Errorf("streams not configured")
	}
	return s.streams.GetByID(ctx, id)
}

// CreateStream creates a new stream and syncs.
func (s *Service) CreateStream(ctx context.Context, st *models.ProxyStream, userID *uuid.UUID) error {
	if s.streams == nil {
		return fmt.Errorf("streams not configured")
	}
	st.HostID = s.cfg.DefaultHostID
	if err := s.streams.Create(ctx, st); err != nil {
		return fmt.Errorf("create stream: %w", err)
	}
	s.auditLog(ctx, st.HostID, userID, "create", "stream", st.ID, fmt.Sprintf(":%d", st.IncomingPort), "")
	if err := s.Sync(ctx); err != nil {
		s.logger.Error("Failed to sync after stream create", "error", err)
	}
	return nil
}

// UpdateStream updates a stream and syncs.
func (s *Service) UpdateStream(ctx context.Context, st *models.ProxyStream, userID *uuid.UUID) error {
	if s.streams == nil {
		return fmt.Errorf("streams not configured")
	}
	if err := s.streams.Update(ctx, st); err != nil {
		return fmt.Errorf("update stream: %w", err)
	}
	s.auditLog(ctx, st.HostID, userID, "update", "stream", st.ID, fmt.Sprintf(":%d", st.IncomingPort), "")
	if err := s.Sync(ctx); err != nil {
		s.logger.Error("Failed to sync after stream update", "error", err)
	}
	return nil
}

// DeleteStream deletes a stream and syncs.
func (s *Service) DeleteStream(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	if s.streams == nil {
		return fmt.Errorf("streams not configured")
	}
	st, err := s.streams.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("get stream for delete: %w", err)
	}
	if err := s.streams.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete stream: %w", err)
	}
	s.auditLog(ctx, st.HostID, userID, "delete", "stream", st.ID, fmt.Sprintf(":%d", st.IncomingPort), "")
	if err := s.Sync(ctx); err != nil {
		s.logger.Error("Failed to sync after stream delete", "error", err)
	}
	return nil
}

// ============================================================================
// Dead Hosts
// ============================================================================

// ListDeadHosts returns all dead hosts for the default host.
func (s *Service) ListDeadHosts(ctx context.Context) ([]*models.ProxyDeadHost, error) {
	if s.deadHosts == nil {
		return nil, nil
	}
	return s.deadHosts.List(ctx, s.cfg.DefaultHostID)
}

// CreateDeadHost creates a new dead host and syncs.
func (s *Service) CreateDeadHost(ctx context.Context, d *models.ProxyDeadHost, userID *uuid.UUID) error {
	if s.deadHosts == nil {
		return fmt.Errorf("dead hosts not configured")
	}
	d.HostID = s.cfg.DefaultHostID
	if err := s.deadHosts.Create(ctx, d); err != nil {
		return fmt.Errorf("create dead host: %w", err)
	}
	name := ""
	if len(d.Domains) > 0 {
		name = d.Domains[0]
	}
	s.auditLog(ctx, d.HostID, userID, "create", "dead_host", d.ID, name, "")
	if err := s.Sync(ctx); err != nil {
		s.logger.Error("Failed to sync after dead host create", "error", err)
	}
	return nil
}

// DeleteDeadHost deletes a dead host and syncs.
func (s *Service) DeleteDeadHost(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	if s.deadHosts == nil {
		return fmt.Errorf("dead hosts not configured")
	}
	d, err := s.deadHosts.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("get dead host for delete: %w", err)
	}
	if err := s.deadHosts.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete dead host: %w", err)
	}
	name := ""
	if len(d.Domains) > 0 {
		name = d.Domains[0]
	}
	s.auditLog(ctx, d.HostID, userID, "delete", "dead_host", d.ID, name, "")
	if err := s.Sync(ctx); err != nil {
		s.logger.Error("Failed to sync after dead host delete", "error", err)
	}
	return nil
}

// ============================================================================
// Access Lists
// ============================================================================

// ListAccessLists returns all access lists for the default host.
func (s *Service) ListAccessLists(ctx context.Context) ([]*models.ProxyAccessList, error) {
	if s.accessLists == nil {
		return nil, nil
	}
	return s.accessLists.List(ctx, s.cfg.DefaultHostID)
}

// GetAccessList retrieves an access list by ID.
func (s *Service) GetAccessList(ctx context.Context, id uuid.UUID) (*models.ProxyAccessList, error) {
	if s.accessLists == nil {
		return nil, fmt.Errorf("access lists not configured")
	}
	return s.accessLists.GetByID(ctx, id)
}

// CreateAccessList creates a new access list.
func (s *Service) CreateAccessList(ctx context.Context, al *models.ProxyAccessList, userID *uuid.UUID) error {
	if s.accessLists == nil {
		return fmt.Errorf("access lists not configured")
	}
	al.HostID = s.cfg.DefaultHostID
	if err := s.accessLists.Create(ctx, al); err != nil {
		return fmt.Errorf("create access list: %w", err)
	}
	s.auditLog(ctx, al.HostID, userID, "create", "access_list", al.ID, al.Name, "")
	return nil
}

// UpdateAccessList updates an access list.
func (s *Service) UpdateAccessList(ctx context.Context, al *models.ProxyAccessList, userID *uuid.UUID) error {
	if s.accessLists == nil {
		return fmt.Errorf("access lists not configured")
	}
	if err := s.accessLists.Update(ctx, al); err != nil {
		return fmt.Errorf("update access list: %w", err)
	}
	s.auditLog(ctx, al.HostID, userID, "update", "access_list", al.ID, al.Name, "")
	return nil
}

// DeleteAccessList deletes an access list.
func (s *Service) DeleteAccessList(ctx context.Context, id uuid.UUID, userID *uuid.UUID) error {
	if s.accessLists == nil {
		return fmt.Errorf("access lists not configured")
	}
	al, err := s.accessLists.GetByID(ctx, id)
	if err != nil {
		return fmt.Errorf("get access list for delete: %w", err)
	}
	if err := s.accessLists.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete access list: %w", err)
	}
	s.auditLog(ctx, al.HostID, userID, "delete", "access_list", al.ID, al.Name, "")
	return nil
}

// ============================================================================
// Custom Locations
// ============================================================================

// SetLocations replaces all locations for a proxy host and syncs.
func (s *Service) SetLocations(ctx context.Context, proxyHostID uuid.UUID, locations []models.ProxyLocation) error {
	if s.locations == nil {
		return fmt.Errorf("locations not configured")
	}
	if err := s.locations.ReplaceForHost(ctx, proxyHostID, locations); err != nil {
		return fmt.Errorf("replace locations for proxy host %s: %w", proxyHostID, err)
	}
	return s.Sync(ctx)
}

// ============================================================================
// Helpers
// ============================================================================

func (s *Service) auditLog(ctx context.Context, hostID uuid.UUID, userID *uuid.UUID, action, resourceType string, resourceID uuid.UUID, resourceName, details string) {
	entry := &models.ProxyAuditLog{
		HostID:       hostID,
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		ResourceName: resourceName,
		Details:      details,
	}
	if err := s.audit.Create(ctx, entry); err != nil {
		s.logger.Error("Failed to write proxy audit log", "action", action, "error", err)
	}
}

func maskToken(token string) string {
	if len(token) <= 4 {
		return "****"
	}
	return "****" + token[len(token)-4:]
}
