// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package discovery provides automatic DNS registration for Docker containers.
// When containers start, A records (and optionally SRV records for exposed ports)
// are created in a dedicated zone. When containers stop, the records are removed.
package discovery

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	dnssvc "github.com/fr4nsys/usulnet/internal/services/dns"
)

// Config holds service discovery configuration.
type Config struct {
	// Enabled activates container→DNS registration.
	Enabled bool
	// Domain is the base zone for discovered containers (e.g. "containers.local").
	Domain string
	// TTL is the record TTL in seconds for auto-created records.
	TTL int
	// CreateSRV generates SRV records for exposed container ports.
	CreateSRV bool
	// IncludeStoppedCleanup removes DNS records when containers stop.
	IncludeStoppedCleanup bool
}

// DefaultConfig returns default service discovery settings.
func DefaultConfig() Config {
	return Config{
		Enabled:               true,
		Domain:                "containers.local",
		TTL:                   30,
		CreateSRV:             true,
		IncludeStoppedCleanup: true,
	}
}

// recordTag is the comment prefix used to identify auto-created records.
// Format: "sd:<containerID>" — allows lookup and cleanup.
const recordTag = "sd:"

// Service manages automatic DNS registration for Docker containers.
// It listens for container lifecycle events and creates/deletes DNS records
// in a dedicated zone managed by the DNS service.
type Service struct {
	dns    *dnssvc.Service
	cfg    Config
	logger *logger.Logger

	// zoneID is the UUID of the auto-managed discovery zone.
	// Resolved lazily on first event.
	zoneID   uuid.UUID
	zoneMu   sync.Mutex
	zoneInit bool

	// Track which containers have been registered (containerID → recordIDs)
	mu       sync.RWMutex
	tracked  map[string][]uuid.UUID // containerID → list of DNS record UUIDs

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewService creates a new service discovery instance.
func NewService(dns *dnssvc.Service, cfg Config, log *logger.Logger) *Service {
	return &Service{
		dns:     dns,
		cfg:     cfg,
		logger:  log.Named("dns.discovery"),
		tracked: make(map[string][]uuid.UUID),
		stopCh:  make(chan struct{}),
	}
}

// Start initializes the discovery service: ensures the zone exists and loads
// existing auto-created records into the tracking map.
func (s *Service) Start(ctx context.Context, hostID uuid.UUID) error {
	if !s.cfg.Enabled {
		return nil
	}

	s.logger.Info("starting DNS service discovery",
		"domain", s.cfg.Domain,
		"ttl", s.cfg.TTL,
		"srv", s.cfg.CreateSRV,
	)

	// Ensure the discovery zone exists
	if err := s.ensureZone(ctx, hostID); err != nil {
		return fmt.Errorf("ensure discovery zone: %w", err)
	}

	// Load existing auto-created records into tracking map
	if err := s.loadTracked(ctx); err != nil {
		s.logger.Warn("failed to load tracked records", "error", err)
	}

	return nil
}

// Stop shuts down the discovery service.
func (s *Service) Stop() {
	close(s.stopCh)
	s.wg.Wait()
}

// HandleContainerEvent is the callback registered with the container service.
// It creates or removes DNS records based on container lifecycle events.
func (s *Service) HandleContainerEvent(ctx context.Context, hostID uuid.UUID, action string, containerID string, container *models.Container) {
	if !s.cfg.Enabled {
		return
	}

	select {
	case <-s.stopCh:
		return
	default:
	}

	switch action {
	case "start":
		if container != nil {
			s.registerContainer(ctx, hostID, container)
		}
	case "stop", "die":
		if s.cfg.IncludeStoppedCleanup {
			s.unregisterContainer(ctx, hostID, containerID)
		}
	case "destroy":
		s.unregisterContainer(ctx, hostID, containerID)
	}
}

// ReconcileAll scans all running containers and ensures DNS records exist.
// Call this periodically as a safety net (e.g. from the container reconciliation worker).
func (s *Service) ReconcileAll(ctx context.Context, hostID uuid.UUID, containers []*models.Container) {
	if !s.cfg.Enabled {
		return
	}

	if err := s.ensureZone(ctx, hostID); err != nil {
		s.logger.Error("failed to ensure zone during reconcile", "error", err)
		return
	}

	// Build set of running container IDs
	running := make(map[string]bool, len(containers))
	for _, c := range containers {
		if c.State == models.ContainerStateRunning {
			running[c.ID] = true
		}
	}

	// Register missing containers
	for _, c := range containers {
		if c.State != models.ContainerStateRunning {
			continue
		}
		s.mu.RLock()
		_, exists := s.tracked[c.ID]
		s.mu.RUnlock()
		if !exists {
			s.registerContainer(ctx, hostID, c)
		}
	}

	// Remove records for containers that are no longer running
	s.mu.RLock()
	toRemove := make([]string, 0)
	for cid := range s.tracked {
		if !running[cid] {
			toRemove = append(toRemove, cid)
		}
	}
	s.mu.RUnlock()

	for _, cid := range toRemove {
		s.unregisterContainer(ctx, hostID, cid)
	}
}

// Stats returns discovery service statistics.
func (s *Service) Stats() DiscoveryStats {
	s.mu.RLock()
	defer s.mu.RUnlock()

	totalRecords := 0
	for _, recs := range s.tracked {
		totalRecords += len(recs)
	}

	return DiscoveryStats{
		Enabled:            s.cfg.Enabled,
		Domain:             s.cfg.Domain,
		TrackedContainers:  len(s.tracked),
		TrackedRecords:     totalRecords,
		ZoneID:             s.zoneID,
	}
}

// DiscoveryStats holds discovery service statistics.
type DiscoveryStats struct {
	Enabled           bool      `json:"enabled"`
	Domain            string    `json:"domain"`
	TrackedContainers int       `json:"tracked_containers"`
	TrackedRecords    int       `json:"tracked_records"`
	ZoneID            uuid.UUID `json:"zone_id"`
}

// ============================================================================
// Internal: zone management
// ============================================================================

// ensureZone creates the discovery zone if it doesn't exist yet.
func (s *Service) ensureZone(ctx context.Context, hostID uuid.UUID) error {
	s.zoneMu.Lock()
	defer s.zoneMu.Unlock()

	if s.zoneInit {
		return nil
	}

	zoneName := ensureTrailingDot(s.cfg.Domain)

	// Check if the zone already exists
	zones, err := s.dns.ListZones(ctx, hostID)
	if err != nil {
		return fmt.Errorf("list zones: %w", err)
	}

	for _, z := range zones {
		if z.Name == zoneName {
			s.zoneID = z.ID
			s.zoneInit = true
			s.logger.Debug("discovery zone already exists", "zone_id", z.ID, "name", zoneName)
			return nil
		}
	}

	// Create the zone
	zone := &models.DNSZone{
		ID:          uuid.New(),
		HostID:      hostID,
		Name:        zoneName,
		Kind:        models.DNSZoneKindPrimary,
		Enabled:     true,
		TTL:         s.cfg.TTL,
		Serial:      time.Now().Unix(),
		Refresh:     3600,
		Retry:       900,
		Expire:      604800,
		MinimumTTL:  s.cfg.TTL,
		PrimaryNS:   "ns1." + zoneName,
		AdminEmail:  "admin." + zoneName,
		Forwarders:  []string{},
		Description: "Auto-managed zone for container service discovery",
	}

	if err := s.dns.CreateZone(ctx, zone); err != nil {
		return fmt.Errorf("create discovery zone: %w", err)
	}

	s.zoneID = zone.ID
	s.zoneInit = true
	s.logger.Info("created discovery zone", "zone_id", zone.ID, "name", zoneName)
	return nil
}

// ============================================================================
// Internal: record management
// ============================================================================

// registerContainer creates DNS records for a running container.
func (s *Service) registerContainer(ctx context.Context, hostID uuid.UUID, c *models.Container) {
	if s.zoneID == uuid.Nil {
		return
	}

	// Clean container name (Docker names start with '/')
	name := cleanContainerName(c.Name)
	if name == "" {
		return
	}

	tag := recordTag + c.ID

	var recordIDs []uuid.UUID

	// Create A records for each network attachment
	for _, net := range c.Networks {
		if net.IPAddress == "" {
			continue
		}

		recName := name + "." + ensureTrailingDot(s.cfg.Domain)
		rec := &models.DNSRecord{
			ID:      uuid.New(),
			ZoneID:  s.zoneID,
			HostID:  hostID,
			Name:    recName,
			Type:    models.DNSRecordTypeA,
			TTL:     s.cfg.TTL,
			Content: net.IPAddress,
			Enabled: true,
			Comment: tag,
		}

		if err := s.dns.CreateRecord(ctx, rec, nil); err != nil {
			s.logger.Warn("failed to create A record",
				"container", name,
				"ip", net.IPAddress,
				"network", net.NetworkName,
				"error", err,
			)
			continue
		}
		recordIDs = append(recordIDs, rec.ID)

		s.logger.Debug("registered container A record",
			"container", name,
			"ip", net.IPAddress,
			"network", net.NetworkName,
		)

		// Also create a network-scoped name: <container>.<network>.containers.local
		if net.NetworkName != "" && net.NetworkName != "bridge" {
			netRecName := name + "." + sanitizeDNSLabel(net.NetworkName) + "." + ensureTrailingDot(s.cfg.Domain)
			netRec := &models.DNSRecord{
				ID:      uuid.New(),
				ZoneID:  s.zoneID,
				HostID:  hostID,
				Name:    netRecName,
				Type:    models.DNSRecordTypeA,
				TTL:     s.cfg.TTL,
				Content: net.IPAddress,
				Enabled: true,
				Comment: tag,
			}
			if err := s.dns.CreateRecord(ctx, netRec, nil); err != nil {
				s.logger.Debug("failed to create network-scoped A record",
					"name", netRecName,
					"error", err,
				)
			} else {
				recordIDs = append(recordIDs, netRec.ID)
			}
		}
	}

	// Create SRV records for exposed ports
	if s.cfg.CreateSRV && len(c.Ports) > 0 {
		for _, p := range c.Ports {
			if p.PrivatePort == 0 {
				continue
			}

			proto := "tcp"
			if p.Type != "" {
				proto = strings.ToLower(p.Type)
			}

			// SRV record: _<port>._<proto>.<container>.containers.local
			srvName := fmt.Sprintf("_%d._%s.%s.%s",
				p.PrivatePort, proto, name, ensureTrailingDot(s.cfg.Domain))

			port := int(p.PrivatePort)
			weight := 100
			priority := 10
			target := name + "." + ensureTrailingDot(s.cfg.Domain)

			srvRec := &models.DNSRecord{
				ID:       uuid.New(),
				ZoneID:   s.zoneID,
				HostID:   hostID,
				Name:     srvName,
				Type:     models.DNSRecordTypeSRV,
				TTL:      s.cfg.TTL,
				Content:  target,
				Priority: &priority,
				Weight:   &weight,
				Port:     &port,
				Enabled:  true,
				Comment:  tag,
			}

			if err := s.dns.CreateRecord(ctx, srvRec, nil); err != nil {
				s.logger.Debug("failed to create SRV record",
					"name", srvName,
					"error", err,
				)
			} else {
				recordIDs = append(recordIDs, srvRec.ID)
			}
		}
	}

	if len(recordIDs) > 0 {
		s.mu.Lock()
		s.tracked[c.ID] = recordIDs
		s.mu.Unlock()

		s.logger.Info("registered container DNS records",
			"container", name,
			"records", len(recordIDs),
		)
	}
}

// unregisterContainer removes all DNS records for a container.
func (s *Service) unregisterContainer(ctx context.Context, hostID uuid.UUID, containerID string) {
	s.mu.Lock()
	recordIDs, exists := s.tracked[containerID]
	if exists {
		delete(s.tracked, containerID)
	}
	s.mu.Unlock()

	if !exists || len(recordIDs) == 0 {
		return
	}

	for _, recID := range recordIDs {
		if err := s.dns.DeleteRecord(ctx, hostID, s.zoneID, recID, nil); err != nil {
			s.logger.Debug("failed to delete discovery record",
				"record_id", recID,
				"container_id", containerID[:12],
				"error", err,
			)
		}
	}

	s.logger.Info("unregistered container DNS records",
		"container_id", containerID[:12],
		"records", len(recordIDs),
	)
}

// loadTracked loads existing auto-created records into the tracking map.
func (s *Service) loadTracked(ctx context.Context) error {
	if s.zoneID == uuid.Nil {
		return nil
	}

	records, err := s.dns.ListRecords(ctx, s.zoneID)
	if err != nil {
		return fmt.Errorf("list records: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, r := range records {
		if !strings.HasPrefix(r.Comment, recordTag) {
			continue
		}
		containerID := strings.TrimPrefix(r.Comment, recordTag)
		s.tracked[containerID] = append(s.tracked[containerID], r.ID)
	}

	s.logger.Info("loaded tracked discovery records",
		"containers", len(s.tracked),
	)
	return nil
}

// ============================================================================
// Helpers
// ============================================================================

// cleanContainerName strips the leading "/" from Docker container names
// and sanitizes for DNS label compatibility.
func cleanContainerName(name string) string {
	name = strings.TrimPrefix(name, "/")
	return sanitizeDNSLabel(name)
}

// sanitizeDNSLabel converts a string to a valid DNS label.
// Replaces invalid characters with hyphens and lowercases everything.
func sanitizeDNSLabel(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			b.WriteRune(c)
		} else if c == '_' || c == '.' || c == ' ' {
			b.WriteRune('-')
		}
		// Skip other characters
	}
	result := b.String()
	result = strings.Trim(result, "-")
	if result == "" {
		return ""
	}
	// DNS labels max 63 chars
	if len(result) > 63 {
		result = result[:63]
	}
	return result
}

// ensureTrailingDot appends a trailing dot to a domain name if absent.
func ensureTrailingDot(domain string) string {
	if !strings.HasSuffix(domain, ".") {
		return domain + "."
	}
	return domain
}
