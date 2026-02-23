// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package dns provides the DNS server management service.
// It stores configuration in PostgreSQL (source of truth) and pushes
// the full zone/record set to the DNS backend on each change.
package dns

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// Config holds DNS service configuration.
type Config struct {
	// Enabled activates the embedded DNS server. Default: true.
	Enabled bool
	// ListenAddr is the listen address (default ":53").
	ListenAddr string
	// Forwarders are upstream DNS servers for recursive queries.
	Forwarders []string
}

// Service manages DNS zones, records, and TSIG keys.
type Service struct {
	zones    ZoneRepository
	records  RecordRepository
	tsigKeys TSIGKeyRepository
	audit    AuditLogRepository
	backend  SyncBackend
	enc      Encryptor
	cfg      Config
	logger   *logger.Logger

	syncMu sync.Mutex
}

// NewService creates a new DNS service.
func NewService(
	zones ZoneRepository,
	records RecordRepository,
	tsigKeys TSIGKeyRepository,
	audit AuditLogRepository,
	enc Encryptor,
	backend SyncBackend,
	cfg Config,
	log *logger.Logger,
) *Service {
	return &Service{
		zones:    zones,
		records:  records,
		tsigKeys: tsigKeys,
		audit:    audit,
		backend:  backend,
		enc:      enc,
		cfg:      cfg,
		logger:   log.Named("dns"),
	}
}

// Backend returns the active DNS backend.
func (s *Service) Backend() SyncBackend {
	return s.backend
}

// ============================================================================
// Zone operations
// ============================================================================

// ListZones retrieves all DNS zones for a host.
func (s *Service) ListZones(ctx context.Context, hostID uuid.UUID) ([]*models.DNSZone, error) {
	return s.zones.List(ctx, hostID)
}

// GetZone retrieves a DNS zone by ID, including its records.
func (s *Service) GetZone(ctx context.Context, id uuid.UUID) (*models.DNSZone, error) {
	zone, err := s.zones.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}
	records, err := s.records.ListByZone(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to load zone records: %w", err)
	}
	zone.Records = make([]models.DNSRecord, len(records))
	for i, r := range records {
		zone.Records[i] = *r
	}
	return zone, nil
}

// CreateZone creates a new DNS zone and syncs the backend.
func (s *Service) CreateZone(ctx context.Context, zone *models.DNSZone) error {
	if err := s.zones.Create(ctx, zone); err != nil {
		return err
	}

	s.logAudit(ctx, zone.HostID, zone.CreatedBy, "create", "zone", zone.ID, zone.Name, "")

	if err := s.Sync(ctx); err != nil {
		s.logger.Error("failed to sync after zone create", "zone", zone.Name, "error", err)
	}
	return nil
}

// UpdateZone updates a DNS zone and syncs the backend.
func (s *Service) UpdateZone(ctx context.Context, zone *models.DNSZone) error {
	if err := s.zones.Update(ctx, zone); err != nil {
		return err
	}
	if err := s.zones.IncrementSerial(ctx, zone.ID); err != nil {
		s.logger.Error("failed to increment serial", "zone", zone.Name, "error", err)
	}

	s.logAudit(ctx, zone.HostID, zone.UpdatedBy, "update", "zone", zone.ID, zone.Name, "")

	if err := s.Sync(ctx); err != nil {
		s.logger.Error("failed to sync after zone update", "zone", zone.Name, "error", err)
	}
	return nil
}

// DeleteZone deletes a DNS zone and syncs the backend.
func (s *Service) DeleteZone(ctx context.Context, hostID uuid.UUID, id uuid.UUID, userID *uuid.UUID) error {
	zone, err := s.zones.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.zones.Delete(ctx, id); err != nil {
		return err
	}

	s.logAudit(ctx, hostID, userID, "delete", "zone", id, zone.Name, "")

	if err := s.Sync(ctx); err != nil {
		s.logger.Error("failed to sync after zone delete", "zone", zone.Name, "error", err)
	}
	return nil
}

// ============================================================================
// Record operations
// ============================================================================

// ListRecords retrieves all DNS records for a zone.
func (s *Service) ListRecords(ctx context.Context, zoneID uuid.UUID) ([]*models.DNSRecord, error) {
	return s.records.ListByZone(ctx, zoneID)
}

// GetRecord retrieves a DNS record by ID.
func (s *Service) GetRecord(ctx context.Context, id uuid.UUID) (*models.DNSRecord, error) {
	return s.records.GetByID(ctx, id)
}

// CreateRecord creates a new DNS record and syncs the backend.
func (s *Service) CreateRecord(ctx context.Context, rec *models.DNSRecord, userID *uuid.UUID) error {
	if err := s.records.Create(ctx, rec); err != nil {
		return err
	}
	if err := s.zones.IncrementSerial(ctx, rec.ZoneID); err != nil {
		s.logger.Error("failed to increment serial", "zone_id", rec.ZoneID, "error", err)
	}

	s.logAudit(ctx, rec.HostID, userID, "create", "record", rec.ID, rec.Name, fmt.Sprintf("type=%s content=%s", rec.Type, rec.Content))

	if err := s.Sync(ctx); err != nil {
		s.logger.Error("failed to sync after record create", "record", rec.Name, "error", err)
	}
	return nil
}

// UpdateRecord updates a DNS record and syncs the backend.
func (s *Service) UpdateRecord(ctx context.Context, rec *models.DNSRecord, userID *uuid.UUID) error {
	if err := s.records.Update(ctx, rec); err != nil {
		return err
	}
	if err := s.zones.IncrementSerial(ctx, rec.ZoneID); err != nil {
		s.logger.Error("failed to increment serial", "zone_id", rec.ZoneID, "error", err)
	}

	s.logAudit(ctx, rec.HostID, userID, "update", "record", rec.ID, rec.Name, fmt.Sprintf("type=%s content=%s", rec.Type, rec.Content))

	if err := s.Sync(ctx); err != nil {
		s.logger.Error("failed to sync after record update", "record", rec.Name, "error", err)
	}
	return nil
}

// DeleteRecord deletes a DNS record and syncs the backend.
func (s *Service) DeleteRecord(ctx context.Context, hostID uuid.UUID, zoneID uuid.UUID, id uuid.UUID, userID *uuid.UUID) error {
	rec, err := s.records.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.records.Delete(ctx, id); err != nil {
		return err
	}
	if err := s.zones.IncrementSerial(ctx, zoneID); err != nil {
		s.logger.Error("failed to increment serial", "zone_id", zoneID, "error", err)
	}

	s.logAudit(ctx, hostID, userID, "delete", "record", id, rec.Name, fmt.Sprintf("type=%s", rec.Type))

	if err := s.Sync(ctx); err != nil {
		s.logger.Error("failed to sync after record delete", "error", err)
	}
	return nil
}

// ============================================================================
// TSIG key operations
// ============================================================================

// ListTSIGKeys retrieves all TSIG keys for a host.
func (s *Service) ListTSIGKeys(ctx context.Context, hostID uuid.UUID) ([]*models.DNSTSIGKey, error) {
	return s.tsigKeys.List(ctx, hostID)
}

// GetTSIGKey retrieves a TSIG key by ID.
func (s *Service) GetTSIGKey(ctx context.Context, id uuid.UUID) (*models.DNSTSIGKey, error) {
	return s.tsigKeys.GetByID(ctx, id)
}

// CreateTSIGKey creates a TSIG key, encrypting the secret at rest.
func (s *Service) CreateTSIGKey(ctx context.Context, k *models.DNSTSIGKey, userID *uuid.UUID) error {
	if s.enc != nil && k.Secret != "" {
		encrypted, err := s.enc.EncryptString(k.Secret)
		if err != nil {
			return fmt.Errorf("failed to encrypt TSIG secret: %w", err)
		}
		k.Secret = encrypted
	}

	if err := s.tsigKeys.Create(ctx, k); err != nil {
		return err
	}

	s.logAudit(ctx, k.HostID, userID, "create", "tsig_key", k.ID, k.Name, "")
	return nil
}

// UpdateTSIGKey updates a TSIG key.
func (s *Service) UpdateTSIGKey(ctx context.Context, k *models.DNSTSIGKey, userID *uuid.UUID) error {
	if s.enc != nil && k.Secret != "" {
		encrypted, err := s.enc.EncryptString(k.Secret)
		if err != nil {
			return fmt.Errorf("failed to encrypt TSIG secret: %w", err)
		}
		k.Secret = encrypted
	}

	if err := s.tsigKeys.Update(ctx, k); err != nil {
		return err
	}

	s.logAudit(ctx, k.HostID, userID, "update", "tsig_key", k.ID, k.Name, "")
	return nil
}

// DeleteTSIGKey deletes a TSIG key.
func (s *Service) DeleteTSIGKey(ctx context.Context, hostID uuid.UUID, id uuid.UUID, userID *uuid.UUID) error {
	k, err := s.tsigKeys.GetByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.tsigKeys.Delete(ctx, id); err != nil {
		return err
	}

	s.logAudit(ctx, hostID, userID, "delete", "tsig_key", id, k.Name, "")
	return nil
}

// ============================================================================
// Audit log
// ============================================================================

// ListAuditLogs retrieves DNS audit log entries for a host.
func (s *Service) ListAuditLogs(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.DNSAuditLog, int, error) {
	return s.audit.List(ctx, hostID, limit, offset)
}

// ============================================================================
// Backend lifecycle
// ============================================================================

// Start starts the DNS backend.
func (s *Service) Start(ctx context.Context) error {
	if s.backend == nil {
		return nil
	}
	s.logger.Info("starting DNS backend", "mode", s.backend.Mode())
	if err := s.backend.Start(ctx); err != nil {
		return fmt.Errorf("failed to start DNS backend: %w", err)
	}
	// Initial sync
	return s.Sync(ctx)
}

// Stop shuts down the DNS backend.
func (s *Service) Stop() error {
	if s.backend == nil {
		return nil
	}
	s.logger.Info("stopping DNS backend")
	return s.backend.Stop()
}

// Healthy checks if the DNS backend is healthy.
func (s *Service) Healthy(ctx context.Context) (bool, error) {
	if s.backend == nil {
		return false, nil
	}
	return s.backend.Healthy(ctx)
}

// Stats returns DNS server statistics.
func (s *Service) Stats() ServerStats {
	if s.backend == nil {
		return ServerStats{}
	}
	return s.backend.Stats()
}

// Sync loads all zone/record data from the database and pushes it to the backend.
func (s *Service) Sync(ctx context.Context) error {
	if s.backend == nil {
		return nil
	}

	s.syncMu.Lock()
	defer s.syncMu.Unlock()

	data, err := s.loadSyncData(ctx)
	if err != nil {
		return fmt.Errorf("failed to load sync data: %w", err)
	}
	return s.backend.Sync(ctx, data)
}

// loadSyncData assembles the full DNS dataset from the database.
func (s *Service) loadSyncData(ctx context.Context) (*SyncData, error) {
	zones, err := s.zones.ListAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list zones: %w", err)
	}

	records := make(map[string][]*models.DNSRecord, len(zones))
	for _, z := range zones {
		recs, err := s.records.ListByZone(ctx, z.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to list records for zone %s: %w", z.Name, err)
		}
		records[z.ID.String()] = recs
	}

	// Load TSIG keys — collect from all hosts represented by zones
	var tsigKeys []*models.DNSTSIGKey
	seenHosts := make(map[uuid.UUID]bool)
	for _, z := range zones {
		if seenHosts[z.HostID] {
			continue
		}
		seenHosts[z.HostID] = true
		keys, err := s.tsigKeys.List(ctx, z.HostID)
		if err != nil {
			return nil, fmt.Errorf("failed to list TSIG keys for host %s: %w", z.HostID, err)
		}
		// Decrypt secrets for the backend
		for _, k := range keys {
			if s.enc != nil && k.Secret != "" {
				decrypted, err := s.enc.DecryptString(k.Secret)
				if err != nil {
					s.logger.Error("failed to decrypt TSIG secret", "key", k.Name, "error", err)
					continue
				}
				k.Secret = decrypted
			}
		}
		tsigKeys = append(tsigKeys, keys...)
	}

	return &SyncData{
		Zones:    zones,
		Records:  records,
		TSIGKeys: tsigKeys,
	}, nil
}

// logAudit creates an audit log entry (best-effort, does not fail the operation).
func (s *Service) logAudit(ctx context.Context, hostID uuid.UUID, userID *uuid.UUID, action, resourceType string, resourceID uuid.UUID, resourceName, details string) {
	entry := &models.DNSAuditLog{
		HostID:       hostID,
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		ResourceName: resourceName,
		Details:      details,
	}
	if err := s.audit.Create(ctx, entry); err != nil {
		s.logger.Error("failed to create DNS audit log", "action", action, "error", err)
	}
}
