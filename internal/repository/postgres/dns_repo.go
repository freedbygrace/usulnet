// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// DNSZoneRepository
// ============================================================================

// DNSZoneRepository implements DNS zone persistence.
type DNSZoneRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewDNSZoneRepository creates a new DNS zone repository.
func NewDNSZoneRepository(db *DB, log *logger.Logger) *DNSZoneRepository {
	return &DNSZoneRepository{
		db:     db,
		logger: log.Named("dns_zone_repo"),
	}
}

// Create inserts a new DNS zone.
func (r *DNSZoneRepository) Create(ctx context.Context, z *models.DNSZone) error {
	if z.ID == uuid.Nil {
		z.ID = uuid.New()
	}
	now := time.Now()
	if z.CreatedAt.IsZero() {
		z.CreatedAt = now
	}
	z.UpdatedAt = now

	query := `
		INSERT INTO dns_zones (
			id, host_id, name, kind, enabled, ttl, serial,
			refresh, retry, expire, minimum_ttl,
			primary_ns, admin_email, forwarders, description,
			created_by, updated_by, created_at, updated_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19
		)`

	_, err := r.db.Exec(ctx, query,
		z.ID, z.HostID, z.Name, string(z.Kind), z.Enabled, z.TTL, z.Serial,
		z.Refresh, z.Retry, z.Expire, z.MinimumTTL,
		z.PrimaryNS, z.AdminEmail, z.Forwarders, z.Description,
		z.CreatedBy, z.UpdatedBy, z.CreatedAt, z.UpdatedAt,
	)
	if err != nil {
		if IsDuplicateKeyError(err) {
			return errors.AlreadyExists("dns_zone").WithDetail("name", z.Name)
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create dns zone")
	}
	return nil
}

// GetByID retrieves a DNS zone by ID.
func (r *DNSZoneRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.DNSZone, error) {
	query := `SELECT * FROM dns_zones WHERE id = $1`
	rows, err := r.db.Query(ctx, query, id)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query dns zone")
	}
	defer rows.Close()

	z, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.DNSZone])
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("dns_zone").WithDetail("id", id.String())
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan dns zone")
	}
	return z, nil
}

// List retrieves DNS zones for a host.
func (r *DNSZoneRepository) List(ctx context.Context, hostID uuid.UUID) ([]*models.DNSZone, error) {
	query := `SELECT * FROM dns_zones WHERE host_id = $1 ORDER BY name ASC`

	rows, err := r.db.Query(ctx, query, hostID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list dns zones")
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.DNSZone])
}

// ListAll retrieves all enabled DNS zones across all hosts.
func (r *DNSZoneRepository) ListAll(ctx context.Context) ([]*models.DNSZone, error) {
	query := `SELECT * FROM dns_zones WHERE enabled = true ORDER BY name ASC`

	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list all dns zones")
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.DNSZone])
}

// Update updates a DNS zone.
func (r *DNSZoneRepository) Update(ctx context.Context, z *models.DNSZone) error {
	z.UpdatedAt = time.Now()

	query := `
		UPDATE dns_zones SET
			name=$2, kind=$3, enabled=$4, ttl=$5, serial=$6,
			refresh=$7, retry=$8, expire=$9, minimum_ttl=$10,
			primary_ns=$11, admin_email=$12, forwarders=$13, description=$14,
			updated_by=$15, updated_at=$16
		WHERE id=$1`

	ct, err := r.db.Exec(ctx, query,
		z.ID, z.Name, string(z.Kind), z.Enabled, z.TTL, z.Serial,
		z.Refresh, z.Retry, z.Expire, z.MinimumTTL,
		z.PrimaryNS, z.AdminEmail, z.Forwarders, z.Description,
		z.UpdatedBy, z.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update dns zone")
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("dns_zone").WithDetail("id", z.ID.String())
	}
	return nil
}

// Delete removes a DNS zone.
func (r *DNSZoneRepository) Delete(ctx context.Context, id uuid.UUID) error {
	ct, err := r.db.Exec(ctx, `DELETE FROM dns_zones WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete dns zone")
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("dns_zone").WithDetail("id", id.String())
	}
	return nil
}

// IncrementSerial atomically increments the zone serial number.
func (r *DNSZoneRepository) IncrementSerial(ctx context.Context, id uuid.UUID) error {
	ct, err := r.db.Exec(ctx,
		`UPDATE dns_zones SET serial = serial + 1, updated_at = NOW() WHERE id = $1`,
		id,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to increment dns zone serial")
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("dns_zone").WithDetail("id", id.String())
	}
	return nil
}

// ============================================================================
// DNSRecordRepository
// ============================================================================

// DNSRecordRepository implements DNS record persistence.
type DNSRecordRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewDNSRecordRepository creates a new DNS record repository.
func NewDNSRecordRepository(db *DB, log *logger.Logger) *DNSRecordRepository {
	return &DNSRecordRepository{
		db:     db,
		logger: log.Named("dns_record_repo"),
	}
}

// Create inserts a new DNS record.
func (r *DNSRecordRepository) Create(ctx context.Context, rec *models.DNSRecord) error {
	if rec.ID == uuid.Nil {
		rec.ID = uuid.New()
	}
	now := time.Now()
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = now
	}
	rec.UpdatedAt = now

	query := `
		INSERT INTO dns_records (
			id, zone_id, host_id, name, type, ttl, content,
			priority, weight, port, enabled, comment,
			created_at, updated_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14
		)`

	_, err := r.db.Exec(ctx, query,
		rec.ID, rec.ZoneID, rec.HostID, rec.Name, string(rec.Type), rec.TTL, rec.Content,
		rec.Priority, rec.Weight, rec.Port, rec.Enabled, rec.Comment,
		rec.CreatedAt, rec.UpdatedAt,
	)
	if err != nil {
		if IsDuplicateKeyError(err) {
			return errors.AlreadyExists("dns_record").WithDetail("name", rec.Name)
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create dns record")
	}
	return nil
}

// GetByID retrieves a DNS record by ID.
func (r *DNSRecordRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.DNSRecord, error) {
	query := `SELECT * FROM dns_records WHERE id = $1`
	rows, err := r.db.Query(ctx, query, id)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query dns record")
	}
	defer rows.Close()

	rec, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.DNSRecord])
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("dns_record").WithDetail("id", id.String())
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan dns record")
	}
	return rec, nil
}

// ListByZone retrieves all DNS records for a zone.
func (r *DNSRecordRepository) ListByZone(ctx context.Context, zoneID uuid.UUID) ([]*models.DNSRecord, error) {
	query := `SELECT * FROM dns_records WHERE zone_id = $1 ORDER BY type ASC, name ASC`

	rows, err := r.db.Query(ctx, query, zoneID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list dns records")
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.DNSRecord])
}

// Update updates a DNS record.
func (r *DNSRecordRepository) Update(ctx context.Context, rec *models.DNSRecord) error {
	rec.UpdatedAt = time.Now()

	query := `
		UPDATE dns_records SET
			name=$2, type=$3, ttl=$4, content=$5,
			priority=$6, weight=$7, port=$8, enabled=$9, comment=$10,
			updated_at=$11
		WHERE id=$1`

	ct, err := r.db.Exec(ctx, query,
		rec.ID, rec.Name, string(rec.Type), rec.TTL, rec.Content,
		rec.Priority, rec.Weight, rec.Port, rec.Enabled, rec.Comment,
		rec.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update dns record")
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("dns_record").WithDetail("id", rec.ID.String())
	}
	return nil
}

// Delete removes a DNS record.
func (r *DNSRecordRepository) Delete(ctx context.Context, id uuid.UUID) error {
	ct, err := r.db.Exec(ctx, `DELETE FROM dns_records WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete dns record")
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("dns_record").WithDetail("id", id.String())
	}
	return nil
}

// ============================================================================
// DNSTSIGKeyRepository
// ============================================================================

// DNSTSIGKeyRepository implements DNS TSIG key persistence.
type DNSTSIGKeyRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewDNSTSIGKeyRepository creates a new DNS TSIG key repository.
func NewDNSTSIGKeyRepository(db *DB, log *logger.Logger) *DNSTSIGKeyRepository {
	return &DNSTSIGKeyRepository{
		db:     db,
		logger: log.Named("dns_tsig_key_repo"),
	}
}

// Create inserts a new TSIG key.
func (r *DNSTSIGKeyRepository) Create(ctx context.Context, k *models.DNSTSIGKey) error {
	if k.ID == uuid.Nil {
		k.ID = uuid.New()
	}
	now := time.Now()
	if k.CreatedAt.IsZero() {
		k.CreatedAt = now
	}
	k.UpdatedAt = now

	query := `
		INSERT INTO dns_tsig_keys (
			id, host_id, name, algorithm, secret, enabled,
			created_at, updated_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8
		)`

	_, err := r.db.Exec(ctx, query,
		k.ID, k.HostID, k.Name, k.Algorithm, k.Secret, k.Enabled,
		k.CreatedAt, k.UpdatedAt,
	)
	if err != nil {
		if IsDuplicateKeyError(err) {
			return errors.AlreadyExists("dns_tsig_key").WithDetail("name", k.Name)
		}
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create dns tsig key")
	}
	return nil
}

// GetByID retrieves a TSIG key by ID.
func (r *DNSTSIGKeyRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.DNSTSIGKey, error) {
	query := `SELECT * FROM dns_tsig_keys WHERE id = $1`
	rows, err := r.db.Query(ctx, query, id)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query dns tsig key")
	}
	defer rows.Close()

	k, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.DNSTSIGKey])
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("dns_tsig_key").WithDetail("id", id.String())
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan dns tsig key")
	}
	return k, nil
}

// List retrieves all TSIG keys for a host.
func (r *DNSTSIGKeyRepository) List(ctx context.Context, hostID uuid.UUID) ([]*models.DNSTSIGKey, error) {
	query := `SELECT * FROM dns_tsig_keys WHERE host_id = $1 ORDER BY name ASC`

	rows, err := r.db.Query(ctx, query, hostID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list dns tsig keys")
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.DNSTSIGKey])
}

// Update updates a TSIG key.
func (r *DNSTSIGKeyRepository) Update(ctx context.Context, k *models.DNSTSIGKey) error {
	k.UpdatedAt = time.Now()

	query := `
		UPDATE dns_tsig_keys SET
			name=$2, algorithm=$3, secret=$4, enabled=$5,
			updated_at=$6
		WHERE id=$1`

	ct, err := r.db.Exec(ctx, query,
		k.ID, k.Name, k.Algorithm, k.Secret, k.Enabled,
		k.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update dns tsig key")
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("dns_tsig_key").WithDetail("id", k.ID.String())
	}
	return nil
}

// Delete removes a TSIG key.
func (r *DNSTSIGKeyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	ct, err := r.db.Exec(ctx, `DELETE FROM dns_tsig_keys WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete dns tsig key")
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("dns_tsig_key").WithDetail("id", id.String())
	}
	return nil
}

// ============================================================================
// DNSAuditLogRepository
// ============================================================================

// DNSAuditLogRepository manages DNS audit log entries.
type DNSAuditLogRepository struct {
	db *DB
}

// NewDNSAuditLogRepository creates a new DNS audit log repository.
func NewDNSAuditLogRepository(db *DB) *DNSAuditLogRepository {
	return &DNSAuditLogRepository{db: db}
}

// Create inserts a DNS audit log entry.
func (r *DNSAuditLogRepository) Create(ctx context.Context, entry *models.DNSAuditLog) error {
	if entry.ID == uuid.Nil {
		entry.ID = uuid.New()
	}
	entry.CreatedAt = time.Now()

	_, err := r.db.Exec(ctx,
		`INSERT INTO dns_audit_log (id, host_id, user_id, action, resource_type, resource_id, resource_name, details, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		entry.ID, entry.HostID, entry.UserID, entry.Action, entry.ResourceType, entry.ResourceID, entry.ResourceName, entry.Details, entry.CreatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create dns audit log entry")
	}
	return nil
}

// List retrieves DNS audit log entries for a host with pagination.
func (r *DNSAuditLogRepository) List(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.DNSAuditLog, int, error) {
	if limit <= 0 {
		limit = 50
	}

	var total int
	err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM dns_audit_log WHERE host_id = $1`, hostID).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to count dns audit log entries")
	}

	rows, err := r.db.Query(ctx,
		`SELECT * FROM dns_audit_log WHERE host_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`,
		hostID, limit, offset,
	)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to list dns audit log entries")
	}
	defer rows.Close()

	entries, err := pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.DNSAuditLog])
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan dns audit log entries")
	}
	return entries, total, nil
}
