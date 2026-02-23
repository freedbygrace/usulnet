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
// SSLTargetRepository
// ============================================================================

// SSLTargetRepository implements SSL target persistence.
type SSLTargetRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewSSLTargetRepository creates a new SSL target repository.
func NewSSLTargetRepository(db *DB, log *logger.Logger) *SSLTargetRepository {
	return &SSLTargetRepository{
		db:     db,
		logger: log.Named("ssl_target_repo"),
	}
}

// Create inserts a new SSL target.
func (r *SSLTargetRepository) Create(ctx context.Context, t *models.SSLTarget) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	now := time.Now()
	if t.CreatedAt.IsZero() {
		t.CreatedAt = now
	}
	t.UpdatedAt = now

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO ssl_targets (
			id, host_id, name, hostname, port,
			auto_discovered, enabled, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9
		)`,
		t.ID, t.HostID, t.Name, t.Hostname, t.Port,
		t.AutoDiscovered, t.Enabled, t.CreatedAt, t.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "ssl: create target")
	}
	return nil
}

// GetByID retrieves an SSL target by ID.
func (r *SSLTargetRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.SSLTarget, error) {
	var t models.SSLTarget
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, host_id, name, hostname, port,
			auto_discovered, enabled, created_at, updated_at
		FROM ssl_targets WHERE id = $1`, id,
	).Scan(
		&t.ID, &t.HostID, &t.Name, &t.Hostname, &t.Port,
		&t.AutoDiscovered, &t.Enabled, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("ssl target")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "ssl: get target by id")
	}
	return &t, nil
}

// List retrieves all SSL targets for a host.
func (r *SSLTargetRepository) List(ctx context.Context, hostID uuid.UUID) ([]models.SSLTarget, error) {
	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, host_id, name, hostname, port,
			auto_discovered, enabled, created_at, updated_at
		FROM ssl_targets
		WHERE host_id = $1
		ORDER BY name ASC`, hostID,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "ssl: list targets")
	}
	defer rows.Close()

	var targets []models.SSLTarget
	for rows.Next() {
		var t models.SSLTarget
		if err := rows.Scan(
			&t.ID, &t.HostID, &t.Name, &t.Hostname, &t.Port,
			&t.AutoDiscovered, &t.Enabled, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "ssl: scan target")
		}
		targets = append(targets, t)
	}
	return targets, nil
}

// Update updates an SSL target.
func (r *SSLTargetRepository) Update(ctx context.Context, t *models.SSLTarget) error {
	t.UpdatedAt = time.Now()

	tag, err := r.db.Pool().Exec(ctx, `
		UPDATE ssl_targets SET
			name=$2, hostname=$3, port=$4,
			auto_discovered=$5, enabled=$6, updated_at=$7
		WHERE id=$1`,
		t.ID, t.Name, t.Hostname, t.Port,
		t.AutoDiscovered, t.Enabled, t.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "ssl: update target")
	}
	if tag.RowsAffected() == 0 {
		return errors.NotFound("ssl target")
	}
	return nil
}

// Delete removes an SSL target.
func (r *SSLTargetRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Pool().Exec(ctx, `DELETE FROM ssl_targets WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "ssl: delete target")
	}
	if tag.RowsAffected() == 0 {
		return errors.NotFound("ssl target")
	}
	return nil
}

// ListEnabled retrieves all enabled SSL targets for a host.
func (r *SSLTargetRepository) ListEnabled(ctx context.Context, hostID uuid.UUID) ([]models.SSLTarget, error) {
	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, host_id, name, hostname, port,
			auto_discovered, enabled, created_at, updated_at
		FROM ssl_targets
		WHERE host_id = $1 AND enabled = true
		ORDER BY name ASC`, hostID,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "ssl: list enabled targets")
	}
	defer rows.Close()

	var targets []models.SSLTarget
	for rows.Next() {
		var t models.SSLTarget
		if err := rows.Scan(
			&t.ID, &t.HostID, &t.Name, &t.Hostname, &t.Port,
			&t.AutoDiscovered, &t.Enabled, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "ssl: scan enabled target")
		}
		targets = append(targets, t)
	}
	return targets, nil
}

// ============================================================================
// SSLScanResultRepository
// ============================================================================

// SSLScanResultRepository implements SSL scan result persistence.
type SSLScanResultRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewSSLScanResultRepository creates a new SSL scan result repository.
func NewSSLScanResultRepository(db *DB, log *logger.Logger) *SSLScanResultRepository {
	return &SSLScanResultRepository{
		db:     db,
		logger: log.Named("ssl_scan_result_repo"),
	}
}

// Create inserts a new SSL scan result.
func (r *SSLScanResultRepository) Create(ctx context.Context, s *models.SSLScanResult) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	if s.ScannedAt.IsZero() {
		s.ScannedAt = time.Now()
	}

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO ssl_scan_results (
			id, target_id, grade, score,
			protocol_versions, cipher_suites,
			certificate_cn, certificate_issuer, certificate_sans,
			cert_not_before, cert_not_after,
			cert_key_type, cert_key_bits, cert_chain_valid, cert_chain_length,
			has_hsts, has_ocsp_stapling, has_sct,
			vulnerabilities, error_message, scan_duration_ms, scanned_at
		) VALUES (
			$1, $2, $3, $4,
			$5, $6,
			$7, $8, $9,
			$10, $11,
			$12, $13, $14, $15,
			$16, $17, $18,
			$19, $20, $21, $22
		)`,
		s.ID, s.TargetID, s.Grade, s.Score,
		s.ProtocolVersions, s.CipherSuites,
		s.CertificateCN, s.CertificateIssuer, s.CertificateSANs,
		s.CertNotBefore, s.CertNotAfter,
		s.CertKeyType, s.CertKeyBits, s.CertChainValid, s.CertChainLength,
		s.HasHSTS, s.HasOCSPStapling, s.HasSCT,
		s.Vulnerabilities, s.ErrorMessage, s.ScanDurationMs, s.ScannedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "ssl: create scan result")
	}
	return nil
}

// GetLatestByTarget retrieves the most recent scan result for a target.
func (r *SSLScanResultRepository) GetLatestByTarget(ctx context.Context, targetID uuid.UUID) (*models.SSLScanResult, error) {
	var s models.SSLScanResult
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, target_id, grade, score,
			protocol_versions, cipher_suites,
			certificate_cn, certificate_issuer, certificate_sans,
			cert_not_before, cert_not_after,
			cert_key_type, cert_key_bits, cert_chain_valid, cert_chain_length,
			has_hsts, has_ocsp_stapling, has_sct,
			vulnerabilities, error_message, scan_duration_ms, scanned_at
		FROM ssl_scan_results
		WHERE target_id = $1
		ORDER BY scanned_at DESC
		LIMIT 1`, targetID,
	).Scan(
		&s.ID, &s.TargetID, &s.Grade, &s.Score,
		&s.ProtocolVersions, &s.CipherSuites,
		&s.CertificateCN, &s.CertificateIssuer, &s.CertificateSANs,
		&s.CertNotBefore, &s.CertNotAfter,
		&s.CertKeyType, &s.CertKeyBits, &s.CertChainValid, &s.CertChainLength,
		&s.HasHSTS, &s.HasOCSPStapling, &s.HasSCT,
		&s.Vulnerabilities, &s.ErrorMessage, &s.ScanDurationMs, &s.ScannedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("ssl scan result")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "ssl: get latest scan result")
	}
	return &s, nil
}

// ListByTarget retrieves paginated scan results for a target.
func (r *SSLScanResultRepository) ListByTarget(ctx context.Context, targetID uuid.UUID, limit, offset int) ([]models.SSLScanResult, int, error) {
	var total int
	err := r.db.Pool().QueryRow(ctx,
		`SELECT COUNT(*) FROM ssl_scan_results WHERE target_id = $1`, targetID,
	).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "ssl: count scan results")
	}

	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, target_id, grade, score,
			protocol_versions, cipher_suites,
			certificate_cn, certificate_issuer, certificate_sans,
			cert_not_before, cert_not_after,
			cert_key_type, cert_key_bits, cert_chain_valid, cert_chain_length,
			has_hsts, has_ocsp_stapling, has_sct,
			vulnerabilities, error_message, scan_duration_ms, scanned_at
		FROM ssl_scan_results
		WHERE target_id = $1
		ORDER BY scanned_at DESC
		LIMIT $2 OFFSET $3`, targetID, limit, offset,
	)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "ssl: list scan results")
	}
	defer rows.Close()

	var results []models.SSLScanResult
	for rows.Next() {
		var s models.SSLScanResult
		if err := rows.Scan(
			&s.ID, &s.TargetID, &s.Grade, &s.Score,
			&s.ProtocolVersions, &s.CipherSuites,
			&s.CertificateCN, &s.CertificateIssuer, &s.CertificateSANs,
			&s.CertNotBefore, &s.CertNotAfter,
			&s.CertKeyType, &s.CertKeyBits, &s.CertChainValid, &s.CertChainLength,
			&s.HasHSTS, &s.HasOCSPStapling, &s.HasSCT,
			&s.Vulnerabilities, &s.ErrorMessage, &s.ScanDurationMs, &s.ScannedAt,
		); err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "ssl: scan result row")
		}
		results = append(results, s)
	}
	return results, total, nil
}

// GetExpiringCerts retrieves scan results where the certificate expires within the given number of days.
func (r *SSLScanResultRepository) GetExpiringCerts(ctx context.Context, hostID uuid.UUID, days int) ([]models.SSLScanResult, error) {
	rows, err := r.db.Pool().Query(ctx, `
		SELECT DISTINCT ON (sr.target_id)
			sr.id, sr.target_id, sr.grade, sr.score,
			sr.protocol_versions, sr.cipher_suites,
			sr.certificate_cn, sr.certificate_issuer, sr.certificate_sans,
			sr.cert_not_before, sr.cert_not_after,
			sr.cert_key_type, sr.cert_key_bits, sr.cert_chain_valid, sr.cert_chain_length,
			sr.has_hsts, sr.has_ocsp_stapling, sr.has_sct,
			sr.vulnerabilities, sr.error_message, sr.scan_duration_ms, sr.scanned_at
		FROM ssl_scan_results sr
		JOIN ssl_targets st ON sr.target_id = st.id
		WHERE st.host_id = $1
			AND sr.cert_not_after IS NOT NULL
			AND sr.cert_not_after <= NOW() + ($2 || ' days')::INTERVAL
		ORDER BY sr.target_id, sr.scanned_at DESC`, hostID, days,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "ssl: get expiring certs")
	}
	defer rows.Close()

	var results []models.SSLScanResult
	for rows.Next() {
		var s models.SSLScanResult
		if err := rows.Scan(
			&s.ID, &s.TargetID, &s.Grade, &s.Score,
			&s.ProtocolVersions, &s.CipherSuites,
			&s.CertificateCN, &s.CertificateIssuer, &s.CertificateSANs,
			&s.CertNotBefore, &s.CertNotAfter,
			&s.CertKeyType, &s.CertKeyBits, &s.CertChainValid, &s.CertChainLength,
			&s.HasHSTS, &s.HasOCSPStapling, &s.HasSCT,
			&s.Vulnerabilities, &s.ErrorMessage, &s.ScanDurationMs, &s.ScannedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "ssl: scan expiring cert row")
		}
		results = append(results, s)
	}
	return results, nil
}

// GetDashboardStats returns aggregate statistics for the SSL observatory dashboard.
func (r *SSLScanResultRepository) GetDashboardStats(ctx context.Context, hostID uuid.UUID) (*models.SSLDashboardStats, error) {
	stats := &models.SSLDashboardStats{
		GradeDistribution: make(map[string]int),
	}

	// Total targets
	err := r.db.Pool().QueryRow(ctx,
		`SELECT COUNT(*) FROM ssl_targets WHERE host_id = $1`, hostID,
	).Scan(&stats.TotalTargets)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "ssl: count targets for stats")
	}

	// Grade distribution from the latest scan per target
	rows, err := r.db.Pool().Query(ctx, `
		SELECT sr.grade, COUNT(*)
		FROM (
			SELECT DISTINCT ON (sr.target_id) sr.grade
			FROM ssl_scan_results sr
			JOIN ssl_targets st ON sr.target_id = st.id
			WHERE st.host_id = $1
			ORDER BY sr.target_id, sr.scanned_at DESC
		) sr
		GROUP BY sr.grade`, hostID,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "ssl: grade distribution")
	}
	defer rows.Close()

	for rows.Next() {
		var grade string
		var count int
		if err := rows.Scan(&grade, &count); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "ssl: scan grade distribution row")
		}
		stats.GradeDistribution[grade] = count
	}

	// Expiring soon (within 30 days)
	err = r.db.Pool().QueryRow(ctx, `
		SELECT COUNT(DISTINCT sr.target_id)
		FROM ssl_scan_results sr
		JOIN ssl_targets st ON sr.target_id = st.id
		WHERE st.host_id = $1
			AND sr.cert_not_after IS NOT NULL
			AND sr.cert_not_after <= NOW() + INTERVAL '30 days'
			AND sr.id = (
				SELECT id FROM ssl_scan_results
				WHERE target_id = sr.target_id
				ORDER BY scanned_at DESC LIMIT 1
			)`, hostID,
	).Scan(&stats.ExpiringSoon)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "ssl: count expiring certs")
	}

	// Last scan time
	var lastScan *time.Time
	err = r.db.Pool().QueryRow(ctx, `
		SELECT MAX(sr.scanned_at)
		FROM ssl_scan_results sr
		JOIN ssl_targets st ON sr.target_id = st.id
		WHERE st.host_id = $1`, hostID,
	).Scan(&lastScan)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "ssl: last scan time")
	}
	stats.LastScanTime = lastScan

	return stats, nil
}
