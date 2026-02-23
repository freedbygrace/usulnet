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
// BackupVerificationRepository
// ============================================================================

type BackupVerificationRepository struct {
	db     *DB
	logger *logger.Logger
}

func NewBackupVerificationRepository(db *DB, log *logger.Logger) *BackupVerificationRepository {
	return &BackupVerificationRepository{
		db:     db,
		logger: log.Named("backup_verify_repo"),
	}
}

func (r *BackupVerificationRepository) Create(ctx context.Context, v *models.BackupVerification) error {
	if v.ID == uuid.Nil {
		v.ID = uuid.New()
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now()
	}

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO backup_verifications (
			id, backup_id, host_id, status, method,
			checksum_valid, files_readable, container_test, data_valid,
			file_count, size_bytes, duration_ms, error_message, details,
			verified_by, started_at, completed_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
		v.ID, v.BackupID, v.HostID, v.Status, v.Method,
		v.ChecksumValid, v.FilesReadable, v.ContainerTest, v.DataValid,
		v.FileCount, v.SizeBytes, v.DurationMs, v.ErrorMessage, v.Details,
		v.VerifiedBy, v.StartedAt, v.CompletedAt, v.CreatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "create backup verification")
	}
	return nil
}

func (r *BackupVerificationRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.BackupVerification, error) {
	var v models.BackupVerification
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, backup_id, host_id, status, method,
			checksum_valid, files_readable, container_test, data_valid,
			file_count, size_bytes, duration_ms, error_message, details,
			verified_by, started_at, completed_at, created_at
		FROM backup_verifications WHERE id = $1`, id,
	).Scan(
		&v.ID, &v.BackupID, &v.HostID, &v.Status, &v.Method,
		&v.ChecksumValid, &v.FilesReadable, &v.ContainerTest, &v.DataValid,
		&v.FileCount, &v.SizeBytes, &v.DurationMs, &v.ErrorMessage, &v.Details,
		&v.VerifiedBy, &v.StartedAt, &v.CompletedAt, &v.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("backup_verification")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get backup verification")
	}
	return &v, nil
}

func (r *BackupVerificationRepository) Update(ctx context.Context, v *models.BackupVerification) error {
	_, err := r.db.Pool().Exec(ctx, `
		UPDATE backup_verifications SET
			status = $2, checksum_valid = $3, files_readable = $4,
			container_test = $5, data_valid = $6, file_count = $7,
			size_bytes = $8, duration_ms = $9, error_message = $10,
			details = $11, started_at = $12, completed_at = $13
		WHERE id = $1`,
		v.ID, v.Status, v.ChecksumValid, v.FilesReadable,
		v.ContainerTest, v.DataValid, v.FileCount,
		v.SizeBytes, v.DurationMs, v.ErrorMessage,
		v.Details, v.StartedAt, v.CompletedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "update backup verification")
	}
	return nil
}

func (r *BackupVerificationRepository) ListByBackup(ctx context.Context, backupID uuid.UUID) ([]models.BackupVerification, error) {
	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, backup_id, host_id, status, method,
			checksum_valid, files_readable, container_test, data_valid,
			file_count, size_bytes, duration_ms, error_message, details,
			verified_by, started_at, completed_at, created_at
		FROM backup_verifications WHERE backup_id = $1
		ORDER BY created_at DESC`, backupID,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "list backup verifications by backup")
	}
	defer rows.Close()

	var results []models.BackupVerification
	for rows.Next() {
		var v models.BackupVerification
		if err := rows.Scan(
			&v.ID, &v.BackupID, &v.HostID, &v.Status, &v.Method,
			&v.ChecksumValid, &v.FilesReadable, &v.ContainerTest, &v.DataValid,
			&v.FileCount, &v.SizeBytes, &v.DurationMs, &v.ErrorMessage, &v.Details,
			&v.VerifiedBy, &v.StartedAt, &v.CompletedAt, &v.CreatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "scan backup verification")
		}
		results = append(results, v)
	}
	return results, nil
}

func (r *BackupVerificationRepository) ListByHost(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.BackupVerification, int, error) {
	var total int
	err := r.db.Pool().QueryRow(ctx,
		`SELECT COUNT(*) FROM backup_verifications WHERE host_id = $1`, hostID,
	).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "count backup verifications")
	}

	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, backup_id, host_id, status, method,
			checksum_valid, files_readable, container_test, data_valid,
			file_count, size_bytes, duration_ms, error_message, details,
			verified_by, started_at, completed_at, created_at
		FROM backup_verifications WHERE host_id = $1
		ORDER BY created_at DESC LIMIT $2 OFFSET $3`, hostID, limit, offset,
	)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "list backup verifications by host")
	}
	defer rows.Close()

	var results []models.BackupVerification
	for rows.Next() {
		var v models.BackupVerification
		if err := rows.Scan(
			&v.ID, &v.BackupID, &v.HostID, &v.Status, &v.Method,
			&v.ChecksumValid, &v.FilesReadable, &v.ContainerTest, &v.DataValid,
			&v.FileCount, &v.SizeBytes, &v.DurationMs, &v.ErrorMessage, &v.Details,
			&v.VerifiedBy, &v.StartedAt, &v.CompletedAt, &v.CreatedAt,
		); err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "scan backup verification")
		}
		results = append(results, v)
	}
	return results, total, nil
}

func (r *BackupVerificationRepository) GetLatestByBackup(ctx context.Context, backupID uuid.UUID) (*models.BackupVerification, error) {
	var v models.BackupVerification
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, backup_id, host_id, status, method,
			checksum_valid, files_readable, container_test, data_valid,
			file_count, size_bytes, duration_ms, error_message, details,
			verified_by, started_at, completed_at, created_at
		FROM backup_verifications WHERE backup_id = $1
		ORDER BY created_at DESC LIMIT 1`, backupID,
	).Scan(
		&v.ID, &v.BackupID, &v.HostID, &v.Status, &v.Method,
		&v.ChecksumValid, &v.FilesReadable, &v.ContainerTest, &v.DataValid,
		&v.FileCount, &v.SizeBytes, &v.DurationMs, &v.ErrorMessage, &v.Details,
		&v.VerifiedBy, &v.StartedAt, &v.CompletedAt, &v.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get latest verification for backup")
	}
	return &v, nil
}

func (r *BackupVerificationRepository) GetStats(ctx context.Context, hostID uuid.UUID) (*models.BackupVerificationStats, error) {
	stats := &models.BackupVerificationStats{}

	err := r.db.Pool().QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 'passed'),
			COUNT(*) FILTER (WHERE status = 'failed')
		FROM backup_verifications WHERE host_id = $1`, hostID,
	).Scan(&stats.TotalVerified, &stats.Passed, &stats.Failed)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get verification stats")
	}

	if stats.TotalVerified > 0 {
		stats.PassRate = float64(stats.Passed) / float64(stats.TotalVerified) * 100
	}

	var lastVerified *time.Time
	err = r.db.Pool().QueryRow(ctx, `
		SELECT MAX(completed_at) FROM backup_verifications WHERE host_id = $1 AND completed_at IS NOT NULL`, hostID,
	).Scan(&lastVerified)
	if err == nil && lastVerified != nil {
		stats.LastVerified = lastVerified.Format("2006-01-02 15:04")
	}

	return stats, nil
}

// ============================================================================
// BackupVerificationScheduleRepository
// ============================================================================

type BackupVerificationScheduleRepository struct {
	db     *DB
	logger *logger.Logger
}

func NewBackupVerificationScheduleRepository(db *DB, log *logger.Logger) *BackupVerificationScheduleRepository {
	return &BackupVerificationScheduleRepository{
		db:     db,
		logger: log.Named("bv_schedule_repo"),
	}
}

func (r *BackupVerificationScheduleRepository) Create(ctx context.Context, s *models.BackupVerificationSchedule) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	now := time.Now()
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	s.UpdatedAt = now

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO backup_verification_schedules (
			id, host_id, schedule, method, max_backups, enabled,
			last_run_at, last_run_status, next_run_at, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		s.ID, s.HostID, s.Schedule, s.Method, s.MaxBackups, s.Enabled,
		s.LastRunAt, s.LastRunStatus, s.NextRunAt, s.CreatedAt, s.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "create verification schedule")
	}
	return nil
}

func (r *BackupVerificationScheduleRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.BackupVerificationSchedule, error) {
	var s models.BackupVerificationSchedule
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, host_id, schedule, method, max_backups, enabled,
			last_run_at, last_run_status, next_run_at, created_at, updated_at
		FROM backup_verification_schedules WHERE id = $1`, id,
	).Scan(
		&s.ID, &s.HostID, &s.Schedule, &s.Method, &s.MaxBackups, &s.Enabled,
		&s.LastRunAt, &s.LastRunStatus, &s.NextRunAt, &s.CreatedAt, &s.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("verification_schedule")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get verification schedule")
	}
	return &s, nil
}

func (r *BackupVerificationScheduleRepository) List(ctx context.Context, hostID uuid.UUID) ([]models.BackupVerificationSchedule, error) {
	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, host_id, schedule, method, max_backups, enabled,
			last_run_at, last_run_status, next_run_at, created_at, updated_at
		FROM backup_verification_schedules WHERE host_id = $1
		ORDER BY created_at DESC`, hostID,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "list verification schedules")
	}
	defer rows.Close()

	var results []models.BackupVerificationSchedule
	for rows.Next() {
		var s models.BackupVerificationSchedule
		if err := rows.Scan(
			&s.ID, &s.HostID, &s.Schedule, &s.Method, &s.MaxBackups, &s.Enabled,
			&s.LastRunAt, &s.LastRunStatus, &s.NextRunAt, &s.CreatedAt, &s.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "scan verification schedule")
		}
		results = append(results, s)
	}
	return results, nil
}

func (r *BackupVerificationScheduleRepository) Update(ctx context.Context, s *models.BackupVerificationSchedule) error {
	s.UpdatedAt = time.Now()
	_, err := r.db.Pool().Exec(ctx, `
		UPDATE backup_verification_schedules SET
			schedule = $2, method = $3, max_backups = $4, enabled = $5,
			last_run_at = $6, last_run_status = $7, next_run_at = $8, updated_at = $9
		WHERE id = $1`,
		s.ID, s.Schedule, s.Method, s.MaxBackups, s.Enabled,
		s.LastRunAt, s.LastRunStatus, s.NextRunAt, s.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "update verification schedule")
	}
	return nil
}

func (r *BackupVerificationScheduleRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Pool().Exec(ctx, `DELETE FROM backup_verification_schedules WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "delete verification schedule")
	}
	return nil
}
