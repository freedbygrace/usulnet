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
// CrontabEntryRepository
// ============================================================================

// CrontabEntryRepository implements crontab entry persistence.
type CrontabEntryRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewCrontabEntryRepository creates a new crontab entry repository.
func NewCrontabEntryRepository(db *DB, log *logger.Logger) *CrontabEntryRepository {
	return &CrontabEntryRepository{
		db:     db,
		logger: log.Named("crontab_entry_repo"),
	}
}

// Create inserts a new crontab entry.
func (r *CrontabEntryRepository) Create(ctx context.Context, e *models.CrontabEntry) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	now := time.Now()
	if e.CreatedAt.IsZero() {
		e.CreatedAt = now
	}
	e.UpdatedAt = now

	query := `
		INSERT INTO crontab_entries (
			id, host_id, name, description, schedule, command_type, command,
			container_id, working_dir, http_method, http_url,
			enabled, run_count, fail_count,
			last_run_at, last_run_status, last_run_output, next_run_at,
			created_by, created_at, updated_at
		) VALUES (
			$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21
		)`

	_, err := r.db.Exec(ctx, query,
		e.ID, e.HostID, e.Name, e.Description, e.Schedule, string(e.CommandType), e.Command,
		e.ContainerID, e.WorkingDir, e.HTTPMethod, e.HTTPURL,
		e.Enabled, e.RunCount, e.FailCount,
		e.LastRunAt, e.LastRunStatus, e.LastRunOutput, e.NextRunAt,
		e.CreatedBy, e.CreatedAt, e.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create crontab entry")
	}
	return nil
}

// GetByID retrieves a crontab entry by ID.
func (r *CrontabEntryRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.CrontabEntry, error) {
	query := `SELECT * FROM crontab_entries WHERE id = $1`
	rows, err := r.db.Query(ctx, query, id)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query crontab entry")
	}
	defer rows.Close()

	e, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.CrontabEntry])
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("crontab_entry").WithDetail("id", id.String())
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan crontab entry")
	}
	return e, nil
}

// List retrieves all crontab entries for a host.
func (r *CrontabEntryRepository) List(ctx context.Context, hostID uuid.UUID) ([]*models.CrontabEntry, error) {
	query := `SELECT * FROM crontab_entries WHERE host_id = $1 ORDER BY name ASC`
	rows, err := r.db.Query(ctx, query, hostID)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list crontab entries")
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.CrontabEntry])
}

// Update updates a crontab entry.
func (r *CrontabEntryRepository) Update(ctx context.Context, e *models.CrontabEntry) error {
	e.UpdatedAt = time.Now()

	query := `
		UPDATE crontab_entries SET
			name=$2, description=$3, schedule=$4, command_type=$5, command=$6,
			container_id=$7, working_dir=$8, http_method=$9, http_url=$10,
			enabled=$11, updated_at=$12
		WHERE id=$1`

	ct, err := r.db.Exec(ctx, query,
		e.ID, e.Name, e.Description, e.Schedule, string(e.CommandType), e.Command,
		e.ContainerID, e.WorkingDir, e.HTTPMethod, e.HTTPURL,
		e.Enabled, e.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update crontab entry")
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("crontab_entry").WithDetail("id", e.ID.String())
	}
	return nil
}

// Delete removes a crontab entry.
func (r *CrontabEntryRepository) Delete(ctx context.Context, id uuid.UUID) error {
	ct, err := r.db.Exec(ctx, `DELETE FROM crontab_entries WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete crontab entry")
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("crontab_entry").WithDetail("id", id.String())
	}
	return nil
}

// UpdateLastRun updates the last run information for a crontab entry.
func (r *CrontabEntryRepository) UpdateLastRun(ctx context.Context, id uuid.UUID, status string, output string, runAt time.Time) error {
	var query string
	if status == "failed" {
		query = `
			UPDATE crontab_entries SET
				last_run_at=$2, last_run_status=$3, last_run_output=$4,
				run_count = run_count + 1, fail_count = fail_count + 1
			WHERE id=$1`
	} else {
		query = `
			UPDATE crontab_entries SET
				last_run_at=$2, last_run_status=$3, last_run_output=$4,
				run_count = run_count + 1
			WHERE id=$1`
	}

	_, err := r.db.Exec(ctx, query, id, runAt, status, output)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update crontab last run")
	}
	return nil
}

// UpdateNextRun updates the next run time for a crontab entry.
func (r *CrontabEntryRepository) UpdateNextRun(ctx context.Context, id uuid.UUID, nextRun *time.Time) error {
	_, err := r.db.Exec(ctx, `UPDATE crontab_entries SET next_run_at=$2 WHERE id=$1`, id, nextRun)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update crontab next run")
	}
	return nil
}

// GetStats returns aggregate statistics for crontab entries.
func (r *CrontabEntryRepository) GetStats(ctx context.Context, hostID uuid.UUID) (*models.CrontabStats, error) {
	query := `
		SELECT
			COUNT(*) AS total,
			COUNT(*) FILTER (WHERE enabled = true) AS enabled,
			COUNT(*) FILTER (WHERE enabled = false) AS disabled
		FROM crontab_entries WHERE host_id = $1`

	var s models.CrontabStats
	err := r.db.QueryRow(ctx, query, hostID).Scan(&s.Total, &s.Enabled, &s.Disabled)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to get crontab stats")
	}
	return &s, nil
}

// ============================================================================
// CrontabExecutionRepository
// ============================================================================

// CrontabExecutionRepository implements crontab execution persistence.
type CrontabExecutionRepository struct {
	db *DB
}

// NewCrontabExecutionRepository creates a new crontab execution repository.
func NewCrontabExecutionRepository(db *DB) *CrontabExecutionRepository {
	return &CrontabExecutionRepository{db: db}
}

// Create inserts a new crontab execution record.
func (r *CrontabExecutionRepository) Create(ctx context.Context, e *models.CrontabExecution) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}

	query := `
		INSERT INTO crontab_executions (
			id, entry_id, host_id, status, output, error,
			exit_code, duration_ms, started_at, finished_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`

	_, err := r.db.Exec(ctx, query,
		e.ID, e.EntryID, e.HostID, e.Status, e.Output, e.Error,
		e.ExitCode, e.DurationMs, e.StartedAt, e.FinishedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create crontab execution")
	}
	return nil
}

// ListByEntry retrieves execution history for a crontab entry.
func (r *CrontabExecutionRepository) ListByEntry(ctx context.Context, entryID uuid.UUID, limit int) ([]*models.CrontabExecution, error) {
	query := `SELECT * FROM crontab_executions WHERE entry_id = $1 ORDER BY started_at DESC LIMIT $2`
	rows, err := r.db.Query(ctx, query, entryID, limit)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list crontab executions")
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.CrontabExecution])
}

// DeleteOlderThan removes execution records older than the specified duration.
func (r *CrontabExecutionRepository) DeleteOlderThan(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)
	ct, err := r.db.Exec(ctx, `DELETE FROM crontab_executions WHERE started_at < $1`, cutoff)
	if err != nil {
		return 0, errors.Wrap(err, errors.CodeDatabaseError, "failed to delete old crontab executions")
	}
	return ct.RowsAffected(), nil
}
