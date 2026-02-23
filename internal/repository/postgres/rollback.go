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
// RollbackPolicyRepository
// ============================================================================

type RollbackPolicyRepository struct {
	db     *DB
	logger *logger.Logger
}

func NewRollbackPolicyRepository(db *DB, log *logger.Logger) *RollbackPolicyRepository {
	return &RollbackPolicyRepository{
		db:     db,
		logger: log.Named("repo.rollback_policies"),
	}
}

func (r *RollbackPolicyRepository) Create(ctx context.Context, p *models.RollbackPolicy) error {
	if p.ID == uuid.Nil {
		p.ID = uuid.New()
	}
	now := time.Now()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO rollback_policies (
			id, stack_id, host_id, enabled, trigger_on,
			health_check_url, health_check_interval, health_check_timeout,
			max_retries, cooldown_minutes, notify_on_rollback,
			created_by, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		p.ID, p.StackID, p.HostID, p.Enabled, p.TriggerOn,
		p.HealthCheckURL, p.HealthCheckInterval, p.HealthCheckTimeout,
		p.MaxRetries, p.CooldownMinutes, p.NotifyOnRollback,
		p.CreatedBy, p.CreatedAt, p.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "create rollback policy")
	}
	return nil
}

func (r *RollbackPolicyRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.RollbackPolicy, error) {
	var p models.RollbackPolicy
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, stack_id, host_id, enabled, trigger_on,
			health_check_url, health_check_interval, health_check_timeout,
			max_retries, cooldown_minutes, notify_on_rollback,
			created_by, created_at, updated_at
		FROM rollback_policies WHERE id = $1`, id,
	).Scan(
		&p.ID, &p.StackID, &p.HostID, &p.Enabled, &p.TriggerOn,
		&p.HealthCheckURL, &p.HealthCheckInterval, &p.HealthCheckTimeout,
		&p.MaxRetries, &p.CooldownMinutes, &p.NotifyOnRollback,
		&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("rollback_policy")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get rollback policy")
	}
	return &p, nil
}

func (r *RollbackPolicyRepository) GetByStackID(ctx context.Context, stackID uuid.UUID) (*models.RollbackPolicy, error) {
	var p models.RollbackPolicy
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, stack_id, host_id, enabled, trigger_on,
			health_check_url, health_check_interval, health_check_timeout,
			max_retries, cooldown_minutes, notify_on_rollback,
			created_by, created_at, updated_at
		FROM rollback_policies WHERE stack_id = $1`, stackID,
	).Scan(
		&p.ID, &p.StackID, &p.HostID, &p.Enabled, &p.TriggerOn,
		&p.HealthCheckURL, &p.HealthCheckInterval, &p.HealthCheckTimeout,
		&p.MaxRetries, &p.CooldownMinutes, &p.NotifyOnRollback,
		&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("rollback_policy")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get rollback policy by stack")
	}
	return &p, nil
}

func (r *RollbackPolicyRepository) List(ctx context.Context, hostID uuid.UUID) ([]models.RollbackPolicy, error) {
	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, stack_id, host_id, enabled, trigger_on,
			health_check_url, health_check_interval, health_check_timeout,
			max_retries, cooldown_minutes, notify_on_rollback,
			created_by, created_at, updated_at
		FROM rollback_policies WHERE host_id = $1
		ORDER BY created_at DESC`, hostID,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "list rollback policies")
	}
	defer rows.Close()

	var results []models.RollbackPolicy
	for rows.Next() {
		var p models.RollbackPolicy
		if err := rows.Scan(
			&p.ID, &p.StackID, &p.HostID, &p.Enabled, &p.TriggerOn,
			&p.HealthCheckURL, &p.HealthCheckInterval, &p.HealthCheckTimeout,
			&p.MaxRetries, &p.CooldownMinutes, &p.NotifyOnRollback,
			&p.CreatedBy, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "scan rollback policy")
		}
		results = append(results, p)
	}
	return results, nil
}

func (r *RollbackPolicyRepository) Update(ctx context.Context, p *models.RollbackPolicy) error {
	p.UpdatedAt = time.Now()
	_, err := r.db.Pool().Exec(ctx, `
		UPDATE rollback_policies SET
			enabled = $2, trigger_on = $3,
			health_check_url = $4, health_check_interval = $5, health_check_timeout = $6,
			max_retries = $7, cooldown_minutes = $8, notify_on_rollback = $9,
			updated_at = $10
		WHERE id = $1`,
		p.ID, p.Enabled, p.TriggerOn,
		p.HealthCheckURL, p.HealthCheckInterval, p.HealthCheckTimeout,
		p.MaxRetries, p.CooldownMinutes, p.NotifyOnRollback,
		p.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "update rollback policy")
	}
	return nil
}

func (r *RollbackPolicyRepository) Delete(ctx context.Context, id uuid.UUID) error {
	_, err := r.db.Pool().Exec(ctx, `DELETE FROM rollback_policies WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "delete rollback policy")
	}
	return nil
}

// ============================================================================
// RollbackExecutionRepository
// ============================================================================

type RollbackExecutionRepository struct {
	db     *DB
	logger *logger.Logger
}

func NewRollbackExecutionRepository(db *DB, log *logger.Logger) *RollbackExecutionRepository {
	return &RollbackExecutionRepository{
		db:     db,
		logger: log.Named("repo.rollback_executions"),
	}
}

func (r *RollbackExecutionRepository) Create(ctx context.Context, e *models.RollbackExecution) error {
	if e.ID == uuid.Nil {
		e.ID = uuid.New()
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now()
	}

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO rollback_executions (
			id, policy_id, stack_id, host_id, trigger_reason,
			from_version, to_version, status, output, error_message,
			compose_snapshot, duration_ms, triggered_by,
			started_at, completed_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		e.ID, e.PolicyID, e.StackID, e.HostID, e.TriggerReason,
		e.FromVersion, e.ToVersion, e.Status, e.Output, e.ErrorMessage,
		e.ComposeSnapshot, e.DurationMs, e.TriggeredBy,
		e.StartedAt, e.CompletedAt, e.CreatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "create rollback execution")
	}
	return nil
}

func (r *RollbackExecutionRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.RollbackExecution, error) {
	var e models.RollbackExecution
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, policy_id, stack_id, host_id, trigger_reason,
			from_version, to_version, status, output, error_message,
			compose_snapshot, duration_ms, triggered_by,
			started_at, completed_at, created_at
		FROM rollback_executions WHERE id = $1`, id,
	).Scan(
		&e.ID, &e.PolicyID, &e.StackID, &e.HostID, &e.TriggerReason,
		&e.FromVersion, &e.ToVersion, &e.Status, &e.Output, &e.ErrorMessage,
		&e.ComposeSnapshot, &e.DurationMs, &e.TriggeredBy,
		&e.StartedAt, &e.CompletedAt, &e.CreatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("rollback_execution")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get rollback execution")
	}
	return &e, nil
}

func (r *RollbackExecutionRepository) ListByStack(ctx context.Context, stackID uuid.UUID, limit, offset int) ([]models.RollbackExecution, int, error) {
	var total int
	err := r.db.Pool().QueryRow(ctx,
		`SELECT COUNT(*) FROM rollback_executions WHERE stack_id = $1`, stackID,
	).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "count rollback executions by stack")
	}

	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, policy_id, stack_id, host_id, trigger_reason,
			from_version, to_version, status, output, error_message,
			compose_snapshot, duration_ms, triggered_by,
			started_at, completed_at, created_at
		FROM rollback_executions WHERE stack_id = $1
		ORDER BY created_at DESC LIMIT $2 OFFSET $3`, stackID, limit, offset,
	)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "list rollback executions by stack")
	}
	defer rows.Close()

	var results []models.RollbackExecution
	for rows.Next() {
		var e models.RollbackExecution
		if err := rows.Scan(
			&e.ID, &e.PolicyID, &e.StackID, &e.HostID, &e.TriggerReason,
			&e.FromVersion, &e.ToVersion, &e.Status, &e.Output, &e.ErrorMessage,
			&e.ComposeSnapshot, &e.DurationMs, &e.TriggeredBy,
			&e.StartedAt, &e.CompletedAt, &e.CreatedAt,
		); err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "scan rollback execution")
		}
		results = append(results, e)
	}
	return results, total, nil
}

func (r *RollbackExecutionRepository) ListByHost(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]models.RollbackExecution, int, error) {
	var total int
	err := r.db.Pool().QueryRow(ctx,
		`SELECT COUNT(*) FROM rollback_executions WHERE host_id = $1`, hostID,
	).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "count rollback executions by host")
	}

	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, policy_id, stack_id, host_id, trigger_reason,
			from_version, to_version, status, output, error_message,
			compose_snapshot, duration_ms, triggered_by,
			started_at, completed_at, created_at
		FROM rollback_executions WHERE host_id = $1
		ORDER BY created_at DESC LIMIT $2 OFFSET $3`, hostID, limit, offset,
	)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "list rollback executions by host")
	}
	defer rows.Close()

	var results []models.RollbackExecution
	for rows.Next() {
		var e models.RollbackExecution
		if err := rows.Scan(
			&e.ID, &e.PolicyID, &e.StackID, &e.HostID, &e.TriggerReason,
			&e.FromVersion, &e.ToVersion, &e.Status, &e.Output, &e.ErrorMessage,
			&e.ComposeSnapshot, &e.DurationMs, &e.TriggeredBy,
			&e.StartedAt, &e.CompletedAt, &e.CreatedAt,
		); err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "scan rollback execution")
		}
		results = append(results, e)
	}
	return results, total, nil
}

func (r *RollbackExecutionRepository) GetStats(ctx context.Context, hostID uuid.UUID) (*models.RollbackStats, error) {
	stats := &models.RollbackStats{}

	err := r.db.Pool().QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 'success'),
			COUNT(*) FILTER (WHERE status = 'failed'),
			COUNT(*) FILTER (WHERE triggered_by IS NULL),
			COUNT(*) FILTER (WHERE triggered_by IS NOT NULL)
		FROM rollback_executions WHERE host_id = $1`, hostID,
	).Scan(&stats.TotalRollbacks, &stats.Successful, &stats.Failed, &stats.AutoTriggered, &stats.ManualTriggers)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get rollback stats")
	}

	err = r.db.Pool().QueryRow(ctx, `
		SELECT MAX(completed_at) FROM rollback_executions WHERE host_id = $1 AND completed_at IS NOT NULL`, hostID,
	).Scan(&stats.LastRollbackAt)
	if err != nil && err != pgx.ErrNoRows {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "get last rollback time")
	}

	return stats, nil
}
