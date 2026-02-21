// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// DriftRepository handles drift detection and configuration snapshot database operations.
type DriftRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewDriftRepository creates a new DriftRepository.
func NewDriftRepository(db *DB, log *logger.Logger) *DriftRepository {
	return &DriftRepository{
		db:     db,
		logger: log.Named("drift_repo"),
	}
}

// snapshotCols is the shared column list for configuration_snapshots SELECT queries.
const snapshotCols = `id, resource_type, resource_id, resource_name, status,
	snapshot, taken_by, taken_at, note`

// driftCols is the shared column list for drift_detections SELECT queries.
const driftCols = `id, resource_type, resource_id, resource_name,
	baseline_snapshot_id, current_snapshot_id, status, severity,
	diffs, diff_count, detected_at, resolved_at, resolved_by, resolution_note`

// scanSnapshot scans a row into a ConfigSnapshot.
func scanSnapshot(row pgx.Row) (*models.ConfigSnapshot, error) {
	var s models.ConfigSnapshot
	err := row.Scan(
		&s.ID, &s.ResourceType, &s.ResourceID, &s.ResourceName, &s.Status,
		&s.Snapshot, &s.TakenBy, &s.TakenAt, &s.Note,
	)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// scanSnapshots scans multiple rows into a slice of ConfigSnapshot.
func scanSnapshots(rows pgx.Rows) ([]*models.ConfigSnapshot, error) {
	var snapshots []*models.ConfigSnapshot
	for rows.Next() {
		var s models.ConfigSnapshot
		err := rows.Scan(
			&s.ID, &s.ResourceType, &s.ResourceID, &s.ResourceName, &s.Status,
			&s.Snapshot, &s.TakenBy, &s.TakenAt, &s.Note,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning snapshot row: %w", err)
		}
		snapshots = append(snapshots, &s)
	}
	return snapshots, rows.Err()
}

// scanDrift scans a row into a DriftDetection.
func scanDrift(row pgx.Row) (*models.DriftDetection, error) {
	var d models.DriftDetection
	err := row.Scan(
		&d.ID, &d.ResourceType, &d.ResourceID, &d.ResourceName,
		&d.BaselineSnapshotID, &d.CurrentSnapshotID, &d.Status, &d.Severity,
		&d.Diffs, &d.DiffCount, &d.DetectedAt, &d.ResolvedAt, &d.ResolvedBy, &d.ResolutionNote,
	)
	if err != nil {
		return nil, err
	}
	return &d, nil
}

// scanDrifts scans multiple rows into a slice of DriftDetection.
func scanDrifts(rows pgx.Rows) ([]*models.DriftDetection, error) {
	var drifts []*models.DriftDetection
	for rows.Next() {
		var d models.DriftDetection
		err := rows.Scan(
			&d.ID, &d.ResourceType, &d.ResourceID, &d.ResourceName,
			&d.BaselineSnapshotID, &d.CurrentSnapshotID, &d.Status, &d.Severity,
			&d.Diffs, &d.DiffCount, &d.DetectedAt, &d.ResolvedAt, &d.ResolvedBy, &d.ResolutionNote,
		)
		if err != nil {
			return nil, fmt.Errorf("scanning drift row: %w", err)
		}
		drifts = append(drifts, &d)
	}
	return drifts, rows.Err()
}

// CreateSnapshot inserts a new configuration snapshot.
func (r *DriftRepository) CreateSnapshot(ctx context.Context, s *models.ConfigSnapshot) error {
	query := `
		INSERT INTO configuration_snapshots (
			resource_type, resource_id, resource_name, status,
			snapshot, taken_by, note
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7
		) RETURNING id, taken_at`

	snapJSON, _ := nullableJSON(s.Snapshot)

	err := r.db.QueryRow(ctx, query,
		s.ResourceType, s.ResourceID, s.ResourceName, s.Status,
		snapJSON, s.TakenBy, s.Note,
	).Scan(&s.ID, &s.TakenAt)
	if err != nil {
		return fmt.Errorf("creating snapshot: %w", err)
	}
	return nil
}

// GetSnapshotByID retrieves a single configuration snapshot by ID.
func (r *DriftRepository) GetSnapshotByID(ctx context.Context, id uuid.UUID) (*models.ConfigSnapshot, error) {
	query := fmt.Sprintf(`SELECT %s FROM configuration_snapshots WHERE id = $1`, snapshotCols)
	s, err := scanSnapshot(r.db.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("getting snapshot %s: %w", id, err)
	}
	return s, nil
}

// GetBaseline retrieves the current baseline snapshot for a resource.
func (r *DriftRepository) GetBaseline(ctx context.Context, resourceType, resourceID string) (*models.ConfigSnapshot, error) {
	query := fmt.Sprintf(
		`SELECT %s FROM configuration_snapshots
		 WHERE status = 'baseline' AND resource_type = $1 AND resource_id = $2
		 ORDER BY taken_at DESC LIMIT 1`,
		snapshotCols,
	)
	s, err := scanSnapshot(r.db.QueryRow(ctx, query, resourceType, resourceID))
	if err != nil {
		return nil, fmt.Errorf("getting baseline for %s/%s: %w", resourceType, resourceID, err)
	}
	return s, nil
}

// GetLatestSnapshot retrieves the most recent snapshot for a resource regardless of status.
func (r *DriftRepository) GetLatestSnapshot(ctx context.Context, resourceType, resourceID string) (*models.ConfigSnapshot, error) {
	query := fmt.Sprintf(
		`SELECT %s FROM configuration_snapshots
		 WHERE resource_type = $1 AND resource_id = $2
		 ORDER BY taken_at DESC LIMIT 1`,
		snapshotCols,
	)
	s, err := scanSnapshot(r.db.QueryRow(ctx, query, resourceType, resourceID))
	if err != nil {
		return nil, fmt.Errorf("getting latest snapshot for %s/%s: %w", resourceType, resourceID, err)
	}
	return s, nil
}

// SetBaseline promotes a snapshot to baseline, archiving any existing baseline for the same resource.
func (r *DriftRepository) SetBaseline(ctx context.Context, snapshotID uuid.UUID) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	// Look up the snapshot to find its resource identifiers.
	var resourceType, resourceID string
	err = tx.QueryRow(ctx,
		`SELECT resource_type, resource_id FROM configuration_snapshots WHERE id = $1`,
		snapshotID,
	).Scan(&resourceType, &resourceID)
	if err != nil {
		return fmt.Errorf("looking up snapshot %s: %w", snapshotID, err)
	}

	// Archive existing baselines for this resource.
	_, err = tx.Exec(ctx,
		`UPDATE configuration_snapshots SET status = 'archived'
		 WHERE resource_type = $1 AND resource_id = $2 AND status = 'baseline'`,
		resourceType, resourceID,
	)
	if err != nil {
		return fmt.Errorf("archiving existing baselines: %w", err)
	}

	// Promote the given snapshot to baseline.
	_, err = tx.Exec(ctx,
		`UPDATE configuration_snapshots SET status = 'baseline' WHERE id = $1`,
		snapshotID,
	)
	if err != nil {
		return fmt.Errorf("setting baseline: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("committing baseline update: %w", err)
	}
	return nil
}

// ListSnapshots retrieves snapshots for a resource, ordered by most recent first.
func (r *DriftRepository) ListSnapshots(ctx context.Context, resourceType, resourceID string, limit int) ([]*models.ConfigSnapshot, error) {
	if limit <= 0 {
		limit = 50
	}
	query := fmt.Sprintf(
		`SELECT %s FROM configuration_snapshots
		 WHERE resource_type = $1 AND resource_id = $2
		 ORDER BY taken_at DESC LIMIT $3`,
		snapshotCols,
	)
	rows, err := r.db.Query(ctx, query, resourceType, resourceID, limit)
	if err != nil {
		return nil, fmt.Errorf("listing snapshots: %w", err)
	}
	defer rows.Close()
	return scanSnapshots(rows)
}

// CreateDrift inserts a new drift detection record.
func (r *DriftRepository) CreateDrift(ctx context.Context, d *models.DriftDetection) error {
	query := `
		INSERT INTO drift_detections (
			resource_type, resource_id, resource_name,
			baseline_snapshot_id, current_snapshot_id,
			status, severity, diffs, diff_count
		) VALUES (
			$1, $2, $3, $4, $5, $6, $7, $8, $9
		) RETURNING id, detected_at`

	diffsJSON, _ := nullableJSON(d.Diffs)

	err := r.db.QueryRow(ctx, query,
		d.ResourceType, d.ResourceID, d.ResourceName,
		d.BaselineSnapshotID, d.CurrentSnapshotID,
		d.Status, d.Severity, diffsJSON, d.DiffCount,
	).Scan(&d.ID, &d.DetectedAt)
	if err != nil {
		return fmt.Errorf("creating drift detection: %w", err)
	}
	return nil
}

// GetDriftByID retrieves a single drift detection by ID.
func (r *DriftRepository) GetDriftByID(ctx context.Context, id uuid.UUID) (*models.DriftDetection, error) {
	query := fmt.Sprintf(`SELECT %s FROM drift_detections WHERE id = $1`, driftCols)
	d, err := scanDrift(r.db.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("getting drift %s: %w", id, err)
	}
	return d, nil
}

// ListDrifts retrieves drift detections with dynamic filtering and pagination.
func (r *DriftRepository) ListDrifts(ctx context.Context, opts models.DriftListOptions) ([]*models.DriftDetection, int, error) {
	var conditions []string
	var args []any
	argIdx := 1

	if opts.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, opts.Status)
		argIdx++
	}
	if opts.Severity != "" {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", argIdx))
		args = append(args, opts.Severity)
		argIdx++
	}
	if opts.ResourceType != "" {
		conditions = append(conditions, fmt.Sprintf("resource_type = $%d", argIdx))
		args = append(args, opts.ResourceType)
		argIdx++
	}
	if opts.ResourceID != "" {
		conditions = append(conditions, fmt.Sprintf("resource_id = $%d", argIdx))
		args = append(args, opts.ResourceID)
		argIdx++
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total matching.
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM drift_detections %s", where)
	var total int
	if err := r.db.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting drifts: %w", err)
	}

	// Fetch page.
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	offset := opts.Offset
	if offset < 0 {
		offset = 0
	}

	dataQuery := fmt.Sprintf(
		"SELECT %s FROM drift_detections %s ORDER BY detected_at DESC LIMIT $%d OFFSET $%d",
		driftCols, where, argIdx, argIdx+1,
	)
	args = append(args, limit, offset)

	rows, err := r.db.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("listing drifts: %w", err)
	}
	defer rows.Close()

	drifts, err := scanDrifts(rows)
	if err != nil {
		return nil, 0, err
	}
	return drifts, total, nil
}

// GetOpenDrifts retrieves all open drift detections, ordered by severity (critical first) then detection time.
func (r *DriftRepository) GetOpenDrifts(ctx context.Context) ([]*models.DriftDetection, error) {
	query := fmt.Sprintf(
		`SELECT %s FROM drift_detections
		 WHERE status = 'open'
		 ORDER BY CASE severity
			WHEN 'critical' THEN 0
			WHEN 'warning' THEN 1
			WHEN 'info' THEN 2
			ELSE 3
		 END, detected_at DESC`,
		driftCols,
	)
	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("getting open drifts: %w", err)
	}
	defer rows.Close()
	return scanDrifts(rows)
}

// ResolveDrift updates a drift detection's status to resolved.
func (r *DriftRepository) ResolveDrift(ctx context.Context, id uuid.UUID, status string, resolvedBy *uuid.UUID, note string) error {
	query := `
		UPDATE drift_detections
		SET status = $1, resolved_at = NOW(), resolved_by = $2, resolution_note = $3
		WHERE id = $4`

	tag, err := r.db.Exec(ctx, query, status, resolvedBy, note, id)
	if err != nil {
		return fmt.Errorf("resolving drift %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("drift %s not found", id)
	}
	return nil
}

// GetDriftStats returns aggregate statistics about open drift detections.
func (r *DriftRepository) GetDriftStats(ctx context.Context) (*models.DriftStats, error) {
	stats := &models.DriftStats{
		ByResource: make(map[string]int),
	}

	// Total open + severity counts in a single query.
	err := r.db.QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE severity = 'critical'),
			COUNT(*) FILTER (WHERE severity = 'warning'),
			COUNT(*) FILTER (WHERE severity = 'info'),
			COUNT(DISTINCT resource_type || '/' || resource_id)
		FROM drift_detections
		WHERE status = 'open'`,
	).Scan(&stats.TotalOpen, &stats.Critical, &stats.Warning, &stats.Info, &stats.ResourcesAffected)
	if err != nil {
		return nil, fmt.Errorf("getting drift stats: %w", err)
	}

	// By resource type.
	rows, err := r.db.Query(ctx,
		`SELECT resource_type, COUNT(*)
		 FROM drift_detections
		 WHERE status = 'open'
		 GROUP BY resource_type
		 ORDER BY COUNT(*) DESC`,
	)
	if err != nil {
		return nil, fmt.Errorf("getting drift resource stats: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var rt string
		var count int
		if err := rows.Scan(&rt, &count); err != nil {
			return nil, err
		}
		stats.ByResource[rt] = count
	}

	return stats, nil
}

// CloseExistingDrifts marks all open drifts for a resource as remediated.
func (r *DriftRepository) CloseExistingDrifts(ctx context.Context, resourceType, resourceID string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE drift_detections
		 SET status = 'remediated', resolved_at = NOW()
		 WHERE resource_type = $1 AND resource_id = $2 AND status = 'open'`,
		resourceType, resourceID,
	)
	if err != nil {
		return fmt.Errorf("closing existing drifts for %s/%s: %w", resourceType, resourceID, err)
	}
	return nil
}
