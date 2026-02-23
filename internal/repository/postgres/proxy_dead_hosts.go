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
)

// ProxyDeadHostRepository implements persistence for proxy dead hosts.
type ProxyDeadHostRepository struct {
	db *DB
}

// NewProxyDeadHostRepository creates a new dead host repository.
func NewProxyDeadHostRepository(db *DB) *ProxyDeadHostRepository {
	return &ProxyDeadHostRepository{db: db}
}

// Create inserts a new proxy dead host.
func (r *ProxyDeadHostRepository) Create(ctx context.Context, d *models.ProxyDeadHost) error {
	if d.ID == uuid.Nil {
		d.ID = uuid.New()
	}
	now := time.Now()
	d.CreatedAt = now
	d.UpdatedAt = now

	query := `
		INSERT INTO proxy_dead_hosts (
			id, host_id, domains,
			ssl_mode, ssl_force_https, certificate_id,
			enabled, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`

	_, err := r.db.Exec(ctx, query,
		d.ID, d.HostID, d.Domains,
		string(d.SSLMode), d.SSLForceHTTPS, d.CertificateID,
		d.Enabled, d.CreatedAt, d.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create proxy dead host")
	}
	return nil
}

// GetByID retrieves a dead host by ID.
func (r *ProxyDeadHostRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ProxyDeadHost, error) {
	rows, err := r.db.Query(ctx, `SELECT * FROM proxy_dead_hosts WHERE id = $1`, id)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query proxy dead host")
	}
	defer rows.Close()

	d, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.ProxyDeadHost])
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("proxy_dead_host").WithDetail("id", id.String())
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan proxy dead host")
	}
	return d, nil
}

// List retrieves all dead hosts for a host.
func (r *ProxyDeadHostRepository) List(ctx context.Context, hostID uuid.UUID) ([]*models.ProxyDeadHost, error) {
	rows, err := r.db.Query(ctx,
		`SELECT * FROM proxy_dead_hosts WHERE host_id = $1 ORDER BY created_at ASC`, hostID,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list proxy dead hosts")
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.ProxyDeadHost])
}

// Delete removes a proxy dead host.
func (r *ProxyDeadHostRepository) Delete(ctx context.Context, id uuid.UUID) error {
	ct, err := r.db.Exec(ctx, `DELETE FROM proxy_dead_hosts WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete proxy dead host")
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("proxy_dead_host").WithDetail("id", id.String())
	}
	return nil
}
