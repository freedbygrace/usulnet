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

// ProxyStreamRepository implements persistence for proxy streams.
type ProxyStreamRepository struct {
	db *DB
}

// NewProxyStreamRepository creates a new stream repository.
func NewProxyStreamRepository(db *DB) *ProxyStreamRepository {
	return &ProxyStreamRepository{db: db}
}

// Create inserts a new proxy stream.
func (r *ProxyStreamRepository) Create(ctx context.Context, s *models.ProxyStream) error {
	if s.ID == uuid.Nil {
		s.ID = uuid.New()
	}
	now := time.Now()
	s.CreatedAt = now
	s.UpdatedAt = now

	query := `
		INSERT INTO proxy_streams (
			id, host_id, incoming_port, forwarding_host, forwarding_port,
			tcp_forwarding, udp_forwarding, enabled, created_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`

	_, err := r.db.Exec(ctx, query,
		s.ID, s.HostID, s.IncomingPort, s.ForwardingHost, s.ForwardingPort,
		s.TCPForwarding, s.UDPForwarding, s.Enabled, s.CreatedAt, s.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to create proxy stream")
	}
	return nil
}

// GetByID retrieves a stream by ID.
func (r *ProxyStreamRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.ProxyStream, error) {
	rows, err := r.db.Query(ctx, `SELECT * FROM proxy_streams WHERE id = $1`, id)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to query proxy stream")
	}
	defer rows.Close()

	s, err := pgx.CollectOneRow(rows, pgx.RowToAddrOfStructByName[models.ProxyStream])
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("proxy_stream").WithDetail("id", id.String())
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to scan proxy stream")
	}
	return s, nil
}

// List retrieves all streams for a host.
func (r *ProxyStreamRepository) List(ctx context.Context, hostID uuid.UUID) ([]*models.ProxyStream, error) {
	rows, err := r.db.Query(ctx,
		`SELECT * FROM proxy_streams WHERE host_id = $1 ORDER BY incoming_port ASC`, hostID,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "failed to list proxy streams")
	}
	defer rows.Close()

	return pgx.CollectRows(rows, pgx.RowToAddrOfStructByName[models.ProxyStream])
}

// Update updates a proxy stream.
func (r *ProxyStreamRepository) Update(ctx context.Context, s *models.ProxyStream) error {
	s.UpdatedAt = time.Now()

	query := `
		UPDATE proxy_streams SET
			incoming_port=$2, forwarding_host=$3, forwarding_port=$4,
			tcp_forwarding=$5, udp_forwarding=$6, enabled=$7, updated_at=$8
		WHERE id=$1`

	ct, err := r.db.Exec(ctx, query,
		s.ID, s.IncomingPort, s.ForwardingHost, s.ForwardingPort,
		s.TCPForwarding, s.UDPForwarding, s.Enabled, s.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to update proxy stream")
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("proxy_stream").WithDetail("id", s.ID.String())
	}
	return nil
}

// Delete removes a proxy stream.
func (r *ProxyStreamRepository) Delete(ctx context.Context, id uuid.UUID) error {
	ct, err := r.db.Exec(ctx, `DELETE FROM proxy_streams WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "failed to delete proxy stream")
	}
	if ct.RowsAffected() == 0 {
		return errors.NotFound("proxy_stream").WithDetail("id", id.String())
	}
	return nil
}
