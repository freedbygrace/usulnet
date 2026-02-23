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
// WireGuardInterfaceRepository
// ============================================================================

// WireGuardInterfaceRepository implements WireGuard interface persistence.
type WireGuardInterfaceRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewWireGuardInterfaceRepository creates a new WireGuard interface repository.
func NewWireGuardInterfaceRepository(db *DB, log *logger.Logger) *WireGuardInterfaceRepository {
	return &WireGuardInterfaceRepository{
		db:     db,
		logger: log.Named("repo.wireguard_interfaces"),
	}
}

// Create inserts a new WireGuard interface.
func (r *WireGuardInterfaceRepository) Create(ctx context.Context, iface *models.WireGuardInterface) error {
	if iface.ID == uuid.Nil {
		iface.ID = uuid.New()
	}
	now := time.Now()
	if iface.CreatedAt.IsZero() {
		iface.CreatedAt = now
	}
	iface.UpdatedAt = now

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO wireguard_interfaces (
			id, host_id, name, display_name, description,
			listen_port, address, private_key, public_key,
			dns, mtu, post_up, post_down,
			enabled, status, peer_count,
			last_handshake, transfer_rx, transfer_tx,
			created_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11, $12, $13,
			$14, $15, $16,
			$17, $18, $19,
			$20, $21, $22
		)`,
		iface.ID, iface.HostID, iface.Name, iface.DisplayName, iface.Description,
		iface.ListenPort, iface.Address, iface.PrivateKey, iface.PublicKey,
		iface.DNS, iface.MTU, iface.PostUp, iface.PostDown,
		iface.Enabled, iface.Status, iface.PeerCount,
		iface.LastHandshake, iface.TransferRx, iface.TransferTx,
		iface.CreatedBy, iface.CreatedAt, iface.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "wireguard: create interface")
	}
	return nil
}

// GetByID returns a WireGuard interface by ID.
func (r *WireGuardInterfaceRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.WireGuardInterface, error) {
	var iface models.WireGuardInterface
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, host_id, name, display_name, description,
			listen_port, address, private_key, public_key,
			dns, mtu, post_up, post_down,
			enabled, status, peer_count,
			last_handshake, transfer_rx, transfer_tx,
			created_by, created_at, updated_at
		FROM wireguard_interfaces WHERE id = $1`, id,
	).Scan(
		&iface.ID, &iface.HostID, &iface.Name, &iface.DisplayName, &iface.Description,
		&iface.ListenPort, &iface.Address, &iface.PrivateKey, &iface.PublicKey,
		&iface.DNS, &iface.MTU, &iface.PostUp, &iface.PostDown,
		&iface.Enabled, &iface.Status, &iface.PeerCount,
		&iface.LastHandshake, &iface.TransferRx, &iface.TransferTx,
		&iface.CreatedBy, &iface.CreatedAt, &iface.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("wireguard_interface")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "wireguard: get interface by id")
	}
	return &iface, nil
}

// Update updates a WireGuard interface.
func (r *WireGuardInterfaceRepository) Update(ctx context.Context, iface *models.WireGuardInterface) error {
	iface.UpdatedAt = time.Now()

	tag, err := r.db.Pool().Exec(ctx, `
		UPDATE wireguard_interfaces SET
			name = $2, display_name = $3, description = $4,
			listen_port = $5, address = $6, private_key = $7, public_key = $8,
			dns = $9, mtu = $10, post_up = $11, post_down = $12,
			enabled = $13, status = $14, peer_count = $15,
			last_handshake = $16, transfer_rx = $17, transfer_tx = $18,
			updated_at = $19
		WHERE id = $1`,
		iface.ID, iface.Name, iface.DisplayName, iface.Description,
		iface.ListenPort, iface.Address, iface.PrivateKey, iface.PublicKey,
		iface.DNS, iface.MTU, iface.PostUp, iface.PostDown,
		iface.Enabled, iface.Status, iface.PeerCount,
		iface.LastHandshake, iface.TransferRx, iface.TransferTx,
		iface.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "wireguard: update interface")
	}
	if tag.RowsAffected() == 0 {
		return errors.NotFound("wireguard_interface")
	}
	return nil
}

// ListByHost returns all WireGuard interfaces for a host.
func (r *WireGuardInterfaceRepository) ListByHost(ctx context.Context, hostID uuid.UUID) ([]*models.WireGuardInterface, error) {
	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, host_id, name, display_name, description,
			listen_port, address, private_key, public_key,
			dns, mtu, post_up, post_down,
			enabled, status, peer_count,
			last_handshake, transfer_rx, transfer_tx,
			created_by, created_at, updated_at
		FROM wireguard_interfaces
		WHERE host_id = $1
		ORDER BY created_at DESC`, hostID,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "wireguard: list interfaces")
	}
	defer rows.Close()

	var interfaces []*models.WireGuardInterface
	for rows.Next() {
		var iface models.WireGuardInterface
		if err := rows.Scan(
			&iface.ID, &iface.HostID, &iface.Name, &iface.DisplayName, &iface.Description,
			&iface.ListenPort, &iface.Address, &iface.PrivateKey, &iface.PublicKey,
			&iface.DNS, &iface.MTU, &iface.PostUp, &iface.PostDown,
			&iface.Enabled, &iface.Status, &iface.PeerCount,
			&iface.LastHandshake, &iface.TransferRx, &iface.TransferTx,
			&iface.CreatedBy, &iface.CreatedAt, &iface.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "wireguard: scan interface")
		}
		interfaces = append(interfaces, &iface)
	}
	return interfaces, nil
}

// Delete removes a WireGuard interface.
func (r *WireGuardInterfaceRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Pool().Exec(ctx, `DELETE FROM wireguard_interfaces WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "wireguard: delete interface")
	}
	if tag.RowsAffected() == 0 {
		return errors.NotFound("wireguard_interface")
	}
	return nil
}

// GetStats returns aggregate WireGuard statistics for a host.
func (r *WireGuardInterfaceRepository) GetStats(ctx context.Context, hostID uuid.UUID) (*models.WireGuardStats, error) {
	stats := &models.WireGuardStats{}

	err := r.db.Pool().QueryRow(ctx, `
		SELECT
			COUNT(*),
			COUNT(*) FILTER (WHERE status = 'active'),
			COALESCE(SUM(peer_count), 0),
			COALESCE(SUM(transfer_rx), 0),
			COALESCE(SUM(transfer_tx), 0)
		FROM wireguard_interfaces WHERE host_id = $1`, hostID,
	).Scan(
		&stats.TotalInterfaces, &stats.ActiveInterfaces,
		&stats.TotalPeers,
		&stats.TotalRx, &stats.TotalTx,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "wireguard: get interface stats")
	}

	err = r.db.Pool().QueryRow(ctx, `
		SELECT COUNT(*) FROM wireguard_peers
		WHERE host_id = $1 AND enabled = true AND last_handshake IS NOT NULL`, hostID,
	).Scan(&stats.ConnectedPeers)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "wireguard: get connected peers count")
	}

	err = r.db.Pool().QueryRow(ctx, `
		SELECT MAX(last_handshake) FROM wireguard_interfaces
		WHERE host_id = $1 AND last_handshake IS NOT NULL`, hostID,
	).Scan(&stats.LastActivity)
	if err != nil && err != pgx.ErrNoRows {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "wireguard: get last activity")
	}

	return stats, nil
}

// ============================================================================
// WireGuardPeerRepository
// ============================================================================

// WireGuardPeerRepository implements WireGuard peer persistence.
type WireGuardPeerRepository struct {
	db     *DB
	logger *logger.Logger
}

// NewWireGuardPeerRepository creates a new WireGuard peer repository.
func NewWireGuardPeerRepository(db *DB, log *logger.Logger) *WireGuardPeerRepository {
	return &WireGuardPeerRepository{
		db:     db,
		logger: log.Named("repo.wireguard_peers"),
	}
}

// Create inserts a new WireGuard peer.
func (r *WireGuardPeerRepository) Create(ctx context.Context, peer *models.WireGuardPeer) error {
	if peer.ID == uuid.Nil {
		peer.ID = uuid.New()
	}
	now := time.Now()
	if peer.CreatedAt.IsZero() {
		peer.CreatedAt = now
	}
	peer.UpdatedAt = now

	_, err := r.db.Pool().Exec(ctx, `
		INSERT INTO wireguard_peers (
			id, interface_id, host_id, name, description,
			public_key, preshared_key, allowed_ips, endpoint,
			persistent_keepalive, enabled,
			last_handshake, transfer_rx, transfer_tx,
			config_qr, created_by, created_at, updated_at
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9,
			$10, $11,
			$12, $13, $14,
			$15, $16, $17, $18
		)`,
		peer.ID, peer.InterfaceID, peer.HostID, peer.Name, peer.Description,
		peer.PublicKey, peer.PresharedKey, peer.AllowedIPs, peer.Endpoint,
		peer.PersistentKeepalive, peer.Enabled,
		peer.LastHandshake, peer.TransferRx, peer.TransferTx,
		peer.ConfigQR, peer.CreatedBy, peer.CreatedAt, peer.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "wireguard: create peer")
	}
	return nil
}

// GetByID returns a WireGuard peer by ID.
func (r *WireGuardPeerRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.WireGuardPeer, error) {
	var peer models.WireGuardPeer
	err := r.db.Pool().QueryRow(ctx, `
		SELECT id, interface_id, host_id, name, description,
			public_key, preshared_key, allowed_ips, endpoint,
			persistent_keepalive, enabled,
			last_handshake, transfer_rx, transfer_tx,
			config_qr, created_by, created_at, updated_at
		FROM wireguard_peers WHERE id = $1`, id,
	).Scan(
		&peer.ID, &peer.InterfaceID, &peer.HostID, &peer.Name, &peer.Description,
		&peer.PublicKey, &peer.PresharedKey, &peer.AllowedIPs, &peer.Endpoint,
		&peer.PersistentKeepalive, &peer.Enabled,
		&peer.LastHandshake, &peer.TransferRx, &peer.TransferTx,
		&peer.ConfigQR, &peer.CreatedBy, &peer.CreatedAt, &peer.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, errors.NotFound("wireguard_peer")
		}
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "wireguard: get peer by id")
	}
	return &peer, nil
}

// Update updates a WireGuard peer.
func (r *WireGuardPeerRepository) Update(ctx context.Context, peer *models.WireGuardPeer) error {
	peer.UpdatedAt = time.Now()

	tag, err := r.db.Pool().Exec(ctx, `
		UPDATE wireguard_peers SET
			name = $2, description = $3,
			public_key = $4, preshared_key = $5,
			allowed_ips = $6, endpoint = $7,
			persistent_keepalive = $8, enabled = $9,
			config_qr = $10, updated_at = $11
		WHERE id = $1`,
		peer.ID, peer.Name, peer.Description,
		peer.PublicKey, peer.PresharedKey,
		peer.AllowedIPs, peer.Endpoint,
		peer.PersistentKeepalive, peer.Enabled,
		peer.ConfigQR, peer.UpdatedAt,
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "wireguard: update peer")
	}
	if tag.RowsAffected() == 0 {
		return errors.NotFound("wireguard_peer")
	}
	return nil
}

// ListByInterface returns all peers for a WireGuard interface.
func (r *WireGuardPeerRepository) ListByInterface(ctx context.Context, interfaceID uuid.UUID) ([]*models.WireGuardPeer, error) {
	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, interface_id, host_id, name, description,
			public_key, preshared_key, allowed_ips, endpoint,
			persistent_keepalive, enabled,
			last_handshake, transfer_rx, transfer_tx,
			config_qr, created_by, created_at, updated_at
		FROM wireguard_peers
		WHERE interface_id = $1
		ORDER BY created_at DESC`, interfaceID,
	)
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeDatabaseError, "wireguard: list peers by interface")
	}
	defer rows.Close()

	var peers []*models.WireGuardPeer
	for rows.Next() {
		var peer models.WireGuardPeer
		if err := rows.Scan(
			&peer.ID, &peer.InterfaceID, &peer.HostID, &peer.Name, &peer.Description,
			&peer.PublicKey, &peer.PresharedKey, &peer.AllowedIPs, &peer.Endpoint,
			&peer.PersistentKeepalive, &peer.Enabled,
			&peer.LastHandshake, &peer.TransferRx, &peer.TransferTx,
			&peer.ConfigQR, &peer.CreatedBy, &peer.CreatedAt, &peer.UpdatedAt,
		); err != nil {
			return nil, errors.Wrap(err, errors.CodeDatabaseError, "wireguard: scan peer")
		}
		peers = append(peers, &peer)
	}
	return peers, nil
}

// ListByHost returns paginated peers for a host.
func (r *WireGuardPeerRepository) ListByHost(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.WireGuardPeer, int, error) {
	var total int
	err := r.db.Pool().QueryRow(ctx,
		`SELECT COUNT(*) FROM wireguard_peers WHERE host_id = $1`, hostID,
	).Scan(&total)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "wireguard: count peers by host")
	}

	rows, err := r.db.Pool().Query(ctx, `
		SELECT id, interface_id, host_id, name, description,
			public_key, preshared_key, allowed_ips, endpoint,
			persistent_keepalive, enabled,
			last_handshake, transfer_rx, transfer_tx,
			config_qr, created_by, created_at, updated_at
		FROM wireguard_peers
		WHERE host_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`, hostID, limit, offset,
	)
	if err != nil {
		return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "wireguard: list peers by host")
	}
	defer rows.Close()

	var peers []*models.WireGuardPeer
	for rows.Next() {
		var peer models.WireGuardPeer
		if err := rows.Scan(
			&peer.ID, &peer.InterfaceID, &peer.HostID, &peer.Name, &peer.Description,
			&peer.PublicKey, &peer.PresharedKey, &peer.AllowedIPs, &peer.Endpoint,
			&peer.PersistentKeepalive, &peer.Enabled,
			&peer.LastHandshake, &peer.TransferRx, &peer.TransferTx,
			&peer.ConfigQR, &peer.CreatedBy, &peer.CreatedAt, &peer.UpdatedAt,
		); err != nil {
			return nil, 0, errors.Wrap(err, errors.CodeDatabaseError, "wireguard: scan peer")
		}
		peers = append(peers, &peer)
	}
	return peers, total, nil
}

// Delete removes a WireGuard peer.
func (r *WireGuardPeerRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Pool().Exec(ctx, `DELETE FROM wireguard_peers WHERE id = $1`, id)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "wireguard: delete peer")
	}
	if tag.RowsAffected() == 0 {
		return errors.NotFound("wireguard_peer")
	}
	return nil
}

// UpdateTransferStats updates the transfer statistics for a peer.
func (r *WireGuardPeerRepository) UpdateTransferStats(ctx context.Context, id uuid.UUID, rx, tx int64, lastHandshake *time.Time) error {
	tag, err := r.db.Pool().Exec(ctx, `
		UPDATE wireguard_peers SET
			transfer_rx = $2, transfer_tx = $3,
			last_handshake = $4, updated_at = $5
		WHERE id = $1`,
		id, rx, tx, lastHandshake, time.Now(),
	)
	if err != nil {
		return errors.Wrap(err, errors.CodeDatabaseError, "wireguard: update transfer stats")
	}
	if tag.RowsAffected() == 0 {
		return errors.NotFound("wireguard_peer")
	}
	return nil
}
