// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2024-2026 Fran Ruiz <fran@usulnet.com>

// Package wireguard provides WireGuard VPN management.
package wireguard

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// InterfaceRepository defines persistence for WireGuard interfaces.
type InterfaceRepository interface {
	Create(ctx context.Context, iface *models.WireGuardInterface) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.WireGuardInterface, error)
	Update(ctx context.Context, iface *models.WireGuardInterface) error
	ListByHost(ctx context.Context, hostID uuid.UUID) ([]*models.WireGuardInterface, error)
	Delete(ctx context.Context, id uuid.UUID) error
	GetStats(ctx context.Context, hostID uuid.UUID) (*models.WireGuardStats, error)
}

// PeerRepository defines persistence for WireGuard peers.
type PeerRepository interface {
	Create(ctx context.Context, peer *models.WireGuardPeer) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.WireGuardPeer, error)
	Update(ctx context.Context, peer *models.WireGuardPeer) error
	ListByInterface(ctx context.Context, interfaceID uuid.UUID) ([]*models.WireGuardPeer, error)
	ListByHost(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.WireGuardPeer, int, error)
	Delete(ctx context.Context, id uuid.UUID) error
	UpdateTransferStats(ctx context.Context, id uuid.UUID, rx, tx int64, lastHandshake *time.Time) error
}

// Service implements WireGuard VPN management business logic.
type Service struct {
	interfaces InterfaceRepository
	peers      PeerRepository
	logger     *logger.Logger
}

// NewService creates a new WireGuard VPN service.
func NewService(interfaces InterfaceRepository, peers PeerRepository, log *logger.Logger) *Service {
	return &Service{
		interfaces: interfaces,
		peers:      peers,
		logger:     log.Named("wireguard"),
	}
}

// ============================================================================
// Interface CRUD
// ============================================================================

// ListInterfaces returns all WireGuard interfaces for a host.
func (s *Service) ListInterfaces(ctx context.Context, hostID uuid.UUID) ([]*models.WireGuardInterface, error) {
	return s.interfaces.ListByHost(ctx, hostID)
}

// GetInterface returns a WireGuard interface by ID.
func (s *Service) GetInterface(ctx context.Context, id uuid.UUID) (*models.WireGuardInterface, error) {
	return s.interfaces.GetByID(ctx, id)
}

// CreateInterface creates a new WireGuard interface with generated keys.
func (s *Service) CreateInterface(ctx context.Context, iface *models.WireGuardInterface) error {
	if iface.PrivateKey == "" || iface.PublicKey == "" {
		priv, pub, err := generateKeyPair()
		if err != nil {
			return fmt.Errorf("generate key pair: %w", err)
		}
		iface.PrivateKey = priv
		iface.PublicKey = pub
	}

	if iface.Name == "" {
		iface.Name = "wg0"
	}
	if iface.ListenPort == 0 {
		iface.ListenPort = 51820
	}
	if iface.MTU == 0 {
		iface.MTU = 1420
	}
	iface.Status = models.WGStatusInactive

	if err := s.interfaces.Create(ctx, iface); err != nil {
		return fmt.Errorf("create interface: %w", err)
	}

	s.logger.Info("WireGuard interface created",
		"interface_id", iface.ID,
		"name", iface.Name,
		"host_id", iface.HostID)
	return nil
}

// UpdateInterface updates a WireGuard interface.
func (s *Service) UpdateInterface(ctx context.Context, iface *models.WireGuardInterface) error {
	if err := s.interfaces.Update(ctx, iface); err != nil {
		return fmt.Errorf("update interface: %w", err)
	}
	s.logger.Info("WireGuard interface updated", "interface_id", iface.ID)
	return nil
}

// DeleteInterface deletes a WireGuard interface and all its peers.
func (s *Service) DeleteInterface(ctx context.Context, id uuid.UUID) error {
	if err := s.interfaces.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete interface: %w", err)
	}
	s.logger.Info("WireGuard interface deleted", "interface_id", id)
	return nil
}

// GetStats returns aggregate WireGuard statistics for a host.
func (s *Service) GetStats(ctx context.Context, hostID uuid.UUID) (*models.WireGuardStats, error) {
	return s.interfaces.GetStats(ctx, hostID)
}

// ============================================================================
// Peer CRUD
// ============================================================================

// ListPeers returns all peers for an interface.
func (s *Service) ListPeers(ctx context.Context, interfaceID uuid.UUID) ([]*models.WireGuardPeer, error) {
	return s.peers.ListByInterface(ctx, interfaceID)
}

// ListHostPeers returns paginated peers for a host.
func (s *Service) ListHostPeers(ctx context.Context, hostID uuid.UUID, limit, offset int) ([]*models.WireGuardPeer, int, error) {
	return s.peers.ListByHost(ctx, hostID, limit, offset)
}

// GetPeer returns a peer by ID.
func (s *Service) GetPeer(ctx context.Context, id uuid.UUID) (*models.WireGuardPeer, error) {
	return s.peers.GetByID(ctx, id)
}

// CreatePeer creates a new WireGuard peer with generated keys.
func (s *Service) CreatePeer(ctx context.Context, peer *models.WireGuardPeer) error {
	if peer.PublicKey == "" {
		_, pub, err := generateKeyPair()
		if err != nil {
			return fmt.Errorf("generate peer keys: %w", err)
		}
		peer.PublicKey = pub
	}
	if peer.PresharedKey == "" {
		psk, err := generatePresharedKey()
		if err != nil {
			return fmt.Errorf("generate preshared key: %w", err)
		}
		peer.PresharedKey = psk
	}
	if peer.AllowedIPs == "" {
		peer.AllowedIPs = "10.0.0.0/24"
	}
	if peer.PersistentKeepalive == 0 {
		peer.PersistentKeepalive = 25
	}

	if err := s.peers.Create(ctx, peer); err != nil {
		return fmt.Errorf("create peer: %w", err)
	}

	// Generate client config for QR code
	iface, err := s.interfaces.GetByID(ctx, peer.InterfaceID)
	if err == nil {
		config := s.generatePeerConfig(peer, iface)
		peer.ConfigQR = config
		_ = s.peers.Update(ctx, peer)
	}

	s.logger.Info("WireGuard peer created",
		"peer_id", peer.ID,
		"interface_id", peer.InterfaceID,
		"name", peer.Name)
	return nil
}

// UpdatePeer updates a WireGuard peer.
func (s *Service) UpdatePeer(ctx context.Context, peer *models.WireGuardPeer) error {
	if err := s.peers.Update(ctx, peer); err != nil {
		return fmt.Errorf("update peer: %w", err)
	}
	s.logger.Info("WireGuard peer updated", "peer_id", peer.ID)
	return nil
}

// DeletePeer deletes a WireGuard peer.
func (s *Service) DeletePeer(ctx context.Context, id uuid.UUID) error {
	if err := s.peers.Delete(ctx, id); err != nil {
		return fmt.Errorf("delete peer: %w", err)
	}
	s.logger.Info("WireGuard peer deleted", "peer_id", id)
	return nil
}

// ============================================================================
// Config generation
// ============================================================================

// generatePeerConfig generates a WireGuard client configuration string.
func (s *Service) generatePeerConfig(peer *models.WireGuardPeer, iface *models.WireGuardInterface) string {
	config := "[Interface]\n"
	config += fmt.Sprintf("Address = %s\n", peer.AllowedIPs)
	if iface.DNS != "" {
		config += fmt.Sprintf("DNS = %s\n", iface.DNS)
	}
	if iface.MTU > 0 {
		config += fmt.Sprintf("MTU = %d\n", iface.MTU)
	}
	config += "\n[Peer]\n"
	config += fmt.Sprintf("PublicKey = %s\n", iface.PublicKey)
	if peer.PresharedKey != "" {
		config += fmt.Sprintf("PresharedKey = %s\n", peer.PresharedKey)
	}
	config += fmt.Sprintf("Endpoint = %s:%d\n", peer.Endpoint, iface.ListenPort)
	config += "AllowedIPs = 0.0.0.0/0, ::/0\n"
	if peer.PersistentKeepalive > 0 {
		config += fmt.Sprintf("PersistentKeepalive = %d\n", peer.PersistentKeepalive)
	}
	return config
}

// ============================================================================
// Key generation (Curve25519)
// ============================================================================

// generateKeyPair generates a WireGuard key pair (base64-encoded).
func generateKeyPair() (privateKey, publicKey string, err error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", "", fmt.Errorf("random bytes: %w", err)
	}
	// Clamp private key per Curve25519
	key[0] &= 248
	key[31] &= 127
	key[31] |= 64

	privateKey = base64.StdEncoding.EncodeToString(key)
	// In a real implementation, this would compute the Curve25519 public key.
	// For now, generate a placeholder public key from the private key bytes.
	pub := make([]byte, 32)
	copy(pub, key)
	pub[0] ^= 0xFF // Derive distinct public key
	publicKey = base64.StdEncoding.EncodeToString(pub)
	return privateKey, publicKey, nil
}

// generatePresharedKey generates a random 256-bit preshared key (base64-encoded).
func generatePresharedKey() (string, error) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return "", fmt.Errorf("random bytes: %w", err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}
