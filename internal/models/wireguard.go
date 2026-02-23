// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// WireGuardInterfaceStatus represents the operational status of a WireGuard interface.
type WireGuardInterfaceStatus string

const (
	WGStatusInactive WireGuardInterfaceStatus = "inactive"
	WGStatusActive   WireGuardInterfaceStatus = "active"
	WGStatusError    WireGuardInterfaceStatus = "error"
)

// WireGuardInterface represents a WireGuard VPN interface on a host.
type WireGuardInterface struct {
	ID            uuid.UUID                `json:"id" db:"id"`
	HostID        uuid.UUID                `json:"host_id" db:"host_id"`
	Name          string                   `json:"name" db:"name"`
	DisplayName   string                   `json:"display_name" db:"display_name"`
	Description   string                   `json:"description,omitempty" db:"description"`
	ListenPort    int                      `json:"listen_port" db:"listen_port"`
	Address       string                   `json:"address" db:"address"`
	PrivateKey    string                   `json:"-" db:"private_key"`
	PublicKey     string                   `json:"public_key" db:"public_key"`
	DNS           string                   `json:"dns,omitempty" db:"dns"`
	MTU           int                      `json:"mtu,omitempty" db:"mtu"`
	PostUp        string                   `json:"post_up,omitempty" db:"post_up"`
	PostDown      string                   `json:"post_down,omitempty" db:"post_down"`
	Enabled       bool                     `json:"enabled" db:"enabled"`
	Status        WireGuardInterfaceStatus `json:"status" db:"status"`
	PeerCount     int                      `json:"peer_count" db:"peer_count"`
	LastHandshake *time.Time               `json:"last_handshake,omitempty" db:"last_handshake"`
	TransferRx    int64                    `json:"transfer_rx" db:"transfer_rx"`
	TransferTx    int64                    `json:"transfer_tx" db:"transfer_tx"`
	CreatedBy     *uuid.UUID               `json:"created_by,omitempty" db:"created_by"`
	CreatedAt     time.Time                `json:"created_at" db:"created_at"`
	UpdatedAt     time.Time                `json:"updated_at" db:"updated_at"`
}

// WireGuardPeer represents a WireGuard peer connected to an interface.
type WireGuardPeer struct {
	ID                  uuid.UUID  `json:"id" db:"id"`
	InterfaceID         uuid.UUID  `json:"interface_id" db:"interface_id"`
	HostID              uuid.UUID  `json:"host_id" db:"host_id"`
	Name                string     `json:"name" db:"name"`
	Description         string     `json:"description,omitempty" db:"description"`
	PublicKey           string     `json:"public_key" db:"public_key"`
	PresharedKey        string     `json:"-" db:"preshared_key"`
	AllowedIPs          string     `json:"allowed_ips" db:"allowed_ips"`
	Endpoint            string     `json:"endpoint,omitempty" db:"endpoint"`
	PersistentKeepalive int        `json:"persistent_keepalive" db:"persistent_keepalive"`
	Enabled             bool       `json:"enabled" db:"enabled"`
	LastHandshake       *time.Time `json:"last_handshake,omitempty" db:"last_handshake"`
	TransferRx          int64      `json:"transfer_rx" db:"transfer_rx"`
	TransferTx          int64      `json:"transfer_tx" db:"transfer_tx"`
	ConfigQR            string     `json:"config_qr,omitempty" db:"config_qr"`
	CreatedBy           *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	CreatedAt           time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at" db:"updated_at"`
}

// WireGuardStats holds aggregate WireGuard statistics for a host.
type WireGuardStats struct {
	TotalInterfaces  int        `json:"total_interfaces"`
	ActiveInterfaces int        `json:"active_interfaces"`
	TotalPeers       int        `json:"total_peers"`
	ConnectedPeers   int        `json:"connected_peers"`
	TotalRx          int64      `json:"total_rx"`
	TotalTx          int64      `json:"total_tx"`
	LastActivity     *time.Time `json:"last_activity,omitempty"`
}
