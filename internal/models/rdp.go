// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// RDPConnectionStatus represents the status of an RDP connection.
type RDPConnectionStatus string

const (
	RDPConnectionActive       RDPConnectionStatus = "active"
	RDPConnectionDisconnected RDPConnectionStatus = "disconnected"
	RDPConnectionError        RDPConnectionStatus = "error"
)

// RDPSecurityMode represents the RDP security protocol.
type RDPSecurityMode string

const (
	RDPSecurityAny RDPSecurityMode = "any"
	RDPSecurityNLA RDPSecurityMode = "nla"
	RDPSecurityTLS RDPSecurityMode = "tls"
	RDPSecurityRDP RDPSecurityMode = "rdp"
)

// RDPConnection represents a saved RDP connection profile.
type RDPConnection struct {
	ID            uuid.UUID           `db:"id" json:"id"`
	UserID        uuid.UUID           `db:"user_id" json:"user_id"`
	Name          string              `db:"name" json:"name"`
	Host          string              `db:"host" json:"host"`
	Port          int                 `db:"port" json:"port"`
	Username      string              `db:"username" json:"username"`
	Domain        string              `db:"domain" json:"domain,omitempty"`
	Password      string              `db:"password" json:"-"` // Encrypted
	Resolution    string              `db:"resolution" json:"resolution,omitempty"`
	ColorDepth    string              `db:"color_depth" json:"color_depth,omitempty"`
	Security      RDPSecurityMode     `db:"security" json:"security"`
	Tags          []string            `db:"tags" json:"tags,omitempty"`
	Status        RDPConnectionStatus `db:"status" json:"status"`
	StatusMessage string              `db:"status_message" json:"status_message,omitempty"`
	LastChecked   *time.Time          `db:"last_checked" json:"last_checked,omitempty"`
	LastConnected *time.Time          `db:"last_connected" json:"last_connected,omitempty"`
	CreatedAt     time.Time           `db:"created_at" json:"created_at"`
	UpdatedAt     time.Time           `db:"updated_at" json:"updated_at"`
}

// CreateRDPConnectionInput is the input for creating an RDP connection.
type CreateRDPConnectionInput struct {
	Name       string          `json:"name"`
	Host       string          `json:"host"`
	Port       int             `json:"port"`
	Username   string          `json:"username"`
	Domain     string          `json:"domain"`
	Password   string          `json:"password"`
	Resolution string          `json:"resolution"`
	ColorDepth string          `json:"color_depth"`
	Security   RDPSecurityMode `json:"security"`
	Tags       []string        `json:"tags"`
}

// UpdateRDPConnectionInput is the input for updating an RDP connection.
type UpdateRDPConnectionInput struct {
	Name       *string          `json:"name"`
	Host       *string          `json:"host"`
	Port       *int             `json:"port"`
	Username   *string          `json:"username"`
	Domain     *string          `json:"domain"`
	Password   *string          `json:"password"`
	Resolution *string          `json:"resolution"`
	ColorDepth *string          `json:"color_depth"`
	Security   *RDPSecurityMode `json:"security"`
	Tags       []string         `json:"tags"`
}
