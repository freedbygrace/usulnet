// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"time"

	"github.com/google/uuid"
)

// DNS Zone types.
type DNSZoneKind string

const (
	DNSZoneKindPrimary   DNSZoneKind = "primary"
	DNSZoneKindSecondary DNSZoneKind = "secondary"
	DNSZoneKindForward   DNSZoneKind = "forward"
)

// DNS Record types.
type DNSRecordType string

const (
	DNSRecordTypeA     DNSRecordType = "A"
	DNSRecordTypeAAAA  DNSRecordType = "AAAA"
	DNSRecordTypeCNAME DNSRecordType = "CNAME"
	DNSRecordTypeMX    DNSRecordType = "MX"
	DNSRecordTypeTXT   DNSRecordType = "TXT"
	DNSRecordTypeNS    DNSRecordType = "NS"
	DNSRecordTypeSRV   DNSRecordType = "SRV"
	DNSRecordTypePTR   DNSRecordType = "PTR"
	DNSRecordTypeCAA   DNSRecordType = "CAA"
	DNSRecordTypeSOA   DNSRecordType = "SOA"
)

// DNSZone represents a DNS zone (e.g., "example.com.").
type DNSZone struct {
	ID          uuid.UUID   `json:"id" db:"id"`
	HostID      uuid.UUID   `json:"host_id" db:"host_id"`
	Name        string      `json:"name" db:"name"`
	Kind        DNSZoneKind `json:"kind" db:"kind"`
	Enabled     bool        `json:"enabled" db:"enabled"`
	TTL         int         `json:"ttl" db:"ttl"`
	Serial      int64       `json:"serial" db:"serial"`
	Refresh     int         `json:"refresh" db:"refresh"`
	Retry       int         `json:"retry" db:"retry"`
	Expire      int         `json:"expire" db:"expire"`
	MinimumTTL  int         `json:"minimum_ttl" db:"minimum_ttl"`
	PrimaryNS   string      `json:"primary_ns" db:"primary_ns"`
	AdminEmail  string      `json:"admin_email" db:"admin_email"`
	Forwarders  []string    `json:"forwarders,omitempty" db:"forwarders"`
	Description string      `json:"description,omitempty" db:"description"`

	// Relations (not persisted directly)
	Records []DNSRecord `json:"records,omitempty" db:"-"`

	// Audit
	CreatedBy *uuid.UUID `json:"created_by,omitempty" db:"created_by"`
	UpdatedBy *uuid.UUID `json:"updated_by,omitempty" db:"updated_by"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
}

// DNSRecord represents a DNS resource record within a zone.
type DNSRecord struct {
	ID       uuid.UUID     `json:"id" db:"id"`
	ZoneID   uuid.UUID     `json:"zone_id" db:"zone_id"`
	HostID   uuid.UUID     `json:"host_id" db:"host_id"`
	Name     string        `json:"name" db:"name"`
	Type     DNSRecordType `json:"type" db:"type"`
	TTL      int           `json:"ttl" db:"ttl"`
	Content  string        `json:"content" db:"content"`
	Priority *int          `json:"priority,omitempty" db:"priority"`
	Weight   *int          `json:"weight,omitempty" db:"weight"`
	Port     *int          `json:"port,omitempty" db:"port"`
	Enabled  bool          `json:"enabled" db:"enabled"`
	Comment  string        `json:"comment,omitempty" db:"comment"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// DNSTSIGKey represents a TSIG key for zone transfers and dynamic updates.
type DNSTSIGKey struct {
	ID        uuid.UUID `json:"id" db:"id"`
	HostID    uuid.UUID `json:"host_id" db:"host_id"`
	Name      string    `json:"name" db:"name"`
	Algorithm string    `json:"algorithm" db:"algorithm"`
	Secret    string    `json:"-" db:"secret"` // encrypted at rest
	Enabled   bool      `json:"enabled" db:"enabled"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// DNSAuditLog records DNS operations for auditing.
type DNSAuditLog struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	HostID       uuid.UUID  `json:"host_id" db:"host_id"`
	UserID       *uuid.UUID `json:"user_id,omitempty" db:"user_id"`
	Action       string     `json:"action" db:"action"`
	ResourceType string     `json:"resource_type" db:"resource_type"`
	ResourceID   uuid.UUID  `json:"resource_id" db:"resource_id"`
	ResourceName string     `json:"resource_name,omitempty" db:"resource_name"`
	Details      string     `json:"details,omitempty" db:"details"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
}
