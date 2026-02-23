// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package dns

import (
	"context"

	"github.com/fr4nsys/usulnet/internal/models"
)

// SyncBackend abstracts the DNS server backend.
// PostgreSQL is the source of truth; Sync pushes the full zone/record set
// to the running DNS server (embedded miekg/dns or external PowerDNS).
type SyncBackend interface {
	// Sync updates the DNS backend with the full zone/record dataset.
	Sync(ctx context.Context, data *SyncData) error

	// Start launches the DNS server (listener goroutines).
	Start(ctx context.Context) error

	// Stop gracefully shuts down the DNS server.
	Stop() error

	// Healthy returns true if the DNS server is running and serving.
	Healthy(ctx context.Context) (bool, error)

	// Mode returns the backend identifier ("embedded" or "powerdns").
	Mode() string

	// Stats returns server statistics.
	Stats() ServerStats
}

// SyncData holds all the data needed to build a DNS configuration.
// The DNS service populates this from the database; backends consume it
// to update their zone/record state.
type SyncData struct {
	Zones    []*models.DNSZone
	Records  map[string][]*models.DNSRecord // zone ID → records
	TSIGKeys []*models.DNSTSIGKey
}

// ServerStats holds DNS server statistics.
type ServerStats struct {
	QueriesTotal   uint64 `json:"queries_total"`
	QueriesSuccess uint64 `json:"queries_success"`
	QueriesFailed  uint64 `json:"queries_failed"`
	ZonesLoaded    int    `json:"zones_loaded"`
	Uptime         int64  `json:"uptime_seconds"`
}
