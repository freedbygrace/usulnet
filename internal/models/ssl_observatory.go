// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// SSLTarget represents a TLS/SSL endpoint to monitor.
type SSLTarget struct {
	ID             uuid.UUID `json:"id" db:"id"`
	HostID         uuid.UUID `json:"host_id" db:"host_id"`
	Name           string    `json:"name" db:"name"`
	Hostname       string    `json:"hostname" db:"hostname"`
	Port           int       `json:"port" db:"port"`
	AutoDiscovered bool      `json:"auto_discovered" db:"auto_discovered"`
	Enabled        bool      `json:"enabled" db:"enabled"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	UpdatedAt      time.Time `json:"updated_at" db:"updated_at"`
}

// SSLScanResult represents the result of scanning an SSL target.
type SSLScanResult struct {
	ID               uuid.UUID       `json:"id" db:"id"`
	TargetID         uuid.UUID       `json:"target_id" db:"target_id"`
	Grade            string          `json:"grade" db:"grade"`
	Score            int             `json:"score" db:"score"`
	ProtocolVersions []string        `json:"protocol_versions" db:"protocol_versions"`
	CipherSuites     json.RawMessage `json:"cipher_suites" db:"cipher_suites"`
	CertificateCN    string          `json:"certificate_cn" db:"certificate_cn"`
	CertificateIssuer string         `json:"certificate_issuer" db:"certificate_issuer"`
	CertificateSANs  []string        `json:"certificate_sans" db:"certificate_sans"`
	CertNotBefore    *time.Time      `json:"cert_not_before,omitempty" db:"cert_not_before"`
	CertNotAfter     *time.Time      `json:"cert_not_after,omitempty" db:"cert_not_after"`
	CertKeyType      string          `json:"cert_key_type" db:"cert_key_type"`
	CertKeyBits      int             `json:"cert_key_bits" db:"cert_key_bits"`
	CertChainValid   bool            `json:"cert_chain_valid" db:"cert_chain_valid"`
	CertChainLength  int             `json:"cert_chain_length" db:"cert_chain_length"`
	HasHSTS          bool            `json:"has_hsts" db:"has_hsts"`
	HasOCSPStapling  bool            `json:"has_ocsp_stapling" db:"has_ocsp_stapling"`
	HasSCT           bool            `json:"has_sct" db:"has_sct"`
	Vulnerabilities  json.RawMessage `json:"vulnerabilities" db:"vulnerabilities"`
	ErrorMessage     string          `json:"error_message" db:"error_message"`
	ScanDurationMs   int             `json:"scan_duration_ms" db:"scan_duration_ms"`
	ScannedAt        time.Time       `json:"scanned_at" db:"scanned_at"`
}

// CreateSSLTargetInput is the input for creating a new SSL target.
type CreateSSLTargetInput struct {
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
	Port     int    `json:"port"`
}

// SSLDashboardStats holds aggregate statistics for the SSL observatory dashboard.
type SSLDashboardStats struct {
	TotalTargets      int            `json:"total_targets"`
	GradeDistribution map[string]int `json:"grade_distribution"`
	ExpiringSoon      int            `json:"expiring_soon"`
	LastScanTime      *time.Time     `json:"last_scan_time,omitempty"`
}
