// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package sslobservatory provides SSL/TLS scanning and certificate analysis.
package sslobservatory

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// TargetRepository defines persistence for SSL targets.
type TargetRepository interface {
	Create(ctx context.Context, target *models.SSLTarget) error
	GetByID(ctx context.Context, id uuid.UUID) (*models.SSLTarget, error)
	List(ctx context.Context, hostID uuid.UUID) ([]models.SSLTarget, error)
	Update(ctx context.Context, target *models.SSLTarget) error
	Delete(ctx context.Context, id uuid.UUID) error
	ListEnabled(ctx context.Context, hostID uuid.UUID) ([]models.SSLTarget, error)
}

// ScanResultRepository defines persistence for scan results.
type ScanResultRepository interface {
	Create(ctx context.Context, result *models.SSLScanResult) error
	GetLatestByTarget(ctx context.Context, targetID uuid.UUID) (*models.SSLScanResult, error)
	ListByTarget(ctx context.Context, targetID uuid.UUID, limit, offset int) ([]models.SSLScanResult, int, error)
	GetExpiringCerts(ctx context.Context, hostID uuid.UUID, withinDays int) ([]models.SSLScanResult, error)
	GetDashboardStats(ctx context.Context, hostID uuid.UUID) (*models.SSLDashboardStats, error)
}

// Service implements SSL Observatory business logic.
type Service struct {
	targets TargetRepository
	scans   ScanResultRepository
	logger  *logger.Logger
}

// NewService creates a new SSL Observatory service.
func NewService(targets TargetRepository, scans ScanResultRepository, log *logger.Logger) *Service {
	return &Service{
		targets: targets,
		scans:   scans,
		logger:  log.Named("ssl_observatory"),
	}
}

// ============================================================================
// Target CRUD
// ============================================================================

// ListTargets returns all SSL targets for a host.
func (s *Service) ListTargets(ctx context.Context, hostID uuid.UUID) ([]models.SSLTarget, error) {
	return s.targets.List(ctx, hostID)
}

// GetTarget returns an SSL target by ID.
func (s *Service) GetTarget(ctx context.Context, id uuid.UUID) (*models.SSLTarget, error) {
	return s.targets.GetByID(ctx, id)
}

// CreateTarget creates a new SSL target.
func (s *Service) CreateTarget(ctx context.Context, hostID uuid.UUID, input models.CreateSSLTargetInput) (*models.SSLTarget, error) {
	port := input.Port
	if port == 0 {
		port = 443
	}

	target := &models.SSLTarget{
		ID:       uuid.New(),
		HostID:   hostID,
		Name:     input.Name,
		Hostname: input.Hostname,
		Port:     port,
		Enabled:  true,
	}

	if err := s.targets.Create(ctx, target); err != nil {
		return nil, err
	}
	return target, nil
}

// DeleteTarget deletes an SSL target.
func (s *Service) DeleteTarget(ctx context.Context, id uuid.UUID) error {
	return s.targets.Delete(ctx, id)
}

// ============================================================================
// Scanning
// ============================================================================

// ScanTarget performs a TLS scan on a single target.
func (s *Service) ScanTarget(ctx context.Context, targetID uuid.UUID) (*models.SSLScanResult, error) {
	target, err := s.targets.GetByID(ctx, targetID)
	if err != nil {
		return nil, fmt.Errorf("get target: %w", err)
	}

	result := s.performScan(ctx, target)

	if err := s.scans.Create(ctx, result); err != nil {
		return nil, fmt.Errorf("save scan result: %w", err)
	}

	return result, nil
}

// ScanAll scans all enabled targets for a host.
func (s *Service) ScanAll(ctx context.Context, hostID uuid.UUID) (int, error) {
	targets, err := s.targets.ListEnabled(ctx, hostID)
	if err != nil {
		return 0, fmt.Errorf("list enabled targets: %w", err)
	}

	scanned := 0
	for _, target := range targets {
		result := s.performScan(ctx, &target)
		if err := s.scans.Create(ctx, result); err != nil {
			s.logger.Error("failed to save scan result", "target", target.Hostname, "error", err)
			continue
		}
		scanned++
	}

	return scanned, nil
}

func (s *Service) performScan(ctx context.Context, target *models.SSLTarget) *models.SSLScanResult {
	start := time.Now()
	addr := fmt.Sprintf("%s:%d", target.Hostname, target.Port)

	result := &models.SSLScanResult{
		ID:       uuid.New(),
		TargetID: target.ID,
		Grade:    "U",
		Score:    0,
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true, // We analyze even invalid certs
	})
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("TLS connection failed: %v", err)
		result.ScanDurationMs = int(time.Since(start).Milliseconds())
		result.ScannedAt = time.Now()
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()

	// Protocol version
	result.ProtocolVersions = []string{tlsVersionName(state.Version)}

	// Cipher suite
	cipherName := tls.CipherSuiteName(state.CipherSuite)
	type cipherInfo struct {
		Name     string `json:"name"`
		ID       uint16 `json:"id"`
		Strength string `json:"strength"`
	}
	ciphers := []cipherInfo{{
		Name:     cipherName,
		ID:       state.CipherSuite,
		Strength: cipherStrength(cipherName),
	}}
	cipherJSON, _ := json.Marshal(ciphers)
	result.CipherSuites = cipherJSON

	// Certificate analysis
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.CertificateCN = cert.Subject.CommonName
		result.CertificateIssuer = cert.Issuer.CommonName
		result.CertNotBefore = &cert.NotBefore
		result.CertNotAfter = &cert.NotAfter
		result.CertKeyBits = certKeyBits(cert)
		result.CertKeyType = certKeyType(cert)
		result.CertChainLength = len(state.PeerCertificates)

		// SANs
		var sans []string
		sans = append(sans, cert.DNSNames...)
		for _, ip := range cert.IPAddresses {
			sans = append(sans, ip.String())
		}
		result.CertificateSANs = sans

		// Chain validity
		opts := x509.VerifyOptions{
			CurrentTime:   time.Now(),
			Intermediates: x509.NewCertPool(),
		}
		for _, ic := range state.PeerCertificates[1:] {
			opts.Intermediates.AddCert(ic)
		}
		_, verifyErr := cert.Verify(opts)
		result.CertChainValid = verifyErr == nil
	}

	// HSTS check
	result.HasHSTS = false // Would require HTTP request, not just TLS

	// OCSP stapling
	result.HasOCSPStapling = len(state.OCSPResponse) > 0

	// SCT
	result.HasSCT = len(state.SignedCertificateTimestamps) > 0

	// Calculate grade and score
	result.Score = s.calculateScore(result, state.Version)
	result.Grade = scoreToGrade(result.Score)

	result.ScanDurationMs = int(time.Since(start).Milliseconds())
	result.ScannedAt = time.Now()

	return result
}

func (s *Service) calculateScore(result *models.SSLScanResult, tlsVersion uint16) int {
	score := 0

	// Protocol score (max 30)
	switch tlsVersion {
	case tls.VersionTLS13:
		score += 30
	case tls.VersionTLS12:
		score += 25
	case tls.VersionTLS11:
		score += 10
	case tls.VersionTLS10:
		score += 5
	}

	// Certificate score (max 30)
	if result.CertChainValid {
		score += 15
	}
	if result.CertNotAfter != nil && result.CertNotAfter.After(time.Now()) {
		score += 10
	}
	if result.CertKeyBits >= 2048 {
		score += 5
	}

	// Features score (max 20)
	if result.HasOCSPStapling {
		score += 5
	}
	if result.HasSCT {
		score += 5
	}
	if result.HasHSTS {
		score += 5
	}
	if result.CertChainLength > 1 && result.CertChainLength < 5 {
		score += 5
	}

	// Cipher score (max 20)
	cipherName := ""
	if result.CipherSuites != nil {
		var ciphers []struct {
			Name string `json:"name"`
		}
		if json.Unmarshal(result.CipherSuites, &ciphers) == nil && len(ciphers) > 0 {
			cipherName = ciphers[0].Name
		}
	}
	if strings.Contains(cipherName, "GCM") || strings.Contains(cipherName, "CHACHA20") {
		score += 20
	} else if strings.Contains(cipherName, "CBC") {
		score += 10
	} else if cipherName != "" {
		score += 5
	}

	return score
}

func scoreToGrade(score int) string {
	if score >= 95 {
		return "A+"
	} else if score >= 85 {
		return "A"
	} else if score >= 70 {
		return "B"
	} else if score >= 55 {
		return "C"
	} else if score >= 40 {
		return "D"
	}
	return "F"
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func cipherStrength(name string) string {
	if strings.Contains(name, "256") || strings.Contains(name, "CHACHA20") {
		return "strong"
	} else if strings.Contains(name, "128") {
		return "acceptable"
	} else if strings.Contains(name, "3DES") || strings.Contains(name, "RC4") {
		return "weak"
	}
	return "unknown"
}

func certKeyType(cert *x509.Certificate) string {
	switch cert.PublicKeyAlgorithm {
	case x509.RSA:
		return "RSA"
	case x509.ECDSA:
		return "ECDSA"
	case x509.Ed25519:
		return "Ed25519"
	default:
		return "unknown"
	}
}

func certKeyBits(cert *x509.Certificate) int {
	switch key := cert.PublicKey.(type) {
	case interface{ Size() int }:
		return key.Size() * 8
	default:
		return 0
	}
}

// ============================================================================
// Dashboard / Queries
// ============================================================================

// GetLatestScan returns the latest scan result for a target.
func (s *Service) GetLatestScan(ctx context.Context, targetID uuid.UUID) (*models.SSLScanResult, error) {
	return s.scans.GetLatestByTarget(ctx, targetID)
}

// ListScans returns paginated scan results for a target.
func (s *Service) ListScans(ctx context.Context, targetID uuid.UUID, limit, offset int) ([]models.SSLScanResult, int, error) {
	return s.scans.ListByTarget(ctx, targetID, limit, offset)
}

// GetExpiringCerts returns certs expiring within N days.
func (s *Service) GetExpiringCerts(ctx context.Context, hostID uuid.UUID, days int) ([]models.SSLScanResult, error) {
	return s.scans.GetExpiringCerts(ctx, hostID, days)
}

// GetDashboardStats returns aggregated dashboard statistics.
func (s *Service) GetDashboardStats(ctx context.Context, hostID uuid.UUID) (*models.SSLDashboardStats, error) {
	return s.scans.GetDashboardStats(ctx, hostID)
}
