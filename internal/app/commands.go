// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"

	"github.com/fr4nsys/usulnet/internal/api"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// RunMigrations runs database migrations
func RunMigrations(cfgFile, action string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cfg, err := LoadConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	db, err := postgres.New(ctx, cfg.Database.URL, postgres.Options{
		MaxOpenConns:    cfg.Database.MaxOpenConns,
		MaxIdleConns:    cfg.Database.MaxIdleConns,
		ConnMaxLifetime: cfg.Database.ConnMaxLifetime,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	switch action {
	case "up":
		return db.Migrate(ctx)
	case "status":
		return db.MigrationStatus(ctx)
	default:
		// Handle down:N format
		if len(action) > 5 && action[:5] == "down:" {
			return db.MigrateDown(ctx, action[5:])
		}
		return fmt.Errorf("unknown migration action: %s", action)
	}
}

// ResetAdminPassword resets the admin user password or creates the admin if missing.
func ResetAdminPassword(cfgFile, newPassword string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg, err := LoadConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	db, err := postgres.New(ctx, cfg.Database.URL, postgres.Options{
		MaxOpenConns: 2,
		MaxIdleConns: 1,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	userRepo := postgres.NewUserRepository(db)

	// Hash the new password
	hash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Try to find admin user
	admin, err := userRepo.GetByUsername(ctx, "admin")
	if err != nil {
		// Admin doesn't exist - create it
		adminUser := &models.User{
			Username:     "admin",
			PasswordHash: hash,
			Role:         models.RoleAdmin,
			IsActive:     true,
		}
		if err := userRepo.Create(ctx, adminUser); err != nil {
			return fmt.Errorf("failed to create admin user: %w", err)
		}
		fmt.Println("Admin user created with new password.")
		return nil
	}

	// Update existing admin
	admin.PasswordHash = hash
	admin.IsActive = true
	if err := userRepo.Update(ctx, admin); err != nil {
		return fmt.Errorf("failed to update admin password: %w", err)
	}

	// Actually unlock the account (Update doesn't touch failed_login_attempts/locked_until)
	if err := userRepo.Unlock(ctx, admin.ID); err != nil {
		return fmt.Errorf("failed to unlock admin account: %w", err)
	}

	fmt.Println("Admin password reset successfully. Account unlocked.")
	return nil
}

// countActiveHandlers counts non-nil handlers in the Handlers struct.
func countActiveHandlers(h *api.Handlers) int {
	count := 0
	if h.System != nil {
		count++
	}
	if h.WebSocket != nil {
		count++
	}
	if h.Auth != nil {
		count++
	}
	if h.Container != nil {
		count++
	}
	if h.Image != nil {
		count++
	}
	if h.Volume != nil {
		count++
	}
	if h.Network != nil {
		count++
	}
	if h.Stack != nil {
		count++
	}
	if h.Host != nil {
		count++
	}
	if h.User != nil {
		count++
	}
	if h.Backup != nil {
		count++
	}
	if h.Security != nil {
		count++
	}
	if h.Config != nil {
		count++
	}
	if h.Update != nil {
		count++
	}
	if h.Job != nil {
		count++
	}
	if h.Notification != nil {
		count++
	}
	if h.Audit != nil {
		count++
	}
	if h.PasswordReset != nil {
		count++
	}
	if h.Proxy != nil {
		count++
	}
	if h.NPM != nil {
		count++
	}
	if h.SSH != nil {
		count++
	}
	if h.OpenAPI != nil {
		count++
	}
	if h.Settings != nil {
		count++
	}
	if h.License != nil {
		count++
	}
	if h.Registry != nil {
		count++
	}
	if h.Calendar != nil {
		count++
	}
	return count
}

// buildNATSTLSConfig creates a *tls.Config from certificate file paths.
func buildNATSTLSConfig(certFile, keyFile, caFile string, skipVerify bool) (*tls.Config, error) {
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: skipVerify, //nolint:gosec // Configurable for dev environments
	}

	// Load CA certificate
	if caFile != "" {
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate %s: %w", caFile, err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", caFile)
		}
		tlsCfg.RootCAs = caCertPool
	}

	// Load client certificate and key for mutual TLS
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return tlsCfg, nil
}
