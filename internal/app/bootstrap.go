// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	dockerpkg "github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/scheduler"
)

// ensureRetentionScheduledJob creates the default database retention cleanup job
// if it doesn't already exist. Runs daily at 03:00 UTC.
func (app *Application) ensureRetentionScheduledJob(ctx context.Context, sched *scheduler.Scheduler) {
	existing, err := sched.ListScheduledJobs(ctx, false)
	if err != nil {
		app.Logger.Warn("Failed to list scheduled jobs for retention check", "error", err)
		return
	}

	// Check if a retention job already exists
	for _, job := range existing {
		if job.Type == models.JobTypeRetention {
			app.Logger.Debug("Retention scheduled job already exists", "job_id", job.ID, "schedule", job.Schedule)
			return
		}
	}

	// Create default retention job: daily at 03:00 UTC
	_, err = sched.CreateScheduledJob(ctx, models.CreateScheduledJobInput{
		Name:        "Database Retention Cleanup",
		Type:        models.JobTypeRetention,
		Schedule:    "0 3 * * *",
		IsEnabled:   true,
		MaxAttempts: 1,
		Priority:    models.JobPriorityLow,
	})
	if err != nil {
		app.Logger.Error("Failed to create retention scheduled job", "error", err)
		return
	}

	app.Logger.Info("Retention scheduled job created (daily at 03:00 UTC)")
}

// ensureDatabaseBackupScheduledJob creates the default automatic database backup
// job if it doesn't already exist. Runs daily at 02:00 UTC with gzip compression,
// encryption enabled, and 7-day retention.
func (app *Application) ensureDatabaseBackupScheduledJob(ctx context.Context, sched *scheduler.Scheduler, hostID uuid.UUID) {
	existing, err := sched.ListScheduledJobs(ctx, false)
	if err != nil {
		app.Logger.Warn("Failed to list scheduled jobs for backup check", "error", err)
		return
	}

	// Check if a database backup job already exists
	for _, job := range existing {
		if job.Type == models.JobTypeBackupCreate && job.Name == "Automatic Database Backup" {
			app.Logger.Debug("Database backup scheduled job already exists", "job_id", job.ID, "schedule", job.Schedule)
			return
		}
	}

	// Create default database backup job: daily at 02:00 UTC
	targetID := "postgresql"
	targetName := "PostgreSQL Database"
	retentionDays := 7
	_, err = sched.CreateScheduledJob(ctx, models.CreateScheduledJobInput{
		Name:        "Automatic Database Backup",
		Type:        models.JobTypeBackupCreate,
		Schedule:    "0 2 * * *",
		HostID:      &hostID,
		TargetID:    &targetID,
		TargetName:  &targetName,
		IsEnabled:   true,
		MaxAttempts: 3,
		Priority:    models.JobPriorityNormal,
		Payload: models.BackupPayload{
			Type:          string(models.BackupTypeSystem),
			TargetID:      targetID,
			Compression:   "gzip",
			Encrypted:     true,
			RetentionDays: retentionDays,
		},
	})
	if err != nil {
		app.Logger.Error("Failed to create database backup scheduled job", "error", err)
		return
	}

	app.Logger.Info("Automatic database backup scheduled job created (daily at 02:00 UTC, 7-day retention)")
}

// bootstrapLocalHost ensures the local Docker host row exists in the hosts table
// and is marked online. This is required for foreign key constraints when syncing
// containers, and ensures the host is always discoverable by the reconciliation
// worker even after a previous Docker failure marked it offline.
func (app *Application) bootstrapLocalHost(ctx context.Context, hostID uuid.UUID) error {
	// The hosts table has UNIQUE(id) as PK and UNIQUE(name). If a previous version of
	// the app used a different standaloneHostID, a row with name='local' and a different
	// id may already exist. The CTE removes any such stale row before the insert so that
	// both unique constraints are always satisfied.
	_, err := app.DB.Exec(ctx, `
		WITH cleanup AS (
			DELETE FROM hosts WHERE name = $2 AND id != $1
		)
		INSERT INTO hosts (id, name, display_name, endpoint_type, endpoint_url, tls_enabled, status, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, false, 'online', CURRENT_TIMESTAMP)
		ON CONFLICT (id) DO UPDATE SET
			status = 'online',
			last_seen_at = CURRENT_TIMESTAMP`,
		hostID, "local", "Local Docker", "local", "unix://"+dockerpkg.LocalSocketPath(),
	)
	if err != nil {
		return fmt.Errorf("bootstrap local host: %w", err)
	}

	app.Logger.Info("Local Docker host bootstrapped in DB (status=online)", "host_id", hostID)
	return nil
}

// bootstrapAdminUser creates a default admin user if none exist.
func (app *Application) bootstrapAdminUser(ctx context.Context, userRepo *postgres.UserRepository) error {
	// Check if any users exist
	users, total, err := userRepo.List(ctx, postgres.UserListOptions{
		Page:    1,
		PerPage: 1,
	})
	if err != nil {
		return fmt.Errorf("check existing users: %w", err)
	}

	_ = users // only need the count
	if total > 0 {
		app.Logger.Info("Users already exist, skipping admin bootstrap", "count", total)
		return nil
	}

	// No users exist - create default admin with well-known password.
	// Users should change this after first login.
	const defaultPassword = "usulnet"

	hash, err := crypto.HashPassword(defaultPassword)
	if err != nil {
		return fmt.Errorf("hash admin password: %w", err)
	}

	adminUser := &models.User{
		Username:     "admin",
		PasswordHash: hash,
		Role:         models.RoleAdmin,
		IsActive:     true,
	}

	if err := userRepo.Create(ctx, adminUser); err != nil {
		return fmt.Errorf("create admin user: %w", err)
	}

	app.Logger.Warn("Default admin user created — change password after first login",
		"username", "admin",
	)
	fmt.Printf("\n============================================================\n")
	fmt.Printf("  DEFAULT ADMIN CREDENTIALS\n")
	fmt.Printf("  Username: admin\n")
	fmt.Printf("  Password: usulnet\n")
	fmt.Printf("  Change this password after first login!\n")
	fmt.Printf("============================================================\n\n")

	return nil
}
