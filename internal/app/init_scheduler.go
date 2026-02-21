// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"

	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/scheduler"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
)

// initScheduler initializes the job scheduler, registers workers, and starts
// the scheduler with cron jobs for retention and backup.
// Requires initDocker and initServices to have populated ic.
func (app *Application) initScheduler(ctx context.Context, ic *initContext) error {
	jobRepo := postgres.NewJobRepository(app.DB)

	queueConfig := scheduler.DefaultQueueConfig()
	jobQueue := scheduler.NewQueue(app.Redis, app.Logger, queueConfig)

	schedulerConfig := scheduler.DefaultConfig()
	sched := scheduler.New(jobQueue, jobRepo, schedulerConfig, app.Logger)

	// Build worker dependencies — MetricsService and InventoryService are nil
	// (workers for those will not be registered, which is safe).
	schedulerDeps := &workers.Dependencies{
		SecurityService: &schedulerSecurityAdapter{svc: ic.securityService},
		DockerClient: &schedulerDockerScanAdapter{
			hostService: ic.hostService,
			hostID:      ic.defaultHostID,
		},
		UpdateService: &schedulerUpdateAdapter{
			svc:    ic.updateService,
			hostID: ic.defaultHostID,
		},
		CleanupService: &schedulerCleanupAdapter{
			imageService:     ic.imageService,
			volumeService:    ic.volumeService,
			networkService:   ic.networkService,
			containerService: ic.containerService,
			hostService:      ic.hostService,
			hostID:           ic.defaultHostID,
		},
		JobCleanupService:   &schedulerJobCleanupAdapter{db: app.DB},
		RetentionService:    &schedulerRetentionAdapter{db: app.DB},
		NotificationService: &schedulerNotificationAdapter{svc: ic.notificationService},
		MetricsService:      nil, // Assigned later after metrics init
		InventoryService:    &schedulerInventoryAdapter{hostService: ic.hostService},
		Logger:              app.Logger,
	}

	// BackupService can be nil if storage initialization failed
	if ic.backupService != nil {
		schedulerDeps.BackupService = &schedulerBackupAdapter{
			svc:    ic.backupService,
			hostID: ic.defaultHostID,
		}
	}

	// Register all available workers
	workers.RegisterDefaultWorkers(sched.Registry(), schedulerDeps)

	// Start scheduler (queue processor, cron, worker pool)
	if err := sched.Start(ctx); err != nil {
		app.Logger.Error("Failed to start scheduler", "error", err)
	} else {
		app.schedulerService = sched
		app.Logger.Info("Scheduler service initialized",
			"worker_pool_size", schedulerConfig.WorkerPoolSize,
		)

		// Register default retention scheduled job (daily at 03:00 UTC)
		app.ensureRetentionScheduledJob(ctx, sched)

		// Register automatic database backup job (daily at 02:00 UTC)
		if ic.backupService != nil {
			app.ensureDatabaseBackupScheduledJob(ctx, sched, ic.defaultHostID)
		}
	}

	// Populate initContext
	ic.scheduler = sched
	ic.schedulerDeps = schedulerDeps

	return nil
}
