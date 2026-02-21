// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"

	dockerpkg "github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	containersvc "github.com/fr4nsys/usulnet/internal/services/container"
	hostsvc "github.com/fr4nsys/usulnet/internal/services/host"
	imagesvc "github.com/fr4nsys/usulnet/internal/services/image"
	networksvc "github.com/fr4nsys/usulnet/internal/services/network"
	stacksvc "github.com/fr4nsys/usulnet/internal/services/stack"
	volumesvc "github.com/fr4nsys/usulnet/internal/services/volume"
)

// initDocker initializes Docker-related services: host, container, image, volume,
// network, and stack services. Connects to the local Docker daemon.
func (app *Application) initDocker(ctx context.Context, ic *initContext) error {
	defaultHostID := standaloneHostID

	// Host service in standalone mode with DB-backed repository for host CRUD
	hostService := hostsvc.NewStandaloneService(hostsvc.DefaultConfig(), app.Logger)
	app.hostService = hostService

	// Wire host repository so Create/Update/Delete hosts work in standalone mode
	stdDBHosts := stdlib.OpenDBFromPool(app.DB.Pool())
	app.hostRepo = postgres.NewHostRepository(sqlx.NewDb(stdDBHosts, "pgx"))
	hostService.SetRepository(app.hostRepo)

	// Create local Docker client and register it
	dockerClient, err := dockerpkg.NewLocalClient(ctx)
	if err != nil {
		app.Logger.Error("Failed to connect to local Docker", "error", err)
		// Non-fatal: services will return errors but app still works
	} else {
		hostService.RegisterClient(defaultHostID.String(), dockerClient)
		app.Logger.Info("Connected to local Docker engine")
	}

	// Start host service (health checks)
	if err := hostService.Start(ctx); err != nil {
		app.Logger.Error("Failed to start host service", "error", err)
	}

	// Bootstrap local host in DB (needed for foreign key in containers table)
	if err := app.bootstrapLocalHost(ctx, defaultHostID); err != nil {
		app.Logger.Error("Failed to bootstrap local host in DB", "error", err)
	}

	// Sync Docker info (version, OS, memory, etc.) into the DB immediately after
	// bootstrapping so the host list and cards show accurate data on first load.
	if err := hostService.SyncDockerInfoForHost(ctx, defaultHostID); err != nil {
		app.Logger.Warn("Failed to sync initial Docker info", "error", err)
	}

	// Container service (syncs container state from Docker to DB)
	containerRepo := postgres.NewContainerRepository(app.DB)
	containerService := containersvc.NewService(containerRepo, hostService, containersvc.DefaultConfig(), app.Logger)
	app.containerService = containerService
	if err := containerService.Start(ctx); err != nil {
		app.Logger.Error("Failed to start container service", "error", err)
	}

	// Do initial sync so dashboard has data immediately.
	// A short delay ensures the host service's background goroutines (initializeConnections,
	// health checks) have settled before we attempt the first sync.
	go func() {
		select {
		case <-time.After(1 * time.Second):
		case <-ctx.Done():
			return
		}
		if err := containerService.SyncHost(ctx, defaultHostID); err != nil {
			app.Logger.Warn("Initial container sync failed (will retry on next interval)", "error", err)
		} else {
			app.Logger.Info("Initial container sync completed")
		}
	}()

	// Image, Volume, Network services (query Docker directly via host service)
	imageService := imagesvc.NewService(hostService, app.Logger)
	volumeService := volumesvc.NewService(hostService, app.Logger)
	networkService := networksvc.NewService(hostService, app.Logger)

	// Stack service
	stacksDir := app.Config.Storage.StacksDir
	if stacksDir == "" {
		stacksDir = app.Config.Storage.Path + "/stacks"
	}
	stackRepo := postgres.NewStackRepository(app.DB)
	stackService := stacksvc.NewService(stackRepo, hostService, containerService, stacksvc.ServiceConfig{
		StacksDir:      stacksDir,
		ComposeCommand: "docker compose",
		DefaultTimeout: 5 * time.Minute,
	}, app.Logger)

	app.Logger.Info("Docker services initialized",
		"host_id", defaultHostID,
	)

	// Populate initContext
	ic.defaultHostID = defaultHostID
	ic.hostService = hostService
	ic.containerService = containerService
	ic.containerRepo = containerRepo
	ic.imageService = imageService
	ic.volumeService = volumeService
	ic.networkService = networkService
	ic.stackService = stackService
	ic.dockerClient = dockerClient

	return nil
}
