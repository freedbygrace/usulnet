// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"

	"github.com/fr4nsys/usulnet/internal/api/handlers"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	calendarsvc "github.com/fr4nsys/usulnet/internal/services/calendar"
	registrysvc "github.com/fr4nsys/usulnet/internal/services/registry"
	usersvc "github.com/fr4nsys/usulnet/internal/services/user"
)

// initAPI initializes API handlers, populates the router, registers health
// checkers, and calls Setup() on the server.
// Requires initAuth, initDocker, initServices, and initScheduler to have populated ic.
func (app *Application) initAPI(ctx context.Context, ic *initContext) error {
	_ = ctx // ctx reserved for future use

	// Create user service for API handler (wire password policy from config)
	userServiceConfig := usersvc.DefaultServiceConfig()
	if app.Config.Security.PasswordMinLength > 0 {
		userServiceConfig.PasswordMinLength = app.Config.Security.PasswordMinLength
	}
	userServiceConfig.PasswordRequireUpper = app.Config.Security.PasswordRequireUpper
	userServiceConfig.PasswordRequireNumber = app.Config.Security.PasswordRequireNumber
	userServiceConfig.PasswordRequireSymbol = app.Config.Security.PasswordRequireSymbol
	if app.Config.Security.MaxFailedLogins > 0 {
		userServiceConfig.MaxFailedLogins = app.Config.Security.MaxFailedLogins
	}
	if app.Config.Security.LockoutDuration > 0 {
		userServiceConfig.LockoutDuration = app.Config.Security.LockoutDuration
	}
	if app.Config.Security.APIKeyLength > 0 {
		userServiceConfig.APIKeyLength = app.Config.Security.APIKeyLength
	}
	userService := usersvc.NewService(
		ic.userRepo,
		ic.apiKeyRepo,
		userServiceConfig,
		app.Logger,
	)
	if ic.licenseProvider != nil {
		userService.SetLimitProvider(ic.licenseProvider)
	}

	// Populate API handlers
	apiHandlers := app.Server.Handlers()
	apiHandlers.Auth = handlers.NewAuthHandler(ic.authService, app.Logger)
	apiHandlers.Container = handlers.NewContainerHandler(ic.containerService, app.Logger)
	apiHandlers.Image = handlers.NewImageHandler(ic.imageService, app.Logger)
	apiHandlers.Volume = handlers.NewVolumeHandler(ic.volumeService, app.Logger)
	apiHandlers.Network = handlers.NewNetworkHandler(ic.networkService, app.Logger)
	apiHandlers.Stack = handlers.NewStackHandler(ic.stackService, app.Logger)
	apiHandlers.Host = handlers.NewHostHandler(ic.hostService, app.Logger)
	apiHandlers.User = handlers.NewUserHandler(userService, app.Logger)
	apiHandlers.Security = handlers.NewSecurityHandler(ic.securityService, app.Logger)
	apiHandlers.Update = handlers.NewUpdateHandler(ic.updateService, app.Logger)
	apiHandlers.WebSocket = handlers.NewWebSocketHandler(ic.containerService, app.Logger)

	if ic.backupService != nil {
		apiHandlers.Backup = handlers.NewBackupHandler(ic.backupService, app.Logger)
	}
	if ic.configService != nil && ic.configSyncService != nil {
		apiHandlers.Config = handlers.NewConfigHandler(ic.configService, ic.configSyncService, app.Logger)
	}
	if ic.notificationService != nil {
		apiHandlers.Notification = handlers.NewNotificationHandler(ic.notificationService, app.Logger)
	}
	if ic.auditService != nil {
		apiHandlers.Audit = handlers.NewAuditHandler(ic.auditService, app.Logger)
	}

	// Wire license provider to handlers that enforce feature/limit gates
	if ic.licenseProvider != nil {
		apiHandlers.User.SetLicenseProvider(ic.licenseProvider)
		apiHandlers.Host.SetLicenseProvider(ic.licenseProvider)
		if apiHandlers.Notification != nil {
			apiHandlers.Notification.SetLicenseProvider(ic.licenseProvider)
		}
		if apiHandlers.Audit != nil {
			apiHandlers.Audit.SetLicenseProvider(ic.licenseProvider)
		}
		if apiHandlers.Backup != nil {
			apiHandlers.Backup.SetLicenseProvider(ic.licenseProvider)
		}
	}
	if app.schedulerService != nil {
		apiHandlers.Job = handlers.NewJobsHandler(app.schedulerService, app.Logger)
	}

	// Settings handler (uses config variable repo for app settings + LDAP config repo)
	{
		settingsConfigRepo := postgres.NewConfigVariableRepository(app.DB, app.Logger)
		settingsLDAPRepo := postgres.NewLDAPConfigRepository(app.DB, app.Logger)
		apiHandlers.Settings = handlers.NewSettingsHandler(settingsConfigRepo, settingsLDAPRepo, nil, app.Logger)
	}

	// License handler
	if ic.licenseProvider != nil {
		apiHandlers.License = handlers.NewLicenseHandler(ic.licenseProvider, nil, app.Logger)
	}

	// Registry browsing service and handler (also used by web handler below)
	registryRepo := postgres.NewRegistryRepository(app.DB)
	var registryEncryptor registrysvc.Encryptor
	if ic.encryptor != nil {
		registryEncryptor = &encryptorAdapter{enc: ic.encryptor}
	}
	registryBrowseSvc := registrysvc.NewService(registryRepo, registryEncryptor, app.Logger)
	{
		apiHandlers.Registry = handlers.NewRegistryHandler(registryBrowseSvc, app.Logger)
		app.Logger.Info("Registry browsing service enabled")
	}

	// OpenAPI documentation endpoint
	apiHandlers.OpenAPI = handlers.NewOpenAPIHandler(Version)

	// Calendar API handler
	calendarRepo := postgres.NewCalendarRepository(app.DB)
	calendarSvc := calendarsvc.NewService(calendarRepo, app.Logger)
	apiHandlers.Calendar = handlers.NewCalendarHandler(calendarSvc, app.Logger)
	app.Logger.Info("Calendar service enabled")

	// Now build the router with all handlers populated
	app.Server.Setup()

	// =========================================================================
	// HEALTH CHECKER REGISTRATION
	// =========================================================================
	// Register health checkers for all infrastructure dependencies so that
	// /health, /healthz, and /ready endpoints report component-level status.

	// PostgreSQL health checker
	if app.DB != nil {
		app.Server.RegisterDatabaseHealth(func(ctx context.Context) error {
			return app.DB.Pool().Ping(ctx)
		})
		app.Logger.Info("Health checker registered: postgresql")
	}

	// Redis health checker (uses HealthCheck: Ping + pool connectivity)
	if app.Redis != nil {
		app.Server.RegisterRedisHealth(func(ctx context.Context) error {
			return app.Redis.HealthCheck(ctx)
		})
		app.Logger.Info("Health checker registered: redis")
	}

	// Docker Engine health checker
	if ic.dockerClient != nil {
		app.Server.RegisterDockerHealth(func(ctx context.Context) error {
			return ic.dockerClient.Ping(ctx)
		})
		app.Logger.Info("Health checker registered: docker")
	}

	// NATS health checker (uses Health: IsConnected + FlushTimeout round-trip)
	if app.NATS != nil {
		app.Server.RegisterNATSHealth(func(ctx context.Context) error {
			return app.NATS.Health(ctx)
		})
		app.Logger.Info("Health checker registered: nats")
	}

	// Disk space health checker (100MB minimum free on the data volume)
	diskPath := app.Config.Storage.Path
	if diskPath == "" {
		diskPath = "/"
	}
	app.Server.RegisterDiskSpaceHealth(diskPath, 100*1024*1024)
	app.Logger.Info("Health checker registered: disk_space", "path", diskPath)

	app.Logger.Info("API handlers initialized",
		"handlers_active", countActiveHandlers(apiHandlers),
	)

	// Populate initContext
	ic.registryRepo = registryRepo
	ic.registryBrowseSvc = registryBrowseSvc

	return nil
}
