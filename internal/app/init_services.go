// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"strings"
	"time"

	licensepkg "github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	backupsvc "github.com/fr4nsys/usulnet/internal/services/backup"
	backupstorage "github.com/fr4nsys/usulnet/internal/services/backup/storage"
	configsvc "github.com/fr4nsys/usulnet/internal/services/config"
	notificationsvc "github.com/fr4nsys/usulnet/internal/services/notification"
	securitysvc "github.com/fr4nsys/usulnet/internal/services/security"
	securityanalyzer "github.com/fr4nsys/usulnet/internal/services/security/analyzer"
	trivypkg "github.com/fr4nsys/usulnet/internal/services/security/trivy"
	teamsvc "github.com/fr4nsys/usulnet/internal/services/team"
	updatesvc "github.com/fr4nsys/usulnet/internal/services/update"
)

// initServices initializes business logic services: license, team, security,
// encryptor, backup, config, update, and notification.
// Requires initAuth and initDocker to have populated ic.
func (app *Application) initServices(ctx context.Context, ic *initContext) error {
	// =========================================================================
	// LICENSE PROVIDER (initialized early — needed by team service and router)
	// =========================================================================

	licenseDataDir := app.Config.Storage.Path
	if licenseDataDir == "" {
		licenseDataDir = "/app/data"
	}
	licenseProvider, err := licensepkg.NewProvider(licenseDataDir, &zapLicenseLogger{sugar: app.Logger.Base().Sugar()})
	if err != nil {
		app.Logger.Warn("License provider initialization failed, running as CE", "error", err)
	} else {
		app.licenseProvider = licenseProvider
		app.Server.RegisterLicenseProvider(licenseProvider)

		// Wire limit provider to services created earlier
		ic.hostService.SetLimitProvider(licenseProvider)

		app.Logger.Info("License provider initialized",
			"edition", licenseProvider.Edition(),
			"instance_id", licenseProvider.InstanceID(),
		)
	}

	// =========================================================================
	// TEAM SERVICE INITIALIZATION
	// =========================================================================

	teamRepo := postgres.NewTeamRepository(app.DB)
	permRepo := postgres.NewResourcePermissionRepository(app.DB)
	licenseLimits := licensepkg.CELimits()
	if licenseProvider != nil {
		licenseLimits = licenseProvider.GetLimits()
	}
	teamService := teamsvc.NewService(teamRepo, permRepo, teamsvc.Config{
		MaxTeams: licenseLimits.MaxTeams,
	}, app.Logger)
	if licenseProvider != nil {
		teamService.SetLimitProvider(licenseProvider)
	}

	app.Logger.Info("Team service initialized", "max_teams", licenseLimits.MaxTeams)

	// =========================================================================
	// SECURITY SERVICE INITIALIZATION
	// =========================================================================

	secScanRepo := postgres.NewSecurityScanRepository(app.DB, app.Logger)
	secIssueRepo := postgres.NewSecurityIssueRepository(app.DB, app.Logger)

	secCfg := securitysvc.DefaultServiceConfig()
	secCfg.ScannerConfig.IncludeCVE = app.Config.Trivy.Enabled

	securityService := securitysvc.NewService(
		secCfg,
		secScanRepo,
		secIssueRepo,
		app.Logger,
	)

	// Register all security analyzers including CIS Docker Benchmark
	securityService.SetAnalyzers([]securitysvc.Analyzer{
		securityanalyzer.NewPrivilegedAnalyzer(),
		securityanalyzer.NewUserAnalyzer(),
		securityanalyzer.NewCapabilitiesAnalyzer(),
		securityanalyzer.NewResourcesAnalyzer(),
		securityanalyzer.NewNetworkAnalyzer(),
		securityanalyzer.NewPortsAnalyzer(),
		securityanalyzer.NewMountsAnalyzer(),
		securityanalyzer.NewEnvAnalyzer(),
		securityanalyzer.NewHealthcheckAnalyzer(),
		securityanalyzer.NewRestartPolicyAnalyzer(),
		securityanalyzer.NewLoggingAnalyzer(),
		securityanalyzer.NewCISBenchmarkAnalyzer(),
	})

	// Initialize Trivy CVE scanner (optional - works if trivy binary is available)
	trivyCfg := trivypkg.DefaultClientConfig()
	if app.Config.Trivy.CacheDir != "" {
		trivyCfg.CacheDir = app.Config.Trivy.CacheDir
	}
	if app.Config.Trivy.Timeout > 0 {
		trivyCfg.Timeout = app.Config.Trivy.Timeout
	}
	if app.Config.Trivy.Severity != "" {
		trivyCfg.Severities = strings.Split(app.Config.Trivy.Severity, ",")
	}
	trivyCfg.IgnoreUnfixed = app.Config.Trivy.IgnoreUnfixed
	trivyClient := trivypkg.NewClient(trivyCfg, app.Logger)
	if app.Config.Trivy.Enabled && trivyClient.IsAvailable() {
		securityService.SetTrivyClient(trivyClient)
		// Update Trivy vulnerability database on startup if configured
		if app.Config.Trivy.UpdateDBOnStart {
			go func() {
				dbCtx, dbCancel := context.WithTimeout(ctx, 10*time.Minute)
				defer dbCancel()
				if err := trivyClient.UpdateDB(dbCtx); err != nil {
					app.Logger.Warn("Failed to update Trivy DB on startup", "error", err)
				} else {
					app.Logger.Info("Trivy vulnerability database updated")
				}
			}()
		}
		app.Logger.Info("Trivy CVE scanner enabled", "cve_scanning", true, "cache_dir", trivyCfg.CacheDir)
	} else if !app.Config.Trivy.Enabled {
		app.Logger.Info("Trivy CVE scanning disabled in config (trivy.enabled=false)")
	} else {
		app.Logger.Info("Trivy not available - CVE scanning disabled (install trivy to enable)")
	}

	app.Logger.Info("Security service initialized", "analyzers", 12)

	// =========================================================================
	// ENCRYPTOR (shared by Config, TOTP, NPM)
	// =========================================================================

	var encryptor *crypto.AESEncryptor
	{
		encKey := app.Config.Security.ConfigEncryptionKey
		if encKey == "" {
			// Derive a 32-byte hex key from JWT secret via SHA-256.
			// WARNING: changing jwt_secret will invalidate all encrypted data
			// (TOTP secrets, NPM credentials, config values). Set
			// USULNET_ENCRYPTION_KEY explicitly for independent key rotation.
			h := crypto.SHA256String(ic.jwtSecret)
			encKey = h[:64] // 64 hex chars = 32 bytes
			app.Logger.Warn("encryption_key not set — deriving from jwt_secret (set USULNET_ENCRYPTION_KEY for independent rotation)")
		}
		var encErr error
		encryptor, encErr = crypto.NewAESEncryptor(encKey)
		if encErr != nil {
			app.Logger.Warn("Failed to create encryptor, TOTP/NPM/ConfigService will be unavailable", "error", encErr)
		}
	}

	// =========================================================================
	// BACKUP SERVICE INITIALIZATION
	// =========================================================================

	var backupService *backupsvc.Service
	{
		// Backup storage backend (local filesystem)
		storagePath := app.Config.Storage.Path + "/backups"
		localStorage, storageErr := backupstorage.NewLocalStorage(storagePath)
		if storageErr != nil {
			app.Logger.Warn("Failed to initialize backup storage, backup service disabled", "error", storageErr, "path", storagePath)
		} else {
			backupRepo := postgres.NewBackupRepository(app.DB)

			// Providers bridge backup service to Docker operations
			volumeProvider := backupsvc.NewDockerVolumeProvider(ic.hostService, ic.volumeService)
			containerProvider := backupsvc.NewDockerContainerProvider(ic.hostService, ic.containerService)

			// Backup config from app config
			backupCfg := backupsvc.DefaultConfig()
			backupCfg.StoragePath = storagePath
			backupCfg.StorageType = app.Config.Storage.Type
			if app.Config.Storage.Backup.RetentionDays > 0 {
				backupCfg.DefaultRetentionDays = app.Config.Storage.Backup.RetentionDays
			}
			// Wire compression from config (default zstd / level 3)
			if comp := app.Config.Storage.Backup.Compression; comp != "" {
				backupCfg.DefaultCompression = models.BackupCompression(comp)
			}
			if app.Config.Storage.Backup.CompressionLevel > 0 {
				backupCfg.CompressionLevel = app.Config.Storage.Backup.CompressionLevel
			}

			// Stack provider bridges backup service to stack operations
			stackProvider := backupsvc.NewDockerStackProvider(ic.stackService, ic.containerService)

			var bkErr error
			backupService, bkErr = backupsvc.NewService(
				localStorage,
				backupRepo,
				volumeProvider,
				containerProvider,
				backupCfg,
				app.Logger,
				backupsvc.WithStackProviderOption(stackProvider),
			)
			if bkErr != nil {
				app.Logger.Error("Failed to create backup service", "error", bkErr)
				backupService = nil
			} else {
				app.backupService = backupService
				if licenseProvider != nil {
					backupService.SetLimitProvider(licenseProvider)
				}
				app.Logger.Info("Backup service initialized", "storage", storagePath)
			}
		}
	}

	// =========================================================================
	// CONFIG SERVICE INITIALIZATION
	// =========================================================================

	var configService *configsvc.Service
	var configSyncService *configsvc.SyncService
	if encryptor != nil {
		configVariableRepo := postgres.NewConfigVariableRepository(app.DB, app.Logger)
		configTemplateRepo := postgres.NewConfigTemplateRepository(app.DB, app.Logger)
		configAuditRepo := postgres.NewConfigAuditRepository(app.DB, app.Logger)
		configSyncRepo := postgres.NewConfigSyncRepository(app.DB, app.Logger)

		configService = configsvc.NewService(
			configVariableRepo,
			configTemplateRepo,
			configAuditRepo,
			configSyncRepo,
			encryptor,
			app.Logger,
		)

		configSyncService = configsvc.NewSyncService(
			configVariableRepo,
			configTemplateRepo,
			configSyncRepo,
			configAuditRepo,
			app.Logger,
		)

		app.Logger.Info("Config service initialized")
	} else {
		app.Logger.Warn("Config service disabled (encryptor not available)")
	}

	// =========================================================================
	// UPDATE SERVICE INITIALIZATION
	// =========================================================================

	updateRepo := postgres.NewUpdateRepository(app.DB.Pool())

	// Docker client adapter for update service (lazy resolution via host service)
	updateDockerAdapter := updatesvc.NewDockerClientAdapter(ic.hostService, ic.defaultHostID)

	// Version checker with in-memory cache
	versionCache := updatesvc.NewMemoryVersionCache()
	checker := updatesvc.NewChecker(nil, versionCache, app.Logger)

	// Register Docker Hub registry client
	dockerHubClient := updatesvc.NewDockerHubClient(nil, app.Logger)
	checker.RegisterClient(dockerHubClient)

	// GHCR registry client
	ghcrClient := updatesvc.NewGHCRClient(nil, app.Logger)
	checker.RegisterClient(ghcrClient)

	// Changelog fetcher with in-memory cache
	changelogCache := updatesvc.NewMemoryChangelogCache()
	changelogFetcher := updatesvc.NewChangelogFetcher(nil, changelogCache, app.Logger)

	// Bridge adapters for backup and security integration
	var updateBackup updatesvc.BackupService
	if backupService != nil {
		updateBackup = &updateBackupAdapter{svc: backupService, hostID: ic.defaultHostID}
	}
	updateSecurity := &updateSecurityAdapter{svc: securityService}

	updateService := updatesvc.NewService(
		updateRepo,
		checker,
		changelogFetcher,
		updateDockerAdapter,
		updateBackup,
		updateSecurity,
		ic.containerRepo,
		nil, // Use default config
		app.Logger,
	)

	app.Logger.Info("Update service initialized",
		"backup_enabled", backupService != nil,
		"security_enabled", true,
	)

	// =========================================================================
	// NOTIFICATION SERVICE INITIALIZATION
	// =========================================================================

	notificationRepo := postgres.NewNotificationRepository(app.DB)
	notificationService := notificationsvc.New(notificationRepo, notificationsvc.DefaultConfig())
	if licenseProvider != nil {
		notificationService.SetLimitProvider(licenseProvider)
	}

	if err := notificationService.Start(ctx); err != nil {
		app.Logger.Error("Failed to start notification service", "error", err)
	} else {
		app.notificationService = notificationService
		app.Logger.Info("Notification service initialized")
	}

	// Populate initContext
	ic.licenseProvider = licenseProvider
	ic.teamService = teamService
	ic.securityService = securityService
	ic.encryptor = encryptor
	ic.backupService = backupService
	ic.configService = configService
	ic.configSyncService = configSyncService
	ic.updateService = updateService
	ic.notificationService = notificationService

	return nil
}
