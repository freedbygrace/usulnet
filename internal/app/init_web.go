// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"path/filepath"
	"time"

	"github.com/fr4nsys/usulnet/internal/api/handlers"
	giteapkg "github.com/fr4nsys/usulnet/internal/integrations/gitea"
	"github.com/fr4nsys/usulnet/internal/integrations/npm"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/repository/redis"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
	authsvc "github.com/fr4nsys/usulnet/internal/services/auth"
	ldapauthsvc "github.com/fr4nsys/usulnet/internal/services/auth/ldap"
	oauthauthsvc "github.com/fr4nsys/usulnet/internal/services/auth/oauth"
	capturesvc "github.com/fr4nsys/usulnet/internal/services/capture"
	changessvc "github.com/fr4nsys/usulnet/internal/services/changes"
	compliancesvc "github.com/fr4nsys/usulnet/internal/services/compliance"
	costoptsvc "github.com/fr4nsys/usulnet/internal/services/costopt"
	dashboardsvc "github.com/fr4nsys/usulnet/internal/services/dashboard"
	databasesvc "github.com/fr4nsys/usulnet/internal/services/database"
	deploysvc "github.com/fr4nsys/usulnet/internal/services/deploy"
	driftsvc "github.com/fr4nsys/usulnet/internal/services/drift"
	ephemeralsvc "github.com/fr4nsys/usulnet/internal/services/ephemeral"
	gitsvc "github.com/fr4nsys/usulnet/internal/services/git"
	gitsyncsvc "github.com/fr4nsys/usulnet/internal/services/gitsync"
	imagesignsvc "github.com/fr4nsys/usulnet/internal/services/imagesign"
	ldapbrowsersvc "github.com/fr4nsys/usulnet/internal/services/ldapbrowser"
	logaggsvc "github.com/fr4nsys/usulnet/internal/services/logagg"
	manifestsvc "github.com/fr4nsys/usulnet/internal/services/manifest"
	metricssvc "github.com/fr4nsys/usulnet/internal/services/metrics"
	monitoringsvc "github.com/fr4nsys/usulnet/internal/services/monitoring"
	opasvc "github.com/fr4nsys/usulnet/internal/services/opa"
	proxysvc "github.com/fr4nsys/usulnet/internal/services/proxy"
	"github.com/fr4nsys/usulnet/internal/services/proxy/caddy"
	nginxbackend "github.com/fr4nsys/usulnet/internal/services/proxy/nginx"
	rdpsvc "github.com/fr4nsys/usulnet/internal/services/rdp"
	recordingsvc "github.com/fr4nsys/usulnet/internal/services/recording"
	runtimesvc "github.com/fr4nsys/usulnet/internal/services/runtime"
	shortcutssvc "github.com/fr4nsys/usulnet/internal/services/shortcuts"
	sshsvc "github.com/fr4nsys/usulnet/internal/services/ssh"
	storagesvc "github.com/fr4nsys/usulnet/internal/services/storage"
	swarmsvc "github.com/fr4nsys/usulnet/internal/services/swarm"
	"github.com/fr4nsys/usulnet/internal/web"
)

// initWeb initializes the web frontend: ServiceRegistry, HandlerDeps, all
// remaining services (proxy, storage, git, SSH, etc.), LDAP/OAuth provider
// wiring, late-bound scheduler workers, and route registration.
// Requires all prior init phases to have populated ic.
func (app *Application) initWeb(ctx context.Context, ic *initContext) error {
	// -------------------------------------------------------------------------
	// Build ServiceRegistry + Handler deps incrementally (constructor injection)
	// -------------------------------------------------------------------------

	// ServiceRegistry deps — core services
	regDeps := web.ServiceRegistryDeps{
		DefaultHostID:    ic.defaultHostID,
		AuthService:      ic.authService,
		UserRepository:   ic.userRepo,
		AuditLogRepo:     ic.auditLogRepo,
		HostService:      ic.hostService,
		ContainerService: ic.containerService,
		ImageService:     ic.imageService,
		VolumeService:    ic.volumeService,
		NetworkService:   ic.networkService,
		StackService:     ic.stackService,
		TeamService:      ic.teamService,
		SecurityService:  ic.securityService,
		UpdateService:    ic.updateService,
		BackupService:    ic.backupService,  // nil-safe
		ConfigService:    ic.configService,  // nil-safe
	}

	// Create session store (reused later for session repo adapter)
	var sessionStore web.SessionStore
	var webSessionStore *web.WebSessionStore
	var redisSessionStore *redis.SessionStore
	if app.Redis != nil {
		redisSessionStore = redis.NewSessionStore(app.Redis, ic.accessTTL)
		cookieCfg := web.CookieConfig{
			Secure:   app.Config.Security.CookieSecure,
			SameSite: parseSameSite(app.Config.Security.CookieSameSite),
			Domain:   app.Config.Security.CookieDomain,
		}
		webSessionStore = web.NewWebSessionStore(redisSessionStore, ic.accessTTL, cookieCfg)
		sessionStore = webSessionStore
		regDeps.SessionStore = webSessionStore
	} else {
		sessionStore = web.NewNullSessionStore()
	}

	// Handler deps — start with core fields, populated incrementally below
	hdlDeps := web.HandlerDeps{
		Version:         Version,
		Commit:          Commit,
		BuildTime:       BuildTime,
		Mode:            app.Config.Mode,
		SessionStore:    sessionStore,
		BaseURL:         app.Config.Server.BaseURL,
		TerminalEnabled: app.Config.Terminal.Enabled,
		TerminalUser:    app.Config.Terminal.User,
		TerminalShell:   app.Config.Terminal.Shell,
		GuacdEnabled:    app.Config.Guacd.Enabled,
		GuacdHost:       app.Config.Guacd.Host,
		GuacdPort:       app.Config.Guacd.Port,
		Logger:          app.Logger,
		DataDir:         app.Config.Storage.Path,
		RedisURL:        app.Config.Redis.URL,
		DBSSLMode:       app.Config.Database.SSLMode,
	}

	// Wire About page probes (nil-safe — handler checks before use)
	if app.DB != nil {
		hdlDeps.DB = app.DB
	}
	if app.Redis != nil {
		hdlDeps.RedisProber = app.Redis
	}
	if app.NATS != nil {
		hdlDeps.NATSProber = &natsProberAdapter{client: app.NATS}
	}

	if ic.licenseProvider != nil {
		hdlDeps.LicenseProvider = ic.licenseProvider
	}

	// TOTP and NPM use the encryptor created earlier
	if ic.encryptor != nil {
		regDeps.Encryptor = ic.encryptor
		hdlDeps.Encryptor = &encryptorAdapter{enc: ic.encryptor}
		hdlDeps.BackupEncryptor = ic.encryptor // *crypto.AESEncryptor satisfies BackupEncryptor directly

		// Derive a dedicated TOTP signing key from the JWT secret using HMAC-SHA256
		// with a fixed label. This avoids raw key reuse across unrelated crypto contexts.
		totpKeyMac := hmac.New(sha256.New, []byte(ic.jwtSecret))
		totpKeyMac.Write([]byte("usulnet:totp-pending-token"))
		hdlDeps.TOTPSigningKey = totpKeyMac.Sum(nil)

		// Wire TOTP validator into the auth service so the API login TOTP gate
		// can verify codes at runtime.
		var replayStore *redis.TOTPReplayStore
		if app.Redis != nil {
			replayStore = redis.NewTOTPReplayStore(app.Redis)
		}
		totpMaxAttempts := 5
		totpLockDuration := 15 * time.Minute
		if app.Config.Security.MaxFailedLogins > 0 {
			totpMaxAttempts = app.Config.Security.MaxFailedLogins
		}
		if app.Config.Security.LockoutDuration > 0 {
			totpLockDuration = app.Config.Security.LockoutDuration
		}
		ic.authService.SetTOTPValidator(&totpValidatorAdapter{
			repo:         ic.userRepo,
			encryptor:    ic.encryptor,
			replayStore:  replayStore,
			maxAttempts:  totpMaxAttempts,
			lockDuration: totpLockDuration,
		})

		// Also pass replay guard and lockout config to the web service registry
		// so the web TOTP flow also gets replay prevention + lockout.
		if replayStore != nil {
			regDeps.TOTPReplayGuard = replayStore
		}
		regDeps.TOTPMaxAttempts = totpMaxAttempts
		regDeps.TOTPLockDuration = totpLockDuration
		app.Logger.Info("TOTP 2FA support enabled (with replay prevention)")
	}

	// Setup NPM Integration (manual connection via Settings UI, gated by npm.enabled)
	if ic.encryptor != nil && app.Config.NPM.Enabled {
		npmConnRepo := postgres.NewNPMConnectionRepository(app.DB)
		npmMappingRepo := postgres.NewContainerProxyMappingRepository(app.DB)
		npmAuditRepo := postgres.NewNPMAuditLogRepository(app.DB)

		npmService := npm.NewService(
			npmConnRepo,
			npmMappingRepo,
			npmAuditRepo,
			ic.encryptor,
			app.Logger.Base(),
		)
		regDeps.NPMService = npmService
		app.Logger.Info("NPM integration available (connect via Settings)")
	}

	// Setup Reverse Proxy Service (nginx by default, Caddy as fallback)
	if ic.encryptor != nil && (app.Config.Nginx.Enabled || app.Config.Caddy.Enabled) {
		proxyHostRepo := postgres.NewProxyHostRepository(app.DB, app.Logger)
		proxyHeaderRepo := postgres.NewProxyHeaderRepository(app.DB)
		proxyCertRepo := postgres.NewProxyCertificateRepository(app.DB, app.Logger)
		proxyDNSRepo := postgres.NewProxyDNSProviderRepository(app.DB, app.Logger)
		proxyAuditRepo := postgres.NewProxyAuditLogRepository(app.DB)

		var backend proxysvc.SyncBackend
		var proxyCfg proxysvc.Config

		if app.Config.Nginx.Enabled {
			// nginx backend (default/recommended)
			nginxCfg := nginxbackend.Config{
				ConfigDir:      app.Config.Nginx.ConfigDir,
				CertDir:        app.Config.Nginx.CertDir,
				ACMEWebRoot:    app.Config.Nginx.ACMEWebRoot,
				ACMEAccountDir: app.Config.Nginx.ACMEAccountDir,
			}
			if nginxCfg.ConfigDir == "" {
				nginxCfg.ConfigDir = "/etc/nginx/conf.d/usulnet"
			}
			if nginxCfg.CertDir == "" {
				nginxCfg.CertDir = "/etc/usulnet/certs"
			}
			if nginxCfg.ACMEWebRoot == "" {
				nginxCfg.ACMEWebRoot = "/var/lib/usulnet/acme"
			}
			if nginxCfg.ACMEAccountDir == "" {
				nginxCfg.ACMEAccountDir = "/var/lib/usulnet/acme/account"
			}
			backend = nginxbackend.NewBackend(nginxCfg)
			proxyCfg = proxysvc.Config{
				ACMEEmail:     app.Config.Nginx.ACMEEmail,
				ListenHTTP:    app.Config.Nginx.ListenHTTP,
				ListenHTTPS:   app.Config.Nginx.ListenHTTPS,
				DefaultHostID: ic.defaultHostID,
			}
			app.Logger.Info("Reverse proxy service: nginx backend")
		} else {
			// Caddy backend (legacy)
			caddyClient := caddy.NewClient(caddy.Config{
				AdminURL: app.Config.Caddy.AdminURL,
				Timeout:  10 * time.Second,
			})
			backend = proxysvc.NewCaddyBackend(caddyClient)
			proxyCfg = proxysvc.Config{
				CaddyAdminURL: app.Config.Caddy.AdminURL,
				ACMEEmail:     app.Config.Caddy.ACMEEmail,
				ListenHTTP:    app.Config.Caddy.ListenHTTP,
				ListenHTTPS:   app.Config.Caddy.ListenHTTPS,
				DefaultHostID: ic.defaultHostID,
			}
			app.Logger.Info("Reverse proxy service: Caddy backend")
		}

		proxyService := proxysvc.NewService(
			proxyHostRepo,
			proxyHeaderRepo,
			proxyCertRepo,
			proxyDNSRepo,
			proxyAuditRepo,
			ic.encryptor,
			backend,
			proxyCfg,
			app.Logger,
		)
		regDeps.ProxyService = proxyService
	}

	// Setup Storage Service (S3, Azure, GCS, B2, SFTP, Local — requires encryption key)
	if ic.encryptor != nil {
		storageConnRepo := postgres.NewStorageConnectionRepository(app.DB, app.Logger)
		storageBucketRepo := postgres.NewStorageBucketRepository(app.DB, app.Logger)
		storageAuditRepo := postgres.NewStorageAuditLogRepository(app.DB, app.Logger)

		storageCfg := storagesvc.Config{
			DefaultHostID: ic.defaultHostID,
		}

		storageService := storagesvc.NewService(
			storageConnRepo,
			storageBucketRepo,
			storageAuditRepo,
			ic.encryptor,
			storageCfg,
			app.Logger,
		)
		regDeps.StorageService = storageService
		if ic.licenseProvider != nil {
			storageService.SetLimitProvider(ic.licenseProvider)
		}
		app.Logger.Info("Storage service available (S3, Azure, GCS, B2, SFTP, Local)")
	}

	// Setup Gitea Integration
	if ic.encryptor != nil {
		giteaConnRepo := postgres.NewGiteaConnectionRepository(app.DB)
		giteaRepoRepo := postgres.NewGiteaRepositoryRepository(app.DB)
		giteaWebhookRepo := postgres.NewGiteaWebhookRepository(app.DB)

		giteaService := giteapkg.NewService(
			giteaConnRepo,
			giteaRepoRepo,
			giteaWebhookRepo,
			ic.encryptor,
			app.Logger,
		)
		regDeps.GiteaService = giteaService
		app.Logger.Info("Gitea integration service enabled")

		// Setup unified Git service (multi-provider: Gitea, GitHub, GitLab)
		gitConnRepo := postgres.NewGitConnectionRepository(app.DB)
		gitRepoRepo := postgres.NewGitRepositoryRepository(app.DB)

		gitService := gitsvc.NewService(
			gitConnRepo,
			gitRepoRepo,
			ic.encryptor,
			app.Logger,
		)
		regDeps.GitService = gitService
		hdlDeps.GitSvcFull = gitService
		if ic.licenseProvider != nil {
			gitService.SetLimitProvider(ic.licenseProvider)
		}
		app.Logger.Info("Unified Git service enabled (Gitea, GitHub, GitLab)")
	}

	// Setup SSH Service
	if ic.encryptor != nil {
		sshKeyRepo := postgres.NewSSHKeyRepository(app.DB, app.Logger)
		sshConnRepo := postgres.NewSSHConnectionRepository(app.DB, app.Logger)
		sshSessionRepo := postgres.NewSSHSessionRepository(app.DB, app.Logger)
		sshTunnelRepo := postgres.NewSSHTunnelRepository(app.DB, app.Logger)

		sshService := sshsvc.NewService(
			sshKeyRepo,
			sshConnRepo,
			sshSessionRepo,
			ic.encryptor,
			app.Logger,
		)
		sshService.SetTunnelRepo(sshTunnelRepo)
		regDeps.SSHService = sshService
		hdlDeps.SSHService = sshService

		apiHandlers := app.Server.Handlers()
		apiHandlers.SSH = handlers.NewSSHHandler(sshService, app.Logger)
		app.Logger.Info("SSH service enabled with tunnel support")
	}

	// Setup Agent Deploy Service (requires PKI for TLS cert generation)
	{
		deploySvc := deploysvc.NewService(app.pkiManager, app.Logger)
		hdlDeps.DeployService = deploySvc
		app.Logger.Info("Agent deploy service enabled",
			"pki_available", app.pkiManager != nil,
		)
	}

	// Setup Shortcuts Service
	{
		shortcutRepo := postgres.NewWebShortcutRepository(app.DB, app.Logger)
		categoryRepo := postgres.NewShortcutCategoryRepository(app.DB, app.Logger)

		shortcutsService := shortcutssvc.NewService(
			shortcutRepo,
			categoryRepo,
			app.Logger,
		)
		hdlDeps.ShortcutsService = shortcutsService
		app.Logger.Info("Shortcuts service enabled")
	}

	// Setup Database Connections Service
	if ic.encryptor != nil {
		dbConnRepo := postgres.NewDatabaseConnectionRepository(app.DB, app.Logger)
		databaseService := databasesvc.NewService(
			dbConnRepo,
			ic.encryptor,
			app.Logger,
		)
		hdlDeps.DatabaseService = databaseService
		app.Logger.Info("Database connections service enabled")

		// LDAP Browser Service
		ldapBrowserRepo := postgres.NewLDAPBrowserRepository(app.DB, app.Logger)
		ldapBrowserService := ldapbrowsersvc.NewService(
			ldapBrowserRepo,
			ic.encryptor,
			app.Logger,
		)
		hdlDeps.LDAPBrowserService = ldapBrowserService
		app.Logger.Info("LDAP browser service enabled")

		// RDP Connection Service
		rdpConnRepo := postgres.NewRDPConnectionRepository(app.DB, app.Logger)
		rdpService := rdpsvc.NewService(rdpConnRepo, ic.encryptor, app.Logger)
		hdlDeps.RDPService = rdpService
		app.Logger.Info("RDP connections service enabled")
	}

	// Setup Packet Capture Service
	{
		captureRepo := postgres.NewCaptureRepository(app.DB, app.Logger)
		app.captureService = capturesvc.NewService(captureRepo, filepath.Join(app.Config.Storage.Path, "captures"), app.Logger)
		hdlDeps.CaptureService = app.captureService
		app.Logger.Info("Packet capture service enabled")
	}

	// Swarm service - wraps Docker Swarm operations with business logic
	swarmService := swarmsvc.NewService(ic.hostService, app.Logger)
	hdlDeps.SwarmService = swarmService
	app.Logger.Info("Swarm service enabled")

	// Notification config repository for web handler
	notificationConfigRepo := postgres.NewNotificationConfigRepository(app.DB)
	hdlDeps.NotificationConfigRepo = notificationConfigRepo
	if ic.notificationService != nil {
		hdlDeps.NotificationSvc = &runbookNotificationAdapter{svc: ic.notificationService}
	}
	app.Logger.Info("Notification config repository enabled")

	// Inject repositories for admin pages (roles, oauth, ldap)
	roleRepo := postgres.NewRoleRepository(app.DB, app.Logger)
	hdlDeps.RoleRepo = roleRepo
	app.Logger.Info("Role repository enabled for web handler")

	oauthConfigRepo := postgres.NewOAuthConfigRepository(app.DB, app.Logger)
	hdlDeps.OAuthConfigRepo = oauthConfigRepo
	app.Logger.Info("OAuth config repository enabled for web handler")

	ldapConfigRepo := postgres.NewLDAPConfigRepository(app.DB, app.Logger)
	hdlDeps.LDAPConfigRepo = ldapConfigRepo
	app.Logger.Info("LDAP config repository enabled for web handler")

	// =========================================================================
	// WIRE LDAP AUTH PROVIDERS INTO AUTH SERVICE
	// Load enabled LDAP configs from DB, build auth providers, and register
	// them with the auth service so that LDAP users can actually log in.
	// =========================================================================
	if ic.encryptor != nil {
		ldapConfigs, ldapErr := ldapConfigRepo.ListEnabled(ctx)
		if ldapErr != nil {
			app.Logger.Warn("Failed to load enabled LDAP configs", "error", ldapErr)
		} else {
			for _, cfg := range ldapConfigs {
				client := ldapauthsvc.ProviderFromModel(cfg, ic.encryptor, app.Logger)
				ic.authService.RegisterLDAPProvider(authsvc.NewLDAPClientAdapter(client))
				app.Logger.Info("LDAP auth provider registered",
					"name", cfg.Name,
					"host", cfg.Host,
				)
			}
			if len(ldapConfigs) > 0 {
				app.Logger.Info("LDAP authentication enabled",
					"providers", len(ldapConfigs),
				)
			}
		}
	}

	// =========================================================================
	// WIRE OAUTH PROVIDERS INTO AUTH SERVICE
	// Load enabled OAuth configs from DB, build providers, and register
	// them with the auth service for OAuth/OIDC login flows.
	// =========================================================================
	{
		oauthConfigs, oauthErr := oauthConfigRepo.ListEnabled(ctx)
		if oauthErr != nil {
			app.Logger.Warn("Failed to load enabled OAuth configs", "error", oauthErr)
		} else {
			for _, cfg := range oauthConfigs {
				oauthCfg := oauthauthsvc.Config{
					Name:          cfg.Name,
					Type:          oauthauthsvc.ProviderType(cfg.Provider),
					ClientID:      cfg.ClientID,
					ClientSecret:  cfg.ClientSecret,
					AuthURL:       cfg.AuthURL,
					TokenURL:      cfg.TokenURL,
					UserInfoURL:   cfg.UserInfoURL,
					Scopes:        cfg.Scopes,
					RedirectURL:   cfg.RedirectURL,
					UserIDClaim:   cfg.UserIDClaim,
					UsernameClaim: cfg.UsernameClaim,
					EmailClaim:    cfg.EmailClaim,
					GroupsClaim:   cfg.GroupsClaim,
					AdminGroup:    cfg.AdminGroup,
					OperatorGroup: cfg.OperatorGroup,
					DefaultRole:   cfg.DefaultRole,
					AutoProvision: cfg.AutoProvision,
					Enabled:       cfg.IsEnabled,
				}

				var rawProvider authsvc.OAuthProvider
				var provErr error

				switch oauthauthsvc.ProviderType(cfg.Provider) {
				case oauthauthsvc.ProviderTypeOIDC, oauthauthsvc.ProviderTypeGoogle, oauthauthsvc.ProviderTypeMicrosoft:
					p, err := oauthauthsvc.NewOIDCProvider(ctx, oauthCfg, app.Logger)
					if err == nil {
						rawProvider = authsvc.NewOAuthProviderAdapter(p)
					}
					provErr = err
				default:
					p, err := oauthauthsvc.NewGenericProvider(oauthCfg, app.Logger)
					if err == nil {
						rawProvider = authsvc.NewOAuthProviderAdapter(p)
					}
					provErr = err
				}

				if provErr != nil {
					app.Logger.Warn("Failed to create OAuth provider",
						"name", cfg.Name,
						"provider", cfg.Provider,
						"error", provErr,
					)
					continue
				}

				ic.authService.RegisterOAuthProvider(cfg.Name, rawProvider)
				app.Logger.Info("OAuth auth provider registered",
					"name", cfg.Name,
					"provider", cfg.Provider,
				)
			}
			if len(oauthConfigs) > 0 {
				app.Logger.Info("OAuth authentication enabled",
					"providers", len(oauthConfigs),
				)
			}
		}
	}

	snippetRepo := postgres.NewSnippetRepository(app.DB)
	hdlDeps.SnippetRepo = snippetRepo
	app.Logger.Info("Snippet repository enabled for web handler")

	// Custom log upload repository
	customLogUploadRepo := postgres.NewCustomLogUploadRepository(app.DB, app.Logger)
	hdlDeps.CustomLogUploadRepo = customLogUploadRepo
	app.Logger.Info("Custom log upload repository enabled for web handler")

	// Preferences repository
	prefsRepo := postgres.NewPreferencesRepo(app.DB.Pool())
	hdlDeps.PrefsRepo = prefsRepo
	app.Logger.Info("Preferences repository enabled for web handler")

	// H1: User repository adapter for profile update/password change
	hdlDeps.UserRepo = &webUserRepoAdapter{repo: ic.userRepo}
	app.Logger.Info("User repository adapter enabled for web handler")

	// H2: Session repository adapter for profile active sessions list
	if redisSessionStore != nil {
		hdlDeps.SessionRepo = &webSessionRepoAdapter{redisStore: redisSessionStore}
		app.Logger.Info("Session repository adapter enabled for web handler")
	}

	// H3: Terminal session repository for terminal history API
	terminalSessionRepo := postgres.NewTerminalSessionRepository(app.DB, app.Logger)
	hdlDeps.TerminalSessionRepo = &webTerminalSessionRepoAdapter{repo: terminalSessionRepo}
	app.Logger.Info("Terminal session repository enabled for web handler")

	// Session recording service (Phase 7.2)
	sessionRecordingRepo := postgres.NewSessionRecordingRepository(app.DB, app.Logger)
	recordingSvc := recordingsvc.NewService(filepath.Join(app.Config.Storage.Path, "recordings"), sessionRecordingRepo, app.Logger)
	hdlDeps.RecordingSvc = recordingSvc
	app.Logger.Info("Session recording service enabled")

	// Registry, Webhook, Runbook, AutoDeploy repositories (reuse shared instances)
	hdlDeps.RegistryRepo = ic.registryRepo
	hdlDeps.RegistryBrowseSvc = ic.registryBrowseSvc

	webhookRepo := postgres.NewOutgoingWebhookRepository(app.DB)
	hdlDeps.WebhookRepo = webhookRepo
	app.Logger.Info("Outgoing webhook repository enabled for web handler")

	runbookRepo := postgres.NewRunbookRepository(app.DB)
	hdlDeps.RunbookRepo = runbookRepo
	app.Logger.Info("Runbook repository enabled for web handler")

	autoDeployRepo := postgres.NewAutoDeployRuleRepository(app.DB)
	hdlDeps.AutoDeployRepo = autoDeployRepo
	app.Logger.Info("Auto-deploy rule repository enabled for web handler")

	// Persistent feature repositories (compliance, secrets, lifecycle, maintenance, gitops, quotas, templates, vulns)
	complianceRepo := postgres.NewComplianceRepository(app.DB)
	hdlDeps.ComplianceRepo = complianceRepo
	app.Logger.Info("Compliance repository enabled for web handler")

	managedSecretRepo := postgres.NewManagedSecretRepository(app.DB)
	hdlDeps.ManagedSecretRepo = managedSecretRepo
	app.Logger.Info("Managed secret repository enabled for web handler")

	lifecycleRepo := postgres.NewLifecycleRepository(app.DB)
	hdlDeps.LifecycleRepo = lifecycleRepo
	app.Logger.Info("Lifecycle repository enabled for web handler")

	maintenanceRepo := postgres.NewMaintenanceRepository(app.DB)
	hdlDeps.MaintenanceRepo = maintenanceRepo
	app.Logger.Info("Maintenance repository enabled for web handler")

	gitOpsRepo := postgres.NewGitOpsRepository(app.DB)
	hdlDeps.GitOpsRepo = gitOpsRepo
	app.Logger.Info("GitOps repository enabled for web handler")

	resourceQuotaRepo := postgres.NewResourceQuotaRepository(app.DB)
	hdlDeps.ResourceQuotaRepo = resourceQuotaRepo
	app.Logger.Info("Resource quota repository enabled for web handler")

	containerTemplateRepo := postgres.NewContainerTemplateRepository(app.DB)
	hdlDeps.ContainerTemplateRepo = containerTemplateRepo
	app.Logger.Info("Container template repository enabled for web handler")

	trackedVulnRepo := postgres.NewTrackedVulnerabilityRepository(app.DB)
	hdlDeps.TrackedVulnRepo = trackedVulnRepo
	app.Logger.Info("Tracked vulnerability repository enabled for web handler")

	// Late-bind workers that depend on repos created after scheduler startup
	if ic.scheduler != nil {
		// Register webhook dispatch, runbook execute, and auto-deploy workers
		ic.scheduler.Registry().Register(workers.NewWebhookDispatchWorker(webhookRepo, app.Logger))
		ic.scheduler.Registry().Register(workers.NewRunbookExecuteWorker(runbookRepo, nil, hdlDeps.NotificationSvc, app.Logger))
		ic.scheduler.Registry().Register(workers.NewAutoDeployWorker(autoDeployRepo, nil, app.Logger))
		ic.scheduler.Registry().Register(workers.NewSLABreachWorker(trackedVulnRepo, nil, app.Logger))
		app.Logger.Info("Late-bound workers registered (webhook_dispatch, runbook_execute, auto_deploy, sla_breach)")

		// Wire job enqueuer to webhook dispatcher for async delivery
		webhookDispatcher := postgres.NewWebhookDispatcher(webhookRepo)
		webhookDispatcher.SetJobEnqueuer(ic.scheduler)
		app.Logger.Info("Webhook dispatcher wired with job enqueuer")
	}

	// Wire auto-deploy deps to Gitea service (if available)
	if regDeps.GiteaService != nil && ic.scheduler != nil {
		regDeps.GiteaService.SetAutoDeployDeps(autoDeployRepo, ic.scheduler)
		app.Logger.Info("Auto-deploy deps wired to Gitea service")
	}

	// Change Management Audit Trail (Phase 3 Enterprise)
	changeEventRepo := postgres.NewChangeEventRepository(app.DB, app.Logger)
	changesSvc := changessvc.NewService(changeEventRepo, app.Logger)
	hdlDeps.ChangesSvc = changesSvc
	app.Logger.Info("Change management audit trail enabled")

	// Drift Detection (Phase 4 Enterprise)
	driftRepo := postgres.NewDriftRepository(app.DB, app.Logger)
	driftSvc := driftsvc.NewService(driftRepo, app.Logger)
	hdlDeps.DriftSvc = driftSvc
	app.Logger.Info("Drift detection enabled")

	// Cost/Resource Optimization (Phase 5 Enterprise)
	resourceOptRepo := postgres.NewResourceOptRepository(app.DB, app.Logger)
	costOptSvc := costoptsvc.NewService(resourceOptRepo, app.Logger)
	hdlDeps.CostOptSvc = costOptSvc
	app.Logger.Info("Cost/resource optimization enabled")

	// H4: Docker client for events page
	if ic.dockerClient != nil {
		regDeps.DockerClient = ic.dockerClient
		app.Logger.Info("Docker events enabled for events page")
	}

	// Metrics service
	metricsRepo := postgres.NewMetricsRepository(app.DB, app.Logger)
	metricsCollector := metricssvc.NewCollector(ic.hostService, app.Logger)
	metricsService := metricssvc.NewService(metricsRepo, metricsCollector, app.Logger)
	regDeps.MetricsService = metricsService
	ic.schedulerDeps.MetricsService = metricsService
	// Register metrics worker now that the service is available
	// (it was nil at initial RegisterDefaultWorkers time)
	if ic.scheduler != nil {
		ic.scheduler.Registry().Register(workers.NewMetricsCollectionWorker(metricsService, app.Logger))
	}
	app.Logger.Info("Metrics service enabled")

	// Alert monitoring service — wire MetricsProvider and NotificationSender adapters
	alertRepo := postgres.NewAlertRepository(app.DB)
	var alertMetrics monitoringsvc.MetricsProvider
	if metricsService != nil {
		alertMetrics = &alertMetricsProviderAdapter{
			metrics: metricsService,
			hostID:  ic.defaultHostID,
		}
	}
	var alertNotifier monitoringsvc.NotificationSender
	if ic.notificationService != nil {
		alertNotifier = &alertNotificationSenderAdapter{svc: ic.notificationService}
	}
	alertSvc := monitoringsvc.NewAlertService(
		alertRepo,
		alertMetrics,
		alertNotifier,
		monitoringsvc.DefaultAlertConfig(),
		app.Logger,
	)
	regDeps.AlertService = alertSvc
	if err := alertSvc.Start(ctx); err != nil {
		app.Logger.Error("Failed to start alert service", "error", err)
	} else {
		app.Logger.Info("Alert monitoring service started",
			"metrics_provider", alertMetrics != nil,
			"notification_sender", alertNotifier != nil,
		)
	}

	// =========================================================================
	// Enterprise Phase 2: Compliance, OPA, Log Aggregation, Image Signing, Runtime Security
	// =========================================================================

	// Log aggregation service
	logRepo := postgres.NewLogRepository(app.DB, app.Logger)
	logAggService := logaggsvc.NewService(logRepo, ic.hostService, logaggsvc.DefaultConfig(), app.Logger)
	hdlDeps.LogAggSvc = logAggService
	app.Logger.Info("Log aggregation service enabled")

	// Compliance framework service
	complianceFrameworkRepo := postgres.NewComplianceFrameworkRepository(app.DB)
	var complianceDocker compliancesvc.DockerInspector
	if ic.dockerClient != nil {
		complianceDocker = &complianceDockerAdapter{client: ic.dockerClient}
	}
	complianceService := compliancesvc.NewService(complianceFrameworkRepo, complianceDocker, app.Logger)
	hdlDeps.ComplianceFrameworkSvc = complianceService
	app.Logger.Info("Compliance framework service enabled")

	// OPA policy engine service
	opaRepo := postgres.NewOPARepository(app.DB)
	opaService := opasvc.NewService(opaRepo, opasvc.DefaultConfig(), app.Logger)
	hdlDeps.OPASvc = opaService
	app.Logger.Info("OPA policy engine service enabled")

	// Image signing service
	imageSignRepo := postgres.NewImageSigningRepository(app.DB)
	imageSignService := imagesignsvc.NewService(imageSignRepo, imagesignsvc.DefaultConfig(), app.Logger)
	hdlDeps.ImageSignSvc = imageSignService
	app.Logger.Info("Image signing service enabled")

	// Runtime security service
	runtimeSecRepo := postgres.NewRuntimeSecurityRepository(app.DB, app.Logger)
	runtimeSecService := runtimesvc.NewService(runtimeSecRepo, ic.hostService, runtimesvc.DefaultConfig(), app.Logger)
	hdlDeps.RuntimeSecSvc = runtimeSecService
	app.Logger.Info("Runtime security service enabled")

	// =========================================================================
	// Phase 3: Market Expansion - GitOps
	// =========================================================================

	// Bidirectional Git sync service
	gitSyncRepo := postgres.NewGitSyncRepository(app.DB, app.Logger)
	gitSyncService := gitsyncsvc.NewService(gitSyncRepo, gitsyncsvc.DefaultConfig(), app.Logger)
	hdlDeps.GitSyncSvc = gitSyncService
	app.Logger.Info("Git sync service enabled")

	// Ephemeral environments service
	ephemeralRepo := postgres.NewEphemeralEnvironmentRepository(app.DB, app.Logger)
	ephemeralCfg := ephemeralsvc.DefaultConfig()
	if app.Config.Server.BaseURL != "" {
		ephemeralCfg.BaseURL = app.Config.Server.BaseURL
	}
	ephemeralService := ephemeralsvc.NewService(ephemeralRepo, ephemeralCfg, app.Logger)
	hdlDeps.EphemeralSvc = ephemeralService
	app.Logger.Info("Ephemeral environments service enabled")

	// Manifest builder service
	manifestRepo := postgres.NewManifestBuilderRepository(app.DB, app.Logger)
	manifestService := manifestsvc.NewService(manifestRepo, manifestsvc.DefaultConfig(), app.Logger)
	hdlDeps.ManifestSvc = manifestService
	app.Logger.Info("Manifest builder service enabled")

	// =========================================================================
	// Phase 4: Custom Dashboards
	// =========================================================================

	dashboardRepo := postgres.NewDashboardRepository(app.DB)
	dashboardService := dashboardsvc.NewService(dashboardRepo, app.Logger)
	hdlDeps.DashboardSvc = dashboardService
	app.Logger.Info("Dashboard layout service enabled")

	// Set scheduler service in registry deps
	if ic.scheduler != nil {
		regDeps.SchedulerService = ic.scheduler
	}

	// -------------------------------------------------------------------------
	// Construct ServiceRegistry + Handler (all deps collected above)
	// -------------------------------------------------------------------------
	serviceRegistry := web.NewServiceRegistry(regDeps)
	hdlDeps.Services = serviceRegistry
	webHandler := web.NewTemplHandler(hdlDeps)

	// Create middleware
	webMiddleware := web.NewMiddleware(
		sessionStore,
		serviceRegistry.Auth(),
		serviceRegistry.Stats(),
		web.MiddlewareConfig{
			SessionName: web.CookieSession,
			LoginPath:   "/login",
			ExcludePaths: []string{
				"/static/",
				"/favicon.ico",
				"/health",
			},
		},
	)

	// Register web routes (all Templ handlers)
	webMiddleware.SetScopeProvider(ic.teamService)
	webMiddleware.SetRoleProvider(&roleProviderAdapter{repo: roleRepo})
	web.RegisterFrontendRoutes(app.Server.Router(), webHandler, webMiddleware)

	app.Logger.Info("Web frontend initialized",
		"engine", "templ",
		"mode", app.Config.Mode,
	)

	return nil
}
