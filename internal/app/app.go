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
	"os/signal"
	"strings"
	"syscall"

	agentpkg "github.com/fr4nsys/usulnet/internal/agent"
	"github.com/fr4nsys/usulnet/internal/api"
	dockerpkg "github.com/fr4nsys/usulnet/internal/docker"
	"github.com/fr4nsys/usulnet/internal/gateway"
	licensepkg "github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/nats"
	"github.com/fr4nsys/usulnet/internal/observability"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/repository/redis"
	"github.com/fr4nsys/usulnet/internal/scheduler"
	backupsvc "github.com/fr4nsys/usulnet/internal/services/backup"
	capturesvc "github.com/fr4nsys/usulnet/internal/services/capture"
	containersvc "github.com/fr4nsys/usulnet/internal/services/container"
	hostsvc "github.com/fr4nsys/usulnet/internal/services/host"
	notificationsvc "github.com/fr4nsys/usulnet/internal/services/notification"
)

// Application holds all application dependencies
type Application struct {
	Config *Config
	Logger *logger.Logger
	DB     *postgres.DB
	Redis  *redis.Client
	NATS   *nats.Client
	Server *api.Server

	// Services requiring graceful shutdown
	backupService       *backupsvc.Service
	notificationService *notificationsvc.Service
	schedulerService    *scheduler.Scheduler

	// License provider (background goroutine)
	licenseProvider *licensepkg.Provider

	// Multi-host components
	gatewayServer *gateway.Server
	agentInstance *agentpkg.Agent
	hostService   *hostsvc.Service

	// Shared repositories (created once, reused across modes)
	hostRepo *postgres.HostRepository

	// PKI
	pkiManager *crypto.PKIManager

	// Packet capture (requires cleanup on shutdown)
	captureService *capturesvc.Service

	// Container service
	containerService *containersvc.Service

	// OpenTelemetry provider (requires flush on shutdown)
	otelProvider *observability.Provider
}

// Run starts the application with the given configuration
func Run(cfgFile, mode string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Load configuration
	cfg, err := LoadConfig(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	// Override mode if provided via CLI
	if mode != "" {
		cfg.Mode = mode
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}

	// Configure Docker socket path: use explicit config, or auto-detect
	if cfg.Docker.Socket != "" {
		dockerpkg.SetLocalSocketPath(cfg.Docker.Socket)
	} else {
		detected := dockerpkg.DetectSocketPath()
		dockerpkg.SetLocalSocketPath(detected)
	}

	// Initialize logger (supports stdout, stderr, and file with rotation)
	log, err := logger.NewFromConfig(cfg.Logging.Level, cfg.Logging.Format, logger.OutputConfig{
		Output: cfg.Logging.Output,
		File: logger.FileConfig{
			Path:       cfg.Logging.File.Path,
			MaxSize:    parseSize(cfg.Logging.File.MaxSize, 100*1024*1024),
			MaxBackups: cfg.Logging.File.MaxBackups,
			MaxAge:     cfg.Logging.File.MaxAge,
			Compress:   cfg.Logging.File.Compress,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}
	defer log.Sync()

	log.Info("Starting usulnet",
		"version", Version,
		"commit", Commit,
		"mode", cfg.Mode,
	)

	log.Info(dockerpkg.FormatDetectedSocket(dockerpkg.LocalSocketPath()),
		"socket", dockerpkg.LocalSocketPath(),
		"configured", cfg.Docker.Socket != "",
	)

	// Initialize OpenTelemetry (tracing + metrics middleware)
	otelCfg := observability.Config{
		Enabled:        cfg.Observability.Tracing.Enabled,
		ServiceName:    "usulnet",
		ServiceVersion: Version,
		Endpoint:       cfg.Observability.Tracing.Endpoint,
		Insecure:       cfg.Observability.Tracing.Insecure,
		SampleRatio:    cfg.Observability.Tracing.SamplingRate,
	}
	otelProvider, otelErr := observability.NewProvider(otelCfg)
	if otelErr != nil {
		log.Warn("Failed to initialize OpenTelemetry, continuing without tracing", "error", otelErr)
	} else if cfg.Observability.Tracing.Enabled {
		log.Info("OpenTelemetry tracing enabled",
			"endpoint", cfg.Observability.Tracing.Endpoint,
			"sampling_rate", cfg.Observability.Tracing.SamplingRate,
		)
	}

	// Initialize PostgreSQL
	dbURL := cfg.Database.URL
	// Enforce SSL mode from config if the URL doesn't already specify one
	if cfg.Database.SSLMode != "" && !strings.Contains(dbURL, "sslmode=") {
		sep := "?"
		if strings.Contains(dbURL, "?") {
			sep = "&"
		}
		dbURL += sep + "sslmode=" + cfg.Database.SSLMode
	}
	// Append SSL certificate paths if configured and not already in the URL
	if cfg.Database.SSLRootCert != "" && !strings.Contains(dbURL, "sslrootcert=") {
		dbURL += "&sslrootcert=" + cfg.Database.SSLRootCert
	}
	if cfg.Database.SSLCert != "" && !strings.Contains(dbURL, "sslcert=") {
		dbURL += "&sslcert=" + cfg.Database.SSLCert
	}
	if cfg.Database.SSLKey != "" && !strings.Contains(dbURL, "sslkey=") {
		dbURL += "&sslkey=" + cfg.Database.SSLKey
	}
	// Log the effective sslmode (from URL or config fallback)
	effectiveSSLMode := cfg.Database.SSLMode
	if idx := strings.Index(dbURL, "sslmode="); idx >= 0 {
		end := strings.IndexByte(dbURL[idx+8:], '&')
		if end < 0 {
			effectiveSSLMode = dbURL[idx+8:]
		} else {
			effectiveSSLMode = dbURL[idx+8 : idx+8+end]
		}
	}
	log.Info("Connecting to PostgreSQL...", "sslmode", effectiveSSLMode)
	db, err := postgres.New(ctx, dbURL, postgres.Options{
		MaxOpenConns:    cfg.Database.MaxOpenConns,
		MaxIdleConns:    cfg.Database.MaxIdleConns,
		ConnMaxLifetime: cfg.Database.ConnMaxLifetime,
		ConnMaxIdleTime: cfg.Database.ConnMaxIdleTime,
		QueryTimeout:    cfg.Database.QueryTimeout,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to PostgreSQL: %w", err)
	}
	defer db.Close()
	log.Info("PostgreSQL connected")

	// Run migrations
	log.Info("Running database migrations...")
	if err := db.Migrate(ctx); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}
	log.Info("Migrations completed")

	// =========================================================================
	// PKI INITIALIZATION (before Redis/NATS, so certs are available for TLS)
	// =========================================================================

	var pkiMgr *crypto.PKIManager
	if cfg.Server.TLS.Enabled && cfg.Mode != "agent" {
		pkiDataDir := cfg.Server.TLS.DataDir
		if pkiDataDir == "" {
			pkiDataDir = cfg.Storage.Path + "/pki"
		}

		pkiMgr, err = crypto.NewPKIManager(pkiDataDir)
		if err != nil {
			return fmt.Errorf("failed to initialize PKI: %w", err)
		}
		log.Info("PKI initialized", "data_dir", pkiDataDir)

		// Auto-generate NATS server cert (for the NATS service to use)
		natsCertPath, natsKeyPath, natsErr := pkiMgr.EnsureNATSServerCert("nats", "localhost")
		if natsErr != nil {
			return fmt.Errorf("failed to ensure NATS server cert: %w", natsErr)
		}
		log.Info("NATS server certificate ready",
			"cert", natsCertPath,
			"key", natsKeyPath,
			"ca", pkiMgr.CACertPath(),
		)

		// Auto-generate PostgreSQL server cert
		pgCertPath, pgKeyPath, pgErr := pkiMgr.EnsurePostgresServerCert("postgres", "localhost")
		if pgErr != nil {
			return fmt.Errorf("failed to ensure PostgreSQL server cert: %w", pgErr)
		}
		log.Info("PostgreSQL server certificate ready",
			"cert", pgCertPath,
			"key", pgKeyPath,
		)

		// Auto-generate Redis server cert
		redisCertPath, redisKeyPath, redisErr := pkiMgr.EnsureRedisServerCert("redis", "localhost")
		if redisErr != nil {
			return fmt.Errorf("failed to ensure Redis server cert: %w", redisErr)
		}
		log.Info("Redis server certificate ready",
			"cert", redisCertPath,
			"key", redisKeyPath,
		)

		// Auto-configure Redis TLS if not explicitly configured
		if !cfg.Redis.TLSEnabled {
			cfg.Redis.TLSEnabled = true
			cfg.Redis.TLSSkipVerify = true // Self-signed, no CA verification by default
			log.Info("Redis TLS auto-configured from PKI")
		}

		// Auto-configure NATS client TLS if not explicitly configured
		if !cfg.NATS.TLS.Enabled && (cfg.Mode == "master" || cfg.NATS.URL != "") {
			// Generate a client cert for the master's NATS connection
			masterCertPath, masterKeyPath, masterErr := pkiMgr.EnsureMasterNATSClientCert()
			if masterErr != nil {
				return fmt.Errorf("failed to ensure master NATS client cert: %w", masterErr)
			}

			cfg.NATS.TLS.Enabled = true
			cfg.NATS.TLS.CertFile = masterCertPath
			cfg.NATS.TLS.KeyFile = masterKeyPath
			cfg.NATS.TLS.CAFile = pkiMgr.CACertPath()
			log.Info("NATS mTLS auto-configured from PKI",
				"cert", masterCertPath,
				"ca", pkiMgr.CACertPath(),
			)
		}
	}

	// Initialize Redis (with TLS if auto-configured by PKI)
	redisURL := cfg.Redis.URL
	// Upgrade redis:// → rediss:// when TLS is enabled
	if cfg.Redis.TLSEnabled && strings.HasPrefix(redisURL, "redis://") {
		redisURL = "rediss://" + strings.TrimPrefix(redisURL, "redis://")
	}
	cfg.Redis.URL = redisURL // Store effective URL for About page detection
	var redisTLSCfg *tls.Config
	if cfg.Redis.TLSEnabled {
		redisTLSCfg = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.Redis.TLSSkipVerify,
		}
		// Load custom CA for server verification
		if cfg.Redis.TLSCAFile != "" {
			caCert, caErr := os.ReadFile(cfg.Redis.TLSCAFile)
			if caErr != nil {
				return fmt.Errorf("failed to read Redis CA cert: %w", caErr)
			}
			caPool := x509.NewCertPool()
			if !caPool.AppendCertsFromPEM(caCert) {
				return fmt.Errorf("failed to parse Redis CA cert from %s", cfg.Redis.TLSCAFile)
			}
			redisTLSCfg.RootCAs = caPool
			redisTLSCfg.InsecureSkipVerify = false
		}
		// Load client certificate for mTLS
		if cfg.Redis.TLSCertFile != "" && cfg.Redis.TLSKeyFile != "" {
			cert, certErr := tls.LoadX509KeyPair(cfg.Redis.TLSCertFile, cfg.Redis.TLSKeyFile)
			if certErr != nil {
				return fmt.Errorf("failed to load Redis client cert: %w", certErr)
			}
			redisTLSCfg.Certificates = []tls.Certificate{cert}
		}
	}
	log.Info("Connecting to Redis...", "tls", cfg.Redis.TLSEnabled)
	rdb, err := redis.New(ctx, redisURL, redis.Options{
		PoolSize:     cfg.Redis.PoolSize,
		MinIdleConns: cfg.Redis.MinIdleConns,
		DialTimeout:  cfg.Redis.DialTimeout,
		ReadTimeout:  cfg.Redis.ReadTimeout,
		WriteTimeout: cfg.Redis.WriteTimeout,
		TLSConfig:    redisTLSCfg,
	})
	if err != nil {
		return fmt.Errorf("failed to connect to Redis: %w", err)
	}
	defer rdb.Close()
	log.Info("Redis connected", "tls", cfg.Redis.TLSEnabled)

	// Initialize NATS (only for master/agent modes or if URL is configured)
	var nc *nats.Client
	if cfg.Mode != "standalone" || cfg.NATS.URL != "" {
		log.Info("Connecting to NATS...")

		natsCfg := nats.Config{
			URL:              cfg.NATS.URL,
			Name:             cfg.NATS.Name,
			Token:            cfg.NATS.Token,
			Username:         cfg.NATS.Username,
			Password:         cfg.NATS.Password,
			MaxReconnects:    cfg.NATS.MaxReconnects,
			ReconnectWait:    cfg.NATS.ReconnectWait,
			JetStreamEnabled: cfg.NATS.JetStream.Enabled,
			JetStreamDomain:  cfg.NATS.JetStream.Domain,
		}

		// Build TLS config if enabled (manual or auto-configured from PKI)
		if cfg.NATS.TLS.Enabled {
			tlsCfg, tlsErr := buildNATSTLSConfig(cfg.NATS.TLS.CertFile, cfg.NATS.TLS.KeyFile, cfg.NATS.TLS.CAFile, cfg.NATS.TLS.SkipVerify)
			if tlsErr != nil {
				return fmt.Errorf("failed to configure NATS TLS: %w", tlsErr)
			}
			natsCfg.TLSConfig = tlsCfg
			log.Info("NATS TLS enabled", "ca_file", cfg.NATS.TLS.CAFile, "cert_file", cfg.NATS.TLS.CertFile)
		}

		nc, err = nats.NewClient(natsCfg, log.Base())
		if err != nil {
			return fmt.Errorf("failed to create NATS client: %w", err)
		}

		if err := nc.Connect(ctx); err != nil {
			nc.Close()
			if cfg.Mode == "standalone" {
				log.Warn("NATS connection failed (optional in standalone mode)", "error", err)
				nc = nil
			} else {
				return fmt.Errorf("failed to connect to NATS (required for %s mode): %w", cfg.Mode, err)
			}
		} else {
			log.Info("NATS connected", "url", cfg.NATS.URL)
		}
		if nc != nil {
			defer nc.Close()
		}
	}

	app := &Application{
		Config:       cfg,
		Logger:       log,
		DB:           db,
		Redis:        rdb,
		NATS:         nc,
		pkiManager:   pkiMgr,
		otelProvider: otelProvider,
	}

	// Start components based on mode
	if err := app.startComponents(ctx); err != nil {
		return fmt.Errorf("failed to start components: %w", err)
	}

	log.Info("usulnet started successfully",
		"host", cfg.Server.Host,
		"port", cfg.Server.Port,
	)

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	<-quit
	log.Info("Shutdown signal received")

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
	defer shutdownCancel()

	if err := app.shutdown(shutdownCtx); err != nil {
		log.Error("Error during shutdown", "error", err)
		return err
	}

	log.Info("usulnet stopped gracefully")
	return nil
}

// startComponents initializes and starts all required components based on mode
func (app *Application) startComponents(ctx context.Context) error {
	switch app.Config.Mode {
	case "standalone":
		return app.startStandalone(ctx)
	case "master":
		return app.startMaster(ctx)
	case "agent":
		return app.startAgent(ctx)
	default:
		return fmt.Errorf("unknown mode: %s", app.Config.Mode)
	}
}

// startStandalone initializes all services for standalone/master mode via a
// phased init pipeline. Each phase populates the shared initContext that
// subsequent phases depend on.
func (app *Application) startStandalone(ctx context.Context) error {
	app.Logger.Info("Starting in standalone mode")

	ic := &initContext{}

	// Phase 1: API server configuration + TLS
	if err := app.initServer(ic); err != nil {
		return fmt.Errorf("init server: %w", err)
	}

	// Phase 2: Auth services (JWT, sessions, audit, admin bootstrap)
	if err := app.initAuth(ctx, ic); err != nil {
		return fmt.Errorf("init auth: %w", err)
	}

	// Phase 3: Docker client + host/container/image/volume/network/stack services
	if err := app.initDocker(ctx, ic); err != nil {
		return fmt.Errorf("init docker: %w", err)
	}

	// Phase 4: Business logic (license, team, security, backup, config, update, notification)
	if err := app.initServices(ctx, ic); err != nil {
		return fmt.Errorf("init services: %w", err)
	}

	// Phase 5: Job scheduler + cron workers
	if err := app.initScheduler(ctx, ic); err != nil {
		return fmt.Errorf("init scheduler: %w", err)
	}

	// Phase 6: API handlers + health checks + router Setup()
	if err := app.initAPI(ctx, ic); err != nil {
		return fmt.Errorf("init api: %w", err)
	}

	// Phase 7: Web frontend (service registry, remaining services, route registration)
	if err := app.initWeb(ctx, ic); err != nil {
		return fmt.Errorf("init web: %w", err)
	}

	// Start server in background — StartAsync blocks until the server is
	// listening or has failed, then returns the error channel.
	errCh := app.Server.StartAsync()

	// Check for immediate startup errors (non-blocking after StartAsync returns)
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("failed to start API server: %w", err)
		}
	default:
		// Server is running
	}

	return nil
}

func (app *Application) startMaster(ctx context.Context) error {
	app.Logger.Info("Starting in master mode")

	// Master mode = standalone (all services + web UI) + gateway (agent management)
	// First, initialize everything standalone does
	if err := app.startStandalone(ctx); err != nil {
		return fmt.Errorf("failed to start standalone services: %w", err)
	}

	// =========================================================================
	// GATEWAY INITIALIZATION (Master-only)
	// =========================================================================

	if app.NATS == nil {
		return fmt.Errorf("NATS connection required for master mode - configure nats.url in config")
	}

	// Reuse host repository created in startStandalone
	// Create gateway server
	gatewayCfg := gateway.DefaultServerConfig()
	gw, err := gateway.NewServer(app.NATS, app.hostRepo, app.containerService, gatewayCfg, app.Logger)
	if err != nil {
		return fmt.Errorf("failed to create gateway server: %w", err)
	}

	// Wire agent event persistence
	agentEventRepo := postgres.NewAgentEventRepository(app.DB)
	gw.SetEventStore(agentEventRepo)
	app.Logger.Info("Agent event persistence enabled")

	// Start gateway (subscriptions, heartbeat monitoring, cleanup loop)
	if err := gw.Start(ctx); err != nil {
		return fmt.Errorf("failed to start gateway server: %w", err)
	}
	app.gatewayServer = gw

	// Wire gateway as command sender for remote host proxy clients
	if app.hostService != nil {
		app.hostService.SetCommandSender(gw)
		app.Logger.Info("Master mode: host service upgraded with command sender")
	}

	// Register gateway API routes on the existing router
	gatewayAPI := gateway.NewAPIHandler(gw, app.Logger)
	gatewayAPI.RegisterRoutes(app.Server.Router())

	app.Logger.Info("Master mode: gateway server started",
		"heartbeat_interval", gatewayCfg.HeartbeatInterval,
		"heartbeat_timeout", gatewayCfg.HeartbeatTimeout,
		"command_timeout", gatewayCfg.CommandTimeout,
	)

	return nil
}

func (app *Application) startAgent(ctx context.Context) error {
	app.Logger.Info("Starting in agent mode")

	// Validate agent configuration
	if app.Config.Agent.Token == "" {
		return fmt.Errorf("agent token required - configure agent.token in config or set USULNET_AGENT_TOKEN")
	}

	// Determine NATS gateway URL
	gatewayURL := app.Config.NATS.URL
	if app.Config.Agent.MasterURL != "" {
		gatewayURL = app.Config.Agent.MasterURL
	}
	if gatewayURL == "" {
		return fmt.Errorf("NATS URL required for agent mode - configure nats.url or agent.master_url")
	}

	// Build agent configuration
	agentCfg := agentpkg.Config{
		AgentID:     app.Config.Agent.ID,
		Token:       app.Config.Agent.Token,
		GatewayURL:  gatewayURL,
		DockerHost:  "unix://" + dockerpkg.LocalSocketPath(),
		Hostname:    app.Config.Agent.Name,
		LogLevel:    app.Config.Logging.Level,
		DataDir:     app.Config.Agent.DataDir,
		TLSEnabled:  app.Config.Agent.TLSEnabled,
		TLSCertFile: app.Config.Agent.TLSCertFile,
		TLSKeyFile:  app.Config.Agent.TLSKeyFile,
		TLSCAFile:   app.Config.Agent.TLSCAFile,
	}

	// Auto-detect hostname if not configured
	if agentCfg.Hostname == "" {
		agentCfg.Hostname, _ = os.Hostname()
	}

	// Create agent instance
	ag, err := agentpkg.New(agentCfg, app.Logger)
	if err != nil {
		return fmt.Errorf("failed to create agent: %w", err)
	}
	app.agentInstance = ag

	// Run agent in background with ready channel for deterministic startup
	agentReady := make(chan struct{})
	agentErrCh := make(chan error, 1)
	go func() {
		if err := ag.Run(ctx, agentReady); err != nil {
			app.Logger.Error("Agent error", "error", err)
			agentErrCh <- err
		}
	}()

	// Wait for agent to be ready or fail
	select {
	case err := <-agentErrCh:
		return fmt.Errorf("agent failed to start: %w", err)
	case <-agentReady:
		// Agent connected and running
	case <-ctx.Done():
		return ctx.Err()
	}

	app.Logger.Info("Agent mode: connected and running",
		"agent_id", agentCfg.AgentID,
		"gateway", gatewayURL,
		"hostname", agentCfg.Hostname,
	)

	return nil
}

// shutdown gracefully stops all components
func (app *Application) shutdown(ctx context.Context) error {
	app.Logger.Info("Shutting down components...")

	// Stop scheduler first (it may be submitting jobs/notifications)
	if app.schedulerService != nil {
		if err := app.schedulerService.Stop(); err != nil {
			app.Logger.Error("Error stopping scheduler", "error", err)
		} else {
			app.Logger.Info("Scheduler stopped")
		}
	}

	// Stop notification service
	if app.notificationService != nil {
		app.notificationService.Stop()
		app.Logger.Info("Notification service stopped")
	}

	// Stop active packet captures
	if app.captureService != nil {
		app.captureService.Cleanup()
		app.Logger.Info("Packet capture service stopped")
	}

	// Stop backup service
	if app.backupService != nil {
		if err := app.backupService.Stop(); err != nil {
			app.Logger.Error("Error stopping backup service", "error", err)
		} else {
			app.Logger.Info("Backup service stopped")
		}
	}

	// Stop gateway server if running (master mode)
	if app.gatewayServer != nil {
		if err := app.gatewayServer.Stop(); err != nil {
			app.Logger.Error("Error stopping gateway server", "error", err)
		} else {
			app.Logger.Info("Gateway server stopped")
		}
	}

	// Stop agent if running (agent mode)
	if app.agentInstance != nil {
		app.agentInstance.Stop()
		app.Logger.Info("Agent stopped")
	}

	// Stop license provider background goroutine
	if app.licenseProvider != nil {
		app.licenseProvider.Stop()
		app.Logger.Info("License provider stopped")
	}

	// Stop API server if running
	if app.Server != nil {
		if err := app.Server.Shutdown(ctx); err != nil {
			app.Logger.Error("Error stopping API server", "error", err)
			return err
		}
	}

	// Flush OpenTelemetry data
	if app.otelProvider != nil {
		if err := app.otelProvider.Shutdown(ctx); err != nil {
			app.Logger.Error("Error flushing OpenTelemetry", "error", err)
		} else {
			app.Logger.Info("OpenTelemetry provider stopped")
		}
	}

	return nil
}
