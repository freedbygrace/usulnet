// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"time"

	"github.com/fr4nsys/usulnet/internal/api"
	dockerpkg "github.com/fr4nsys/usulnet/internal/docker"
	licensepkg "github.com/fr4nsys/usulnet/internal/license"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/scheduler"
	"github.com/fr4nsys/usulnet/internal/scheduler/workers"
	auditsvc "github.com/fr4nsys/usulnet/internal/services/audit"
	authsvc "github.com/fr4nsys/usulnet/internal/services/auth"
	backupsvc "github.com/fr4nsys/usulnet/internal/services/backup"
	configsvc "github.com/fr4nsys/usulnet/internal/services/config"
	containersvc "github.com/fr4nsys/usulnet/internal/services/container"
	hostsvc "github.com/fr4nsys/usulnet/internal/services/host"
	imagesvc "github.com/fr4nsys/usulnet/internal/services/image"
	networksvc "github.com/fr4nsys/usulnet/internal/services/network"
	notificationsvc "github.com/fr4nsys/usulnet/internal/services/notification"
	registrysvc "github.com/fr4nsys/usulnet/internal/services/registry"
	securitysvc "github.com/fr4nsys/usulnet/internal/services/security"
	stacksvc "github.com/fr4nsys/usulnet/internal/services/stack"
	teamsvc "github.com/fr4nsys/usulnet/internal/services/team"
	updatesvc "github.com/fr4nsys/usulnet/internal/services/update"
	volumesvc "github.com/fr4nsys/usulnet/internal/services/volume"

	"github.com/google/uuid"
)

// initContext carries shared state between initialization phases in startStandalone.
// Each init function populates fields that subsequent phases depend on.
type initContext struct {
	// Server config (populated by initServer, consumed by initAuth for TokenValidator/APIKeyAuth, initAPI for Setup)
	serverCfg api.ServerConfig

	// Auth (populated by initAuth)
	authService  *authsvc.Service
	userRepo     *postgres.UserRepository
	sessionRepo  *postgres.SessionRepository
	apiKeyRepo   *postgres.APIKeyRepository
	auditLogRepo *postgres.AuditLogRepository
	auditService *auditsvc.Service
	jwtSecret    string
	accessTTL    time.Duration

	// Docker (populated by initDocker)
	defaultHostID    uuid.UUID
	hostService      *hostsvc.Service
	containerService *containersvc.Service
	containerRepo    *postgres.ContainerRepository
	imageService     *imagesvc.Service
	volumeService    *volumesvc.Service
	networkService   *networksvc.Service
	stackService     *stacksvc.Service
	dockerClient     *dockerpkg.Client

	// Services (populated by initServices)
	licenseProvider     *licensepkg.Provider
	teamService         *teamsvc.Service
	securityService     *securitysvc.Service
	encryptor           *crypto.AESEncryptor
	backupService       *backupsvc.Service
	configService       *configsvc.Service
	configSyncService   *configsvc.SyncService
	updateService       *updatesvc.Service
	notificationService *notificationsvc.Service

	// Scheduler (populated by initScheduler)
	scheduler     *scheduler.Scheduler
	schedulerDeps *workers.Dependencies

	// API (populated by initAPI)
	registryRepo      *postgres.RegistryRepository
	registryBrowseSvc *registrysvc.Service
}
