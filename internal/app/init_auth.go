// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"fmt"
	"time"

	apimiddleware "github.com/fr4nsys/usulnet/internal/api/middleware"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/repository/redis"
	auditsvc "github.com/fr4nsys/usulnet/internal/services/audit"
	authsvc "github.com/fr4nsys/usulnet/internal/services/auth"
	"github.com/fr4nsys/usulnet/internal/web"
)

// initAuth initializes authentication services, JWT, sessions, audit logging,
// blacklist, and API key auth. Bootstraps admin user if none exist.
// Requires ic.serverCfg to be populated (from initServer).
func (app *Application) initAuth(ctx context.Context, ic *initContext) error {
	// Create repositories
	userRepo := postgres.NewUserRepository(app.DB)
	sessionRepo := postgres.NewSessionRepository(app.DB)
	apiKeyRepo := postgres.NewAPIKeyRepository(app.DB)

	// Create JWT service
	jwtSecret := app.Config.Security.JWTSecret
	if jwtSecret == "" {
		// This should never happen — Config.Validate() requires jwt_secret.
		// Fail hard rather than silently running with an insecure default.
		return fmt.Errorf("security.jwt_secret is required — set USULNET_JWT_SECRET")
	}
	// Wire JWT/refresh expiry from config (defaults: 24h / 168h)
	accessTTL := app.Config.Security.JWTExpiry
	if accessTTL <= 0 {
		accessTTL = 24 * time.Hour
	}
	refreshTTL := app.Config.Security.RefreshExpiry
	if refreshTTL <= 0 {
		refreshTTL = 7 * 24 * time.Hour
	}
	jwtService := authsvc.NewJWTService(authsvc.JWTConfig{
		Secret:          jwtSecret,
		Issuer:          "usulnet",
		AccessTokenTTL:  accessTTL,
		RefreshTokenTTL: refreshTTL,
	})

	// Create session service (session TTL matches JWT expiry from config)
	sessionSvc := authsvc.NewSessionService(
		sessionRepo,
		jwtService,
		authsvc.SessionConfig{
			MaxSessionsPerUser: 10,
			SessionTTL:         accessTTL,
			CleanupInterval:    1 * time.Hour,
			ExtendOnActivity:   true,
			ExtendThreshold:    accessTTL / 4,
		},
		app.Logger,
	)

	// Create auth service
	authService := authsvc.NewService(
		userRepo,
		sessionRepo,
		apiKeyRepo,
		jwtService,
		sessionSvc,
		authsvc.DefaultAuthConfig(),
		app.Logger,
	)

	// Initialize JWT blacklist for immediate token revocation
	jwtBlacklist := redis.NewJWTBlacklist(app.Redis)
	authService.SetJWTBlacklist(jwtBlacklist)
	app.Logger.Info("JWT blacklist enabled for immediate token revocation")

	// Wire audit logging service for auth events (login/logout/password change)
	auditLogRepo := postgres.NewAuditLogRepository(app.DB, app.Logger)
	auditService := auditsvc.NewService(auditLogRepo, app.Logger, auditsvc.DefaultConfig())
	authService.SetAuditService(auditService)
	auditService.StartCleanupWorker(ctx)
	web.SetAuditDBService(auditService)
	app.Logger.Info("Audit logging service enabled (persistent DB + in-memory cache)")

	// Wire JWT blacklist into API middleware for immediate token revocation.
	// Every incoming JWT is checked against Redis to catch logouts, password changes,
	// and admin-initiated revocations before the token's natural expiry.
	// If Redis is unavailable, we fail open (allow the request) because the JWT
	// signature is still cryptographically validated — forged tokens are still rejected.
	// Only revoked-but-unexpired tokens would briefly work during a Redis outage.
	ic.serverCfg.RouterConfig.TokenValidator = func(ctx context.Context, _ string, claims *apimiddleware.UserClaims) error {
		var issuedAt time.Time
		if claims.IssuedAt != nil {
			issuedAt = claims.IssuedAt.Time
		}
		err := jwtBlacklist.ValidateToken(ctx, redis.TokenValidator{
			JTI:      claims.ID,
			UserID:   claims.UserID,
			IssuedAt: issuedAt,
		})
		if err != nil && err != redis.ErrTokenBlacklisted {
			// Redis infrastructure error (connection refused, timeout, etc.)
			// Log the issue but allow the request — JWT signature is still valid.
			app.Logger.Warn("JWT blacklist check failed, failing open to preserve availability", "error", err)
			return nil
		}
		return err
	}
	app.Logger.Info("JWT blacklist wired to API middleware")

	// Wire API key authentication into API middleware
	ic.serverCfg.RouterConfig.APIKeyAuth = func(ctx context.Context, apiKey string) (*apimiddleware.UserClaims, error) {
		user, _, err := authService.AuthenticateAPIKey(ctx, apiKey)
		if err != nil {
			return nil, err
		}
		email := ""
		if user.Email != nil {
			email = *user.Email
		}
		return &apimiddleware.UserClaims{
			UserID:   user.ID.String(),
			Username: user.Username,
			Email:    email,
			Role:     string(user.Role),
		}, nil
	}
	app.Logger.Info("API key authentication enabled")

	// Bootstrap admin user if no users exist
	if err := app.bootstrapAdminUser(ctx, userRepo); err != nil {
		app.Logger.Error("Failed to bootstrap admin user", "error", err)
		// Non-fatal: continue startup
	}

	// Populate initContext
	ic.authService = authService
	ic.userRepo = userRepo
	ic.sessionRepo = sessionRepo
	ic.apiKeyRepo = apiKeyRepo
	ic.auditLogRepo = auditLogRepo
	ic.auditService = auditService
	ic.jwtSecret = jwtSecret
	ic.accessTTL = accessTTL

	return nil
}
