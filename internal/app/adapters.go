// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package app

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/fr4nsys/usulnet/internal/nats"
	"github.com/fr4nsys/usulnet/internal/pkg/crypto"
	totppkg "github.com/fr4nsys/usulnet/internal/pkg/totp"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
	"github.com/fr4nsys/usulnet/internal/repository/redis"
)

// standaloneHostID is the well-known host ID used for the local Docker
// daemon in standalone (non-agent) mode.
var standaloneHostID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// zapLicenseLogger adapts zap.SugaredLogger to satisfy license.Logger.
type zapLicenseLogger struct {
	sugar *zap.SugaredLogger
}

func (z *zapLicenseLogger) Info(msg string, keysAndValues ...any) {
	z.sugar.Infow(msg, keysAndValues...)
}
func (z *zapLicenseLogger) Warn(msg string, keysAndValues ...any) {
	z.sugar.Warnw(msg, keysAndValues...)
}
func (z *zapLicenseLogger) Error(msg string, keysAndValues ...any) {
	z.sugar.Errorw(msg, keysAndValues...)
}

// encryptorAdapter wraps *crypto.AESEncryptor to satisfy the web.Encryptor interface
// which expects Encrypt(string)(string,error) and Decrypt(string)(string,error).
type encryptorAdapter struct {
	enc *crypto.AESEncryptor
}

func (a *encryptorAdapter) Encrypt(plaintext string) (string, error) {
	return a.enc.EncryptString(plaintext)
}

func (a *encryptorAdapter) Decrypt(ciphertext string) (string, error) {
	return a.enc.DecryptString(ciphertext)
}

// totpValidatorAdapter bridges the auth service's TOTPValidator interface
// (which uses uuid.UUID) to the user repo + AES encryptor + TOTP package.
// It also enforces replay prevention via Redis and lockout via failed attempts.
type totpValidatorAdapter struct {
	repo         *postgres.UserRepository
	encryptor    *crypto.AESEncryptor
	replayStore  *redis.TOTPReplayStore
	maxAttempts  int
	lockDuration time.Duration
}

func (a *totpValidatorAdapter) ValidateTOTPCode(ctx context.Context, userID uuid.UUID, code string) (bool, error) {
	user, err := a.repo.GetByID(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("get user for TOTP validation: %w", err)
	}
	if !user.HasTOTP() {
		return false, fmt.Errorf("totp not enabled for user")
	}
	if user.IsLocked() {
		return false, fmt.Errorf("user account is locked")
	}

	secret, err := a.encryptor.DecryptString(*user.TOTPSecret)
	if err != nil {
		return false, fmt.Errorf("decrypt totp secret: %w", err)
	}

	valid, err := totppkg.Validate(code, secret)
	if err != nil {
		return false, err
	}

	if !valid {
		// Increment failed login attempts (TOTP failures count toward lockout)
		if a.maxAttempts > 0 {
			_ = a.repo.IncrementFailedAttempts(ctx, userID, a.maxAttempts, a.lockDuration)
		}
		return false, nil
	}

	// Check for replay: reject codes that were already consumed
	if a.replayStore != nil {
		replayed, replayErr := a.replayStore.MarkCodeUsed(ctx, userID.String(), code)
		if replayErr != nil {
			// Fail closed: if Redis is down, reject the code
			return false, fmt.Errorf("totp replay check unavailable: %w", replayErr)
		}
		if replayed {
			return false, nil
		}
	}

	// Valid + not replayed → reset failed attempts
	_ = a.repo.ResetFailedAttempts(ctx, userID)
	return true, nil
}

// natsProberAdapter wraps *nats.Client to satisfy the web.NATSProber interface.
// ServerInfo() returns a formatted string instead of the nats.ServerInfo struct.
type natsProberAdapter struct {
	client *nats.Client
}

func (a *natsProberAdapter) IsConnected() bool { return a.client.IsConnected() }
func (a *natsProberAdapter) IsTLS() bool        { return a.client.IsTLS() }
func (a *natsProberAdapter) ServerInfo() string {
	info := a.client.ServerInfo()
	if info.ServerName != "" {
		return fmt.Sprintf("NATS %s (%s)", info.ServerName, info.URL)
	}
	if info.URL != "" {
		return info.URL
	}
	return "NATS"
}
