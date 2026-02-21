// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

// Package testutil provides shared test helpers, fixtures, and mock
// constructors used across the usulnet test suite. Import this package in
// test files to avoid duplicating logger setup, model factories, and token
// generation.
package testutil

import (
	"io"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
	authsvc "github.com/fr4nsys/usulnet/internal/services/auth"
)

// ---------------------------------------------------------------------------
// Logger helpers
// ---------------------------------------------------------------------------

// NewTestLogger returns a logger that discards all output. It never fails.
func NewTestLogger(t testing.TB) *logger.Logger {
	t.Helper()
	log, err := logger.NewWithOutput("error", "console", io.Discard)
	if err != nil {
		t.Fatalf("testutil.NewTestLogger: %v", err)
	}
	return log
}

// ---------------------------------------------------------------------------
// Model fixtures
// ---------------------------------------------------------------------------

// TestUserID is a stable UUID used across test fixtures.
var TestUserID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// TestHostID is a stable host UUID for standalone-mode tests.
var TestHostID = uuid.MustParse("00000000-0000-0000-0000-000000000010")

// TestUser returns a fully populated admin user suitable for most tests.
func TestUser() *models.User {
	email := "test@example.com"
	return &models.User{
		ID:       TestUserID,
		Username: "testuser",
		Email:    &email,
		Role:     models.RoleAdmin,
		IsActive: true,
	}
}

// TestViewer returns a read-only viewer user.
func TestViewer() *models.User {
	email := "viewer@example.com"
	return &models.User{
		ID:       uuid.MustParse("00000000-0000-0000-0000-000000000002"),
		Username: "viewer",
		Email:    &email,
		Role:     models.RoleViewer,
		IsActive: true,
	}
}

// TestContainer returns a minimal running container model.
func TestContainer(hostID uuid.UUID) *models.Container {
	return &models.Container{
		ID:     "abc123def456",
		HostID: hostID,
		Name:   "test-container",
		Image:  "alpine:latest",
		State:  models.ContainerStateRunning,
	}
}

// ---------------------------------------------------------------------------
// JWT token helpers
// ---------------------------------------------------------------------------

const testJWTSecret = "test-jwt-secret-at-least-32-characters-long!!"

// GenerateTestToken returns a valid JWT access token for the given user.
// Useful for API handler tests that need an Authorization header.
func GenerateTestToken(t testing.TB, user *models.User) string {
	t.Helper()
	svc := authsvc.NewJWTService(authsvc.JWTConfig{
		Secret:          testJWTSecret,
		Issuer:          "usulnet-test",
		AccessTokenTTL:  1 * time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
	})
	token, _, err := svc.GenerateAccessToken(user)
	if err != nil {
		t.Fatalf("testutil.GenerateTestToken: %v", err)
	}
	return token
}

// TestJWTSecret returns the shared JWT secret used by GenerateTestToken.
// Pass this to auth middleware in handler tests.
func TestJWTSecret() string {
	return testJWTSecret
}
