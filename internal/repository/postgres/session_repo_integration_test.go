// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

// createTestUserForSession inserts a user and returns its ID (sessions require FK).
func createTestUserForSession(t *testing.T, suffix string) uuid.UUID {
	t.Helper()
	repo := postgres.NewUserRepository(testDB)
	user := newTestUser("session-owner-" + suffix)
	if err := repo.Create(context.Background(), user); err != nil {
		t.Fatalf("create session owner: %v", err)
	}
	return user.ID
}

func newTestSession(userID uuid.UUID, suffix string) *models.Session {
	hash := sha256.Sum256([]byte("refresh-token-" + suffix))
	ua := "TestAgent/1.0"
	ip := "127.0.0.1"
	return &models.Session{
		UserID:           userID,
		RefreshTokenHash: hex.EncodeToString(hash[:]),
		UserAgent:        &ua,
		IPAddress:        &ip,
		ExpiresAt:        time.Now().Add(24 * time.Hour),
	}
}

// ============================================================================
// Session CRUD
// ============================================================================

func TestSessionRepo_CreateAndGet(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewSessionRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "sessions", "users") })

	userID := createTestUserForSession(t, "create")
	session := newTestSession(userID, "create")

	if err := repo.Create(ctx, session); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if session.ID == uuid.Nil {
		t.Error("expected session ID to be set")
	}

	got, err := repo.GetByID(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.UserID != userID {
		t.Errorf("user_id = %s, want %s", got.UserID, userID)
	}
}

func TestSessionRepo_GetByRefreshTokenHash(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewSessionRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "sessions", "users") })

	userID := createTestUserForSession(t, "refresh")
	session := newTestSession(userID, "refresh")
	if err := repo.Create(ctx, session); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByRefreshTokenHash(ctx, session.RefreshTokenHash)
	if err != nil {
		t.Fatalf("GetByRefreshTokenHash: %v", err)
	}
	if got.ID != session.ID {
		t.Error("session ID mismatch")
	}
}

func TestSessionRepo_Delete(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewSessionRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "sessions", "users") })

	userID := createTestUserForSession(t, "delete")
	session := newTestSession(userID, "delete")
	if err := repo.Create(ctx, session); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := repo.Delete(ctx, session.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := repo.GetByID(ctx, session.ID)
	if err == nil {
		t.Fatal("expected NotFound after delete")
	}
}

func TestSessionRepo_DeleteByUserID(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewSessionRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "sessions", "users") })

	userID := createTestUserForSession(t, "deluser")
	for i := 0; i < 3; i++ {
		s := newTestSession(userID, fmt.Sprintf("deluser-%d", i))
		if err := repo.Create(ctx, s); err != nil {
			t.Fatalf("Create session %d: %v", i, err)
		}
	}

	deleted, err := repo.DeleteByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("DeleteByUserID: %v", err)
	}
	if deleted != 3 {
		t.Errorf("deleted = %d, want 3", deleted)
	}
}

// ============================================================================
// Session listing
// ============================================================================

func TestSessionRepo_ListByUserID(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewSessionRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "sessions", "users") })

	userID := createTestUserForSession(t, "list")
	for i := 0; i < 3; i++ {
		s := newTestSession(userID, fmt.Sprintf("list-%d", i))
		if err := repo.Create(ctx, s); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	sessions, err := repo.ListByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("ListByUserID: %v", err)
	}
	if len(sessions) != 3 {
		t.Errorf("len = %d, want 3", len(sessions))
	}
}

func TestSessionRepo_CountByUserID(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewSessionRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "sessions", "users") })

	userID := createTestUserForSession(t, "count")
	for i := 0; i < 2; i++ {
		s := newTestSession(userID, fmt.Sprintf("count-%d", i))
		if err := repo.Create(ctx, s); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	count, err := repo.CountByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("CountByUserID: %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
}

// ============================================================================
// Session expiry and validity
// ============================================================================

func TestSessionRepo_IsValid(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewSessionRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "sessions", "users") })

	userID := createTestUserForSession(t, "valid")

	// Active session
	active := newTestSession(userID, "valid-active")
	active.ExpiresAt = time.Now().Add(1 * time.Hour)
	if err := repo.Create(ctx, active); err != nil {
		t.Fatalf("Create active: %v", err)
	}

	valid, err := repo.IsValid(ctx, active.ID)
	if err != nil {
		t.Fatalf("IsValid: %v", err)
	}
	if !valid {
		t.Error("expected active session to be valid")
	}

	// Expired session
	expired := newTestSession(userID, "valid-expired")
	expired.ExpiresAt = time.Now().Add(-1 * time.Hour)
	if err := repo.Create(ctx, expired); err != nil {
		t.Fatalf("Create expired: %v", err)
	}

	valid, err = repo.IsValid(ctx, expired.ID)
	if err != nil {
		t.Fatalf("IsValid expired: %v", err)
	}
	if valid {
		t.Error("expected expired session to be invalid")
	}
}

func TestSessionRepo_DeleteExpired(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewSessionRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "sessions", "users") })

	userID := createTestUserForSession(t, "expired")

	// Create expired and active sessions
	expired := newTestSession(userID, "old")
	expired.ExpiresAt = time.Now().Add(-1 * time.Hour)
	if err := repo.Create(ctx, expired); err != nil {
		t.Fatalf("Create expired: %v", err)
	}

	active := newTestSession(userID, "active")
	active.ExpiresAt = time.Now().Add(1 * time.Hour)
	if err := repo.Create(ctx, active); err != nil {
		t.Fatalf("Create active: %v", err)
	}

	deleted, err := repo.DeleteExpired(ctx)
	if err != nil {
		t.Fatalf("DeleteExpired: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1", deleted)
	}

	// Active session should still exist
	_, err = repo.GetByID(ctx, active.ID)
	if err != nil {
		t.Errorf("active session missing after DeleteExpired: %v", err)
	}
}

// ============================================================================
// Session refresh and extend
// ============================================================================

func TestSessionRepo_UpdateRefreshToken(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewSessionRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "sessions", "users") })

	userID := createTestUserForSession(t, "refresh-update")
	session := newTestSession(userID, "refresh-update")
	if err := repo.Create(ctx, session); err != nil {
		t.Fatalf("Create: %v", err)
	}

	newHash := sha256.Sum256([]byte("new-refresh-token"))
	newExpiry := time.Now().Add(48 * time.Hour)
	if err := repo.UpdateRefreshToken(ctx, session.ID, hex.EncodeToString(newHash[:]), newExpiry); err != nil {
		t.Fatalf("UpdateRefreshToken: %v", err)
	}

	got, err := repo.GetByID(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.RefreshTokenHash != hex.EncodeToString(newHash[:]) {
		t.Error("refresh token hash not updated")
	}
}

func TestSessionRepo_Extend(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewSessionRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "sessions", "users") })

	userID := createTestUserForSession(t, "extend")
	session := newTestSession(userID, "extend")
	if err := repo.Create(ctx, session); err != nil {
		t.Fatalf("Create: %v", err)
	}

	newExpiry := time.Now().Add(72 * time.Hour)
	if err := repo.Extend(ctx, session.ID, newExpiry); err != nil {
		t.Fatalf("Extend: %v", err)
	}

	got, err := repo.GetByID(ctx, session.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	// Compare with second-level precision (DB truncates)
	if got.ExpiresAt.Before(newExpiry.Add(-1 * time.Second)) {
		t.Error("expires_at not extended")
	}
}

// ============================================================================
// APIKey CRUD
// ============================================================================

func TestAPIKeyRepo_CreateAndGet(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewAPIKeyRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "api_keys", "users") })

	userID := createTestUserForSession(t, "apikey")
	hash := sha256.Sum256([]byte("api-key-secret"))
	key := &models.APIKey{
		UserID:  userID,
		Name:    "test-key",
		KeyHash: hex.EncodeToString(hash[:]),
		Prefix:  "usn_1234",
	}

	if err := repo.Create(ctx, key); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if key.ID == uuid.Nil {
		t.Error("expected ID to be set")
	}

	got, err := repo.GetByID(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Name != "test-key" {
		t.Errorf("name = %q, want test-key", got.Name)
	}
	if got.Prefix != "usn_1234" {
		t.Errorf("prefix = %q, want usn_1234", got.Prefix)
	}
}

func TestAPIKeyRepo_GetByKeyHash(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewAPIKeyRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "api_keys", "users") })

	userID := createTestUserForSession(t, "keyhash")
	hash := sha256.Sum256([]byte("key-for-hash-lookup"))
	key := &models.APIKey{
		UserID:  userID,
		Name:    "hash-key",
		KeyHash: hex.EncodeToString(hash[:]),
		Prefix:  "usn_hash",
	}
	if err := repo.Create(ctx, key); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByKeyHash(ctx, key.KeyHash)
	if err != nil {
		t.Fatalf("GetByKeyHash: %v", err)
	}
	if got.ID != key.ID {
		t.Error("ID mismatch")
	}
}

func TestAPIKeyRepo_ListByUserID(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewAPIKeyRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "api_keys", "users") })

	userID := createTestUserForSession(t, "listkeys")
	for i := 0; i < 3; i++ {
		hash := sha256.Sum256([]byte(fmt.Sprintf("key-%d", i)))
		k := &models.APIKey{
			UserID:  userID,
			Name:    fmt.Sprintf("key-%d", i),
			KeyHash: hex.EncodeToString(hash[:]),
			Prefix:  fmt.Sprintf("usn_%04d", i),
		}
		if err := repo.Create(ctx, k); err != nil {
			t.Fatalf("Create key %d: %v", i, err)
		}
	}

	keys, err := repo.ListByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("ListByUserID: %v", err)
	}
	if len(keys) != 3 {
		t.Errorf("len = %d, want 3", len(keys))
	}
}

func TestAPIKeyRepo_Delete(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewAPIKeyRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "api_keys", "users") })

	userID := createTestUserForSession(t, "delkey")
	hash := sha256.Sum256([]byte("delete-key"))
	key := &models.APIKey{
		UserID:  userID,
		Name:    "del-key",
		KeyHash: hex.EncodeToString(hash[:]),
		Prefix:  "usn_del1",
	}
	if err := repo.Create(ctx, key); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := repo.Delete(ctx, key.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := repo.GetByID(ctx, key.ID)
	if err == nil {
		t.Fatal("expected NotFound after delete")
	}
}

func TestAPIKeyRepo_UpdateLastUsed(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewAPIKeyRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "api_keys", "users") })

	userID := createTestUserForSession(t, "lastused")
	hash := sha256.Sum256([]byte("last-used-key"))
	key := &models.APIKey{
		UserID:  userID,
		Name:    "used-key",
		KeyHash: hex.EncodeToString(hash[:]),
		Prefix:  "usn_used",
	}
	if err := repo.Create(ctx, key); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := repo.UpdateLastUsed(ctx, key.ID); err != nil {
		t.Fatalf("UpdateLastUsed: %v", err)
	}

	got, err := repo.GetByID(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.LastUsedAt == nil {
		t.Error("expected last_used_at to be set")
	}
}

func TestAPIKeyRepo_CountByUserID(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewAPIKeyRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "api_keys", "users") })

	userID := createTestUserForSession(t, "countkeys")
	for i := 0; i < 2; i++ {
		hash := sha256.Sum256([]byte(fmt.Sprintf("count-key-%d", i)))
		k := &models.APIKey{
			UserID:  userID,
			Name:    fmt.Sprintf("count-key-%d", i),
			KeyHash: hex.EncodeToString(hash[:]),
			Prefix:  fmt.Sprintf("usn_c%03d", i),
		}
		if err := repo.Create(ctx, k); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	count, err := repo.CountByUserID(ctx, userID)
	if err != nil {
		t.Fatalf("CountByUserID: %v", err)
	}
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
}

func TestAPIKeyRepo_ExistsByName(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewAPIKeyRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "api_keys", "users") })

	userID := createTestUserForSession(t, "existskey")
	hash := sha256.Sum256([]byte("exists-key"))
	k := &models.APIKey{
		UserID:  userID,
		Name:    "My Key",
		KeyHash: hex.EncodeToString(hash[:]),
		Prefix:  "usn_exst",
	}
	if err := repo.Create(ctx, k); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Case-insensitive name check
	exists, err := repo.ExistsByName(ctx, userID, "my key")
	if err != nil {
		t.Fatalf("ExistsByName: %v", err)
	}
	if !exists {
		t.Error("expected key name to exist")
	}

	exists, err = repo.ExistsByName(ctx, userID, "other key")
	if err != nil {
		t.Fatalf("ExistsByName: %v", err)
	}
	if exists {
		t.Error("expected key name to not exist")
	}
}
