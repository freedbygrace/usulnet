// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
	"github.com/fr4nsys/usulnet/internal/repository/postgres"
)

func newTestUser(username string) *models.User {
	email := username + "@test.local"
	return &models.User{
		Username:     username,
		Email:        &email,
		PasswordHash: "$2a$10$fakehashfakehashfakehashfakehashfakehashfakehash1234",
		Role:         models.RoleViewer,
		IsActive:     true,
	}
}

// ============================================================================
// Create
// ============================================================================

func TestUserRepo_Create(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users") })

	user := newTestUser("create-user")
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if user.ID == uuid.Nil {
		t.Error("expected ID to be set")
	}
	if user.CreatedAt.IsZero() {
		t.Error("expected CreatedAt to be set")
	}
}

func TestUserRepo_Create_DuplicateUsername(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users") })

	user1 := newTestUser("dup-user")
	if err := repo.Create(ctx, user1); err != nil {
		t.Fatalf("Create first: %v", err)
	}

	user2 := newTestUser("dup-user")
	user2.Email = nil // avoid email dup
	err := repo.Create(ctx, user2)
	if err == nil {
		t.Fatal("expected AlreadyExists error")
	}

	var appErr *apperrors.AppError
	if !errors.As(err, &appErr) || appErr.Code != "CONFLICT" {
		t.Errorf("expected CONFLICT error code, got: %v", err)
	}
}

// ============================================================================
// GetByID / GetByUsername / GetByEmail
// ============================================================================

func TestUserRepo_GetByID(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users") })

	user := newTestUser("get-by-id")
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}

	if got.Username != "get-by-id" {
		t.Errorf("username = %q, want %q", got.Username, "get-by-id")
	}
	if got.Role != models.RoleViewer {
		t.Errorf("role = %q, want %q", got.Role, models.RoleViewer)
	}
	if !got.IsActive {
		t.Error("expected is_active = true")
	}
}

func TestUserRepo_GetByID_NotFound(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()

	_, err := repo.GetByID(ctx, uuid.New())
	if err == nil {
		t.Fatal("expected NotFound error")
	}

	var appErr *apperrors.AppError
	if !errors.As(err, &appErr) || appErr.Code != "NOT_FOUND" {
		t.Errorf("expected NOT_FOUND, got: %v", err)
	}
}

func TestUserRepo_GetByUsername(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users") })

	user := newTestUser("get-by-username")
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Case-insensitive lookup
	got, err := repo.GetByUsername(ctx, "Get-By-Username")
	if err != nil {
		t.Fatalf("GetByUsername: %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("ID mismatch: got %s, want %s", got.ID, user.ID)
	}
}

func TestUserRepo_GetByEmail(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users") })

	user := newTestUser("get-by-email")
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := repo.GetByEmail(ctx, "Get-By-Email@test.local")
	if err != nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if got.ID != user.ID {
		t.Errorf("ID mismatch")
	}
}

// ============================================================================
// Update
// ============================================================================

func TestUserRepo_Update(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users") })

	user := newTestUser("update-user")
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create: %v", err)
	}

	newEmail := "updated@test.local"
	user.Email = &newEmail
	user.Role = models.RoleOperator
	if err := repo.Update(ctx, user); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetByID after update: %v", err)
	}
	if got.Role != models.RoleOperator {
		t.Errorf("role = %q, want operator", got.Role)
	}
	if got.Email == nil || *got.Email != newEmail {
		t.Errorf("email = %v, want %q", got.Email, newEmail)
	}
}

func TestUserRepo_Update_NotFound(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()

	user := &models.User{ID: uuid.New(), Role: models.RoleViewer}
	err := repo.Update(ctx, user)
	if err == nil {
		t.Fatal("expected NotFound error")
	}
}

// ============================================================================
// Delete
// ============================================================================

func TestUserRepo_Delete(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users") })

	user := newTestUser("delete-user")
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := repo.Delete(ctx, user.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	_, err := repo.GetByID(ctx, user.ID)
	if err == nil {
		t.Fatal("expected NotFound after delete")
	}
}

func TestUserRepo_Delete_NotFound(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()

	err := repo.Delete(ctx, uuid.New())
	if err == nil {
		t.Fatal("expected NotFound error")
	}
}

// ============================================================================
// List
// ============================================================================

func TestUserRepo_List(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users") })

	// Create 5 users
	for i := 0; i < 5; i++ {
		u := newTestUser("list-user-" + string(rune('a'+i)))
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create user %d: %v", i, err)
		}
	}

	// Page 1 of 2
	users, total, err := repo.List(ctx, postgres.UserListOptions{Page: 1, PerPage: 3})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 5 {
		t.Errorf("total = %d, want 5", total)
	}
	if len(users) != 3 {
		t.Errorf("len(users) = %d, want 3", len(users))
	}

	// Page 2 of 2
	users2, _, err := repo.List(ctx, postgres.UserListOptions{Page: 2, PerPage: 3})
	if err != nil {
		t.Fatalf("List page 2: %v", err)
	}
	if len(users2) != 2 {
		t.Errorf("len(users) page 2 = %d, want 2", len(users2))
	}
}

func TestUserRepo_List_SearchFilter(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users") })

	u1 := newTestUser("searchable-alice")
	u2 := newTestUser("searchable-bob")
	u3 := newTestUser("other-charlie")
	for _, u := range []*models.User{u1, u2, u3} {
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	users, total, err := repo.List(ctx, postgres.UserListOptions{
		Page: 1, PerPage: 10, Search: "searchable",
	})
	if err != nil {
		t.Fatalf("List with search: %v", err)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if len(users) != 2 {
		t.Errorf("len(users) = %d, want 2", len(users))
	}
}

func TestUserRepo_List_RoleFilter(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users") })

	admin := newTestUser("role-admin")
	admin.Role = models.RoleAdmin
	viewer := newTestUser("role-viewer")
	viewer.Role = models.RoleViewer
	for _, u := range []*models.User{admin, viewer} {
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	role := models.RoleAdmin
	users, total, err := repo.List(ctx, postgres.UserListOptions{
		Page: 1, PerPage: 10, Role: &role,
	})
	if err != nil {
		t.Fatalf("List with role filter: %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(users) != 1 || users[0].Role != models.RoleAdmin {
		t.Error("expected only admin user")
	}
}

// ============================================================================
// ExistsByUsername / ExistsByEmail
// ============================================================================

func TestUserRepo_ExistsByUsername(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users") })

	user := newTestUser("exists-user")
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create: %v", err)
	}

	exists, err := repo.ExistsByUsername(ctx, "exists-user")
	if err != nil {
		t.Fatalf("ExistsByUsername: %v", err)
	}
	if !exists {
		t.Error("expected user to exist")
	}

	exists, err = repo.ExistsByUsername(ctx, "no-such-user")
	if err != nil {
		t.Fatalf("ExistsByUsername: %v", err)
	}
	if exists {
		t.Error("expected user to not exist")
	}
}

func TestUserRepo_ExistsByEmail(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users") })

	user := newTestUser("exists-email")
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create: %v", err)
	}

	exists, err := repo.ExistsByEmail(ctx, "exists-email@test.local")
	if err != nil {
		t.Fatalf("ExistsByEmail: %v", err)
	}
	if !exists {
		t.Error("expected email to exist")
	}
}

// ============================================================================
// Login tracking
// ============================================================================

func TestUserRepo_UpdateLastLogin(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users") })

	user := newTestUser("login-user")
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := repo.UpdateLastLogin(ctx, user.ID); err != nil {
		t.Fatalf("UpdateLastLogin: %v", err)
	}

	got, err := repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.LastLoginAt == nil {
		t.Error("expected LastLoginAt to be set")
	}
}

func TestUserRepo_IncrementFailedAttempts(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users") })

	user := newTestUser("fail-login")
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Increment below lockout threshold
	if err := repo.IncrementFailedAttempts(ctx, user.ID, 5, 15*time.Minute); err != nil {
		t.Fatalf("IncrementFailedAttempts: %v", err)
	}

	got, err := repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.FailedLoginAttempts != 1 {
		t.Errorf("failed attempts = %d, want 1", got.FailedLoginAttempts)
	}
	if got.LockedUntil != nil {
		t.Error("expected not locked after 1 attempt")
	}

	// Exceed lockout threshold
	for i := 0; i < 4; i++ {
		if err := repo.IncrementFailedAttempts(ctx, user.ID, 5, 15*time.Minute); err != nil {
			t.Fatalf("IncrementFailedAttempts %d: %v", i+2, err)
		}
	}

	got, err = repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetByID after lockout: %v", err)
	}
	if got.LockedUntil == nil {
		t.Error("expected locked after 5 attempts")
	}
}

func TestUserRepo_Unlock(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users") })

	user := newTestUser("unlock-user")
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Lock the user
	for i := 0; i < 5; i++ {
		_ = repo.IncrementFailedAttempts(ctx, user.ID, 5, 15*time.Minute)
	}

	// Unlock
	if err := repo.Unlock(ctx, user.ID); err != nil {
		t.Fatalf("Unlock: %v", err)
	}

	got, err := repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.LockedUntil != nil {
		t.Error("expected not locked after unlock")
	}
	if got.FailedLoginAttempts != 0 {
		t.Errorf("failed attempts = %d, want 0", got.FailedLoginAttempts)
	}
}

// ============================================================================
// Password management
// ============================================================================

func TestUserRepo_UpdatePassword(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users") })

	user := newTestUser("pw-user")
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create: %v", err)
	}

	newHash := "$2a$10$newhashnewhashnewhashnewhashnewhashnewhashnewhash"
	if err := repo.UpdatePassword(ctx, user.ID, newHash); err != nil {
		t.Fatalf("UpdatePassword: %v", err)
	}

	got, err := repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.PasswordHash != newHash {
		t.Error("password hash not updated")
	}
}

func TestUserRepo_PasswordHistory(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users", "password_history") })

	user := newTestUser("pw-history")
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Save a few password hashes
	hashes := []string{"hash-1", "hash-2", "hash-3"}
	for _, h := range hashes {
		if err := repo.SavePasswordHistory(ctx, user.ID, h); err != nil {
			t.Fatalf("SavePasswordHistory: %v", err)
		}
	}

	history, err := repo.GetPasswordHistory(ctx, user.ID, 10)
	if err != nil {
		t.Fatalf("GetPasswordHistory: %v", err)
	}
	if len(history) != 3 {
		t.Errorf("history count = %d, want 3", len(history))
	}
}

// ============================================================================
// TOTP
// ============================================================================

func TestUserRepo_TOTP(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users") })

	user := newTestUser("totp-user")
	if err := repo.Create(ctx, user); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Set TOTP secret
	if err := repo.SetTOTPSecret(ctx, user.ID, "encrypted-secret-base64"); err != nil {
		t.Fatalf("SetTOTPSecret: %v", err)
	}

	// Enable TOTP
	if err := repo.EnableTOTP(ctx, user.ID); err != nil {
		t.Fatalf("EnableTOTP: %v", err)
	}

	got, err := repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if !got.TOTPEnabled {
		t.Error("expected TOTP enabled")
	}

	// Disable TOTP
	if err := repo.DisableTOTP(ctx, user.ID); err != nil {
		t.Fatalf("DisableTOTP: %v", err)
	}

	got, err = repo.GetByID(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.TOTPEnabled {
		t.Error("expected TOTP disabled")
	}
}

// ============================================================================
// Stats
// ============================================================================

func TestUserRepo_GetStats(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users") })

	admin := newTestUser("stats-admin")
	admin.Role = models.RoleAdmin
	inactive := newTestUser("stats-inactive")
	inactive.IsActive = false

	for _, u := range []*models.User{admin, inactive} {
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("Create: %v", err)
		}
	}

	stats, err := repo.GetStats(ctx)
	if err != nil {
		t.Fatalf("GetStats: %v", err)
	}
	if stats.Total != 2 {
		t.Errorf("total = %d, want 2", stats.Total)
	}
	if stats.Active != 1 {
		t.Errorf("active = %d, want 1", stats.Active)
	}
	if stats.Inactive != 1 {
		t.Errorf("inactive = %d, want 1", stats.Inactive)
	}
}

// ============================================================================
// LDAP user creation
// ============================================================================

func TestUserRepo_GetOrCreateLDAPUser(t *testing.T) {
	if testDB == nil {
		t.Skip("no test database")
	}
	repo := postgres.NewUserRepository(testDB)
	ctx := context.Background()
	t.Cleanup(func() { truncateTables(t, "users") })

	// First call creates the user
	user, created, err := repo.GetOrCreateLDAPUser(ctx, "ldap-user", "ldap@test.local", "cn=ldap,dc=test", models.RoleViewer)
	if err != nil {
		t.Fatalf("GetOrCreateLDAPUser: %v", err)
	}
	if !created {
		t.Error("expected user to be created")
	}
	if user.Username != "ldap-user" {
		t.Errorf("username = %q, want ldap-user", user.Username)
	}
	if !user.IsLDAP {
		t.Error("expected is_ldap = true")
	}

	// Second call returns existing user
	user2, created, err := repo.GetOrCreateLDAPUser(ctx, "ldap-user", "ldap@test.local", "cn=ldap,dc=test", models.RoleViewer)
	if err != nil {
		t.Fatalf("GetOrCreateLDAPUser second call: %v", err)
	}
	if created {
		t.Error("expected user to not be created")
	}
	if user2.ID != user.ID {
		t.Error("expected same user ID")
	}
}
