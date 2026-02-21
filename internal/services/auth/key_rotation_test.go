// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/models"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// Mock repository
// ============================================================================

type mockSigningKeyRepo struct {
	mu   sync.Mutex
	keys map[uuid.UUID]*signingKeyRow
}

type signingKeyRow struct {
	key          *SigningKey
	encryptedKey []byte
}

func newMockSigningKeyRepo() *mockSigningKeyRepo {
	return &mockSigningKeyRepo{
		keys: make(map[uuid.UUID]*signingKeyRow),
	}
}

func (m *mockSigningKeyRepo) Create(_ context.Context, key *SigningKey, encryptedKey []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keys[key.ID] = &signingKeyRow{
		key: &SigningKey{
			ID:          key.ID,
			KeyHash:     key.KeyHash,
			Secret:      string(encryptedKey), // In tests without encryption, encrypted = plaintext
			Algorithm:   key.Algorithm,
			Status:      key.Status,
			CreatedAt:   key.CreatedAt,
			ActivatedAt: key.ActivatedAt,
			ExpiresAt:   key.ExpiresAt,
			RevokedAt:   key.RevokedAt,
		},
		encryptedKey: encryptedKey,
	}
	return nil
}

func (m *mockSigningKeyRepo) GetActiveKeys(_ context.Context) ([]*SigningKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []*SigningKey
	for _, row := range m.keys {
		if row.key.Status != "revoked" {
			k := *row.key
			result = append(result, &k)
		}
	}
	return result, nil
}

func (m *mockSigningKeyRepo) GetByID(_ context.Context, id uuid.UUID) (*SigningKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if row, ok := m.keys[id]; ok {
		k := *row.key
		return &k, nil
	}
	return nil, nil
}

func (m *mockSigningKeyRepo) UpdateStatus(_ context.Context, id uuid.UUID, status string, revokedAt *time.Time, _ *uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if row, ok := m.keys[id]; ok {
		row.key.Status = status
		row.key.RevokedAt = revokedAt
	}
	return nil
}

func (m *mockSigningKeyRepo) DeleteExpired(_ context.Context) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	var count int64
	for id, row := range m.keys {
		if row.key.ExpiresAt != nil && now.After(*row.key.ExpiresAt) {
			delete(m.keys, id)
			count++
		}
	}
	return count, nil
}

func (m *mockSigningKeyRepo) keyCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.keys)
}

// ============================================================================
// Test helpers
// ============================================================================

func newTestKeyRotationService() (*KeyRotationService, *mockSigningKeyRepo) {
	jwtSvc := newTestJWTService()
	repo := newMockSigningKeyRepo()
	log := logger.Nop()
	config := &KeyRotationConfig{
		MaxActiveKeys:      2,
		KeyRetentionPeriod: 7 * 24 * time.Hour,
		RotationInterval:   7 * 24 * time.Hour,
		KeyLength:          32,
	}
	svc := NewKeyRotationService(config, repo, jwtSvc, log)
	return svc, repo
}

// ============================================================================
// Constructor tests
// ============================================================================

func TestNewKeyRotationService_Defaults(t *testing.T) {
	jwtSvc := newTestJWTService()
	repo := newMockSigningKeyRepo()
	log := logger.Nop()

	// Nil config should use defaults
	svc := NewKeyRotationService(nil, repo, jwtSvc, log)
	if svc.config.MaxActiveKeys != 2 {
		t.Errorf("expected MaxActiveKeys=2, got %d", svc.config.MaxActiveKeys)
	}
	if svc.config.KeyLength != 64 {
		t.Errorf("expected KeyLength=64, got %d", svc.config.KeyLength)
	}
}

func TestNewKeyRotationService_MinKeyLength(t *testing.T) {
	jwtSvc := newTestJWTService()
	repo := newMockSigningKeyRepo()
	log := logger.Nop()

	config := &KeyRotationConfig{KeyLength: 10} // below minimum
	svc := NewKeyRotationService(config, repo, jwtSvc, log)
	if svc.config.KeyLength != 64 {
		t.Errorf("expected KeyLength=64 for input below 32, got %d", svc.config.KeyLength)
	}
}

// ============================================================================
// Initialize
// ============================================================================

func TestKeyRotation_Initialize_CreatesInitialKey(t *testing.T) {
	svc, repo := newTestKeyRotationService()
	ctx := context.Background()

	if err := svc.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	if repo.keyCount() != 1 {
		t.Errorf("expected 1 key in repo, got %d", repo.keyCount())
	}
	if svc.GetActiveKeyCount() == 0 {
		t.Error("expected at least one active key")
	}
	if svc.GetSigningKey() == "" {
		t.Error("expected non-empty signing key")
	}
}

func TestKeyRotation_Initialize_LoadsExistingKeys(t *testing.T) {
	svc, _ := newTestKeyRotationService()
	ctx := context.Background()

	// Initialize once to create the initial key
	if err := svc.Initialize(ctx); err != nil {
		t.Fatalf("first Initialize: %v", err)
	}
	firstKey := svc.GetSigningKey()

	// Re-initialize should load the existing key, not create a new one
	if err := svc.Initialize(ctx); err != nil {
		t.Fatalf("second Initialize: %v", err)
	}
	if svc.GetSigningKey() != firstKey {
		t.Error("expected same signing key after re-initialize")
	}
}

// ============================================================================
// Rotate key
// ============================================================================

func TestKeyRotation_RotateKey(t *testing.T) {
	svc, repo := newTestKeyRotationService()
	ctx := context.Background()

	if err := svc.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	initialKey := svc.GetSigningKey()
	initialCount := svc.GetActiveKeyCount()

	newKey, err := svc.RotateKey(ctx, nil)
	if err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	if newKey == nil {
		t.Fatal("expected non-nil new key")
	}
	if svc.GetSigningKey() == initialKey {
		t.Error("expected signing key to change after rotation")
	}
	if svc.GetActiveKeyCount() <= initialCount {
		t.Error("expected more active keys after rotation")
	}
	if repo.keyCount() < 2 {
		t.Error("expected at least 2 keys in repo after rotation")
	}
}

func TestKeyRotation_RotateKey_TokensContinueToValidate(t *testing.T) {
	svc, _ := newTestKeyRotationService()
	ctx := context.Background()

	if err := svc.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	user := testUser()
	// Generate token with the initial key
	tokenStr, _, err := svc.GenerateTokenWithKey(user)
	if err != nil {
		t.Fatalf("GenerateTokenWithKey: %v", err)
	}

	// Rotate key
	if _, err := svc.RotateKey(ctx, nil); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// Token generated with old key should still validate
	claims, err := svc.ValidateTokenWithRotation(tokenStr)
	if err != nil {
		t.Fatalf("ValidateTokenWithRotation after rotation: %v", err)
	}
	if claims.UserID != user.ID.String() {
		t.Errorf("expected user ID %s, got %s", user.ID, claims.UserID)
	}

	// Tokens from the new key should also validate
	newTokenStr, _, err := svc.GenerateTokenWithKey(user)
	if err != nil {
		t.Fatalf("GenerateTokenWithKey after rotation: %v", err)
	}
	claims2, err := svc.ValidateTokenWithRotation(newTokenStr)
	if err != nil {
		t.Fatalf("ValidateTokenWithRotation for new key: %v", err)
	}
	if claims2.UserID != user.ID.String() {
		t.Errorf("expected user ID %s, got %s", user.ID, claims2.UserID)
	}
}

// ============================================================================
// Revoke key
// ============================================================================

func TestKeyRotation_RevokeKey_CannotRevokeCurrent(t *testing.T) {
	svc, _ := newTestKeyRotationService()
	ctx := context.Background()

	if err := svc.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	info := svc.GetRotationInfo()
	err := svc.RevokeKey(ctx, info.CurrentKeyID, nil)
	if err == nil {
		t.Fatal("expected error when revoking current signing key")
	}
}

func TestKeyRotation_RevokeKey_RevokesOldKey(t *testing.T) {
	svc, _ := newTestKeyRotationService()
	ctx := context.Background()

	if err := svc.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	initialKeyID := svc.GetRotationInfo().CurrentKeyID

	// Rotate to create a second key
	if _, err := svc.RotateKey(ctx, nil); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// Revoke the initial (now old) key
	err := svc.RevokeKey(ctx, initialKeyID, nil)
	if err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}

	// Active count should have decreased
	countBefore := svc.GetActiveKeyCount()
	// The revoked key should not be in the valid set
	for _, info := range []uuid.UUID{initialKeyID} {
		found := false
		svc.mu.RLock()
		for _, k := range svc.validKeys {
			if k.ID == info {
				found = true
			}
		}
		svc.mu.RUnlock()
		if found {
			t.Errorf("revoked key %s still in validKeys", info)
		}
	}
	_ = countBefore
}

// ============================================================================
// NeedsRotation
// ============================================================================

func TestKeyRotation_NeedsRotation_NoKey(t *testing.T) {
	svc, _ := newTestKeyRotationService()
	if !svc.NeedsRotation() {
		t.Error("expected NeedsRotation=true when no key is set")
	}
}

func TestKeyRotation_NeedsRotation_AfterInitialize(t *testing.T) {
	svc, _ := newTestKeyRotationService()
	ctx := context.Background()

	if err := svc.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	if svc.NeedsRotation() {
		t.Error("expected NeedsRotation=false immediately after initialize")
	}
}

// ============================================================================
// GetRotationInfo
// ============================================================================

func TestKeyRotation_GetRotationInfo(t *testing.T) {
	svc, _ := newTestKeyRotationService()
	ctx := context.Background()

	if err := svc.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	info := svc.GetRotationInfo()
	if info.CurrentKeyID == uuid.Nil {
		t.Error("expected non-nil current key ID")
	}
	if info.ActiveKeyCount == 0 {
		t.Error("expected positive active key count")
	}
	if info.RotationInterval == "" {
		t.Error("expected non-empty rotation interval")
	}
	if info.NextRotationAt == nil {
		t.Error("expected non-nil next rotation time")
	}
}

// ============================================================================
// ValidateTokenWithRotation edge cases
// ============================================================================

func TestValidateTokenWithRotation_InvalidToken(t *testing.T) {
	svc, _ := newTestKeyRotationService()
	ctx := context.Background()

	if err := svc.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	_, err := svc.ValidateTokenWithRotation("invalid-token")
	if err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestValidateTokenWithRotation_RevokedKeyDoesNotValidate(t *testing.T) {
	svc, _ := newTestKeyRotationService()
	ctx := context.Background()

	if err := svc.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	user := &models.User{
		ID:       uuid.New(),
		Username: "rotuser",
		Role:     models.RoleViewer,
		IsActive: true,
	}

	// Generate token with current key
	tokenStr, _, err := svc.GenerateTokenWithKey(user)
	if err != nil {
		t.Fatalf("GenerateTokenWithKey: %v", err)
	}
	initialKeyID := svc.GetRotationInfo().CurrentKeyID

	// Rotate key (so initial is now old)
	if _, err := svc.RotateKey(ctx, nil); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// Revoke the old key
	if err := svc.RevokeKey(ctx, initialKeyID, nil); err != nil {
		t.Fatalf("RevokeKey: %v", err)
	}

	// Token from revoked key should no longer validate
	_, err = svc.ValidateTokenWithRotation(tokenStr)
	if err == nil {
		t.Fatal("expected error for token signed with revoked key")
	}
}

// ============================================================================
// CleanupExpiredKeys
// ============================================================================

func TestKeyRotation_CleanupExpiredKeys(t *testing.T) {
	svc, repo := newTestKeyRotationService()
	ctx := context.Background()

	if err := svc.Initialize(ctx); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	// Manually add an expired key to the repo
	expired := time.Now().Add(-1 * time.Hour)
	expiredKey := &SigningKey{
		ID:        uuid.New(),
		KeyHash:   "expiredhash",
		Secret:    "expiredsecret",
		Algorithm: "HS256",
		Status:    "retired",
		CreatedAt: time.Now().Add(-30 * 24 * time.Hour),
		ExpiresAt: &expired,
	}
	repo.Create(ctx, expiredKey, []byte("expiredsecret"))

	initialCount := repo.keyCount()

	count, err := svc.CleanupExpiredKeys(ctx)
	if err != nil {
		t.Fatalf("CleanupExpiredKeys: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 cleaned up key, got %d", count)
	}
	if repo.keyCount() >= initialCount {
		t.Error("expected fewer keys after cleanup")
	}
}

// ============================================================================
// Helpers
// ============================================================================

func TestHashKey_Deterministic(t *testing.T) {
	h1 := hashKey("test-key")
	h2 := hashKey("test-key")
	if h1 != h2 {
		t.Error("expected same hash for same key")
	}

	h3 := hashKey("different-key")
	if h1 == h3 {
		t.Error("expected different hash for different key")
	}
}

func TestGenerateSigningKey(t *testing.T) {
	key1, err := generateSigningKey(32)
	if err != nil {
		t.Fatalf("generateSigningKey: %v", err)
	}
	if len(key1) == 0 {
		t.Fatal("expected non-empty key")
	}

	key2, err := generateSigningKey(32)
	if err != nil {
		t.Fatalf("generateSigningKey: %v", err)
	}
	if key1 == key2 {
		t.Error("expected different keys")
	}
}
