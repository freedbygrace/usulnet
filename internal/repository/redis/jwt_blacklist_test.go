// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package redis

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
)

// newTestClient starts an in-memory miniredis server and returns a Client
// connected to it. The server is closed when the test finishes.
func newTestClient(t *testing.T) *Client {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	return &Client{rdb: rdb}
}

// newTestClientWithMR returns both the Client and the miniredis server so
// tests can manipulate time.
func newTestClientWithMR(t *testing.T) (*Client, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := goredis.NewClient(&goredis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	return &Client{rdb: rdb}, mr
}

func TestBlacklistToken(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	jti := "token-abc-123"
	expiresAt := time.Now().Add(10 * time.Minute)

	if err := bl.BlacklistToken(ctx, jti, expiresAt, "logout"); err != nil {
		t.Fatalf("BlacklistToken: %v", err)
	}

	blacklisted, err := bl.IsBlacklisted(ctx, jti)
	if err != nil {
		t.Fatalf("IsBlacklisted: %v", err)
	}
	if !blacklisted {
		t.Fatal("expected token to be blacklisted")
	}
}

func TestBlacklistToken_DefaultReason(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	jti := "token-no-reason"
	expiresAt := time.Now().Add(5 * time.Minute)

	if err := bl.BlacklistToken(ctx, jti, expiresAt, ""); err != nil {
		t.Fatalf("BlacklistToken: %v", err)
	}

	reason, err := bl.GetBlacklistReason(ctx, jti)
	if err != nil {
		t.Fatalf("GetBlacklistReason: %v", err)
	}
	if reason != "revoked" {
		t.Fatalf("expected reason 'revoked', got %q", reason)
	}
}

func TestBlacklistToken_AlreadyExpired(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	jti := "token-expired"
	expiresAt := time.Now().Add(-1 * time.Minute) // already expired

	if err := bl.BlacklistToken(ctx, jti, expiresAt, "logout"); err != nil {
		t.Fatalf("BlacklistToken: %v", err)
	}

	// Should not be stored because token is already expired
	blacklisted, err := bl.IsBlacklisted(ctx, jti)
	if err != nil {
		t.Fatalf("IsBlacklisted: %v", err)
	}
	if blacklisted {
		t.Fatal("expired token should not be stored in blacklist")
	}
}

func TestIsBlacklisted_NotBlacklisted(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	blacklisted, err := bl.IsBlacklisted(ctx, "nonexistent-jti")
	if err != nil {
		t.Fatalf("IsBlacklisted: %v", err)
	}
	if blacklisted {
		t.Fatal("expected non-existent token to not be blacklisted")
	}
}

func TestGetBlacklistReason(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	jti := "token-with-reason"
	expiresAt := time.Now().Add(10 * time.Minute)

	if err := bl.BlacklistToken(ctx, jti, expiresAt, "password_change"); err != nil {
		t.Fatalf("BlacklistToken: %v", err)
	}

	reason, err := bl.GetBlacklistReason(ctx, jti)
	if err != nil {
		t.Fatalf("GetBlacklistReason: %v", err)
	}
	if reason != "password_change" {
		t.Fatalf("expected reason 'password_change', got %q", reason)
	}
}

func TestGetBlacklistReason_NotBlacklisted(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	reason, err := bl.GetBlacklistReason(ctx, "missing-jti")
	if err != nil {
		t.Fatalf("GetBlacklistReason: %v", err)
	}
	if reason != "" {
		t.Fatalf("expected empty reason, got %q", reason)
	}
}

func TestRemoveFromBlacklist(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	jti := "token-to-remove"
	expiresAt := time.Now().Add(10 * time.Minute)

	if err := bl.BlacklistToken(ctx, jti, expiresAt, "logout"); err != nil {
		t.Fatalf("BlacklistToken: %v", err)
	}

	// Verify blacklisted
	blacklisted, err := bl.IsBlacklisted(ctx, jti)
	if err != nil {
		t.Fatalf("IsBlacklisted: %v", err)
	}
	if !blacklisted {
		t.Fatal("expected token to be blacklisted before removal")
	}

	// Remove
	if err := bl.RemoveFromBlacklist(ctx, jti); err != nil {
		t.Fatalf("RemoveFromBlacklist: %v", err)
	}

	// Verify no longer blacklisted
	blacklisted, err = bl.IsBlacklisted(ctx, jti)
	if err != nil {
		t.Fatalf("IsBlacklisted: %v", err)
	}
	if blacklisted {
		t.Fatal("expected token to not be blacklisted after removal")
	}
}

func TestRemoveFromBlacklist_NonExistent(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	// Removing a non-existent key should not error (DEL is idempotent)
	if err := bl.RemoveFromBlacklist(ctx, "never-existed"); err != nil {
		t.Fatalf("RemoveFromBlacklist: %v", err)
	}
}

func TestBlacklistToken_ExpiryViaMiniRedis(t *testing.T) {
	client, mr := newTestClientWithMR(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	jti := "token-expiry"
	expiresAt := time.Now().Add(2 * time.Minute)

	if err := bl.BlacklistToken(ctx, jti, expiresAt, "logout"); err != nil {
		t.Fatalf("BlacklistToken: %v", err)
	}

	// Should be present
	blacklisted, err := bl.IsBlacklisted(ctx, jti)
	if err != nil {
		t.Fatalf("IsBlacklisted: %v", err)
	}
	if !blacklisted {
		t.Fatal("expected token to be blacklisted")
	}

	// Fast-forward past expiry
	mr.FastForward(3 * time.Minute)

	blacklisted, err = bl.IsBlacklisted(ctx, jti)
	if err != nil {
		t.Fatalf("IsBlacklisted after expiry: %v", err)
	}
	if blacklisted {
		t.Fatal("expected token blacklist entry to have expired")
	}
}

func TestBlacklistUserTokens(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	userID := "user-42"
	issuedBefore := time.Now()
	ttl := 10 * time.Minute

	if err := bl.BlacklistUserTokens(ctx, userID, issuedBefore, ttl); err != nil {
		t.Fatalf("BlacklistUserTokens: %v", err)
	}

	// Token issued before the blacklist time should be blacklisted
	oldTokenTime := issuedBefore.Add(-1 * time.Minute)
	blacklisted, err := bl.IsUserTokenBlacklisted(ctx, userID, oldTokenTime)
	if err != nil {
		t.Fatalf("IsUserTokenBlacklisted: %v", err)
	}
	if !blacklisted {
		t.Fatal("expected old token to be blacklisted")
	}

	// Token issued after the blacklist time should NOT be blacklisted
	newTokenTime := issuedBefore.Add(1 * time.Minute)
	blacklisted, err = bl.IsUserTokenBlacklisted(ctx, userID, newTokenTime)
	if err != nil {
		t.Fatalf("IsUserTokenBlacklisted: %v", err)
	}
	if blacklisted {
		t.Fatal("expected new token to not be blacklisted")
	}
}

func TestIsUserTokenBlacklisted_NoEntry(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	blacklisted, err := bl.IsUserTokenBlacklisted(ctx, "no-such-user", time.Now())
	if err != nil {
		t.Fatalf("IsUserTokenBlacklisted: %v", err)
	}
	if blacklisted {
		t.Fatal("expected no blacklist for unknown user")
	}
}

func TestClearUserBlacklist(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	userID := "user-clear"
	if err := bl.BlacklistUserTokens(ctx, userID, time.Now(), 10*time.Minute); err != nil {
		t.Fatalf("BlacklistUserTokens: %v", err)
	}

	if err := bl.ClearUserBlacklist(ctx, userID); err != nil {
		t.Fatalf("ClearUserBlacklist: %v", err)
	}

	// After clearing, old tokens should no longer be blacklisted
	blacklisted, err := bl.IsUserTokenBlacklisted(ctx, userID, time.Now().Add(-5*time.Minute))
	if err != nil {
		t.Fatalf("IsUserTokenBlacklisted: %v", err)
	}
	if blacklisted {
		t.Fatal("expected user blacklist to be cleared")
	}
}

func TestGetBlacklistCount(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	expiresAt := time.Now().Add(10 * time.Minute)
	for i := 0; i < 5; i++ {
		jti := "count-token-" + string(rune('a'+i))
		if err := bl.BlacklistToken(ctx, jti, expiresAt, "test"); err != nil {
			t.Fatalf("BlacklistToken[%d]: %v", i, err)
		}
	}

	count, err := bl.GetBlacklistCount(ctx)
	if err != nil {
		t.Fatalf("GetBlacklistCount: %v", err)
	}
	if count != 5 {
		t.Fatalf("expected count 5, got %d", count)
	}
}

func TestGetBlacklistCount_Empty(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	count, err := bl.GetBlacklistCount(ctx)
	if err != nil {
		t.Fatalf("GetBlacklistCount: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected count 0, got %d", count)
	}
}

func TestValidateToken_Valid(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	err := bl.ValidateToken(ctx, TokenValidator{
		JTI:      "valid-jti",
		UserID:   "user-1",
		IssuedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
}

func TestValidateToken_BlacklistedByJTI(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	jti := "blacklisted-jti"
	expiresAt := time.Now().Add(10 * time.Minute)
	if err := bl.BlacklistToken(ctx, jti, expiresAt, "logout"); err != nil {
		t.Fatalf("BlacklistToken: %v", err)
	}

	err := bl.ValidateToken(ctx, TokenValidator{
		JTI:      jti,
		UserID:   "user-1",
		IssuedAt: time.Now(),
	})
	if !errors.Is(err, ErrTokenBlacklisted) {
		t.Fatalf("expected ErrTokenBlacklisted, got %v", err)
	}
}

func TestValidateToken_BlacklistedByUser(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	userID := "user-validate"
	blacklistTime := time.Now()
	if err := bl.BlacklistUserTokens(ctx, userID, blacklistTime, 10*time.Minute); err != nil {
		t.Fatalf("BlacklistUserTokens: %v", err)
	}

	err := bl.ValidateToken(ctx, TokenValidator{
		JTI:      "some-jti",
		UserID:   userID,
		IssuedAt: blacklistTime.Add(-1 * time.Minute), // issued before blacklist
	})
	if !errors.Is(err, ErrTokenBlacklisted) {
		t.Fatalf("expected ErrTokenBlacklisted, got %v", err)
	}
}

func TestValidateToken_EmptyJTI(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	// With empty JTI, only user-level check runs.
	// No user blacklist entry, so it should pass.
	err := bl.ValidateToken(ctx, TokenValidator{
		JTI:      "",
		UserID:   "user-x",
		IssuedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("ValidateToken with empty JTI: %v", err)
	}
}

func TestValidateToken_EmptyUserID(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	// With empty UserID, only JTI check runs.
	err := bl.ValidateToken(ctx, TokenValidator{
		JTI:      "some-jti",
		UserID:   "",
		IssuedAt: time.Now(),
	})
	if err != nil {
		t.Fatalf("ValidateToken with empty UserID: %v", err)
	}
}

func TestValidateToken_ZeroIssuedAt(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)
	ctx := context.Background()

	userID := "user-zero-iat"
	if err := bl.BlacklistUserTokens(ctx, userID, time.Now(), 10*time.Minute); err != nil {
		t.Fatalf("BlacklistUserTokens: %v", err)
	}

	// Zero IssuedAt should skip user-level check (per the !v.IssuedAt.IsZero() guard)
	err := bl.ValidateToken(ctx, TokenValidator{
		JTI:      "some-jti",
		UserID:   userID,
		IssuedAt: time.Time{},
	})
	if err != nil {
		t.Fatalf("ValidateToken with zero IssuedAt: %v", err)
	}
}

func TestBlacklistKey(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)

	key := bl.blacklistKey("abc-123")
	expected := "jwt:blacklist:abc-123"
	if key != expected {
		t.Fatalf("expected key %q, got %q", expected, key)
	}
}

func TestUserBlacklistKey(t *testing.T) {
	client := newTestClient(t)
	bl := NewJWTBlacklist(client)

	key := bl.userBlacklistKey("user-42")
	expected := "jwt:blacklist:user:user-42"
	if key != expected {
		t.Fatalf("expected key %q, got %q", expected, key)
	}
}
