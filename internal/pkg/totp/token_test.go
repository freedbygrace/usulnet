// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package totp

import (
	"strings"
	"testing"
	"time"
)

// ============================================================================
// GeneratePendingToken / ValidatePendingToken
// ============================================================================

func TestPendingToken_RoundTrip(t *testing.T) {
	secret := []byte("my-super-secret-key-for-testing!")
	userID := "user-123-abc"

	token := GeneratePendingToken(userID, secret)
	if token == "" {
		t.Fatal("GeneratePendingToken() returned empty")
	}

	// Token should have two parts (payload.signature)
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		t.Errorf("token should have 2 parts, got %d", len(parts))
	}

	gotUserID, err := ValidatePendingToken(token, secret)
	if err != nil {
		t.Fatalf("ValidatePendingToken() error: %v", err)
	}
	if gotUserID != userID {
		t.Errorf("userID = %q, want %q", gotUserID, userID)
	}
}

func TestPendingToken_DifferentSecrets(t *testing.T) {
	secret1 := []byte("secret-one-abcdefgh")
	secret2 := []byte("secret-two-abcdefgh")

	token := GeneratePendingToken("user-1", secret1)

	_, err := ValidatePendingToken(token, secret2)
	if err == nil {
		t.Error("ValidatePendingToken should fail with wrong secret")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("error should mention signature, got: %v", err)
	}
}

func TestPendingToken_InvalidFormat(t *testing.T) {
	secret := []byte("test-secret")

	_, err := ValidatePendingToken("no-dot-here", secret)
	if err == nil {
		t.Error("should fail for invalid token format")
	}
}

func TestPendingToken_TamperedPayload(t *testing.T) {
	secret := []byte("test-secret-key-1234")
	token := GeneratePendingToken("user-1", secret)

	parts := strings.SplitN(token, ".", 2)
	// Tamper with the payload
	tampered := "dGFtcGVyZWQ" + "." + parts[1]

	_, err := ValidatePendingToken(tampered, secret)
	if err == nil {
		t.Error("should fail for tampered payload")
	}
}

func TestPendingToken_TTL(t *testing.T) {
	if PendingTokenTTL != 5*time.Minute {
		t.Errorf("PendingTokenTTL = %v, want 5m", PendingTokenTTL)
	}
}

// ============================================================================
// GeneratePendingToken with various user IDs
// ============================================================================

func TestPendingToken_VariousUserIDs(t *testing.T) {
	secret := []byte("test-secret-for-various-ids")

	userIDs := []string{
		"simple",
		"user-with-dashes",
		"user_with_underscores",
		"550e8400-e29b-41d4-a716-446655440000", // UUID format
		"user@domain.com",
	}

	for _, uid := range userIDs {
		t.Run(uid, func(t *testing.T) {
			token := GeneratePendingToken(uid, secret)
			got, err := ValidatePendingToken(token, secret)
			if err != nil {
				t.Fatalf("ValidatePendingToken() error: %v", err)
			}
			if got != uid {
				t.Errorf("got userID = %q, want %q", got, uid)
			}
		})
	}
}
