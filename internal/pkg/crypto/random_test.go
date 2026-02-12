// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package crypto

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

// ============================================================================
// RandomBytes
// ============================================================================

func TestRandomBytes(t *testing.T) {
	b, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes() error: %v", err)
	}
	if len(b) != 32 {
		t.Errorf("RandomBytes() length = %d, want 32", len(b))
	}
}

func TestRandomBytes_Unique(t *testing.T) {
	b1, _ := RandomBytes(16)
	b2, _ := RandomBytes(16)
	if string(b1) == string(b2) {
		t.Error("RandomBytes should produce unique outputs")
	}
}

// ============================================================================
// RandomHex
// ============================================================================

func TestRandomHex(t *testing.T) {
	s, err := RandomHex(16)
	if err != nil {
		t.Fatalf("RandomHex() error: %v", err)
	}
	// 16 bytes = 32 hex chars
	if len(s) != 32 {
		t.Errorf("RandomHex(16) length = %d, want 32", len(s))
	}
	// Should be valid hex
	if _, err := hex.DecodeString(s); err != nil {
		t.Errorf("RandomHex output is not valid hex: %v", err)
	}
}

// ============================================================================
// RandomBase64 / RandomBase64Raw
// ============================================================================

func TestRandomBase64(t *testing.T) {
	s, err := RandomBase64(32)
	if err != nil {
		t.Fatalf("RandomBase64() error: %v", err)
	}
	if s == "" {
		t.Fatal("RandomBase64() returned empty string")
	}
	// Should be valid URL-safe base64
	if _, err := base64.URLEncoding.DecodeString(s); err != nil {
		t.Errorf("RandomBase64 output is not valid URL-safe base64: %v", err)
	}
}

func TestRandomBase64Raw(t *testing.T) {
	s, err := RandomBase64Raw(32)
	if err != nil {
		t.Fatalf("RandomBase64Raw() error: %v", err)
	}
	if s == "" {
		t.Fatal("RandomBase64Raw() returned empty string")
	}
	// Should be valid standard base64
	if _, err := base64.StdEncoding.DecodeString(s); err != nil {
		t.Errorf("RandomBase64Raw output is not valid standard base64: %v", err)
	}
}

// ============================================================================
// GenerateAPIKey
// ============================================================================

func TestGenerateAPIKey(t *testing.T) {
	key, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey() error: %v", err)
	}
	// 32 bytes = 64 hex chars
	if len(key) != 64 {
		t.Errorf("GenerateAPIKey() length = %d, want 64", len(key))
	}
	if _, err := hex.DecodeString(key); err != nil {
		t.Errorf("GenerateAPIKey output is not valid hex: %v", err)
	}
}

func TestGenerateAPIKey_Unique(t *testing.T) {
	k1, _ := GenerateAPIKey()
	k2, _ := GenerateAPIKey()
	if k1 == k2 {
		t.Error("GenerateAPIKey should produce unique keys")
	}
}

// ============================================================================
// GenerateToken / GenerateRefreshToken / GenerateSecret / GenerateAgentToken
// ============================================================================

func TestGenerateToken(t *testing.T) {
	token, err := GenerateToken()
	if err != nil {
		t.Fatalf("GenerateToken() error: %v", err)
	}
	if token == "" {
		t.Fatal("GenerateToken() returned empty string")
	}
}

func TestGenerateRefreshToken(t *testing.T) {
	token, err := GenerateRefreshToken()
	if err != nil {
		t.Fatalf("GenerateRefreshToken() error: %v", err)
	}
	if token == "" {
		t.Fatal("GenerateRefreshToken() returned empty string")
	}
	// Refresh token should be longer than regular token (48 bytes vs 32)
	regularToken, _ := GenerateToken()
	if len(token) <= len(regularToken) {
		t.Error("refresh token should be longer than regular token")
	}
}

func TestGenerateSecret(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error: %v", err)
	}
	if secret == "" {
		t.Fatal("GenerateSecret() returned empty string")
	}
}

func TestGenerateAgentToken(t *testing.T) {
	token, err := GenerateAgentToken()
	if err != nil {
		t.Fatalf("GenerateAgentToken() error: %v", err)
	}
	// 32 bytes hex = 64 chars
	if len(token) != 64 {
		t.Errorf("GenerateAgentToken() length = %d, want 64", len(token))
	}
}

// ============================================================================
// GenerateNonce
// ============================================================================

func TestGenerateNonce(t *testing.T) {
	nonce, err := GenerateNonce(12)
	if err != nil {
		t.Fatalf("GenerateNonce() error: %v", err)
	}
	if len(nonce) != 12 {
		t.Errorf("GenerateNonce(12) length = %d, want 12", len(nonce))
	}
}

// ============================================================================
// RandomInt / RandomIntRange
// ============================================================================

func TestRandomInt(t *testing.T) {
	for i := 0; i < 100; i++ {
		n, err := RandomInt(10)
		if err != nil {
			t.Fatalf("RandomInt() error: %v", err)
		}
		if n < 0 || n >= 10 {
			t.Errorf("RandomInt(10) = %d, want [0, 10)", n)
		}
	}
}

func TestRandomIntRange(t *testing.T) {
	for i := 0; i < 100; i++ {
		n, err := RandomIntRange(5, 10)
		if err != nil {
			t.Fatalf("RandomIntRange() error: %v", err)
		}
		if n < 5 || n > 10 {
			t.Errorf("RandomIntRange(5, 10) = %d, want [5, 10]", n)
		}
	}
}

func TestRandomIntRange_SwapsMinMax(t *testing.T) {
	// When min > max, should swap
	n, err := RandomIntRange(10, 5)
	if err != nil {
		t.Fatalf("RandomIntRange(10, 5) error: %v", err)
	}
	if n < 5 || n > 10 {
		t.Errorf("RandomIntRange(10, 5) = %d, should be in [5, 10]", n)
	}
}

// ============================================================================
// RandomString / RandomAlphanumeric / RandomNumeric
// ============================================================================

func TestRandomString(t *testing.T) {
	s, err := RandomString(20, "abc")
	if err != nil {
		t.Fatalf("RandomString() error: %v", err)
	}
	if len(s) != 20 {
		t.Errorf("RandomString() length = %d, want 20", len(s))
	}
	for _, c := range s {
		if c != 'a' && c != 'b' && c != 'c' {
			t.Errorf("RandomString() contains char %c not in charset", c)
		}
	}
}

func TestRandomString_DefaultCharset(t *testing.T) {
	s, err := RandomString(16, "")
	if err != nil {
		t.Fatalf("RandomString() error: %v", err)
	}
	if len(s) != 16 {
		t.Errorf("RandomString() length = %d, want 16", len(s))
	}
}

func TestRandomAlphanumeric(t *testing.T) {
	s, err := RandomAlphanumeric(32)
	if err != nil {
		t.Fatalf("RandomAlphanumeric() error: %v", err)
	}
	if len(s) != 32 {
		t.Errorf("length = %d, want 32", len(s))
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			t.Errorf("contains non-alphanumeric char: %c", c)
		}
	}
}

func TestRandomNumeric(t *testing.T) {
	s, err := RandomNumeric(8)
	if err != nil {
		t.Fatalf("RandomNumeric() error: %v", err)
	}
	if len(s) != 8 {
		t.Errorf("length = %d, want 8", len(s))
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			t.Errorf("contains non-numeric char: %c", c)
		}
	}
}

// ============================================================================
// MustRandomHex / MustRandomBytes
// ============================================================================

func TestMustRandomHex(t *testing.T) {
	s := MustRandomHex(16)
	if len(s) != 32 {
		t.Errorf("MustRandomHex(16) length = %d, want 32", len(s))
	}
}

func TestMustRandomBytes(t *testing.T) {
	b := MustRandomBytes(16)
	if len(b) != 16 {
		t.Errorf("MustRandomBytes(16) length = %d, want 16", len(b))
	}
}
