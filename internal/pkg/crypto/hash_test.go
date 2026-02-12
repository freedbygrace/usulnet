// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package crypto

import (
	"encoding/hex"
	"strings"
	"testing"
)

// ============================================================================
// HashPassword / CheckPassword
// ============================================================================

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("MyP@ssw0rd!")
	if err != nil {
		t.Fatalf("HashPassword() error: %v", err)
	}
	if hash == "" {
		t.Fatal("HashPassword() returned empty hash")
	}
	// bcrypt hashes start with $2a$ or $2b$
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("hash should be bcrypt format, got: %s", hash[:10])
	}
}

func TestHashPassword_DifferentOutputsForSameInput(t *testing.T) {
	h1, err := HashPassword("password")
	if err != nil {
		t.Fatalf("first HashPassword() error: %v", err)
	}
	h2, err := HashPassword("password")
	if err != nil {
		t.Fatalf("second HashPassword() error: %v", err)
	}
	if h1 == h2 {
		t.Error("bcrypt should produce different hashes for same password (random salt)")
	}
}

func TestCheckPassword(t *testing.T) {
	password := "S3cur3P@ss!"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() error: %v", err)
	}

	if !CheckPassword(password, hash) {
		t.Error("CheckPassword should return true for correct password")
	}
	if CheckPassword("wrong-password", hash) {
		t.Error("CheckPassword should return false for wrong password")
	}
}

// ============================================================================
// HashPasswordWithCost
// ============================================================================

func TestHashPasswordWithCost(t *testing.T) {
	hash, err := HashPasswordWithCost("password", 4)
	if err != nil {
		t.Fatalf("HashPasswordWithCost() error: %v", err)
	}
	if !CheckPassword("password", hash) {
		t.Error("password hashed with custom cost should still verify")
	}
}

func TestHashPasswordWithCost_InvalidCostFallsBackToDefault(t *testing.T) {
	hash, err := HashPasswordWithCost("password", 0)
	if err != nil {
		t.Fatalf("HashPasswordWithCost(0) error: %v", err)
	}
	if !CheckPassword("password", hash) {
		t.Error("password hashed with invalid cost should still verify (fallback)")
	}
}

// ============================================================================
// SHA256 / SHA256String / SHA256Bytes
// ============================================================================

func TestSHA256(t *testing.T) {
	// Known SHA-256 of "hello"
	got := SHA256([]byte("hello"))
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Errorf("SHA256('hello') = %q, want %q", got, want)
	}
}

func TestSHA256String(t *testing.T) {
	got := SHA256String("hello")
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Errorf("SHA256String('hello') = %q, want %q", got, want)
	}
}

func TestSHA256Bytes(t *testing.T) {
	got := SHA256Bytes([]byte("hello"))
	if len(got) != 32 {
		t.Errorf("SHA256Bytes length = %d, want 32", len(got))
	}
	// Verify it matches hex-encoded version
	if hex.EncodeToString(got) != SHA256([]byte("hello")) {
		t.Error("SHA256Bytes and SHA256 should produce consistent output")
	}
}

func TestSHA256_Deterministic(t *testing.T) {
	h1 := SHA256String("test-data")
	h2 := SHA256String("test-data")
	if h1 != h2 {
		t.Error("SHA256 should be deterministic")
	}
}

func TestSHA256_DifferentInputs(t *testing.T) {
	h1 := SHA256String("input1")
	h2 := SHA256String("input2")
	if h1 == h2 {
		t.Error("different inputs should produce different hashes")
	}
}

// ============================================================================
// SHA512 / SHA512String
// ============================================================================

func TestSHA512(t *testing.T) {
	got := SHA512([]byte("hello"))
	if len(got) != 128 { // 64 bytes = 128 hex chars
		t.Errorf("SHA512 hex length = %d, want 128", len(got))
	}
}

func TestSHA512String(t *testing.T) {
	h1 := SHA512String("hello")
	h2 := SHA512String("hello")
	if h1 != h2 {
		t.Error("SHA512String should be deterministic")
	}
	if len(h1) != 128 {
		t.Errorf("SHA512String length = %d, want 128", len(h1))
	}
}

// ============================================================================
// HMAC-SHA256
// ============================================================================

func TestHMACSHA256(t *testing.T) {
	mac := HMACSHA256([]byte("message"), []byte("key"))
	if mac == "" {
		t.Fatal("HMACSHA256 returned empty string")
	}
	// SHA256 HMAC produces 32 bytes = 64 hex chars
	if len(mac) != 64 {
		t.Errorf("HMACSHA256 length = %d, want 64", len(mac))
	}
}

func TestHMACSHA256String(t *testing.T) {
	mac := HMACSHA256String("message", "key")
	if len(mac) != 64 {
		t.Errorf("HMACSHA256String length = %d, want 64", len(mac))
	}
}

func TestHMACSHA256Verify(t *testing.T) {
	msg := []byte("message")
	key := []byte("secret-key")
	mac := HMACSHA256(msg, key)

	if !HMACSHA256Verify(msg, key, mac) {
		t.Error("HMACSHA256Verify should return true for valid MAC")
	}
	if HMACSHA256Verify(msg, key, "invalid-hex") {
		t.Error("HMACSHA256Verify should return false for invalid hex")
	}
	if HMACSHA256Verify([]byte("different"), key, mac) {
		t.Error("HMACSHA256Verify should return false for different message")
	}
	if HMACSHA256Verify(msg, []byte("wrong-key"), mac) {
		t.Error("HMACSHA256Verify should return false for wrong key")
	}
}

// ============================================================================
// HMAC-SHA512
// ============================================================================

func TestHMACSHA512(t *testing.T) {
	mac := HMACSHA512([]byte("message"), []byte("key"))
	// SHA512 HMAC produces 64 bytes = 128 hex chars
	if len(mac) != 128 {
		t.Errorf("HMACSHA512 length = %d, want 128", len(mac))
	}
}

// ============================================================================
// HashAPIKey / CheckAPIKey
// ============================================================================

func TestHashAPIKey(t *testing.T) {
	key := "usn_abcdef0123456789abcdef0123456789"
	hash := HashAPIKey(key)
	if hash == "" {
		t.Fatal("HashAPIKey returned empty")
	}
	if hash == key {
		t.Error("HashAPIKey should not return the plaintext key")
	}
}

func TestCheckAPIKey(t *testing.T) {
	key := "usn_test-api-key-12345"
	hash := HashAPIKey(key)

	if !CheckAPIKey(key, hash) {
		t.Error("CheckAPIKey should return true for matching key")
	}
	if CheckAPIKey("wrong-key", hash) {
		t.Error("CheckAPIKey should return false for wrong key")
	}
}

// ============================================================================
// HashToken / CheckToken
// ============================================================================

func TestHashToken(t *testing.T) {
	token := "refresh-token-abcdef123456"
	hash := HashToken(token)
	if hash == "" {
		t.Fatal("HashToken returned empty")
	}
}

func TestCheckToken(t *testing.T) {
	token := "my-refresh-token"
	hash := HashToken(token)

	if !CheckToken(token, hash) {
		t.Error("CheckToken should return true for matching token")
	}
	if CheckToken("wrong-token", hash) {
		t.Error("CheckToken should return false for wrong token")
	}
}
