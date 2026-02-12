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
// GenerateSecret
// ============================================================================

func TestGenerateSecret(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error: %v", err)
	}
	if secret == "" {
		t.Fatal("GenerateSecret() returned empty string")
	}
	// Base32 without padding, 20 bytes = 32 chars
	if len(secret) != 32 {
		t.Errorf("GenerateSecret() length = %d, want 32", len(secret))
	}
}

func TestGenerateSecret_Unique(t *testing.T) {
	s1, _ := GenerateSecret()
	s2, _ := GenerateSecret()
	if s1 == s2 {
		t.Error("GenerateSecret should produce unique secrets")
	}
}

func TestGenerateSecret_IsBase32(t *testing.T) {
	secret, _ := GenerateSecret()
	// All chars should be valid base32 (A-Z, 2-7)
	for _, c := range strings.ToUpper(secret) {
		if !((c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')) {
			t.Errorf("secret contains non-base32 char: %c", c)
			break
		}
	}
}

// ============================================================================
// GenerateCode
// ============================================================================

func TestGenerateCode(t *testing.T) {
	secret, _ := GenerateSecret()
	code, err := GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode() error: %v", err)
	}
	if len(code) != DefaultDigits {
		t.Errorf("code length = %d, want %d", len(code), DefaultDigits)
	}
	// Should be all digits
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Errorf("code contains non-digit: %c", c)
		}
	}
}

func TestGenerateCode_DeterministicForSameTime(t *testing.T) {
	secret, _ := GenerateSecret()
	now := time.Now()

	c1, _ := GenerateCode(secret, now)
	c2, _ := GenerateCode(secret, now)
	if c1 != c2 {
		t.Error("same secret + same time should produce same code")
	}
}

func TestGenerateCode_DifferentSecretsProduceDifferentCodes(t *testing.T) {
	s1, _ := GenerateSecret()
	s2, _ := GenerateSecret()
	now := time.Now()

	c1, _ := GenerateCode(s1, now)
	c2, _ := GenerateCode(s2, now)
	// Different secrets should almost certainly produce different codes
	// (1 in 1M chance of collision for 6 digits)
	if c1 == c2 {
		t.Log("Warning: different secrets produced same code (possible but unlikely)")
	}
}

func TestGenerateCode_InvalidSecret(t *testing.T) {
	_, err := GenerateCode("!!!invalid!!!", time.Now())
	if err == nil {
		t.Error("GenerateCode with invalid secret should error")
	}
}

// ============================================================================
// Validate
// ============================================================================

func TestValidate_CurrentCode(t *testing.T) {
	secret, _ := GenerateSecret()
	code, _ := GenerateCode(secret, time.Now())

	valid, err := Validate(code, secret)
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if !valid {
		t.Error("Validate should accept the current TOTP code")
	}
}

func TestValidate_WrongCode(t *testing.T) {
	secret, _ := GenerateSecret()

	valid, err := Validate("000000", secret)
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	// "000000" is very unlikely to be the actual code
	// But we can't guarantee it, so just check there's no error
	_ = valid
}

func TestValidate_WrongLength(t *testing.T) {
	secret, _ := GenerateSecret()

	valid, err := Validate("123", secret)
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if valid {
		t.Error("Validate should reject codes with wrong length")
	}
}

func TestValidate_InvalidSecret(t *testing.T) {
	_, err := Validate("123456", "!!!invalid!!!")
	if err == nil {
		t.Error("Validate with invalid secret should error")
	}
}

func TestValidate_AcceptsAdjacentPeriod(t *testing.T) {
	secret, _ := GenerateSecret()
	// Generate code for 30 seconds ago (previous period)
	code, _ := GenerateCode(secret, time.Now().Add(-DefaultPeriod*time.Second))

	valid, err := Validate(code, secret)
	if err != nil {
		t.Fatalf("Validate() error: %v", err)
	}
	if !valid {
		t.Error("Validate should accept code from adjacent time period (skew)")
	}
}

// ============================================================================
// OTPAuthURI
// ============================================================================

func TestOTPAuthURI(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP"
	uri := OTPAuthURI(secret, "user@example.com", "")

	if !strings.HasPrefix(uri, "otpauth://totp/") {
		t.Errorf("URI should start with otpauth://totp/, got: %s", uri)
	}
	if !strings.Contains(uri, "secret="+secret) {
		t.Errorf("URI should contain secret, got: %s", uri)
	}
	if !strings.Contains(uri, "issuer="+DefaultIssuer) {
		t.Errorf("URI should contain default issuer, got: %s", uri)
	}
	if !strings.Contains(uri, "algorithm=SHA1") {
		t.Errorf("URI should specify SHA1 algorithm, got: %s", uri)
	}
	if !strings.Contains(uri, "digits=6") {
		t.Errorf("URI should specify 6 digits, got: %s", uri)
	}
	if !strings.Contains(uri, "period=30") {
		t.Errorf("URI should specify 30s period, got: %s", uri)
	}
}

func TestOTPAuthURI_CustomIssuer(t *testing.T) {
	uri := OTPAuthURI("SECRET", "user", "MyApp")
	if !strings.Contains(uri, "issuer=MyApp") {
		t.Errorf("URI should use custom issuer, got: %s", uri)
	}
}

// ============================================================================
// Constants
// ============================================================================

func TestConstants(t *testing.T) {
	if DefaultDigits != 6 {
		t.Errorf("DefaultDigits = %d, want 6", DefaultDigits)
	}
	if DefaultPeriod != 30 {
		t.Errorf("DefaultPeriod = %d, want 30", DefaultPeriod)
	}
	if DefaultSecretSize != 20 {
		t.Errorf("DefaultSecretSize = %d, want 20", DefaultSecretSize)
	}
	if DefaultIssuer != "usulnet" {
		t.Errorf("DefaultIssuer = %q, want 'usulnet'", DefaultIssuer)
	}
	if DefaultSkew != 1 {
		t.Errorf("DefaultSkew = %d, want 1", DefaultSkew)
	}
}

// ============================================================================
// decodeSecret (internal)
// ============================================================================

func TestDecodeSecret_NormalizesCase(t *testing.T) {
	// Generate a code with lowercase secret
	secret, _ := GenerateSecret()
	lower := strings.ToLower(secret)

	code, err := GenerateCode(lower, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode with lowercase secret error: %v", err)
	}
	if len(code) != DefaultDigits {
		t.Error("lowercase secret should produce valid code")
	}
}

func TestDecodeSecret_HandlesSpaces(t *testing.T) {
	secret, _ := GenerateSecret()
	// Add spaces (common in QR code manual entry)
	spaced := secret[:4] + " " + secret[4:8] + " " + secret[8:]

	code, err := GenerateCode(spaced, time.Now())
	if err != nil {
		t.Fatalf("GenerateCode with spaced secret error: %v", err)
	}
	if len(code) != DefaultDigits {
		t.Error("spaced secret should produce valid code")
	}
}
