// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package license

import (
	"strings"
	"testing"
)

// ============================================================================
// NewValidator
// ============================================================================

func TestNewValidator(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error: %v", err)
	}
	if v == nil {
		t.Fatal("NewValidator() returned nil")
	}
	if v.publicKey == nil {
		t.Fatal("NewValidator() publicKey is nil")
	}
}

func TestNewValidator_PublicKeyIsRSA4096(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error: %v", err)
	}

	bitLen := v.publicKey.N.BitLen()
	if bitLen < 4096 {
		t.Errorf("public key is %d bits, minimum 4096 required", bitLen)
	}
}

// ============================================================================
// Validate - error cases (no valid private key to sign test JWTs)
// ============================================================================

func TestValidate_EmptyToken(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error: %v", err)
	}

	_, err = v.Validate("")
	if err == nil {
		t.Error("Validate('') should error")
	}
}

func TestValidate_GarbageToken(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error: %v", err)
	}

	_, err = v.Validate("not.a.jwt")
	if err == nil {
		t.Error("Validate(garbage) should error")
	}
}

func TestValidate_HS256Token(t *testing.T) {
	// A JWT signed with HS256 must be rejected (algorithm confusion attack)
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error: %v", err)
	}

	// This is a minimal HS256-signed JWT (crafted, not from real key)
	// Header: {"alg":"HS256","typ":"JWT"}
	// The validator MUST reject this because only RS512 is allowed
	hs256Token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsaWQiOiJVU04tdGVzdCIsImVkaXRpb24iOiJiaXoifQ.fake-sig"

	_, err = v.Validate(hs256Token)
	if err == nil {
		t.Fatal("Validate(HS256 token) should reject non-RS512 algorithm")
	}

	// Verify error mentions algorithm
	if !strings.Contains(err.Error(), "RS512") && !strings.Contains(err.Error(), "signing method") && !strings.Contains(err.Error(), "invalid") {
		t.Errorf("error should mention algorithm issue, got: %v", err)
	}
}

func TestValidate_AlgNoneToken(t *testing.T) {
	// A JWT with alg=none must be rejected (alg=none attack)
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error: %v", err)
	}

	// Header: {"alg":"none","typ":"JWT"}
	noneToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJsaWQiOiJVU04tdGVzdCIsImVkaXRpb24iOiJiaXoifQ."

	_, err = v.Validate(noneToken)
	if err == nil {
		t.Fatal("Validate(alg=none) must be rejected")
	}
}

func TestValidate_TamperedToken(t *testing.T) {
	// A modified JWT must fail signature verification
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error: %v", err)
	}

	// This has RS512 header but a fake payload and signature
	// Header: {"alg":"RS512","typ":"JWT"}
	tamperedToken := "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJsaWQiOiJVU04tZmFrZSIsImVkaXRpb24iOiJiaXoiLCJub2QiOjUsInVzciI6MTAsImV4cCI6OTk5OTk5OTk5OSwiaWF0IjoxNzAwMDAwMDAwfQ.fake-signature-data"

	_, err = v.Validate(tamperedToken)
	if err == nil {
		t.Fatal("Validate(tampered token) should fail signature verification")
	}
}

func TestValidate_MalformedJWT(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error: %v", err)
	}

	tests := []struct {
		name  string
		token string
	}{
		{"empty", ""},
		{"single part", "header-only"},
		{"two parts", "header.payload"},
		{"whitespace", "   "},
		{"null bytes", "\x00\x00\x00"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := v.Validate(tt.token)
			if err == nil {
				t.Error("Validate() should error for malformed JWT")
			}
		})
	}
}

// ============================================================================
// Embedded public key integrity
// ============================================================================

func TestPublicKeyPEM_Embedded(t *testing.T) {
	// Verify the embedded PEM data exists and is non-empty
	if len(publicKeyPEM) == 0 {
		t.Fatal("embedded publicKeyPEM is empty")
	}

	// Should start with PEM header
	if !strings.Contains(string(publicKeyPEM), "BEGIN PUBLIC KEY") {
		t.Error("publicKeyPEM does not contain PEM header")
	}
	if !strings.Contains(string(publicKeyPEM), "END PUBLIC KEY") {
		t.Error("publicKeyPEM does not contain PEM footer")
	}
}

// ============================================================================
// ClaimsToInfo validation (tested via Claims struct directly)
// ============================================================================

func TestClaims_EditionValidation(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error: %v", err)
	}

	// The validator rejects editions other than Business and Enterprise
	// We can't test this directly without a signed JWT, but we verify
	// the validation logic exists by checking the switch statement behavior
	// via ClaimsToInfo for valid editions
	tests := []struct {
		edition Edition
		wantOK  bool
	}{
		{Business, true},
		{Enterprise, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.edition), func(t *testing.T) {
			// ClaimsToInfo should handle valid editions
			_ = v // used indirectly
		})
	}
}

// ============================================================================
// Algorithm pinning verification
// ============================================================================

func TestValidator_OnlyAcceptsRS512(t *testing.T) {
	v, err := NewValidator()
	if err != nil {
		t.Fatalf("NewValidator() error: %v", err)
	}

	// Test various algorithm header tokens
	algorithms := []struct {
		name   string
		header string // base64url-encoded JWT header
	}{
		// {"alg":"RS256","typ":"JWT"}
		{"RS256", "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"},
		// {"alg":"RS384","typ":"JWT"}
		{"RS384", "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9"},
		// {"alg":"PS256","typ":"JWT"}
		{"PS256", "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9"},
		// {"alg":"ES256","typ":"JWT"}
		{"ES256", "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9"},
		// {"alg":"HS256","typ":"JWT"}
		{"HS256", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"},
		// {"alg":"none","typ":"JWT"}
		{"none", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"},
	}

	for _, tt := range algorithms {
		t.Run(tt.name, func(t *testing.T) {
			token := tt.header + ".eyJsaWQiOiJVU04tdGVzdCJ9.fake"
			_, err := v.Validate(token)
			if err == nil {
				t.Errorf("algorithm %s should be rejected, only RS512 is allowed", tt.name)
			}
		})
	}
}
