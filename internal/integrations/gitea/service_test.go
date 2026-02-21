// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package gitea

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ---------------------------------------------------------------------------
// ValidateWebhookSignature tests
// ---------------------------------------------------------------------------

func TestValidateWebhookSignature_Valid(t *testing.T) {
	secret := "my-webhook-secret"
	body := []byte(`{"action":"push","ref":"refs/heads/main"}`)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	signature := hex.EncodeToString(mac.Sum(nil))

	if !ValidateWebhookSignature(secret, body, signature) {
		t.Error("expected valid signature")
	}
}

func TestValidateWebhookSignature_Invalid(t *testing.T) {
	secret := "my-webhook-secret"
	body := []byte(`{"action":"push"}`)

	if ValidateWebhookSignature(secret, body, "invalid-signature") {
		t.Error("expected invalid signature")
	}
}

func TestValidateWebhookSignature_EmptySecret(t *testing.T) {
	if ValidateWebhookSignature("", []byte("body"), "sig") {
		t.Error("expected false for empty secret")
	}
}

func TestValidateWebhookSignature_EmptySignature(t *testing.T) {
	if ValidateWebhookSignature("secret", []byte("body"), "") {
		t.Error("expected false for empty signature")
	}
}

func TestValidateWebhookSignature_TamperedBody(t *testing.T) {
	secret := "secret"
	original := []byte(`{"action":"push"}`)
	tampered := []byte(`{"action":"delete"}`)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(original)
	signature := hex.EncodeToString(mac.Sum(nil))

	if ValidateWebhookSignature(secret, tampered, signature) {
		t.Error("expected false for tampered body")
	}
}

func TestValidateWebhookSignature_WrongSecret(t *testing.T) {
	body := []byte(`test`)

	mac := hmac.New(sha256.New, []byte("secret-a"))
	mac.Write(body)
	signature := hex.EncodeToString(mac.Sum(nil))

	if ValidateWebhookSignature("secret-b", body, signature) {
		t.Error("expected false for wrong secret")
	}
}

// ---------------------------------------------------------------------------
// strPtr tests
// ---------------------------------------------------------------------------

func TestStrPtr_Empty(t *testing.T) {
	if strPtr("") != nil {
		t.Error("strPtr(\"\") should return nil")
	}
}

func TestStrPtr_NonEmpty(t *testing.T) {
	result := strPtr("hello")
	if result == nil {
		t.Fatal("strPtr(\"hello\") returned nil")
	}
	if *result != "hello" {
		t.Errorf("*strPtr = %q, want %q", *result, "hello")
	}
}

func TestStrPtr_Whitespace(t *testing.T) {
	result := strPtr(" ")
	if result == nil {
		t.Fatal("strPtr(\" \") should return non-nil")
	}
	if *result != " " {
		t.Errorf("*strPtr = %q, want %q", *result, " ")
	}
}

// ---------------------------------------------------------------------------
// base64Encode tests
// ---------------------------------------------------------------------------

func TestBase64Encode(t *testing.T) {
	data := []byte("hello world")
	got := base64Encode(data)
	want := base64.StdEncoding.EncodeToString(data)
	if got != want {
		t.Errorf("base64Encode = %q, want %q", got, want)
	}
}

func TestBase64Encode_Empty(t *testing.T) {
	got := base64Encode([]byte{})
	if got != "" {
		t.Errorf("base64Encode(empty) = %q, want empty", got)
	}
}

func TestBase64Encode_Binary(t *testing.T) {
	data := []byte{0x00, 0xFF, 0x80, 0x7F}
	got := base64Encode(data)
	want := base64.StdEncoding.EncodeToString(data)
	if got != want {
		t.Errorf("base64Encode = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// NewService tests
// ---------------------------------------------------------------------------

func TestNewService(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestNewService_WithLogger(t *testing.T) {
	log := logger.Nop()
	svc := NewService(nil, nil, nil, nil, log)
	if svc == nil {
		t.Fatal("expected non-nil service")
	}
}

func TestSetAutoDeployDeps(t *testing.T) {
	svc := NewService(nil, nil, nil, nil, nil)
	svc.SetAutoDeployDeps(nil, nil)
	if svc.autoDeployRepo != nil {
		t.Error("expected nil autoDeployRepo")
	}
}

// ---------------------------------------------------------------------------
// Struct types tests
// ---------------------------------------------------------------------------

func TestCreateConnectionInput_Fields(t *testing.T) {
	input := CreateConnectionInput{
		Name:          "My Gitea",
		URL:           "https://gitea.example.com",
		APIToken:      "token123",
		WebhookSecret: "secret",
	}
	if input.Name != "My Gitea" {
		t.Errorf("Name = %q", input.Name)
	}
	if input.URL != "https://gitea.example.com" {
		t.Errorf("URL = %q", input.URL)
	}
}

func TestTestResult_Fields(t *testing.T) {
	r := TestResult{
		Success:  true,
		Version:  "1.22.0",
		Username: "admin",
		IsAdmin:  true,
	}
	if !r.Success {
		t.Error("Success should be true")
	}
	if r.Version != "1.22.0" {
		t.Errorf("Version = %q", r.Version)
	}
}

func TestTestResult_Error(t *testing.T) {
	r := TestResult{
		Success: false,
		Error:   "connection refused",
	}
	if r.Success {
		t.Error("Success should be false")
	}
	if r.Error != "connection refused" {
		t.Errorf("Error = %q", r.Error)
	}
}
