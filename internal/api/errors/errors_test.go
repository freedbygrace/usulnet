// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package errors

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ============================================================================
// APIError
// ============================================================================

func TestAPIError_ImplementsErrorInterface(t *testing.T) {
	var _ error = &APIError{}
}

func TestAPIError_Error(t *testing.T) {
	e := &APIError{Status: 404, Code: ErrCodeNotFound, Message: "user not found"}
	if e.Error() != "user not found" {
		t.Errorf("Error() = %q, want %q", e.Error(), "user not found")
	}
}

// ============================================================================
// NewError / NewErrorWithDetails
// ============================================================================

func TestNewError(t *testing.T) {
	e := NewError(http.StatusBadRequest, ErrCodeValidation, "bad input")
	if e.Status != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusBadRequest)
	}
	if e.Code != ErrCodeValidation {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeValidation)
	}
	if e.Message != "bad input" {
		t.Errorf("Message = %q, want %q", e.Message, "bad input")
	}
	if e.Details != nil {
		t.Error("Details should be nil")
	}
}

func TestNewErrorWithDetails(t *testing.T) {
	details := map[string]string{"field": "email"}
	e := NewErrorWithDetails(http.StatusBadRequest, ErrCodeMissingField, "missing", details)
	if e.Details == nil {
		t.Fatal("Details should not be nil")
	}
}

// ============================================================================
// WriteError
// ============================================================================

func TestWriteError(t *testing.T) {
	w := httptest.NewRecorder()
	e := NewError(http.StatusNotFound, ErrCodeNotFound, "not found")
	WriteError(w, e)

	if w.Code != http.StatusNotFound {
		t.Errorf("status code = %d, want %d", w.Code, http.StatusNotFound)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}
	if xct := w.Header().Get("X-Content-Type-Options"); xct != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", xct)
	}

	var body APIError
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if body.Code != ErrCodeNotFound {
		t.Errorf("body.Code = %q, want %q", body.Code, ErrCodeNotFound)
	}
}

func TestWriteErrorWithRequestID(t *testing.T) {
	w := httptest.NewRecorder()
	e := NewError(http.StatusInternalServerError, ErrCodeInternal, "error")
	WriteErrorWithRequestID(w, e, "req-123")

	var body APIError
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}
	if body.RequestID != "req-123" {
		t.Errorf("RequestID = %q, want %q", body.RequestID, "req-123")
	}
}

// ============================================================================
// Authentication error constructors
// ============================================================================

func TestUnauthorized(t *testing.T) {
	e := Unauthorized("")
	if e.Status != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusUnauthorized)
	}
	if e.Code != ErrCodeUnauthorized {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeUnauthorized)
	}
	if e.Message != "Authentication required" {
		t.Errorf("Message = %q, want default message", e.Message)
	}
}

func TestUnauthorized_CustomMessage(t *testing.T) {
	e := Unauthorized("custom msg")
	if e.Message != "custom msg" {
		t.Errorf("Message = %q, want %q", e.Message, "custom msg")
	}
}

func TestInvalidToken(t *testing.T) {
	e := InvalidToken("")
	if e.Status != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusUnauthorized)
	}
	if e.Code != ErrCodeInvalidToken {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeInvalidToken)
	}
}

func TestExpiredToken(t *testing.T) {
	e := ExpiredToken()
	if e.Status != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusUnauthorized)
	}
	if e.Code != ErrCodeExpiredToken {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeExpiredToken)
	}
}

func TestRevokedToken(t *testing.T) {
	e := RevokedToken()
	if e.Status != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusUnauthorized)
	}
	if e.Code != ErrCodeRevokedToken {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeRevokedToken)
	}
}

func TestInvalidAPIKey(t *testing.T) {
	e := InvalidAPIKey()
	if e.Status != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusUnauthorized)
	}
	if e.Code != ErrCodeInvalidAPIKey {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeInvalidAPIKey)
	}
}

func TestInvalidCredentials(t *testing.T) {
	e := InvalidCredentials()
	if e.Status != http.StatusUnauthorized {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusUnauthorized)
	}
	if e.Code != ErrCodeInvalidCredentials {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeInvalidCredentials)
	}
}

// ============================================================================
// Authorization error constructors
// ============================================================================

func TestForbidden(t *testing.T) {
	e := Forbidden("")
	if e.Status != http.StatusForbidden {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusForbidden)
	}
	if e.Code != ErrCodeForbidden {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeForbidden)
	}
	if e.Message != "Access denied" {
		t.Errorf("Message = %q, want default", e.Message)
	}
}

// ============================================================================
// Resource error constructors
// ============================================================================

func TestNotFound(t *testing.T) {
	e := NotFound("container")
	if e.Status != http.StatusNotFound {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusNotFound)
	}
	if !strings.Contains(e.Message, "container") {
		t.Errorf("Message should mention resource, got: %s", e.Message)
	}
}

func TestNotFound_Empty(t *testing.T) {
	e := NotFound("")
	if e.Message != "Resource not found" {
		t.Errorf("Message = %q, want default message", e.Message)
	}
}

func TestContainerNotFound(t *testing.T) {
	e := ContainerNotFound("abc123")
	if e.Status != http.StatusNotFound {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusNotFound)
	}
	if e.Code != ErrCodeContainerNotFound {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeContainerNotFound)
	}
}

func TestImageNotFound(t *testing.T) {
	e := ImageNotFound("nginx:latest")
	if e.Code != ErrCodeImageNotFound {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeImageNotFound)
	}
}

func TestHostNotFound(t *testing.T) {
	e := HostNotFound("host-1")
	if e.Code != ErrCodeHostNotFound {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeHostNotFound)
	}
}

func TestAlreadyExists(t *testing.T) {
	e := AlreadyExists("user")
	if e.Status != http.StatusConflict {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusConflict)
	}
	if e.Code != ErrCodeAlreadyExists {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeAlreadyExists)
	}
}

func TestConflict(t *testing.T) {
	e := Conflict("")
	if e.Status != http.StatusConflict {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusConflict)
	}
	if e.Message != "Resource conflict" {
		t.Errorf("Message = %q, want default", e.Message)
	}
}

// ============================================================================
// Validation error constructors
// ============================================================================

func TestValidationFailed(t *testing.T) {
	errs := ValidationErrors{
		{Field: "email", Message: "required"},
		{Field: "name", Message: "too short"},
	}
	e := ValidationFailed(errs)
	if e.Status != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusBadRequest)
	}
	if e.Code != ErrCodeValidation {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeValidation)
	}
	if e.Details == nil {
		t.Error("Details should contain validation errors")
	}
}

func TestInvalidInput(t *testing.T) {
	e := InvalidInput("")
	if e.Status != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusBadRequest)
	}
	if e.Message != "Invalid input" {
		t.Errorf("Message = %q, want default", e.Message)
	}
}

func TestMissingField(t *testing.T) {
	e := MissingField("username")
	if e.Status != http.StatusBadRequest {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusBadRequest)
	}
	if e.Code != ErrCodeMissingField {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeMissingField)
	}
}

// ============================================================================
// Rate limiting
// ============================================================================

func TestRateLimited(t *testing.T) {
	e := RateLimited(30)
	if e.Status != http.StatusTooManyRequests {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusTooManyRequests)
	}
	if e.Code != ErrCodeRateLimited {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeRateLimited)
	}
}

// ============================================================================
// Server error constructors
// ============================================================================

func TestInternal(t *testing.T) {
	e := Internal("")
	if e.Status != http.StatusInternalServerError {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusInternalServerError)
	}
	if e.Message != "Internal server error" {
		t.Errorf("Message = %q, want default", e.Message)
	}
}

func TestServiceUnavailable(t *testing.T) {
	e := ServiceUnavailable("")
	if e.Status != http.StatusServiceUnavailable {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusServiceUnavailable)
	}
}

func TestDockerError(t *testing.T) {
	e := DockerError("")
	if e.Status != http.StatusInternalServerError {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusInternalServerError)
	}
	if e.Code != ErrCodeDockerError {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeDockerError)
	}
}

func TestHostUnreachable(t *testing.T) {
	e := HostUnreachable("host-1")
	if e.Status != http.StatusServiceUnavailable {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusServiceUnavailable)
	}
	if e.Code != ErrCodeHostUnreachable {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeHostUnreachable)
	}
}

func TestTimeout(t *testing.T) {
	e := Timeout("")
	if e.Status != http.StatusGatewayTimeout {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusGatewayTimeout)
	}
	if e.Message != "Request timed out" {
		t.Errorf("Message = %q, want default", e.Message)
	}
}

// ============================================================================
// License error constructors - critical for license enforcement
// ============================================================================

func TestLicenseRequired_HTTP402(t *testing.T) {
	e := LicenseRequired("multi_node")
	if e.Status != http.StatusPaymentRequired {
		t.Errorf("LicenseRequired Status = %d, want %d (402 Payment Required)", e.Status, http.StatusPaymentRequired)
	}
	if e.Code != ErrCodeLicenseRequired {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeLicenseRequired)
	}
}

func TestLicenseExpired_HTTP402(t *testing.T) {
	e := LicenseExpired()
	if e.Status != http.StatusPaymentRequired {
		t.Errorf("LicenseExpired Status = %d, want %d (402 Payment Required)", e.Status, http.StatusPaymentRequired)
	}
	if e.Code != ErrCodeLicenseExpired {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeLicenseExpired)
	}
}

func TestFeatureDisabled_HTTP403(t *testing.T) {
	e := FeatureDisabled("ldap")
	if e.Status != http.StatusForbidden {
		t.Errorf("FeatureDisabled Status = %d, want %d (403 Forbidden)", e.Status, http.StatusForbidden)
	}
	if e.Code != ErrCodeFeatureDisabled {
		t.Errorf("Code = %q, want %q", e.Code, ErrCodeFeatureDisabled)
	}
}

// ============================================================================
// FromError / FromAppError
// ============================================================================

func TestFromError_Nil(t *testing.T) {
	if FromError(nil) != nil {
		t.Error("FromError(nil) should return nil")
	}
}

func TestFromError_AlreadyAPIError(t *testing.T) {
	orig := NewError(http.StatusNotFound, ErrCodeNotFound, "not found")
	got := FromError(orig)
	if got != orig {
		t.Error("FromError should return same APIError if already API error")
	}
}

func TestFromError_PlainError(t *testing.T) {
	e := FromError(http.ErrNoCookie)
	if e.Status != http.StatusInternalServerError {
		t.Errorf("Status = %d, want %d", e.Status, http.StatusInternalServerError)
	}
}

func TestFromAppError_PlainError(t *testing.T) {
	e := FromAppError(http.ErrNoCookie)
	if e.Status != http.StatusInternalServerError {
		t.Errorf("Status = %d, want %d for plain error", e.Status, http.StatusInternalServerError)
	}
}

// ============================================================================
// ErrorCode constants
// ============================================================================

func TestErrorCodeConstants_NotEmpty(t *testing.T) {
	codes := []ErrorCode{
		ErrCodeUnauthorized, ErrCodeForbidden, ErrCodeInvalidToken,
		ErrCodeExpiredToken, ErrCodeRevokedToken, ErrCodeInvalidAPIKey,
		ErrCodeSessionExpired, ErrCodeInvalidCredentials,
		ErrCodeValidation, ErrCodeInvalidInput, ErrCodeMissingField, ErrCodeInvalidFormat,
		ErrCodeNotFound, ErrCodeAlreadyExists, ErrCodeConflict, ErrCodeGone,
		ErrCodeRateLimited, ErrCodeTooManyRequests,
		ErrCodeInternal, ErrCodeServiceUnavailable, ErrCodeTimeout, ErrCodeDatabaseError,
		ErrCodeDockerError, ErrCodeContainerNotFound, ErrCodeImageNotFound,
		ErrCodeNetworkNotFound, ErrCodeVolumeNotFound, ErrCodeHostNotFound, ErrCodeHostUnreachable,
		ErrCodeLicenseRequired, ErrCodeLicenseExpired, ErrCodeLicenseInvalid, ErrCodeFeatureDisabled,
	}

	for _, code := range codes {
		if code == "" {
			t.Error("ErrorCode constant should not be empty")
		}
	}
}

// ============================================================================
// License error HTTP status consistency
// ============================================================================

func TestLicenseErrors_HTTPStatusConsistency(t *testing.T) {
	// License-related errors must use HTTP 402 (Payment Required)
	// Feature disabled uses HTTP 403 (Forbidden)
	tests := []struct {
		name   string
		err    *APIError
		status int
	}{
		{"LicenseRequired", LicenseRequired("feature"), http.StatusPaymentRequired},
		{"LicenseExpired", LicenseExpired(), http.StatusPaymentRequired},
		{"FeatureDisabled", FeatureDisabled("ldap"), http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Status != tt.status {
				t.Errorf("%s Status = %d, want %d", tt.name, tt.err.Status, tt.status)
			}
		})
	}
}
