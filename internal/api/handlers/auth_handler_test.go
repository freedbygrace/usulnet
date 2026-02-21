// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/api/handlers"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// ============================================================================
// Test helpers
// ============================================================================

// newAuthTestRouter creates a chi router with the AuthHandler routes mounted.
// The authService is nil — tests must not reach service method calls.
func newAuthTestRouter(t *testing.T) chi.Router {
	t.Helper()
	log := logger.Nop()
	h := handlers.NewAuthHandler(nil, log)
	r := chi.NewRouter()
	r.Mount("/auth", h.Routes())
	return r
}

// doAuthRequest performs an HTTP request against the auth test router,
// optionally injecting user claims into context.
func doAuthRequest(t *testing.T, router chi.Router, method, path, body, userID, username, role string) *httptest.ResponseRecorder {
	t.Helper()
	var bodyReader *strings.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}
	var req *http.Request
	if bodyReader != nil {
		req = httptest.NewRequest(method, path, bodyReader)
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, nil)
	}

	if userID != "" {
		req = withUserContext(req, userID, username, role)
	}

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// ============================================================================
// Constructor tests
// ============================================================================

func TestNewAuthHandler_NilService(t *testing.T) {
	log := logger.Nop()
	h := handlers.NewAuthHandler(nil, log)
	if h == nil {
		t.Fatal("NewAuthHandler returned nil with nil service")
	}
}

func TestNewAuthHandler_NilLogger(t *testing.T) {
	h := handlers.NewAuthHandler(nil, nil)
	if h == nil {
		t.Fatal("NewAuthHandler returned nil with nil logger")
	}
}

func TestNewAuthHandler_WithLogger(t *testing.T) {
	log := logger.Nop()
	h := handlers.NewAuthHandler(nil, log)
	if h == nil {
		t.Fatal("NewAuthHandler returned nil")
	}
}

// ============================================================================
// Routes registration tests
// ============================================================================

func TestAuthHandler_Routes_AreRegistered(t *testing.T) {
	router := newAuthTestRouter(t)

	// Verify key routes exist by checking that they don't return 404/405.
	routes := []struct {
		method string
		path   string
	}{
		{"POST", "/auth/login"},
		{"POST", "/auth/refresh"},
		{"POST", "/auth/logout"},
		{"POST", "/auth/logout/all"},
		{"POST", "/auth/logout/others"},
		{"GET", "/auth/sessions"},
		{"DELETE", "/auth/sessions/" + uuid.New().String()},
		{"POST", "/auth/change-password"},
		{"GET", "/auth/me"},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			w := doAuthRequest(t, router, route.method, route.path, "", "", "", "")
			if w.Code == http.StatusNotFound || w.Code == http.StatusMethodNotAllowed {
				t.Errorf("route %s %s returned %d — not registered", route.method, route.path, w.Code)
			}
		})
	}
}

func TestAuthHandler_Routes_ReturnsRouter(t *testing.T) {
	h := handlers.NewAuthHandler(nil, logger.Nop())
	r := h.Routes()
	if r == nil {
		t.Fatal("Routes() returned nil")
	}
}

// ============================================================================
// Request/Response JSON roundtrip tests
// ============================================================================

func TestLoginRequest_JSONRoundtrip(t *testing.T) {
	original := handlers.LoginRequest{
		Username: "admin",
		Password: "secret123",
		TOTPCode: "123456",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal LoginRequest: %v", err)
	}

	var decoded handlers.LoginRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal LoginRequest: %v", err)
	}

	if decoded.Username != original.Username {
		t.Errorf("Username: got %q, want %q", decoded.Username, original.Username)
	}
	if decoded.Password != original.Password {
		t.Errorf("Password: got %q, want %q", decoded.Password, original.Password)
	}
	if decoded.TOTPCode != original.TOTPCode {
		t.Errorf("TOTPCode: got %q, want %q", decoded.TOTPCode, original.TOTPCode)
	}
}

func TestLoginRequest_JSONTags(t *testing.T) {
	req := handlers.LoginRequest{
		Username: "user1",
		Password: "pass1",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}

	if _, ok := raw["username"]; !ok {
		t.Error("expected 'username' JSON key")
	}
	if _, ok := raw["password"]; !ok {
		t.Error("expected 'password' JSON key")
	}
	// totp_code should be omitted when empty
	if _, ok := raw["totp_code"]; ok {
		t.Error("expected 'totp_code' to be omitted when empty")
	}
}

func TestLoginRequest_JSONTags_WithTOTP(t *testing.T) {
	req := handlers.LoginRequest{
		Username: "user1",
		Password: "pass1",
		TOTPCode: "999999",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}

	if raw["totp_code"] != "999999" {
		t.Errorf("expected totp_code=999999, got %v", raw["totp_code"])
	}
}

func TestLoginResponse_JSONRoundtrip(t *testing.T) {
	original := handlers.LoginResponse{
		AccessToken:  "access-token-value",
		RefreshToken: "refresh-token-value",
		ExpiresAt:    "2026-02-20T00:00:00Z",
		User: handlers.UserResponse{
			ID:       uuid.New().String(),
			Username: "admin",
			Role:     "admin",
		},
		RequiresTOTP: false,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal LoginResponse: %v", err)
	}

	var decoded handlers.LoginResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal LoginResponse: %v", err)
	}

	if decoded.AccessToken != original.AccessToken {
		t.Errorf("AccessToken: got %q, want %q", decoded.AccessToken, original.AccessToken)
	}
	if decoded.RefreshToken != original.RefreshToken {
		t.Errorf("RefreshToken: got %q, want %q", decoded.RefreshToken, original.RefreshToken)
	}
	if decoded.ExpiresAt != original.ExpiresAt {
		t.Errorf("ExpiresAt: got %q, want %q", decoded.ExpiresAt, original.ExpiresAt)
	}
	if decoded.User.Username != original.User.Username {
		t.Errorf("User.Username: got %q, want %q", decoded.User.Username, original.User.Username)
	}
	if decoded.RequiresTOTP != original.RequiresTOTP {
		t.Errorf("RequiresTOTP: got %v, want %v", decoded.RequiresTOTP, original.RequiresTOTP)
	}
}

func TestLoginResponse_JSONRoundtrip_RequiresTOTP(t *testing.T) {
	original := handlers.LoginResponse{
		User: handlers.UserResponse{
			ID:       uuid.New().String(),
			Username: "user-with-2fa",
			Role:     "admin",
		},
		RequiresTOTP: true,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}

	if raw["requires_totp"] != true {
		t.Errorf("expected requires_totp=true, got %v", raw["requires_totp"])
	}

	// access_token and refresh_token should be omitted when empty
	if _, ok := raw["access_token"]; ok {
		t.Error("expected access_token to be omitted when empty")
	}
	if _, ok := raw["refresh_token"]; ok {
		t.Error("expected refresh_token to be omitted when empty")
	}
}

func TestRefreshRequest_JSONRoundtrip(t *testing.T) {
	original := handlers.RefreshRequest{
		RefreshToken: "my-refresh-token",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal RefreshRequest: %v", err)
	}

	var decoded handlers.RefreshRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal RefreshRequest: %v", err)
	}

	if decoded.RefreshToken != original.RefreshToken {
		t.Errorf("RefreshToken: got %q, want %q", decoded.RefreshToken, original.RefreshToken)
	}
}

func TestChangePasswordRequest_JSONRoundtrip(t *testing.T) {
	original := handlers.ChangePasswordRequest{
		CurrentPassword: "old-password",
		NewPassword:     "new-password",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal ChangePasswordRequest: %v", err)
	}

	var decoded handlers.ChangePasswordRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal ChangePasswordRequest: %v", err)
	}

	if decoded.CurrentPassword != original.CurrentPassword {
		t.Errorf("CurrentPassword: got %q, want %q", decoded.CurrentPassword, original.CurrentPassword)
	}
	if decoded.NewPassword != original.NewPassword {
		t.Errorf("NewPassword: got %q, want %q", decoded.NewPassword, original.NewPassword)
	}
}

func TestChangePasswordRequest_JSONTags(t *testing.T) {
	req := handlers.ChangePasswordRequest{
		CurrentPassword: "old",
		NewPassword:     "new",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to unmarshal to map: %v", err)
	}

	if _, ok := raw["current_password"]; !ok {
		t.Error("expected 'current_password' JSON key")
	}
	if _, ok := raw["new_password"]; !ok {
		t.Error("expected 'new_password' JSON key")
	}
}

func TestRefreshResponse_JSONRoundtrip(t *testing.T) {
	original := handlers.RefreshResponse{
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		ExpiresAt:    "2026-03-01T12:00:00Z",
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal RefreshResponse: %v", err)
	}

	var decoded handlers.RefreshResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal RefreshResponse: %v", err)
	}

	if decoded.AccessToken != original.AccessToken {
		t.Errorf("AccessToken: got %q, want %q", decoded.AccessToken, original.AccessToken)
	}
	if decoded.RefreshToken != original.RefreshToken {
		t.Errorf("RefreshToken: got %q, want %q", decoded.RefreshToken, original.RefreshToken)
	}
	if decoded.ExpiresAt != original.ExpiresAt {
		t.Errorf("ExpiresAt: got %q, want %q", decoded.ExpiresAt, original.ExpiresAt)
	}
}

func TestSessionResponse_JSONRoundtrip(t *testing.T) {
	original := handlers.SessionResponse{
		ID:        uuid.New().String(),
		UserAgent: "Mozilla/5.0",
		IPAddress: "192.168.1.1",
		CreatedAt: "2026-02-19T10:00:00Z",
		ExpiresAt: "2026-02-20T10:00:00Z",
		IsCurrent: true,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("failed to marshal SessionResponse: %v", err)
	}

	var decoded handlers.SessionResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal SessionResponse: %v", err)
	}

	if decoded.ID != original.ID {
		t.Errorf("ID: got %q, want %q", decoded.ID, original.ID)
	}
	if decoded.UserAgent != original.UserAgent {
		t.Errorf("UserAgent: got %q, want %q", decoded.UserAgent, original.UserAgent)
	}
	if decoded.IPAddress != original.IPAddress {
		t.Errorf("IPAddress: got %q, want %q", decoded.IPAddress, original.IPAddress)
	}
	if decoded.CreatedAt != original.CreatedAt {
		t.Errorf("CreatedAt: got %q, want %q", decoded.CreatedAt, original.CreatedAt)
	}
	if decoded.ExpiresAt != original.ExpiresAt {
		t.Errorf("ExpiresAt: got %q, want %q", decoded.ExpiresAt, original.ExpiresAt)
	}
	if decoded.IsCurrent != original.IsCurrent {
		t.Errorf("IsCurrent: got %v, want %v", decoded.IsCurrent, original.IsCurrent)
	}
}

// ============================================================================
// Login handler: input validation (these fail before reaching authService)
// ============================================================================

func TestAuthHandler_Login_EmptyBody(t *testing.T) {
	router := newAuthTestRouter(t)

	w := doAuthRequest(t, router, "POST", "/auth/login", "", "", "", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuthHandler_Login_InvalidJSON(t *testing.T) {
	router := newAuthTestRouter(t)

	w := doAuthRequest(t, router, "POST", "/auth/login", "{bad json}", "", "", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuthHandler_Login_MissingUsername(t *testing.T) {
	router := newAuthTestRouter(t)
	body := `{"password":"secret"}`

	w := doAuthRequest(t, router, "POST", "/auth/login", body, "", "", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuthHandler_Login_MissingPassword(t *testing.T) {
	router := newAuthTestRouter(t)
	body := `{"username":"admin"}`

	w := doAuthRequest(t, router, "POST", "/auth/login", body, "", "", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuthHandler_Login_EmptyUsername(t *testing.T) {
	router := newAuthTestRouter(t)
	body := `{"username":"","password":"secret"}`

	w := doAuthRequest(t, router, "POST", "/auth/login", body, "", "", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuthHandler_Login_EmptyPassword(t *testing.T) {
	router := newAuthTestRouter(t)
	body := `{"username":"admin","password":""}`

	w := doAuthRequest(t, router, "POST", "/auth/login", body, "", "", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// ============================================================================
// RefreshToken handler: input validation
// ============================================================================

func TestAuthHandler_RefreshToken_EmptyBody(t *testing.T) {
	router := newAuthTestRouter(t)

	w := doAuthRequest(t, router, "POST", "/auth/refresh", "", "", "", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuthHandler_RefreshToken_InvalidJSON(t *testing.T) {
	router := newAuthTestRouter(t)

	w := doAuthRequest(t, router, "POST", "/auth/refresh", "{not valid}", "", "", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuthHandler_RefreshToken_MissingToken(t *testing.T) {
	router := newAuthTestRouter(t)
	body := `{"refresh_token":""}`

	w := doAuthRequest(t, router, "POST", "/auth/refresh", body, "", "", "")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// ============================================================================
// ChangePassword handler: input validation (requires auth context)
// ============================================================================

func TestAuthHandler_ChangePassword_NoAuth(t *testing.T) {
	router := newAuthTestRouter(t)
	body := `{"current_password":"old","new_password":"new"}`

	// Protected route — no user context should be rejected by RequireAuth.
	w := doAuthRequest(t, router, "POST", "/auth/change-password", body, "", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuthHandler_ChangePassword_EmptyBody(t *testing.T) {
	router := newAuthTestRouter(t)

	w := doAuthRequest(t, router, "POST", "/auth/change-password", "", uuid.New().String(), "admin", "admin")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuthHandler_ChangePassword_InvalidJSON(t *testing.T) {
	router := newAuthTestRouter(t)

	w := doAuthRequest(t, router, "POST", "/auth/change-password", "{bad}", uuid.New().String(), "admin", "admin")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuthHandler_ChangePassword_MissingCurrentPassword(t *testing.T) {
	router := newAuthTestRouter(t)
	body := `{"new_password":"newpass123"}`

	w := doAuthRequest(t, router, "POST", "/auth/change-password", body, uuid.New().String(), "admin", "admin")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuthHandler_ChangePassword_MissingNewPassword(t *testing.T) {
	router := newAuthTestRouter(t)
	body := `{"current_password":"oldpass123"}`

	w := doAuthRequest(t, router, "POST", "/auth/change-password", body, uuid.New().String(), "admin", "admin")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// ============================================================================
// Protected routes: require authentication
// ============================================================================

func TestAuthHandler_LogoutAll_NoAuth(t *testing.T) {
	router := newAuthTestRouter(t)

	w := doAuthRequest(t, router, "POST", "/auth/logout/all", "", "", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuthHandler_LogoutOthers_NoAuth(t *testing.T) {
	router := newAuthTestRouter(t)

	w := doAuthRequest(t, router, "POST", "/auth/logout/others", "", "", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuthHandler_GetSessions_NoAuth(t *testing.T) {
	router := newAuthTestRouter(t)

	w := doAuthRequest(t, router, "GET", "/auth/sessions", "", "", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuthHandler_RevokeSession_NoAuth(t *testing.T) {
	router := newAuthTestRouter(t)
	sessionID := uuid.New().String()

	w := doAuthRequest(t, router, "DELETE", "/auth/sessions/"+sessionID, "", "", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuthHandler_GetCurrentUser_NoAuth(t *testing.T) {
	router := newAuthTestRouter(t)

	w := doAuthRequest(t, router, "GET", "/auth/me", "", "", "", "")
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// ============================================================================
// GetCurrentUser handler: with auth context (no service dependency)
// ============================================================================

func TestAuthHandler_GetCurrentUser_WithAuth(t *testing.T) {
	router := newAuthTestRouter(t)
	userID := uuid.New().String()

	w := doAuthRequest(t, router, "GET", "/auth/me", "", userID, "testadmin", "admin")
	assertStatus(t, w, http.StatusOK)

	body := assertJSON(t, w)
	if body["user_id"] != userID {
		t.Errorf("expected user_id=%s, got %v", userID, body["user_id"])
	}
	if body["username"] != "testadmin" {
		t.Errorf("expected username=testadmin, got %v", body["username"])
	}
	if body["role"] != "admin" {
		t.Errorf("expected role=admin, got %v", body["role"])
	}
}

func TestAuthHandler_GetCurrentUser_FieldsPresent(t *testing.T) {
	router := newAuthTestRouter(t)
	userID := uuid.New().String()

	w := doAuthRequest(t, router, "GET", "/auth/me", "", userID, "viewer-user", "viewer")
	assertStatus(t, w, http.StatusOK)

	body := assertJSON(t, w)
	expectedFields := []string{"user_id", "username", "role", "session_id"}
	for _, field := range expectedFields {
		if _, ok := body[field]; !ok {
			t.Errorf("expected field %q in response, not found", field)
		}
	}
}

// ============================================================================
// Logout handler: no panic with nil service when no context/body
// ============================================================================

func TestAuthHandler_Logout_NoAuthNoPanic(t *testing.T) {
	router := newAuthTestRouter(t)

	// Logout without auth context and empty body should succeed with 204.
	// claims will be nil so authService.Logout is never called.
	// ParseJSON on an empty body returns error, so LogoutByRefreshToken is skipped.
	w := doAuthRequest(t, router, "POST", "/auth/logout", "", "", "", "")
	// Should return 204 (NoContent) — the handler calls NoContent unconditionally
	// after the optional cleanup blocks.
	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// ============================================================================
// RevokeSession: invalid UUID parameter
// ============================================================================

func TestAuthHandler_RevokeSession_InvalidUUID(t *testing.T) {
	router := newAuthTestRouter(t)

	w := doAuthRequest(t, router, "DELETE", "/auth/sessions/not-a-uuid", "", uuid.New().String(), "admin", "admin")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// ============================================================================
// Method not allowed: wrong HTTP method for known paths
// ============================================================================

func TestAuthHandler_Login_WrongMethod(t *testing.T) {
	router := newAuthTestRouter(t)

	w := doAuthRequest(t, router, "GET", "/auth/login", "", "", "", "")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuthHandler_Refresh_WrongMethod(t *testing.T) {
	router := newAuthTestRouter(t)

	w := doAuthRequest(t, router, "GET", "/auth/refresh", "", "", "", "")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuthHandler_Me_WrongMethod(t *testing.T) {
	router := newAuthTestRouter(t)

	w := doAuthRequest(t, router, "POST", "/auth/me", "", uuid.New().String(), "admin", "admin")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestAuthHandler_Sessions_WrongMethod(t *testing.T) {
	router := newAuthTestRouter(t)

	w := doAuthRequest(t, router, "POST", "/auth/sessions", "", uuid.New().String(), "admin", "admin")
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d. Body: %s", w.Code, w.Body.String())
	}
}
