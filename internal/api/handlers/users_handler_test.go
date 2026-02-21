// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/api/handlers"
	"github.com/fr4nsys/usulnet/internal/pkg/logger"
)

// newUserTestRouter creates a chi router with the UserHandler routes mounted.
// The userService is nil — tests must not call through to service methods.
// This is suitable for testing auth enforcement, input validation, and edge cases.
func newUserTestRouter(t *testing.T) chi.Router {
	t.Helper()
	log := logger.Nop()
	h := handlers.NewUserHandler(nil, log)
	r := chi.NewRouter()
	r.Mount("/users", h.Routes())
	return r
}

// doUserRequest performs an HTTP request against the user test router,
// injecting user claims into context via chi middleware.
func doUserRequest(t *testing.T, router chi.Router, method, path, body, userID, username, role string) *httptest.ResponseRecorder {
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
// Auth enforcement: admin-only endpoints reject non-admin users
// ============================================================================

func TestUserHandler_List_RequiresAdmin(t *testing.T) {
	router := newUserTestRouter(t)

	tests := []struct {
		name     string
		role     string
		wantCode int
	}{
		{"viewer gets 403", "viewer", http.StatusForbidden},
		{"operator gets 403", "operator", http.StatusForbidden},
		{"no auth gets 403", "", http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			userID := uuid.New().String()
			if tc.role == "" {
				userID = ""
			}
			w := doUserRequest(t, router, "GET", "/users", "", userID, "testuser", tc.role)
			if w.Code != tc.wantCode {
				t.Errorf("expected %d, got %d. Body: %s", tc.wantCode, w.Code, w.Body.String())
			}
		})
	}
}

func TestUserHandler_Create_RequiresAdmin(t *testing.T) {
	router := newUserTestRouter(t)
	body := `{"username":"newuser","password":"password123"}`

	w := doUserRequest(t, router, "POST", "/users", body, uuid.New().String(), "viewer", "viewer")
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUserHandler_Get_RequiresAdmin(t *testing.T) {
	router := newUserTestRouter(t)
	targetID := uuid.New().String()

	w := doUserRequest(t, router, "GET", "/users/"+targetID, "", uuid.New().String(), "viewer", "viewer")
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUserHandler_Update_RequiresAdmin(t *testing.T) {
	router := newUserTestRouter(t)
	targetID := uuid.New().String()
	body := `{"email":"new@example.com"}`

	w := doUserRequest(t, router, "PUT", "/users/"+targetID, body, uuid.New().String(), "viewer", "viewer")
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUserHandler_Delete_RequiresAdmin(t *testing.T) {
	router := newUserTestRouter(t)
	targetID := uuid.New().String()

	w := doUserRequest(t, router, "DELETE", "/users/"+targetID, "", uuid.New().String(), "viewer", "viewer")
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUserHandler_Activate_RequiresAdmin(t *testing.T) {
	router := newUserTestRouter(t)
	targetID := uuid.New().String()

	w := doUserRequest(t, router, "POST", "/users/"+targetID+"/activate", "", uuid.New().String(), "operator", "operator")
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUserHandler_Deactivate_RequiresAdmin(t *testing.T) {
	router := newUserTestRouter(t)
	targetID := uuid.New().String()

	w := doUserRequest(t, router, "POST", "/users/"+targetID+"/deactivate", "", uuid.New().String(), "operator", "operator")
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUserHandler_Unlock_RequiresAdmin(t *testing.T) {
	router := newUserTestRouter(t)
	targetID := uuid.New().String()

	w := doUserRequest(t, router, "POST", "/users/"+targetID+"/unlock", "", uuid.New().String(), "operator", "operator")
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUserHandler_GetStats_RequiresAdmin(t *testing.T) {
	router := newUserTestRouter(t)

	w := doUserRequest(t, router, "GET", "/users/stats", "", uuid.New().String(), "viewer", "viewer")
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUserHandler_ListAPIKeys_RequiresAdmin(t *testing.T) {
	router := newUserTestRouter(t)
	targetID := uuid.New().String()

	w := doUserRequest(t, router, "GET", "/users/"+targetID+"/api-keys", "", uuid.New().String(), "viewer", "viewer")
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUserHandler_CreateAPIKey_RequiresAdmin(t *testing.T) {
	router := newUserTestRouter(t)
	targetID := uuid.New().String()
	body := `{"name":"test-key"}`

	w := doUserRequest(t, router, "POST", "/users/"+targetID+"/api-keys", body, uuid.New().String(), "viewer", "viewer")
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUserHandler_DeleteAPIKey_RequiresAdmin(t *testing.T) {
	router := newUserTestRouter(t)
	targetID := uuid.New().String()
	keyID := uuid.New().String()

	w := doUserRequest(t, router, "DELETE", "/users/"+targetID+"/api-keys/"+keyID, "", uuid.New().String(), "viewer", "viewer")
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// ============================================================================
// Input validation: Create requires username and password
// ============================================================================

func TestUserHandler_Create_MissingUsername(t *testing.T) {
	router := newUserTestRouter(t)
	body := `{"password":"password123"}`

	w := doUserRequest(t, router, "POST", "/users", body, uuid.New().String(), "admin", "admin")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUserHandler_Create_MissingPassword(t *testing.T) {
	router := newUserTestRouter(t)
	body := `{"username":"newuser"}`

	w := doUserRequest(t, router, "POST", "/users", body, uuid.New().String(), "admin", "admin")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUserHandler_Create_InvalidJSON(t *testing.T) {
	router := newUserTestRouter(t)
	body := `{invalid json}`

	w := doUserRequest(t, router, "POST", "/users", body, uuid.New().String(), "admin", "admin")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUserHandler_Create_EmptyBody(t *testing.T) {
	router := newUserTestRouter(t)

	w := doUserRequest(t, router, "POST", "/users", "", uuid.New().String(), "admin", "admin")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// ============================================================================
// URL parameter validation: invalid UUID
// ============================================================================

func TestUserHandler_Get_InvalidUUID(t *testing.T) {
	router := newUserTestRouter(t)

	w := doUserRequest(t, router, "GET", "/users/not-a-uuid", "", uuid.New().String(), "admin", "admin")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUserHandler_Update_InvalidUUID(t *testing.T) {
	router := newUserTestRouter(t)
	body := `{"email":"new@example.com"}`

	w := doUserRequest(t, router, "PUT", "/users/not-a-uuid", body, uuid.New().String(), "admin", "admin")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUserHandler_Delete_InvalidUUID(t *testing.T) {
	router := newUserTestRouter(t)

	w := doUserRequest(t, router, "DELETE", "/users/not-a-uuid", "", uuid.New().String(), "admin", "admin")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// ============================================================================
// Self-deletion prevention
// ============================================================================

func TestUserHandler_Delete_CannotDeleteSelf(t *testing.T) {
	router := newUserTestRouter(t)
	myID := uuid.New().String()

	w := doUserRequest(t, router, "DELETE", "/users/"+myID, "", myID, "admin", "admin")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "cannot delete your own account") {
		t.Errorf("expected self-deletion error message, got: %s", w.Body.String())
	}
}

// ============================================================================
// Self-deactivation prevention
// ============================================================================

func TestUserHandler_Deactivate_CannotDeactivateSelf(t *testing.T) {
	router := newUserTestRouter(t)
	myID := uuid.New().String()

	w := doUserRequest(t, router, "POST", "/users/"+myID+"/deactivate", "", myID, "admin", "admin")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "cannot deactivate your own account") {
		t.Errorf("expected self-deactivation error message, got: %s", w.Body.String())
	}
}

// ============================================================================
// Profile endpoints (self-service — any authenticated user)
// ============================================================================

func TestUserHandler_GetProfile_RequiresAuth(t *testing.T) {
	router := newUserTestRouter(t)

	// No user in context → GetUserID returns error
	w := doUserRequest(t, router, "GET", "/users/profile", "", "", "", "")
	// Should fail — either 401/403/500 depending on how error is handled
	if w.Code == http.StatusOK {
		t.Error("expected non-200 for unauthenticated profile request")
	}
}

func TestUserHandler_UpdateProfile_InvalidJSON(t *testing.T) {
	router := newUserTestRouter(t)
	body := `{bad json}`

	w := doUserRequest(t, router, "PUT", "/users/profile", body, uuid.New().String(), "viewer", "viewer")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// ============================================================================
// CreateAPIKey input validation
// ============================================================================

func TestUserHandler_CreateAPIKey_MissingName(t *testing.T) {
	router := newUserTestRouter(t)
	targetID := uuid.New().String()
	body := `{}`

	w := doUserRequest(t, router, "POST", "/users/"+targetID+"/api-keys", body, uuid.New().String(), "admin", "admin")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUserHandler_CreateAPIKey_InvalidExpiresAt(t *testing.T) {
	router := newUserTestRouter(t)
	targetID := uuid.New().String()
	body := `{"name":"test-key","expires_at":"not-a-date"}`

	w := doUserRequest(t, router, "POST", "/users/"+targetID+"/api-keys", body, uuid.New().String(), "admin", "admin")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUserHandler_CreateMyAPIKey_MissingName(t *testing.T) {
	router := newUserTestRouter(t)
	body := `{}`

	w := doUserRequest(t, router, "POST", "/users/profile/api-keys", body, uuid.New().String(), "viewer", "viewer")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestUserHandler_CreateMyAPIKey_InvalidExpiresAt(t *testing.T) {
	router := newUserTestRouter(t)
	body := `{"name":"test-key","expires_at":"bad-date"}`

	w := doUserRequest(t, router, "POST", "/users/profile/api-keys", body, uuid.New().String(), "viewer", "viewer")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// ============================================================================
// DeleteMyAPIKey: invalid keyID
// ============================================================================

func TestUserHandler_DeleteMyAPIKey_InvalidUUID(t *testing.T) {
	router := newUserTestRouter(t)

	w := doUserRequest(t, router, "DELETE", "/users/profile/api-keys/not-a-uuid", "", uuid.New().String(), "viewer", "viewer")
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d. Body: %s", w.Code, w.Body.String())
	}
}

// ============================================================================
// Route registration: routes exist
// ============================================================================

func TestUserHandler_Routes_AreRegistered(t *testing.T) {
	router := newUserTestRouter(t)

	// Verify key routes exist by checking that they don't return 404/405
	routes := []struct {
		method string
		path   string
	}{
		{"GET", "/users"},
		{"GET", "/users/stats"},
		{"POST", "/users"},
		{"GET", "/users/" + uuid.New().String()},
		{"PUT", "/users/" + uuid.New().String()},
		{"DELETE", "/users/" + uuid.New().String()},
		{"GET", "/users/profile"},
		{"PUT", "/users/profile"},
		{"GET", "/users/profile/api-keys"},
		{"POST", "/users/profile/api-keys"},
		{"DELETE", "/users/profile/api-keys/" + uuid.New().String()},
	}

	for _, route := range routes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			w := doUserRequest(t, router, route.method, route.path, "", "", "", "")
			// Route exists if we don't get 404 (Method Not Allowed) or 405
			if w.Code == http.StatusNotFound || w.Code == http.StatusMethodNotAllowed {
				t.Errorf("route %s %s returned %d — not registered", route.method, route.path, w.Code)
			}
		})
	}
}
