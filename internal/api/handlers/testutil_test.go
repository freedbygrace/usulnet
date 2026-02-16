// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/fr4nsys/usulnet/internal/api"
	"github.com/fr4nsys/usulnet/internal/api/handlers"
	"github.com/fr4nsys/usulnet/internal/api/middleware"
)

const testJWTSecret = "test-secret-key-for-testing-purposes-only-minimum-32-chars"

// testSuite provides shared test infrastructure for handler tests.
type testSuite struct {
	router  chi.Router
	handler *api.Handlers
}

// setupTestSuite creates a test suite with the system handler configured.
func setupTestSuite(t *testing.T) *testSuite {
	t.Helper()

	systemHandler := handlers.NewSystemHandler("test-version", "test-commit", "2026-01-01T00:00:00Z", nil)

	h := &api.Handlers{
		System: systemHandler,
	}

	config := api.RouterConfig{
		JWTSecret:          testJWTSecret,
		CORSConfig:         middleware.DefaultCORSConfig(),
		RateLimitPerMinute: 1000,
		RequestTimeout:     5 * time.Second,
		MetricsEnabled:     false,
	}

	router := api.NewRouter(config, h)

	return &testSuite{
		router:  router,
		handler: h,
	}
}

// generateTestToken creates a valid JWT token for testing.
func generateTestToken(t *testing.T, userID, username, role string) string {
	t.Helper()

	claims := middleware.UserClaims{
		UserID:   userID,
		Username: username,
		Role:     role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "usulnet-test",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(testJWTSecret))
	if err != nil {
		t.Fatalf("failed to generate test token: %v", err)
	}

	return tokenString
}

// testUser returns a test user UUID.
func testUser() string {
	return uuid.New().String()
}

// doRequest performs an HTTP request against the test router.
func doRequest(t *testing.T, router chi.Router, method, path string, body string, token string) *httptest.ResponseRecorder {
	t.Helper()

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req := httptest.NewRequest(method, path, bodyReader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// assertStatus checks the HTTP status code.
func assertStatus(t *testing.T, w *httptest.ResponseRecorder, expected int) {
	t.Helper()
	if w.Code != expected {
		t.Errorf("expected status %d, got %d. Body: %s", expected, w.Code, w.Body.String())
	}
}

// assertJSON checks that the response is valid JSON and returns the parsed body.
func assertJSON(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	contentType := w.Header().Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		t.Errorf("expected Content-Type application/json, got %s", contentType)
	}

	var result map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Errorf("failed to parse JSON response: %v. Body: %s", err, w.Body.String())
	}
	return result
}

// assertErrorCode checks the error code in the JSON response.
func assertErrorCode(t *testing.T, w *httptest.ResponseRecorder, expectedCode string) {
	t.Helper()
	var errResp struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Errorf("failed to parse error response: %v. Body: %s", err, w.Body.String())
		return
	}
	if errResp.Code != expectedCode {
		t.Errorf("expected error code %q, got %q", expectedCode, errResp.Code)
	}
}

// withUserContext adds user claims to the request context.
func withUserContext(r *http.Request, userID, username, role string) *http.Request {
	claims := &middleware.UserClaims{
		UserID:   userID,
		Username: username,
		Role:     role,
	}
	ctx := context.WithValue(r.Context(), middleware.UserContextKey, claims)
	return r.WithContext(ctx)
}
