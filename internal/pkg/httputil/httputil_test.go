// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package httputil

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apperrors "github.com/fr4nsys/usulnet/internal/pkg/errors"
)

// ============================================================================
// JSONResponse
// ============================================================================

func TestJSONResponse(t *testing.T) {
	w := httptest.NewRecorder()
	JSONResponse(w, http.StatusOK, map[string]string{"key": "value"})

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if body["key"] != "value" {
		t.Errorf("body[key] = %q, want 'value'", body["key"])
	}
}

func TestJSONResponse_NilData(t *testing.T) {
	w := httptest.NewRecorder()
	JSONResponse(w, http.StatusNoContent, nil)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNoContent)
	}
	if w.Body.Len() != 0 {
		t.Errorf("body should be empty for nil data, got %d bytes", w.Body.Len())
	}
}

// ============================================================================
// ErrorResponse
// ============================================================================

func TestErrorResponse(t *testing.T) {
	w := httptest.NewRecorder()
	ErrorResponse(w, http.StatusBadRequest, "invalid input")

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if body["error"] != true {
		t.Error("body.error should be true")
	}
	if body["message"] != "invalid input" {
		t.Errorf("body.message = %v, want 'invalid input'", body["message"])
	}
	if int(body["status"].(float64)) != http.StatusBadRequest {
		t.Errorf("body.status = %v, want %d", body["status"], http.StatusBadRequest)
	}
}

// ============================================================================
// HandleError
// ============================================================================

func TestHandleError_Nil(t *testing.T) {
	w := httptest.NewRecorder()
	HandleError(w, nil)
	// Should not write anything
	if w.Code != http.StatusOK {
		t.Errorf("HandleError(nil) should not change status, got %d", w.Code)
	}
}

func TestHandleError_NotFoundError(t *testing.T) {
	w := httptest.NewRecorder()
	HandleError(w, apperrors.NewNotFoundError("user"))

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

func TestHandleError_AlreadyExistsError(t *testing.T) {
	w := httptest.NewRecorder()
	HandleError(w, apperrors.NewAlreadyExistsError("email"))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", w.Code, http.StatusConflict)
	}
}

func TestHandleError_ValidationError(t *testing.T) {
	w := httptest.NewRecorder()
	HandleError(w, apperrors.NewValidationError("invalid"))

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestHandleError_UnauthorizedError(t *testing.T) {
	w := httptest.NewRecorder()
	HandleError(w, apperrors.NewUnauthorizedError("no token"))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestHandleError_ForbiddenError(t *testing.T) {
	w := httptest.NewRecorder()
	HandleError(w, apperrors.NewForbiddenError("denied"))

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
}

func TestHandleError_ConflictError(t *testing.T) {
	w := httptest.NewRecorder()
	HandleError(w, apperrors.NewConflictError("duplicate"))

	if w.Code != http.StatusConflict {
		t.Errorf("status = %d, want %d", w.Code, http.StatusConflict)
	}
}

func TestHandleError_InternalError(t *testing.T) {
	w := httptest.NewRecorder()
	HandleError(w, apperrors.NewInternalError("crash"))

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", w.Code, http.StatusInternalServerError)
	}
}

func TestHandleError_GenericError(t *testing.T) {
	w := httptest.NewRecorder()
	HandleError(w, http.ErrNoCookie)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d for generic error", w.Code, http.StatusInternalServerError)
	}
}

// ============================================================================
// PaginatedResponse
// ============================================================================

func TestPaginatedResponse(t *testing.T) {
	w := httptest.NewRecorder()
	data := []string{"a", "b", "c"}
	PaginatedResponse(w, data, 100, 1, 10)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	pagination, ok := body["pagination"].(map[string]interface{})
	if !ok {
		t.Fatal("pagination should be a map")
	}
	if int(pagination["total"].(float64)) != 100 {
		t.Errorf("total = %v, want 100", pagination["total"])
	}
	if int(pagination["page"].(float64)) != 1 {
		t.Errorf("page = %v, want 1", pagination["page"])
	}
	if int(pagination["per_page"].(float64)) != 10 {
		t.Errorf("per_page = %v, want 10", pagination["per_page"])
	}
	if int(pagination["total_pages"].(float64)) != 10 {
		t.Errorf("total_pages = %v, want 10", pagination["total_pages"])
	}
	if pagination["has_next"] != true {
		t.Error("has_next should be true for page 1 of 10")
	}
	if pagination["has_prev"] != false {
		t.Error("has_prev should be false for page 1")
	}
}

func TestPaginatedResponse_LastPage(t *testing.T) {
	w := httptest.NewRecorder()
	PaginatedResponse(w, []string{}, 25, 3, 10)

	var body map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &body)
	pagination := body["pagination"].(map[string]interface{})

	if pagination["has_next"] != false {
		t.Error("has_next should be false for last page")
	}
	if pagination["has_prev"] != true {
		t.Error("has_prev should be true for page 3")
	}
}

// ============================================================================
// QueryInt / QueryBool
// ============================================================================

func TestQueryInt(t *testing.T) {
	r := httptest.NewRequest("GET", "/test?page=5&bad=abc", nil)

	if got := QueryInt(r, "page", 1); got != 5 {
		t.Errorf("QueryInt(page) = %d, want 5", got)
	}
	if got := QueryInt(r, "missing", 1); got != 1 {
		t.Errorf("QueryInt(missing) = %d, want 1 (default)", got)
	}
	if got := QueryInt(r, "bad", 1); got != 1 {
		t.Errorf("QueryInt(bad) = %d, want 1 (default for invalid)", got)
	}
}

func TestQueryBool(t *testing.T) {
	r := httptest.NewRequest("GET", "/test?a=true&b=1&c=yes&d=false&e=0", nil)

	if !QueryBool(r, "a") {
		t.Error("QueryBool('true') should be true")
	}
	if !QueryBool(r, "b") {
		t.Error("QueryBool('1') should be true")
	}
	if !QueryBool(r, "c") {
		t.Error("QueryBool('yes') should be true")
	}
	if QueryBool(r, "d") {
		t.Error("QueryBool('false') should be false")
	}
	if QueryBool(r, "e") {
		t.Error("QueryBool('0') should be false")
	}
	if QueryBool(r, "missing") {
		t.Error("QueryBool(missing) should be false")
	}
}

// ============================================================================
// BindJSON
// ============================================================================

func TestBindJSON(t *testing.T) {
	body := strings.NewReader(`{"name":"test","count":42}`)
	r := httptest.NewRequest("POST", "/test", body)

	var result struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	if err := BindJSON(r, &result); err != nil {
		t.Fatalf("BindJSON() error: %v", err)
	}
	if result.Name != "test" {
		t.Errorf("Name = %q, want 'test'", result.Name)
	}
	if result.Count != 42 {
		t.Errorf("Count = %d, want 42", result.Count)
	}
}

func TestBindJSON_NilBody(t *testing.T) {
	r := httptest.NewRequest("GET", "/test", nil)
	r.Body = nil

	var result map[string]string
	if err := BindJSON(r, &result); err == nil {
		t.Error("BindJSON should error for nil body")
	}
}

func TestBindJSON_InvalidJSON(t *testing.T) {
	body := strings.NewReader("not json")
	r := httptest.NewRequest("POST", "/test", body)

	var result map[string]string
	if err := BindJSON(r, &result); err == nil {
		t.Error("BindJSON should error for invalid JSON")
	}
}

// ============================================================================
// Created / NoContent / Accepted
// ============================================================================

func TestCreated(t *testing.T) {
	w := httptest.NewRecorder()
	Created(w, "/api/v1/users/123", map[string]string{"id": "123"})

	if w.Code != http.StatusCreated {
		t.Errorf("status = %d, want %d", w.Code, http.StatusCreated)
	}
	if loc := w.Header().Get("Location"); loc != "/api/v1/users/123" {
		t.Errorf("Location = %q, want '/api/v1/users/123'", loc)
	}
}

func TestCreated_EmptyLocation(t *testing.T) {
	w := httptest.NewRecorder()
	Created(w, "", map[string]string{"id": "123"})

	if loc := w.Header().Get("Location"); loc != "" {
		t.Errorf("Location = %q, want empty", loc)
	}
}

func TestNoContent(t *testing.T) {
	w := httptest.NewRecorder()
	NoContent(w)

	if w.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNoContent)
	}
}

func TestAccepted(t *testing.T) {
	w := httptest.NewRecorder()
	Accepted(w, map[string]string{"status": "processing"})

	if w.Code != http.StatusAccepted {
		t.Errorf("status = %d, want %d", w.Code, http.StatusAccepted)
	}
}
