// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package handlers_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apierrors "github.com/fr4nsys/usulnet/internal/api/errors"
	"github.com/fr4nsys/usulnet/internal/api/handlers"
)

func TestBaseHandler_JSON(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	w := httptest.NewRecorder()
	h.JSON(w, http.StatusOK, map[string]string{"key": "value"})

	assertStatus(t, w, http.StatusOK)
	body := assertJSON(t, w)
	if body["key"] != "value" {
		t.Errorf("expected key=value, got %v", body["key"])
	}
}

func TestBaseHandler_JSON_NilData(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	w := httptest.NewRecorder()
	h.JSON(w, http.StatusNoContent, nil)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}

func TestBaseHandler_Created(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	w := httptest.NewRecorder()
	h.Created(w, map[string]string{"id": "123"})

	assertStatus(t, w, http.StatusCreated)
	body := assertJSON(t, w)
	if body["id"] != "123" {
		t.Errorf("expected id=123, got %v", body["id"])
	}
}

func TestBaseHandler_OK(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	w := httptest.NewRecorder()
	h.OK(w, map[string]string{"status": "ok"})

	assertStatus(t, w, http.StatusOK)
}

func TestBaseHandler_NoContent(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	w := httptest.NewRecorder()
	h.NoContent(w)

	if w.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d", w.Code)
	}
}

func TestBaseHandler_BadRequest(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	w := httptest.NewRecorder()
	h.BadRequest(w, "invalid input")

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

func TestBaseHandler_NotFound(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	w := httptest.NewRecorder()
	h.NotFound(w, "container")

	assertStatus(t, w, http.StatusNotFound)
}

func TestBaseHandler_Forbidden(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	w := httptest.NewRecorder()
	h.Forbidden(w, "access denied")

	assertStatus(t, w, http.StatusForbidden)
}

func TestBaseHandler_HandleError_WrappedAPIError(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	w := httptest.NewRecorder()
	h.HandleError(w, fmt.Errorf("context: %w", apierrors.Forbidden("wrapped forbidden")))

	assertStatus(t, w, http.StatusForbidden)
	assertErrorCode(t, w, string(apierrors.ErrCodeForbidden))
}

func TestBaseHandler_ParseJSON_ValidInput(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	body := `{"name": "test", "value": 42}`
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")

	var result struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	err := h.ParseJSON(r, &result)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if result.Name != "test" {
		t.Errorf("expected name=test, got %s", result.Name)
	}
	if result.Value != 42 {
		t.Errorf("expected value=42, got %d", result.Value)
	}
}

func TestBaseHandler_ParseJSON_EmptyBody(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	r := httptest.NewRequest(http.MethodPost, "/", nil)

	var result struct{}
	err := h.ParseJSON(r, &result)
	if err == nil {
		t.Error("expected error for empty body")
	}
}

func TestBaseHandler_ParseJSON_InvalidJSON(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("not json"))
	r.Header.Set("Content-Type", "application/json")

	var result struct{}
	err := h.ParseJSON(r, &result)
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestBaseHandler_GetPagination_Defaults(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	params := h.GetPagination(r)

	if params.Page != 1 {
		t.Errorf("expected default page=1, got %d", params.Page)
	}
	if params.PerPage != 20 {
		t.Errorf("expected default per_page=20, got %d", params.PerPage)
	}
	if params.Offset != 0 {
		t.Errorf("expected default offset=0, got %d", params.Offset)
	}
}

func TestBaseHandler_GetPagination_Custom(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	r := httptest.NewRequest(http.MethodGet, "/?page=3&per_page=50", nil)
	params := h.GetPagination(r)

	if params.Page != 3 {
		t.Errorf("expected page=3, got %d", params.Page)
	}
	if params.PerPage != 50 {
		t.Errorf("expected per_page=50, got %d", params.PerPage)
	}
	if params.Offset != 100 {
		t.Errorf("expected offset=100, got %d", params.Offset)
	}
}

func TestBaseHandler_GetPagination_MaxPerPage(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	r := httptest.NewRequest(http.MethodGet, "/?per_page=999", nil)
	params := h.GetPagination(r)

	if params.PerPage != 100 {
		t.Errorf("expected clamped per_page=100, got %d", params.PerPage)
	}
}

func TestBaseHandler_GetSort_Defaults(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	sort := h.GetSort(r, "created_at")

	if sort.Field != "created_at" {
		t.Errorf("expected default field=created_at, got %s", sort.Field)
	}
	if sort.Order != "asc" {
		t.Errorf("expected default order=asc, got %s", sort.Order)
	}
}

func TestBaseHandler_GetSort_Custom(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	r := httptest.NewRequest(http.MethodGet, "/?sort=name&order=desc", nil)
	sort := h.GetSort(r, "created_at")

	if sort.Field != "name" {
		t.Errorf("expected field=name, got %s", sort.Field)
	}
	if sort.Order != "desc" {
		t.Errorf("expected order=desc, got %s", sort.Order)
	}
}

func TestBaseHandler_GetSort_InvalidOrder(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	r := httptest.NewRequest(http.MethodGet, "/?order=invalid", nil)
	sort := h.GetSort(r, "created_at")

	if sort.Order != "asc" {
		t.Errorf("expected fallback order=asc, got %s", sort.Order)
	}
}

func TestNewPaginatedResponse(t *testing.T) {
	data := []string{"a", "b", "c"}
	params := handlers.PaginationParams{Page: 2, PerPage: 10, Offset: 10}

	resp := handlers.NewPaginatedResponse(data, 25, params)

	if resp.Total != 25 {
		t.Errorf("expected total=25, got %d", resp.Total)
	}
	if resp.Page != 2 {
		t.Errorf("expected page=2, got %d", resp.Page)
	}
	if resp.PerPage != 10 {
		t.Errorf("expected per_page=10, got %d", resp.PerPage)
	}
	if resp.TotalPages != 3 {
		t.Errorf("expected total_pages=3, got %d", resp.TotalPages)
	}

	// Verify JSON serialization
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(b, &parsed); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if parsed["total"] != float64(25) {
		t.Errorf("JSON total expected 25, got %v", parsed["total"])
	}
}

func TestBaseHandler_RequireAdmin(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	tests := []struct {
		name    string
		role    string
		wantErr bool
	}{
		{"admin allowed", "admin", false},
		{"operator denied", "operator", true},
		{"viewer denied", "viewer", true},
		{"empty role denied", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r = withUserContext(r, testUser(), "test", tt.role)

			err := h.RequireAdmin(r)
			if tt.wantErr && err == nil {
				t.Error("expected error but got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error but got: %v", err)
			}
		})
	}
}

func TestBaseHandler_GetUserRole(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	t.Run("with user context", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r = withUserContext(r, testUser(), "admin-user", "admin")

		role := h.GetUserRole(r)
		if role != "admin" {
			t.Errorf("expected role=admin, got %s", role)
		}
	})

	t.Run("without user context", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)

		role := h.GetUserRole(r)
		if role != "" {
			t.Errorf("expected empty role, got %s", role)
		}
	})
}

func TestBaseHandler_QueryParam(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	r := httptest.NewRequest(http.MethodGet, "/?key=value&empty=", nil)

	if got := h.QueryParam(r, "key"); got != "value" {
		t.Errorf("expected value, got %s", got)
	}
	if got := h.QueryParam(r, "empty"); got != "" {
		t.Errorf("expected empty, got %s", got)
	}
	if got := h.QueryParam(r, "missing"); got != "" {
		t.Errorf("expected empty for missing, got %s", got)
	}
}

func TestBaseHandler_QueryParamBool(t *testing.T) {
	h := handlers.NewBaseHandler(nil)

	tests := []struct {
		query    string
		key      string
		def      bool
		expected bool
	}{
		{"?flag=true", "flag", false, true},
		{"?flag=false", "flag", true, false},
		{"?flag=1", "flag", false, true},
		{"?flag=invalid", "flag", true, true},
		{"", "flag", true, true},
	}

	for _, tt := range tests {
		r := httptest.NewRequest(http.MethodGet, "/"+tt.query, nil)
		got := h.QueryParamBool(r, tt.key, tt.def)
		if got != tt.expected {
			t.Errorf("QueryParamBool(%s, %s, %v) = %v, want %v", tt.query, tt.key, tt.def, got, tt.expected)
		}
	}
}
