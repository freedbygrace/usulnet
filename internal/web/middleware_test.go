// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2024-2026 usulnet contributors
// https://github.com/fr4nsys/usulnet

package web

import (
	"context"
	"testing"
)

// ============================================================================
// Context extraction tests
// ============================================================================

func TestGetUserFromContext(t *testing.T) {
	t.Run("returns user when present", func(t *testing.T) {
		user := &UserContext{
			ID:       "test-id",
			Username: "testuser",
			Role:     "admin",
		}
		ctx := context.WithValue(context.Background(), ContextKeyUser, user)
		got := GetUserFromContext(ctx)
		if got == nil {
			t.Fatal("expected user, got nil")
		}
		if got.Username != "testuser" {
			t.Errorf("GetUserFromContext().Username = %q, want %q", got.Username, "testuser")
		}
		if got.Role != "admin" {
			t.Errorf("GetUserFromContext().Role = %q, want %q", got.Role, "admin")
		}
	})

	t.Run("returns nil when not present", func(t *testing.T) {
		ctx := context.Background()
		got := GetUserFromContext(ctx)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("returns nil for wrong type", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyUser, "not-a-user")
		got := GetUserFromContext(ctx)
		if got != nil {
			t.Errorf("expected nil for wrong type, got %v", got)
		}
	})
}

func TestGetThemeFromContext(t *testing.T) {
	t.Run("returns theme when present", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyTheme, "light")
		got := GetThemeFromContext(ctx)
		if got != "light" {
			t.Errorf("GetThemeFromContext() = %q, want %q", got, "light")
		}
	})

	t.Run("returns dark as default", func(t *testing.T) {
		ctx := context.Background()
		got := GetThemeFromContext(ctx)
		if got != "dark" {
			t.Errorf("GetThemeFromContext() = %q, want %q (default)", got, "dark")
		}
	})

	t.Run("returns dark for empty string", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyTheme, "")
		got := GetThemeFromContext(ctx)
		if got != "dark" {
			t.Errorf("GetThemeFromContext() = %q, want %q (default for empty)", got, "dark")
		}
	})
}

func TestGetCSRFTokenFromContext(t *testing.T) {
	t.Run("returns token when present", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyCSRFToken, "abc123token")
		got := GetCSRFTokenFromContext(ctx)
		if got != "abc123token" {
			t.Errorf("GetCSRFTokenFromContext() = %q, want %q", got, "abc123token")
		}
	})

	t.Run("returns empty when not present", func(t *testing.T) {
		ctx := context.Background()
		got := GetCSRFTokenFromContext(ctx)
		if got != "" {
			t.Errorf("GetCSRFTokenFromContext() = %q, want empty", got)
		}
	})
}

func TestGetStatsFromContext(t *testing.T) {
	t.Run("returns stats when present", func(t *testing.T) {
		stats := &GlobalStats{
			ContainersTotal: 10,
			ImagesCount:     20,
		}
		ctx := context.WithValue(context.Background(), ContextKeyStats, stats)
		got := GetStatsFromContext(ctx)
		if got == nil {
			t.Fatal("expected stats, got nil")
		}
		if got.ContainersTotal != 10 {
			t.Errorf("ContainersTotal = %d, want 10", got.ContainersTotal)
		}
	})

	t.Run("returns nil when not present", func(t *testing.T) {
		ctx := context.Background()
		got := GetStatsFromContext(ctx)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
}

func TestGetFlashFromContext(t *testing.T) {
	t.Run("returns flash when present", func(t *testing.T) {
		flash := &FlashMessage{
			Type:    "success",
			Message: "Operation completed",
		}
		ctx := context.WithValue(context.Background(), ContextKeyFlash, flash)
		got := GetFlashFromContext(ctx)
		if got == nil {
			t.Fatal("expected flash, got nil")
		}
		if got.Type != "success" {
			t.Errorf("Flash.Type = %q, want %q", got.Type, "success")
		}
		if got.Message != "Operation completed" {
			t.Errorf("Flash.Message = %q, want %q", got.Message, "Operation completed")
		}
	})

	t.Run("returns nil when not present", func(t *testing.T) {
		ctx := context.Background()
		got := GetFlashFromContext(ctx)
		if got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})
}

func TestGetActiveHostIDFromContext(t *testing.T) {
	t.Run("returns host ID when present", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyActiveHost, "host-123")
		got := GetActiveHostIDFromContext(ctx)
		if got != "host-123" {
			t.Errorf("GetActiveHostIDFromContext() = %q, want %q", got, "host-123")
		}
	})

	t.Run("returns empty when not present", func(t *testing.T) {
		ctx := context.Background()
		got := GetActiveHostIDFromContext(ctx)
		if got != "" {
			t.Errorf("GetActiveHostIDFromContext() = %q, want empty", got)
		}
	})
}

// ============================================================================
// hasLegacyPermission tests
// ============================================================================

func TestHasLegacyPermission(t *testing.T) {
	tests := []struct {
		name       string
		role       string
		permission string
		want       bool
	}{
		// Operator permissions
		{"operator has container:view", "operator", "container:view", true},
		{"operator has container:create", "operator", "container:create", true},
		{"operator has container:exec", "operator", "container:exec", true},
		{"operator has image:pull", "operator", "image:pull", true},
		{"operator has stack:deploy", "operator", "stack:deploy", true},
		{"operator has security:scan", "operator", "security:scan", true},
		{"operator has config:create", "operator", "config:create", true},
		{"operator denied user:create", "operator", "user:create", false},
		{"operator denied settings:update", "operator", "settings:update", false},

		// Viewer permissions (read-only)
		{"viewer has container:view", "viewer", "container:view", true},
		{"viewer has container:logs", "viewer", "container:logs", true},
		{"viewer has image:view", "viewer", "image:view", true},
		{"viewer has host:view", "viewer", "host:view", true},
		{"viewer has backup:view", "viewer", "backup:view", true},
		{"viewer denied container:create", "viewer", "container:create", false},
		{"viewer denied container:start", "viewer", "container:start", false},
		{"viewer denied image:pull", "viewer", "image:pull", false},

		// Unknown/other roles always denied
		{"admin denied (not legacy)", "admin", "container:view", false},
		{"unknown denied", "unknown", "container:view", false},
		{"empty role denied", "", "container:view", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasLegacyPermission(tt.role, tt.permission)
			if got != tt.want {
				t.Errorf("hasLegacyPermission(%q, %q) = %v, want %v",
					tt.role, tt.permission, got, tt.want)
			}
		})
	}
}
